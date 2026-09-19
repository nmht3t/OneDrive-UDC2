#!/usr/bin/env python3

import argparse
import json
import os
import tempfile
from pathlib import Path


FIELDS = {
    "tenant_id": "TENANT_ID",
    "client_id": "CLIENT_ID",
    "client_secret": "CLIENT_SECRET",
    "drive_id": "DRIVE_ID",
    "inbox_folder_id": "INBOX_FOLDER_ID",
    "outbox_folder_id": "OUTBOX_FOLDER_ID",
}


def c_string(value):
    if "\0" in value:
        raise ValueError("configuration values cannot contain NUL bytes")
    escaped = []
    for byte in value.encode("utf-8"):
        if byte == ord('"'):
            escaped.append('\\"')
        elif byte == ord("\\"):
            escaped.append("\\\\")
        elif 0x20 <= byte <= 0x7E:
            escaped.append(chr(byte))
        else:
            escaped.append("\\%03o" % byte)
    return '"%s"' % "".join(escaped)


def generate(config_path, output_path):
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    missing = [key for key in FIELDS if not isinstance(config.get(key), str) or not config[key]]
    if missing:
        raise ValueError("missing: %s" % ", ".join(missing))

    lines = [
        "#ifndef ONEDRIVE_UDC2_CONFIG_H",
        "#define ONEDRIVE_UDC2_CONFIG_H",
        "",
    ]
    for key, macro in FIELDS.items():
        lines.append("#define %-18s %s" % (macro, c_string(config[key])))
    lines.extend(["", "#endif", ""])

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    contents = "\n".join(lines)
    try:
        unchanged = output.read_text(encoding="utf-8") == contents
    except FileNotFoundError:
        unchanged = False
    if unchanged:
        os.chmod(output, 0o600)
        print("Unchanged: %s" % output)
        return

    fd, temp_path = tempfile.mkstemp(prefix=output.name + ".", dir=output.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(contents)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, output)
        os.chmod(output, 0o600)
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise

    print("Generated: %s" % output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    generate(args.config, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
