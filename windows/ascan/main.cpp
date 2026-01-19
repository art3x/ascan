#include "pch.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>  // for _beginthreadex
#include <stdio.h>    // for snprintf, sscanf
#include <ctype.h>    // for isdigit()

#include "output.h"
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

int main(int argc, char* argv[]);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow) {
    return main(__argc, __argv);
}

// Global output pointer.
Output* output = NULL;

#define G_THREAD_LIMIT 20
#define G_TIMEOUT_DEFAULT 300
#define G_RECHECKS 0

// Global configuration variables
int g_threadLimit = G_THREAD_LIMIT;
static int g_ctimeout = G_TIMEOUT_DEFAULT;
int g_rechecks = G_RECHECKS; // Rechecks global

// Console ANSI capability
bool g_supportsANSI = false;

// Scan settings
static int g_pingEnabled = 1;
static int g_isPingOnly = 0;
static int g_netbiosEnabled = 0;
static int g_udpEnabled = 0; // UDP Flag

static LONG g_pingProgress = 0;
static LONG g_portProgress = 0;
static bool g_headerPrintedStdout = false;

// ----------------------
// Global Structures
// ----------------------
typedef struct _IPResult {
    char ip[INET_ADDRSTRLEN];
    char netbiosName[256];
    char** details;
    int detailCount;
    int detailCapacity;
    int* openPorts;
    int openCount;
    int openCapacity;
    CRITICAL_SECTION cs;
    int responded;
} IPResult;

static IPResult* g_ipResults = NULL;
static int g_ipCount = 0;

static void print_header_stdout() {
    if (g_supportsANSI) printf("\033[36m");
    printf(" _____     _   _____             \n");
    printf("|  _  |___| |_|   __|___ ___ ___ \n");
    printf("|     |  _|  _|__   |  _| .'|   |\n");
    printf("|__|__|_| |_| |_____|___|__,|_|_|\n");
    if (g_supportsANSI) printf("\033[32m");
    printf("ArtScan by @art3x (Windows) ver 1.4\n");
    if (g_supportsANSI) printf("\033[34m");
    printf("https://github.com/art3x\n");
    if (g_supportsANSI) printf("\033[0m");
    printf("\n");
}

static void cleanup_ip_results() {
    if (!g_ipResults) return;
    for (int i = 0; i < g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        DeleteCriticalSection(&ipRes->cs);
        for (int j = 0; j < ipRes->detailCount; j++) {
            free(ipRes->details[j]);
        }
        free(ipRes->details);
        free(ipRes->openPorts);
    }
    free(g_ipResults);
    g_ipResults = NULL;
    g_ipCount = 0;
}

void initConsoleColorSupport() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            if (dwMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) {
                g_supportsANSI = true;
            }
        }
    }
}

void add_ip_result(int ipIndex, int port, const char* message) {
    if (ipIndex < 0 || ipIndex >= g_ipCount) return;
    IPResult* ipRes = &g_ipResults[ipIndex];
    EnterCriticalSection(&ipRes->cs);

    if (ipRes->detailCount >= ipRes->detailCapacity) {
        int newCapacity = (ipRes->detailCapacity == 0) ? 4 : ipRes->detailCapacity * 2;
        char** newDetails = (char**)realloc(ipRes->details, newCapacity * sizeof(char*));
        if (!newDetails) { LeaveCriticalSection(&ipRes->cs); return; }
        ipRes->details = newDetails;
        ipRes->detailCapacity = newCapacity;
    }
    ipRes->details[ipRes->detailCount] = _strdup(message);
    ipRes->detailCount++;

    if (ipRes->openCount >= ipRes->openCapacity) {
        int newCapacity = (ipRes->openCapacity == 0) ? 4 : ipRes->openCapacity * 2;
        int* newPorts = (int*)realloc(ipRes->openPorts, newCapacity * sizeof(int));
        if (!newPorts) { LeaveCriticalSection(&ipRes->cs); return; }
        ipRes->openPorts = newPorts;
        ipRes->openCapacity = newCapacity;
    }
    ipRes->openPorts[ipRes->openCount++] = port;
    LeaveCriticalSection(&ipRes->cs);
}

int cmp_int(const void* a, const void* b) {
    return (*(const int*)a) - (*(const int*)b);
}

static const char* strcasestr_local(const char* haystack, const char* needle) {
    if (!haystack || !needle || !*needle) return haystack;
    size_t nlen = strlen(needle);
    for (const char* p = haystack; *p; p++) {
        if (_strnicmp(p, needle, nlen) == 0) return p;
    }
    return NULL;
}

// ----------------------
// UDP Payload Helper
// ----------------------
int get_udp_payload(int port, char* buffer, int bufSize) {
    memset(buffer, 0, bufSize);

    // DNS (53)
    if (port == 53) {
        char dnsPkt[] =
            "\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            "\x06google\x03com\x00\x00\x01\x00\x01";
        if (bufSize >= sizeof(dnsPkt) - 1) {
            memcpy(buffer, dnsPkt, sizeof(dnsPkt) - 1);
            return sizeof(dnsPkt) - 1;
        }
    }
    // NTP (123)
    else if (port == 123) {
        char ntpPkt[48] = { 0 };
        ntpPkt[0] = 0x1B;
        if (bufSize >= 48) {
            memcpy(buffer, ntpPkt, 48);
            return 48;
        }
    }
    // SNMP (161)
    else if (port == 161) {
        char snmpPkt[] = "\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa1\x19\x02\x04\x1a\x2b\x3c\x4d\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00";
        if (bufSize >= sizeof(snmpPkt) - 1) {
            memcpy(buffer, snmpPkt, sizeof(snmpPkt) - 1);
            return sizeof(snmpPkt) - 1;
        }
    }
    // NetBIOS NS (137)
    else if (port == 137) {
        char nbPkt[] = "\x80\x96\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01";
        if (bufSize >= sizeof(nbPkt) - 1) {
            memcpy(buffer, nbPkt, sizeof(nbPkt) - 1);
            return sizeof(nbPkt) - 1;
        }
    }
    // SSDP (1900)
    else if (port == 1900) {
        const char* ssdp = "M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nST: ssdp:all\r\nMan: \"ssdp:discover\"\r\nMX: 3\r\n\r\n";
        if (bufSize >= (int)strlen(ssdp)) {
            strcpy(buffer, ssdp);
            return (int)strlen(ssdp);
        }
    }

    return 0;
}

// ----------------------
// HTTP Helper (TCP only)
// ----------------------
static int is_http_like_port(int port) {
    switch (port) {
    case 80: case 443: case 8000: case 8008: case 8080: case 8081:
    case 8082: case 8086: case 8088: case 8090: case 8091: case 8443:
    case 8888: case 9000: case 9080: case 9090: case 9091: case 9092:
    case 9200: case 5601:
        return 1;
    default:
        return 0;
    }
}

static void summarize_http(const char* resp, char* out, size_t outsz) {
    if (!out || outsz == 0) return;
    out[0] = '\0';
    if (!resp) return;

    char statusLine[160] = { 0 };
    const char* p = strstr(resp, "HTTP/");
    if (p) {
        const char* lineEnd = strpbrk(p, "\r\n");
        size_t len = lineEnd ? (size_t)(lineEnd - p) : strlen(p);
        if (len >= sizeof(statusLine)) len = sizeof(statusLine) - 1;
        strncpy(statusLine, p, len);
        statusLine[len] = '\0';
    }

    char version[32] = { 0 };
    char reason[96] = { 0 };
    int statusCode = 0;
    if (statusLine[0]) {
        sscanf_s(statusLine, "%31s %d %95[^\r\n]", version, (unsigned)_countof(version), &statusCode, reason, (unsigned)_countof(reason));
    }

    char title[256] = { 0 };
    const char* titleStart = strcasestr_local(resp, "<title");
    if (titleStart) {
        titleStart = strchr(titleStart, '>');
        if (titleStart) {
            titleStart++;
            const char* titleEnd = strcasestr_local(titleStart, "</title>");
            if (titleEnd && titleEnd > titleStart) {
                size_t len = (size_t)(titleEnd - titleStart);
                if (len >= sizeof(title)) len = sizeof(title) - 1;
                strncpy(title, titleStart, len);
                title[len] = '\0';
            }
        }
    }

    for (char* c = title; *c; c++) {
        if (*c == '\r' || *c == '\n' || *c == '\t') *c = ' ';
    }
    char* tstart = title;
    while (*tstart == ' ') tstart++;
    char* tend = tstart + strlen(tstart);
    while (tend > tstart && *(tend - 1) == ' ') { *(--tend) = '\0'; }
    if (strlen(tstart) > 192) tstart[192] = '\0';

    char statusColored[200] = { 0 };
    if (statusCode > 0) {
        const char* colorStart = "\033[0m";
        if (statusCode >= 200 && statusCode < 300) colorStart = "\033[32m";
        else if (statusCode >= 300 && statusCode < 500) colorStart = "\033[33m";
        else if (statusCode >= 500 && statusCode < 600) colorStart = "\033[31m";
        const char* colorEnd = "\033[0m";
        if (version[0]) {
            snprintf(statusColored, sizeof(statusColored), "%s %s%d%s%s%s",
                version, colorStart, statusCode, colorEnd,
                reason[0] ? " " : "", reason);
        }
        else {
            snprintf(statusColored, sizeof(statusColored), "%s%d%s%s%s",
                colorStart, statusCode, colorEnd,
                reason[0] ? " " : "", reason);
        }
    }
    else if (statusLine[0]) {
        strncpy(statusColored, statusLine, sizeof(statusColored) - 1);
    }

    const char* titleColorStart = g_supportsANSI ? "\033[97m" : "";
    const char* titleColorEnd = g_supportsANSI ? "\033[0m" : "";
    if (statusCode >= 200 && statusCode < 300 && tstart[0]) {
        snprintf(out, outsz, "%s | Title: %s%s%s", statusColored, titleColorStart, tstart, titleColorEnd);
    }
    else if (statusColored[0]) {
        snprintf(out, outsz, "%s", statusColored);
    }
    else if (tstart[0]) {
        snprintf(out, outsz, "Title: %s%s%s", titleColorStart, tstart, titleColorEnd);
    }
}

typedef struct {
    const char* label;
    volatile LONG* counter;
    int total;
    volatile LONG stopFlag;
} ProgressCtx;

unsigned __stdcall progress_thread(void* param) {
    ProgressCtx* ctx = (ProgressCtx*)param;
    int last = -1;
    while (!ctx->stopFlag) {
        int done = (int)InterlockedCompareExchange((volatile LONG*)ctx->counter, 0, 0);
        if (done > ctx->total) done = ctx->total;
        if (done != last) {
            double pct = ctx->total ? (done * 100.0 / ctx->total) : 100.0;
            printf("\r[%s] %d/%d (%.1f%%)", ctx->label, done, ctx->total, pct);
            fflush(stdout);
            last = done;
        }
        Sleep(100);
    }
    int done = (int)InterlockedCompareExchange((volatile LONG*)ctx->counter, 0, 0);
    if (done > ctx->total) done = ctx->total;
    double pct = ctx->total ? (done * 100.0 / ctx->total) : 100.0;
    printf("\r[%s] %d/%d (%.1f%%)\n", ctx->label, done, ctx->total, pct);
    fflush(stdout);
    return 0;
}

// ----------------------
// Ping
// ----------------------
#define ICMP_ECHO_DATA "abcdefghijklmnopqrstuvwabdcefghi"
#define ICMP_REPLY_SIZE (sizeof(ICMP_ECHO_REPLY) + sizeof(ICMP_ECHO_DATA))
#define ICMP_TIMEOUT_DEFAULT 1800 

DWORD ping_ip(HANDLE hIcmpFile, IPAddr ip, PICMP_ECHO_REPLY reply) {
    IP_OPTION_INFORMATION options = { 0 };
    options.Ttl = 128;
    return IcmpSendEcho2(
        hIcmpFile, NULL, NULL, NULL, ip,
        (LPVOID)ICMP_ECHO_DATA, sizeof(ICMP_ECHO_DATA) - 1,
        &options, reply, ICMP_REPLY_SIZE, ICMP_TIMEOUT_DEFAULT
    );
}

typedef struct _PingThreadData {
    char ip[INET_ADDRSTRLEN];
    int ipIndex;
} PingThreadData;

unsigned __stdcall ping_thread(void* param) {
    PingThreadData* data = (PingThreadData*)param;
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        free(data);
        return 0;
    }
    struct in_addr addr;
    if (inet_pton(AF_INET, data->ip, &addr) != 1) {
        free(data);
        IcmpCloseHandle(hIcmp);
        return 0;
    }
    IPAddr ipAddr = addr.s_addr;
    char replyBuffer[ICMP_REPLY_SIZE];
    PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)replyBuffer;
    DWORD dwRetVal = ping_ip(hIcmp, ipAddr, reply);
    if (dwRetVal != 0 && reply->Status == IP_SUCCESS) {
        InterlockedExchange((volatile LONG*)&g_ipResults[data->ipIndex].responded, 1);
        if (g_netbiosEnabled) {
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr = addr;
            char host[NI_MAXHOST] = { 0 };
            int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0);
            if (res == 0) {
                EnterCriticalSection(&g_ipResults[data->ipIndex].cs);
                strncpy(g_ipResults[data->ipIndex].netbiosName, host, sizeof(g_ipResults[data->ipIndex].netbiosName) - 1);
                g_ipResults[data->ipIndex].netbiosName[sizeof(g_ipResults[data->ipIndex].netbiosName) - 1] = '\0';
                LeaveCriticalSection(&g_ipResults[data->ipIndex].cs);
            }
        }
        if (g_isPingOnly) {
            char message[256];
            if (g_ipResults[data->ipIndex].netbiosName[0] != '\0')
                snprintf(message, sizeof(message), "%s (%s) responded to ping", data->ip, g_ipResults[data->ipIndex].netbiosName);
            else
                snprintf(message, sizeof(message), "%s responded to ping", data->ip);
            add_ip_result(data->ipIndex, 0, message);
        }
    }
    IcmpCloseHandle(hIcmp);
    free(data);
    InterlockedIncrement(&g_pingProgress);
    return 0;
}

// ----------------------
// Parsing
// ----------------------
int parse_ports(const char* input, int** ports, int* count) {
    if (!input || !ports || !count) return 0;
    if (_stricmp(input, "all") == 0) {
        int* arr = (int*)malloc(sizeof(int) * 65535);
        if (!arr) return 0;
        for (int i = 0; i < 65535; i++) arr[i] = i + 1;
        *ports = arr;
        *count = 65535;
        return 1;
    }
    if (strchr(input, ',') != NULL) {
        char* copy = _strdup(input);
        if (!copy) return 0;
        int tokenCount = 0;
        char* token = strtok(copy, ",");
        while (token) {
            tokenCount++;
            token = strtok(NULL, ",");
        }
        free(copy);
        int* arr = (int*)malloc(sizeof(int) * tokenCount);
        if (!arr) return 0;
        copy = _strdup(input);
        if (!copy) { free(arr); return 0; }
        int idx = 0;
        token = strtok(copy, ",");
        while (token) {
            char* endptr;
            long port = strtol(token, &endptr, 10);
            if (port <= 0 || port > 65535) {
                free(copy);
                free(arr);
                return 0;
            }
            arr[idx++] = (int)port;
            token = strtok(NULL, ",");
        }
        free(copy);
        *ports = arr;
        *count = tokenCount;
        return 1;
    }
    else {
        const char* p = input;
        char* endptr;
        long first = strtol(p, &endptr, 10);
        if (first <= 0 || first > 65535) return 0;
        while (*endptr && !isdigit((unsigned char)*endptr) && *endptr != '-') {
            endptr++;
        }
        if (*endptr == '-') {
            const char* dashPos = endptr + 1;
            if (!isdigit((unsigned char)*dashPos)) {
                int* arr = (int*)malloc(sizeof(int));
                if (!arr) return 0;
                arr[0] = (int)first;
                *ports = arr;
                *count = 1;
                return 1;
            }
            else {
                long second = strtol(dashPos, &endptr, 10);
                if (second <= 0 || second > 65535 || second < first)
                    return 0;
                int cnt = (int)(second - first + 1);
                int* arr = (int*)malloc(sizeof(int) * cnt);
                if (!arr) return 0;
                for (int i = 0; i < cnt; i++) {
                    arr[i] = (int)first + i;
                }
                *ports = arr;
                *count = cnt;
                return 1;
            }
        }
        else {
            int* arr = (int*)malloc(sizeof(int));
            if (!arr) return 0;
            arr[0] = (int)first;
            *ports = arr;
            *count = 1;
            return 1;
        }
    }
}

int parse_ip_range(const char* input, char* startIp, char* endIp) {
    const char* dash = strchr(input, '-');
    if (!dash) {
        strncpy(startIp, input, INET_ADDRSTRLEN);
        startIp[INET_ADDRSTRLEN - 1] = '\0';
        strncpy(endIp, input, INET_ADDRSTRLEN);
        endIp[INET_ADDRSTRLEN - 1] = '\0';
    }
    else {
        size_t len = dash - input;
        if (len >= INET_ADDRSTRLEN)
            return 0;
        strncpy(startIp, input, len);
        startIp[len] = '\0';
        if (strchr(dash + 1, '.') == NULL) {
            strncpy(endIp, startIp, INET_ADDRSTRLEN);
            endIp[INET_ADDRSTRLEN - 1] = '\0';
            char* lastDot = strrchr(endIp, '.');
            if (!lastDot) return 0;
            size_t remain = INET_ADDRSTRLEN - (lastDot - endIp + 1);
            snprintf(lastDot + 1, remain, "%s", dash + 1);
        }
        else {
            strncpy(endIp, dash + 1, INET_ADDRSTRLEN);
            endIp[INET_ADDRSTRLEN - 1] = '\0';
        }
    }
    return 1;
}

uint32_t ip_to_int(const char* ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return 0;
    return ntohl(addr.s_addr);
}

void int_to_ip(uint32_t ipInt, char* buffer) {
    struct in_addr addr;
    addr.s_addr = htonl(ipInt);
    inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
}

int resolve_hostname_to_ip(const char* hostname, char* ip_buffer, size_t buffer_len) {
    struct addrinfo hints, * result;
    int status;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) return 0;
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)result->ai_addr;
    if (inet_ntop(AF_INET, &ipv4->sin_addr, ip_buffer, buffer_len) == NULL) {
        freeaddrinfo(result);
        return 0;
    }
    freeaddrinfo(result);
    return 1;
}

// ----------------------
// Core Scanning Logic (TCP + UDP)
// ----------------------
typedef struct _ThreadData {
    char ip[INET_ADDRSTRLEN];
    int port;
    int ipIndex;
} ThreadData;

int scan_port(const char* ip, int port, int ipIndex) {
    int totalAttempts = 1 + g_rechecks;
    int attempt;
    int success = 0;
    char message[1024] = { 0 };
    int ctimeout = g_ctimeout;
    const char* greenStart = g_supportsANSI ? "\033[32m" : "";
    const char* greenEnd = g_supportsANSI ? "\033[0m" : "";

    for (attempt = 0; attempt < totalAttempts; attempt++) {
        if (g_udpEnabled) {
            // ================= UDP SCAN =================
            SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (sock == INVALID_SOCKET) continue;

            struct sockaddr_in server;
            memset(&server, 0, sizeof(server));
            server.sin_family = AF_INET;
            server.sin_port = htons(port);
            inet_pton(AF_INET, ip, &server.sin_addr);

            if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
                closesocket(sock);
                continue;
            }

            char udpPayload[512];
            int pLoadSize = get_udp_payload(port, udpPayload, sizeof(udpPayload));

            if (send(sock, udpPayload, pLoadSize, 0) == SOCKET_ERROR) {
                closesocket(sock);
                continue;
            }

            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sock, &readfds);
            struct timeval tv;
            tv.tv_sec = ctimeout / 1000;
            tv.tv_usec = (ctimeout % 1000) * 1000;

            int res = select(0, &readfds, NULL, NULL, &tv);

            if (res > 0 && FD_ISSET(sock, &readfds)) {
                char recvBuf[1024];
                int recvLen = recv(sock, recvBuf, sizeof(recvBuf) - 1, 0);
                if (recvLen >= 0) {
                    snprintf(message, sizeof(message), "%s:%d %sopen%s (UDP response)", ip, port, greenStart, greenEnd);
                    success = 1;
                    closesocket(sock);
                    add_ip_result(ipIndex, port, message);
                    break;
                }
                else {
                    if (WSAGetLastError() == WSAECONNRESET) {
                        // ICMP Port Unreachable -> CLOSED
                    }
                }
            }
            closesocket(sock);
        }
        else {
            // ================= TCP SCAN =================
            SOCKET sock;
            struct sockaddr_in server;
            char buffer[1024];
            int result;
            fd_set writefds;
            struct timeval tv;

            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) continue;

            DWORD timeout = (DWORD)(ctimeout > 0 ? ctimeout : 100);
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

            u_long mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);

            memset(&server, 0, sizeof(server));
            server.sin_family = AF_INET;
            server.sin_port = htons(port);
            inet_pton(AF_INET, ip, &server.sin_addr);

            if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
                if (WSAGetLastError() == WSAEWOULDBLOCK) {
                    FD_ZERO(&writefds);
                    FD_SET(sock, &writefds);
                    tv.tv_sec = ctimeout / 1000;
                    tv.tv_usec = (ctimeout % 1000) * 1000;
                    int res = select(0, NULL, &writefds, NULL, &tv);
                    if (!(res > 0 && FD_ISSET(sock, &writefds))) {
                        closesocket(sock);
                        continue;
                    }
                    int err = 0; int errlen = sizeof(err);
                    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &errlen) != 0 || err != 0) {
                        closesocket(sock);
                        continue;
                    }
                }
                else {
                    closesocket(sock);
                    continue;
                }
            }

            mode = 0;
            ioctlsocket(sock, FIONBIO, &mode);

            char httpInfo[256] = { 0 };
            memset(buffer, 0, sizeof(buffer));

            if (is_http_like_port(port)) {
                char httpRequest[256];
                snprintf(httpRequest, sizeof(httpRequest),
                    "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: ascan\r\nConnection: close\r\n\r\n",
                    ip);
                send(sock, httpRequest, (int)strlen(httpRequest), 0);
                char httpResponse[2048];
                int totalReceived = 0;
                while (totalReceived < (int)sizeof(httpResponse) - 1) {
                    int recvResult = recv(sock, httpResponse + totalReceived, sizeof(httpResponse) - totalReceived - 1, 0);
                    if (recvResult <= 0) break;
                    totalReceived += recvResult;
                }
                httpResponse[totalReceived] = '\0';
                summarize_http(httpResponse, httpInfo, sizeof(httpInfo));
            }

            if (!httpInfo[0]) {
                result = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (result > 0) {
                    buffer[result] = '\0';
                    char* newline = strpbrk(buffer, "\r\n");
                    if (newline) *newline = '\0';
                    if (strncmp(buffer, "HTTP/", 5) == 0) {
                        summarize_http(buffer, httpInfo, sizeof(httpInfo));
                    }
                }
            }

            if (httpInfo[0]) {
                snprintf(message, sizeof(message), "%s:%d %sopen%s. %s", ip, port, greenStart, greenEnd, httpInfo);
            }
            else if (buffer[0]) {
                snprintf(message, sizeof(message), "%s:%d %sopen%s %s", ip, port, greenStart, greenEnd, buffer);
            }
            else {
                snprintf(message, sizeof(message), "%s:%d %sopen%s", ip, port, greenStart, greenEnd);
            }
            success = 1;
            closesocket(sock);
            add_ip_result(ipIndex, port, message);
            break;
        }
    }
    return success;
}

unsigned __stdcall port_thread(void* param) {
    ThreadData* data = (ThreadData*)param;
    scan_port(data->ip, data->port, data->ipIndex);
    free(data);
    InterlockedIncrement(&g_portProgress);
    return 0;
}

// ----------------------
// run_port_scan
// ----------------------
int run_port_scan(const char* targetSpec, const char* portRange) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        append(output, "WSAStartup failed\n");
        return -1;
    }
    g_pingProgress = 0;
    g_portProgress = 0;

    DWORD startTime = GetTickCount();

    char startIp[INET_ADDRSTRLEN], endIp[INET_ADDRSTRLEN];

    if (strchr(targetSpec, '-') != NULL) {
        if (!parse_ip_range(targetSpec, startIp, endIp)) {
            append(output, "Invalid IP range format: %s\n", targetSpec);
            WSACleanup();
            return -1;
        }
    }
    else {
        if (resolve_hostname_to_ip(targetSpec, startIp, sizeof(startIp))) {
            strncpy(endIp, startIp, INET_ADDRSTRLEN);
            append(output, "[+] Resolved %s -> %s\n", targetSpec, startIp);
        }
        else {
            struct in_addr addr_test;
            if (inet_pton(AF_INET, targetSpec, &addr_test) == 1) {
                strncpy(startIp, targetSpec, INET_ADDRSTRLEN);
                strncpy(endIp, targetSpec, INET_ADDRSTRLEN);
            }
            else {
                append(output, "Error: Could not resolve hostname '%s' and it is not a valid IP or IP range.\n", targetSpec);
                WSACleanup();
                return -1;
            }
        }
    }

    int* portList = NULL;
    int portCount = 0;
    if (!g_isPingOnly) {
        if (!parse_ports(portRange, &portList, &portCount)) {
            append(output, "Invalid port specification\n");
            WSACleanup();
            return -1;
        }
    }

    int isRangeScan = (strcmp(startIp, endIp) != 0);
    uint32_t ipStart = ip_to_int(startIp);
    uint32_t ipEnd = ip_to_int(endIp);
    if (ipStart == 0 || ipEnd == 0) {
        append(output, "IP conversion failed\n");
        WSACleanup();
        if (portList) free(portList);
        return -1;
    }

    g_ipCount = (int)(ipEnd - ipStart + 1);
    g_ipResults = (IPResult*)malloc(sizeof(IPResult) * g_ipCount);
    if (!g_ipResults) {
        append(output, "Memory allocation failed for IP results\n");
        WSACleanup();
        if (portList) free(portList);
        return -1;
    }
    for (uint32_t i = 0; i < (uint32_t)g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        int_to_ip(ipStart + i, ipRes->ip);
        ipRes->netbiosName[0] = '\0';
        ipRes->details = NULL;
        ipRes->detailCount = 0;
        ipRes->detailCapacity = 0;
        ipRes->openPorts = NULL;
        ipRes->openCount = 0;
        ipRes->openCapacity = 0;
        ipRes->responded = 0;
        InitializeCriticalSection(&ipRes->cs);
    }

    if (g_pingEnabled) {
        ProgressCtx pingCtx = { "Ping", &g_pingProgress, g_ipCount, 0 };
        HANDLE pingProgHandle = NULL;
        if (g_ipCount > 0) {
            pingProgHandle = (HANDLE)_beginthreadex(NULL, 0, progress_thread, &pingCtx, 0, NULL);
        }

        int pingThreadCount = 0;
        int pingThreadCapacity = g_threadLimit;
        HANDLE* pingHandles = (HANDLE*)malloc(sizeof(HANDLE) * pingThreadCapacity);
        if (!pingHandles) {
            append(output, "Memory allocation failed for ping handles\n");
            WSACleanup();
            cleanup_ip_results();
            if (portList) free(portList);
            return -1;
        }
        for (uint32_t ip = ipStart; ip <= ipEnd; ip++) {
            char ipStr[INET_ADDRSTRLEN];
            int_to_ip(ip, ipStr);
            int ipIndex = (int)(ip - ipStart);

            PingThreadData* data = (PingThreadData*)malloc(sizeof(PingThreadData));
            if (!data) continue;
            strncpy(data->ip, ipStr, INET_ADDRSTRLEN);
            data->ip[INET_ADDRSTRLEN - 1] = '\0';
            data->ipIndex = ipIndex;

            uintptr_t hThread = _beginthreadex(NULL, 0, ping_thread, data, 0, NULL);
            if (hThread != 0) {
                if (pingThreadCount >= pingThreadCapacity) {
                    WaitForMultipleObjects(pingThreadCount, pingHandles, TRUE, INFINITE);
                    for (int i = 0; i < pingThreadCount; i++) CloseHandle(pingHandles[i]);
                    pingThreadCount = 0;
                }
                pingHandles[pingThreadCount++] = (HANDLE)hThread;
            }
            else {
                free(data);
            }
        }
        if (pingThreadCount > 0) {
            WaitForMultipleObjects(pingThreadCount, pingHandles, TRUE, INFINITE);
            for (int i = 0; i < pingThreadCount; i++) CloseHandle(pingHandles[i]);
        }
        free(pingHandles);
        if (pingProgHandle) {
            pingCtx.stopFlag = 1;
            WaitForSingleObject(pingProgHandle, INFINITE);
            CloseHandle(pingProgHandle);
        }
    }

    if (g_isPingOnly) {
        WSACleanup();
    }
    else {
        long portTaskTotal = 0;
        for (uint32_t ip = ipStart; ip <= ipEnd; ip++) {
            int ipIndex = (int)(ip - ipStart);
            if (g_pingEnabled && !g_ipResults[ipIndex].responded) continue;
            portTaskTotal += portCount;
        }

        ProgressCtx portCtx = { "Ports", &g_portProgress, (int)portTaskTotal, 0 };
        HANDLE portProgHandle = NULL;
        if (portTaskTotal > 0) {
            portProgHandle = (HANDLE)_beginthreadex(NULL, 0, progress_thread, &portCtx, 0, NULL);
        }

        int threadCount = 0;
        int capacity = g_threadLimit;
        HANDLE* handles = (HANDLE*)malloc(sizeof(HANDLE) * capacity);
        if (!handles) {
            append(output, "Memory allocation failed for port scan handles\n");
            WSACleanup();
            cleanup_ip_results();
            if (portList) free(portList);
            return -1;
        }
        for (uint32_t ip = ipStart; ip <= ipEnd; ip++) {
            char ipStr[INET_ADDRSTRLEN];
            int_to_ip(ip, ipStr);
            int ipIndex = (int)(ip - ipStart);

            if (g_pingEnabled && !g_ipResults[ipIndex].responded) continue;

            for (int i = 0; i < portCount; i++) {
                int port = portList[i];
                ThreadData* data = (ThreadData*)malloc(sizeof(ThreadData));
                if (!data) continue;
                strncpy(data->ip, ipStr, INET_ADDRSTRLEN);
                data->ip[INET_ADDRSTRLEN - 1] = '\0';
                data->port = port;
                data->ipIndex = ipIndex;
                uintptr_t hThread = _beginthreadex(NULL, 0, port_thread, data, 0, NULL);
                if (hThread != 0) {
                    if (threadCount >= capacity) {
                        WaitForMultipleObjects(threadCount, handles, TRUE, INFINITE);
                        for (int i = 0; i < threadCount; i++) CloseHandle(handles[i]);
                        threadCount = 0;
                    }
                    handles[threadCount++] = (HANDLE)hThread;
                }
                else {
                    free(data);
                }
            }
        }
        if (threadCount > 0) {
            WaitForMultipleObjects(threadCount, handles, TRUE, INFINITE);
            for (int i = 0; i < threadCount; i++) CloseHandle(handles[i]);
        }
        free(handles);
        if (portProgHandle) {
            portCtx.stopFlag = 1;
            WaitForSingleObject(portProgHandle, INFINITE);
            CloseHandle(portProgHandle);
            printf("\n");
        }
        WSACleanup();
        if (portList) free(portList);
    }

    append(output, "\n");
    for (int i = 0; i < g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        if (ipRes->detailCount > 0) {
            for (int j = 0; j < ipRes->detailCount; j++) {
                append(output, "%s\n", ipRes->details[j]);
            }
            if (isRangeScan && (i != g_ipCount - 1)) {
                append(output, "------------------\n");
            }
        }
    }

    if (g_supportsANSI) append(output, "\033[33m");
    append(output, "\nSummary:\n");
    if (g_supportsANSI) append(output, "\033[0m");

    for (int i = 0; i < g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        if (ipRes->openCount > 0) {
            if (g_isPingOnly) {
                if (ipRes->netbiosName[0] != '\0') {
                    append(output, "%s (%s) responded to ping\n", ipRes->ip, ipRes->netbiosName);
                }
                else {
                    append(output, "%s responded to ping\n", ipRes->ip);
                }
            }
            else {
                qsort(ipRes->openPorts, ipRes->openCount, sizeof(int), cmp_int);
                char portsStr[512] = { 0 };
                size_t offset = 0;
                for (int j = 0; j < ipRes->openCount; j++) {
                    int n = snprintf(portsStr + offset, sizeof(portsStr) - offset, "%d%s",
                        ipRes->openPorts[j], (j < ipRes->openCount - 1 ? "," : ""));
                    if (n < 0 || (size_t)n >= sizeof(portsStr) - offset) break;
                    offset += n;
                }
                if (ipRes->netbiosName[0] != '\0') {
                    append(output, "%s: %s (%s)\n", ipRes->ip, portsStr, ipRes->netbiosName);
                }
                else {
                    append(output, "%s: %s\n", ipRes->ip, portsStr);
                }
            }
        }
    }

    DWORD endTime = GetTickCount();
    double seconds = (endTime - startTime) / 1000.0;
    append(output, "\nScan Duration: %.2f s\n", seconds);

    cleanup_ip_results();
    return 0;
}

// ----------------------
// Execute
// ----------------------
int Execute(char* argsBuffer, uint32_t bufferSize, goCallback callback) {
    output = NewOutput(128, callback);
    if (!output) {
        static char errorMsg[] = "[!] Failed to allocate output buffer\n";
        if (callback) callback(errorMsg, (int)strlen(errorMsg));
        return 1;
    }

    g_threadLimit = G_THREAD_LIMIT;
    g_ctimeout = G_TIMEOUT_DEFAULT;
    g_rechecks = G_RECHECKS;
    g_pingEnabled = 1;
    g_isPingOnly = 0;
    g_netbiosEnabled = 0;
    g_udpEnabled = 0;
    int isNoPorts = 0;

    if (bufferSize < 1) {
        append(output, "[!] Usage: <target> [portRange] [options]\n");
        return failure(output);
    }

    char* buf = (char*)malloc(bufferSize + 1);
    if (buf == NULL) {
        append(output, "[!] Memory allocation error.\n");
        return failure(output);
    }
    memcpy(buf, argsBuffer, bufferSize);
    buf[bufferSize] = '\0';
    buf[strcspn(buf, "\r\n")] = '\0';

    if (strstr(buf, "-h") != NULL) {
        append(output, "Usage: <target> [portRange] [options]\n");
        append(output, "  target:    Hostname, IP, or range (e.g., 192.168.1.1-100)\n");
        append(output, "  portRange: Single, range (80-90), list (80,443), or 'all'\n");
        append(output, "Options:\n");
        append(output, "  -T <num>:  Thread limit (default: 20, max: 50)\n");
        append(output, "  -t <ms>:   Scan timeout in msec (default: 300)\n");
        append(output, "  -r <num>:  Set extra rechecks for unanswered ports (default: 0, max: 10)\n");
        append(output, "  -u:        Perform UDP scan instead of TCP\n");
        append(output, "  -Pn:       Disable ping\n");
        append(output, "  -i:        Ping scan only\n");
        append(output, "  -Nb:       Enable hostname resolution\n");
        append(output, "  -h:        Display this help\n");
        free(buf);
        return success(output);
    }

    char* targetRange = NULL;
    char* portRange = NULL;
    bool pingOnlyFlag = false;

    char* token = strtok(buf, " ");
    while (token != NULL) {
        if (token[0] == '-') {
            if (strncmp(token, "-T", 2) == 0) {
                const char* valueStr = token + 2;
                if (*valueStr == '\0') { valueStr = strtok(NULL, " "); }
                if (valueStr) g_threadLimit = atoi(valueStr);
                if (g_threadLimit > 50 || g_threadLimit < 1) g_threadLimit = 50;
            }
            else if (strncmp(token, "-t", 2) == 0) {
                const char* valueStr = token + 2;
                if (*valueStr == '\0') { valueStr = strtok(NULL, " "); }
                if (valueStr) g_ctimeout = atoi(valueStr);
                if (g_ctimeout < 10) g_ctimeout = 10;
            }
            else if (strncmp(token, "-r", 2) == 0) {
                const char* valueStr = token + 2;
                if (*valueStr == '\0') { valueStr = strtok(NULL, " "); }
                if (valueStr) g_rechecks = atoi(valueStr);
                if (g_rechecks > 10 || g_rechecks < 0) g_rechecks = 10;
            }
            else if (strcmp(token, "-Pn") == 0) {
                g_pingEnabled = 0;
            }
            else if (strcmp(token, "-i") == 0) {
                pingOnlyFlag = true;
            }
            else if (strcmp(token, "-Nb") == 0) {
                g_netbiosEnabled = 1;
            }
            else if (strcmp(token, "-u") == 0 || strcmp(token, "-sU") == 0) {
                g_udpEnabled = 1;
            }
        }
        else {
            if (targetRange == NULL) {
                targetRange = _strdup(token);
            }
            else if (portRange == NULL) {
                portRange = _strdup(token);
            }
        }
        token = strtok(NULL, " ");
    }
    free(buf);

    if (targetRange == NULL) {
        append(output, "[!] No target specified. Use -h for help.\n");
        if (portRange) free(portRange);
        return failure(output);
    }

    if (pingOnlyFlag) {
        g_isPingOnly = 1;
        if (portRange) { free(portRange); portRange = NULL; }
    }
    else {
        if (portRange == NULL) {
            // Different default ports for UDP vs TCP
            if (g_udpEnabled) {
                portRange = _strdup("53,67,68,69,88,111,123,137,138,161,162,389,443,464,500,514,520,1194,1701,1812,1813,1900,2049,2055,2056,2123,2152,2222,3074,3222,3478,3479,3480,3784,3785,4500,4739,4789,5004,5005,5060,5061,5349,5353,5355,6081,8125,8472,9600,9995,9996,19302,20000,25826,27015,47808,51820");
            }
            else {
                portRange = _strdup("20,21,22,23,25,53,65,66,69,80,88,110,111,135,139,143,194,389,443,445,464,465,587,593,636,873,993,995,1194,1433,1494,1521,1540,1666,1801,1812,1813,2049,2179,2222,2383,2598,3000,3268,3269,3306,3333,3389,4444,4848,5000,5044,5060,5061,5432,5555,5601,5631,5666,5671,5672,5693,5900,5931,5938,5984,5985,5986,6160,6200,6379,6443,6600,6771,7001,7474,7687,7777,7990,8000,8006,8080,8081,8082,8086,8088,8090,8091,8200,8443,8444,8500,8529,8530,8531,8600,8888,8912,9000,9042,9080,9090,9092,9160,9200,9229,9300,9389,9443,9515,9999,10000,10001,10011,10050,10051,11211,15672,17990,27015,27017,30033,47001");
            }
            isNoPorts = 1;
        }
        g_isPingOnly = 0;
    }

    if (!g_headerPrintedStdout) {
        print_header_stdout();
        g_headerPrintedStdout = true;
    }

    if (g_supportsANSI) printf("\033[97m");
    printf("[.] Scanning Target: %s\n", targetRange);
    printf("[.] Protocol: %s\n", g_udpEnabled ? "UDP" : "TCP");
    if (!g_isPingOnly) {
        if (!isNoPorts) printf("[.] PORT(s): %s\n", portRange);
        else printf("[.] PORT(s): %s\n", g_udpEnabled ? "Top 57 UDP" : "Top 123 TCP");
    }
    else {
        printf("[.] Ping-only scan mode\n");
    }
    printf("[.] Threads: %d   Rechecks: %d   Timeout: %d\n", g_threadLimit, g_rechecks, g_ctimeout);
    if (!g_pingEnabled) printf("[.] Ping disabled (-Pn flag used)\n");
    if (g_supportsANSI) printf("\033[0m");
    printf("\n");

    int scanResult = run_port_scan(targetRange, portRange);

    free(targetRange);
    if (portRange) free(portRange);

    int exitCode = (scanResult == 0) ? success(output) : failure(output);
    output = NULL;
    return exitCode;
}

int console_callback(char* text, int len) {
    printf("%s", text);
    return 0;
}

int main(int argc, char* argv[]) {
    initConsoleColorSupport();
    if (argc < 2) {
        print_header_stdout();
        g_headerPrintedStdout = true;
        printf("Usage: <target> [portRange] [options]\n");
        printf("Use -h for more details.\n");
        return 1;
    }

    char argsBuffer[1024] = { 0 };
    int pos = 0;
    for (int i = 1; i < argc; i++) {
        int n = snprintf(argsBuffer + pos, sizeof(argsBuffer) - pos, "%s ", argv[i]);
        if (n < 0 || n >= (int)(sizeof(argsBuffer) - pos)) break;
        pos += n;
    }

    return Execute(argsBuffer, (uint32_t)strlen(argsBuffer), console_callback);
}