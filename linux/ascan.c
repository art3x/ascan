#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdatomic.h>
#include <ctype.h>
#include <netdb.h>
#include <strings.h>

// Default configuration
static int g_threadLimit    = 100;
static int g_ctimeout       = 300; // msec
static int g_rechecks       = 0;
static int g_pingEnabled    = 1;
static int g_isPingOnly     = 0;
static int g_netbiosEnabled = 0; // -Nb flag support

// Top 123 common ports as default
static const char* DEFAULT_PORTS =
"20,21,22,23,25,53,65,66,69,80,88,110,111,135,139,143,194,389,443,"
"445,464,465,587,593,636,873,993,995,1194,1433,1494,1521,1540,1666,1801,"
"1812,1813,2049,2179,2222,2383,2598,3000,3268,3269,3306,3333,3389,4444,"
"4848,5000,5044,5060,5061,5432,5555,5601,5631,5666,5671,5672,5693,5900,"
"5931,5938,5984,5985,5986,6160,6200,6379,6443,6600,6771,7001,7474,7687,"
"7777,7990,8000,8006,8080,8081,8082,8086,8088,8090,8091,8200,8443,8444,8500,"
"8529,8530,8531,8600,8888,8912,9000,9042,9080,9090,9092,9160,9200,9229,9300,9389,"
"9443,9515,9999,10000,10001,10011,10050,10051,11211,15672,17990,27015,27017,30033,47001";

// Per-IP result struct
typedef struct {
    char ip[INET_ADDRSTRLEN];
    char netbiosName[NI_MAXHOST]; // Changed to standard macro
    char **details;
    int detailCount, detailCap;
    int *openPorts;
    int openCount, openCap;
    atomic_int responded;
    pthread_mutex_t cs;
} IPResult;

static IPResult *g_ipResults = NULL;
static int g_ipCount = 0;
static int *g_ports = NULL;
static int g_portCount = 0;
static atomic_int g_taskIndex;
static atomic_int g_pingProgress;
static atomic_int g_portProgress;

static void print_header(void) {
    printf("\033[36m");
    printf(" _____     _   _____             \n");
    printf("|  _  |___| |_|   __|___ ___ ___ \n");
    printf("|     |  _|  _|__   |  _| .'|   |\n");
    printf("|__|__|_| |_| |_____|___|__,|_|_|\n");
    printf("\033[32mArtScan by @art3x (Linux) ver 1.3\033[0m\n");
    printf("\033[34mhttps://github.com/art3x\033[0m\n\n");
}


static int cmp_int(const void *a, const void *b) {
    return (*(const int*)a - *(const int*)b);
}

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

static void summarize_http(const char *resp, char *out, size_t outsz) {
    out[0] = '\0';
    if (!resp || !out || outsz == 0) return;

    char statusLine[160] = {0};
    const char *p = strstr(resp, "HTTP/");
    if (p) {
        const char *lineEnd = strpbrk(p, "\r\n");
        size_t len = lineEnd ? (size_t)(lineEnd - p) : strlen(p);
        if (len >= sizeof(statusLine)) len = sizeof(statusLine) - 1;
        strncpy(statusLine, p, len);
        statusLine[len] = '\0';
    }

    char version[32] = {0};
    char reason[96] = {0};
    int statusCode = 0;
    if (statusLine[0]) {
        sscanf(statusLine, "%31s %d %95[^\r\n]", version, &statusCode, reason);
    }

    char title[160] = {0};
    const char *titleStart = strcasestr(resp, "<title");
    if (titleStart) {
        titleStart = strchr(titleStart, '>');
        if (titleStart) {
            titleStart++;
            const char *titleEnd = strcasestr(titleStart, "</title>");
            if (titleEnd && titleEnd > titleStart) {
                size_t len = (size_t)(titleEnd - titleStart);
                if (len >= sizeof(title)) len = sizeof(title) - 1;
                strncpy(title, titleStart, len);
                title[len] = '\0';
            }
        }
    }

    // Sanitize title: replace newlines/tabs with space
    for (char *c = title; *c; c++) {
        if (*c == '\r' || *c == '\n' || *c == '\t') *c = ' ';
    }
    // Trim spaces at ends
    char *tstart = title;
    while (*tstart == ' ') tstart++;
    char *tend = tstart + strlen(tstart);
    while (tend > tstart && *(tend - 1) == ' ') { *(--tend) = '\0'; }
    // Truncate overly long titles
    if (strlen(tstart) > 192) tstart[192] = '\0';

    char statusColored[200] = {0};
    if (statusCode > 0) {
        const char *colorStart = "";
        if (statusCode >= 200 && statusCode < 300) colorStart = "\033[32m";
        else if (statusCode >= 300 && statusCode < 500) colorStart = "\033[33m";
        else if (statusCode >= 500 && statusCode < 600) colorStart = "\033[31m";
        const char *colorEnd = colorStart[0] ? "\033[0m" : "";
        if (version[0]) {
            snprintf(statusColored, sizeof(statusColored), "%s %s%d%s%s%s",
                     version, colorStart, statusCode, colorEnd,
                     reason[0] ? " " : "", reason);
        } else {
            snprintf(statusColored, sizeof(statusColored), "%s%d%s%s%s",
                     colorStart, statusCode, colorEnd,
                     reason[0] ? " " : "", reason);
        }
    } else if (statusLine[0]) {
        strncpy(statusColored, statusLine, sizeof(statusColored) - 1);
    }

    const char *titleColorStart = "\033[97m";
    const char *titleColorEnd = "\033[0m";
    if (statusColored[0] && tstart[0]) {
        snprintf(out, outsz, "%s | Title: %s%s%s", statusColored, titleColorStart, tstart, titleColorEnd);
    } else if (statusColored[0]) {
        snprintf(out, outsz, "%s", statusColored);
    } else if (tstart[0]) {
        snprintf(out, outsz, "Title: %s%s%s", titleColorStart, tstart, titleColorEnd);
    }
}

typedef struct {
    const char *label;
    atomic_int *counter;
    int total;
    atomic_int stopFlag;
} ProgressCtx;

static void *progress_worker(void *arg) {
    ProgressCtx *ctx = arg;
    int last = -1;
    while (!atomic_load(&ctx->stopFlag)) {
        int done = atomic_load(ctx->counter);
        if (done > ctx->total) done = ctx->total;
        if (done != last) {
            double pct = ctx->total ? (done * 100.0 / ctx->total) : 100.0;
            printf("\r[%s] %d/%d (%.1f%%)", ctx->label, done, ctx->total, pct);
            fflush(stdout);
            last = done;
        }
        usleep(100000);
    }
    int done = atomic_load(ctx->counter);
    if (done > ctx->total) done = ctx->total;
    double pct = ctx->total ? (done * 100.0 / ctx->total) : 100.0;
    printf("\r[%s] %d/%d (%.1f%%)\n", ctx->label, done, ctx->total, pct);
    fflush(stdout);
    return NULL;
}


// ICMP checksum
static unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Thread-safe append of detail
static void add_detail(int idx, const char *msg) {
    IPResult *r = &g_ipResults[idx];
    pthread_mutex_lock(&r->cs);
    if (r->detailCount >= r->detailCap) {
        r->detailCap = r->detailCap ? r->detailCap * 2 : 4;
        r->details = realloc(r->details, r->detailCap * sizeof(char*));
    }
    r->details[r->detailCount++] = strdup(msg);
    pthread_mutex_unlock(&r->cs);
}

// Thread-safe record open port
static void add_open(int idx, int port) {
    IPResult *r = &g_ipResults[idx];
    pthread_mutex_lock(&r->cs);
    if (r->openCount >= r->openCap) {
        r->openCap = r->openCap ? r->openCap * 2 : 4;
        r->openPorts = realloc(r->openPorts, r->openCap * sizeof(int));
    }
    r->openPorts[r->openCount++] = port;
    pthread_mutex_unlock(&r->cs);
}

// Parse ports spec (e.g. "22,80-90")
static int parse_ports(const char *spec) {
    if (!spec) return 0;
    if (!strcasecmp(spec, "all")) {
        g_portCount = 65535;
        g_ports = malloc(g_portCount * sizeof(int));
        if (!g_ports) return 0;
        for (int p = 0; p < g_portCount; p++) g_ports[p] = p + 1;
        return 1;
    }
    char *s = strdup(spec);
    char *tok = strtok(s, ",");
    int *tmp = malloc(65536 * sizeof(int));
    int cnt = 0;
    while (tok) {
        int a, b;
        if (sscanf(tok, "%d-%d", &a, &b) == 2) {
            if (a < 1 || b > 65535 || b < a) { free(s); free(tmp); return 0; }
            for (int p = a; p <= b; p++) tmp[cnt++] = p;
        } else {
            a = atoi(tok);
            if (a < 1 || a > 65535) { free(s); free(tmp); return 0; }
            tmp[cnt++] = a;
        }
        tok = strtok(NULL, ",");
    }
    free(s);
    if (cnt > 0) {
        g_ports = malloc(cnt * sizeof(int));
        memcpy(g_ports, tmp, cnt * sizeof(int));
    }
    g_portCount = cnt;
    free(tmp);
    return 1;
}

// Helper to resolve a hostname to an IPv4 string
int resolve_hostname_to_ip(const char* hostname, char* ip_buffer, size_t buffer_len) {
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Force IPv4 to match the rest of the code
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        return 0; // Failed to resolve
    }

    struct sockaddr_in* ipv4 = (struct sockaddr_in*)result->ai_addr;
    if (inet_ntop(AF_INET, &ipv4->sin_addr, ip_buffer, buffer_len) == NULL) {
        freeaddrinfo(result);
        return 0; // Conversion failed
    }

    freeaddrinfo(result);
    return 1; // Success
}

// Parses IP range syntax (e.g., 1.2.3.4-100) into start and end IP strings
int parse_ip_range_spec(const char *spec, char *startIp, char* endIp) {
    const char *dash = strchr(spec, '-');
    if (!dash) return 0; // Not a range

    size_t len = dash - spec;
    if (len >= INET_ADDRSTRLEN) return 0;
    memcpy(startIp, spec, len); startIp[len] = '\0';

    if (!strchr(dash + 1, '.')) {
        // Shorthand notation like 192.168.1.1-100
        char tmp[INET_ADDRSTRLEN];
        strncpy(tmp, startIp, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';
        char *lastDot = strrchr(tmp, '.');
        if (!lastDot) return 0;
        *(lastDot + 1) = '\0'; // Cut after the last dot
        snprintf(endIp, INET_ADDRSTRLEN, "%s%s", tmp, dash + 1);
    } else {
        // Full IP range like 192.168.1.1-192.168.1.100
        snprintf(endIp, INET_ADDRSTRLEN, "%s", dash + 1);
    }
    return 1;
}

// Sets up the global IP result array from start and end IP strings
int setup_ip_targets(const char *startIp, const char *endIp) {
    struct in_addr ia, ib;
    if (inet_pton(AF_INET, startIp, &ia) != 1) return 0;
    if (inet_pton(AF_INET, endIp, &ib) != 1) return 0;
    uint32_t s = ntohl(ia.s_addr), e = ntohl(ib.s_addr);
    if (e < s) return 0;
    g_ipCount = e - s + 1;
    g_ipResults = calloc(g_ipCount, sizeof(IPResult));
    if (!g_ipResults) return 0;
    for (int i = 0; i < g_ipCount; i++) {
        uint32_t ipn = htonl(s + i);
        inet_ntop(AF_INET, &ipn, g_ipResults[i].ip, sizeof(g_ipResults[i].ip));
        g_ipResults[i].netbiosName[0] = '\0';
        pthread_mutex_init(&g_ipResults[i].cs, NULL);
        atomic_init(&g_ipResults[i].responded, 0);
    }
    return 1;
}

enum { ICMP_PACKET_SIZE = sizeof(struct icmphdr) + 32 };

// Ping thread
static void *worker_ping(void *_) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { return NULL; }
    struct timeval tv = { g_ctimeout / 1000, (g_ctimeout % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char pkt[ICMP_PACKET_SIZE];
    struct icmphdr *hdr = (struct icmphdr*)pkt;

    while (1) {
        int idx = atomic_fetch_add(&g_taskIndex, 1);
        if (idx >= g_ipCount) break;

        memset(pkt, 0, ICMP_PACKET_SIZE);
        hdr->type = ICMP_ECHO;
        hdr->code = 0;
        hdr->un.echo.id = htons(getpid() & 0xFFFF);
        hdr->un.echo.sequence = htons(idx & 0xFFFF);
        hdr->checksum = 0;
        hdr->checksum = checksum(hdr, ICMP_PACKET_SIZE);

        struct sockaddr_in dst = { .sin_family = AF_INET };
        inet_pton(AF_INET, g_ipResults[idx].ip, &dst.sin_addr);
        sendto(sock, pkt, ICMP_PACKET_SIZE, 0, (struct sockaddr*)&dst, sizeof(dst));

        char buf[1500];
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        while (1) {
            int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&peer, &plen);
            if (n <= 0) break;

            struct ip *ip_hdr = (struct ip*)buf;
            unsigned ihl = ip_hdr->ip_hl * 4;
            if ((unsigned)n < ihl + sizeof(struct icmphdr)) continue;
            struct icmphdr *icm = (struct icmphdr*)(buf + ihl);

            if (icm->type == ICMP_ECHOREPLY && icm->un.echo.id == hdr->un.echo.id && icm->un.echo.sequence == hdr->un.echo.sequence) {
                atomic_store(&g_ipResults[idx].responded, 1);

                if (g_netbiosEnabled) {
                    char host[NI_MAXHOST] = {0};
                    if (getnameinfo((struct sockaddr*)&peer, plen, host, sizeof(host), NULL, 0, 0) == 0) {
                        pthread_mutex_lock(&g_ipResults[idx].cs);
                        strncpy(g_ipResults[idx].netbiosName, host, sizeof(g_ipResults[idx].netbiosName) - 1);
                        pthread_mutex_unlock(&g_ipResults[idx].cs);
                    }
                }

                if (g_isPingOnly) {
                    char m[NI_MAXHOST + 100];
                    pthread_mutex_lock(&g_ipResults[idx].cs);
                    if (g_ipResults[idx].netbiosName[0]) {
                        snprintf(m, sizeof(m), "%s (%s) responded to ping", g_ipResults[idx].ip, g_ipResults[idx].netbiosName);
                    } else {
                        snprintf(m, sizeof(m), "%s responded to ping", g_ipResults[idx].ip);
                    }
                    pthread_mutex_unlock(&g_ipResults[idx].cs);
                    add_detail(idx, m);
                    add_open(idx, 0); // Use 0 port as a flag for summary
                }
                break;
            }
        }
        atomic_fetch_add(&g_pingProgress, 1);
    }
    close(sock);
    return NULL;
}


// Port scan worker thread (with retries)
static void *worker_port(void *_) {
    int total = g_ipCount * g_portCount;
    while (1) {
        int t = atomic_fetch_add(&g_taskIndex, 1);
        if (t >= total) break;

        int idx  = t / g_portCount;
        int port = g_ports[t % g_portCount];
        if (g_pingEnabled && !atomic_load(&g_ipResults[idx].responded)) { atomic_fetch_add(&g_portProgress, 1); continue; }

        char banner[512];
        char msg[1024];
        int open_success = 0;
        char httpInfo[256] = {0};

        for (int attempt = 0; attempt <= g_rechecks; attempt++) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;

            fcntl(sock, F_SETFL, O_NONBLOCK);
            struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
            inet_pton(AF_INET, g_ipResults[idx].ip, &sa.sin_addr);
            connect(sock, (void*)&sa, sizeof(sa));

            fd_set wf; FD_ZERO(&wf); FD_SET(sock, &wf);
            struct timeval tvc = {g_ctimeout / 1000, (g_ctimeout % 1000) * 1000};

            if (select(sock + 1, NULL, &wf, NULL, &tvc) > 0) {
                int err = 0; socklen_t el = sizeof(err);
                if (!getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &el) && err == 0) {
                    struct timeval rto = {g_ctimeout / 1000, (g_ctimeout % 1000) * 1000};
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));
                    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) & ~O_NONBLOCK);

                    if (is_http_like_port(port)) {
                        char req[256];
                        snprintf(req, sizeof(req),
                                 "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: ascan\r\nConnection: close\r\n\r\n",
                                 g_ipResults[idx].ip);
                        send(sock, req, strlen(req), 0);
                        char resp[2048];
                        int total = 0;
                        while (total < (int)sizeof(resp) - 1) {
                            int n = recv(sock, resp + total, sizeof(resp) - 1 - total, 0);
                            if (n <= 0) break;
                            total += n;
                            if (strstr(resp, "\r\n\r\n")) break; // got headers
                        }
                        resp[total] = '\0';
                        summarize_http(resp, httpInfo, sizeof(httpInfo));
                    }

                    if (!httpInfo[0]) {
                        memset(banner, 0, sizeof(banner));
                        int n = recv(sock, banner, sizeof(banner) - 1, 0);
                        if (n > 0) { banner[n] = '\0'; char *p = strpbrk(banner, "\r\n"); if (p) *p = '\0'; }
                    }

                    if (httpInfo[0]) {
                        snprintf(msg, sizeof(msg), "%s:%d \033[32mopen\033[0m. %s", g_ipResults[idx].ip, port, httpInfo);
                    } else if (banner[0]) {
                        snprintf(msg, sizeof(msg), "%s:%d \033[32mopen\033[0m %s", g_ipResults[idx].ip, port, banner);
                    } else {
                        snprintf(msg, sizeof(msg), "%s:%d \033[32mopen\033[0m", g_ipResults[idx].ip, port);
                    }
                    add_open(idx, port);
                    add_detail(idx, msg);
                    open_success = 1;
                }
            }
            close(sock);
            if (open_success) break;
        }
        atomic_fetch_add(&g_portProgress, 1);
    }
    return NULL;
}

int main(int argc, char **argv) {
    char *targetSpec = NULL;
    char *portSpec = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-T") && i + 1 < argc) g_threadLimit = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) g_ctimeout = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-r") && i + 1 < argc) g_rechecks = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-Pn")) g_pingEnabled = 0;
        else if (!strcmp(argv[i], "-i")) g_isPingOnly = 1;
        else if (!strcmp(argv[i], "-Nb")) g_netbiosEnabled = 1;
        else if (!strcmp(argv[i], "-h")) {
            printf("Usage: %s <target> [ports] [options]\n", argv[0]);
            printf("  target:    Hostname (e.g., scanme.nmap.org), single IP, or range (192.168.1.1-100)\n");
            printf("  ports:     Single port, range (80-90), comma-separated list (22,80,443), or 'all'\n");
            printf("Options:\n");
            printf("  -T <num>:  Set thread limit (default: %d)\n", 100);
            printf("  -t <ms>:   Set port scan timeout in msec (default: %d)\n", 300);
            printf("  -r <num>:  Set extra rechecks for unanswered ports (default: %d)\n", 0);
            printf("  -Pn:       Disable ping (skip host discovery)\n");
            printf("  -i:        Perform icmp scan only (skip port scan)\n");
            printf("  -Nb:       Enable hostname resolution via reverse DNS lookup\n");
            printf("  -h:        Display this help message\n");
            return 0;
        } else if (argv[i][0] == '-') { fprintf(stderr, "Unknown option: %s\n", argv[i]); return 1; }
        else {
            if (!targetSpec) targetSpec = argv[i];
            else if (!portSpec) portSpec = argv[i];
        }
    }

    print_header();

    if (!targetSpec) { fprintf(stderr, "Error: Target required. Use -h for help.\n"); return 1; }
    if (!portSpec && !g_isPingOnly) portSpec = (char*)DEFAULT_PORTS;

    char startIp[INET_ADDRSTRLEN], endIp[INET_ADDRSTRLEN];
    if (parse_ip_range_spec(targetSpec, startIp, endIp)) {
        // It's a range.
    } else {
        // It's a single host. Try to resolve or validate.
        if (!resolve_hostname_to_ip(targetSpec, startIp, sizeof(startIp))) {
            struct in_addr addr_test;
            if (inet_pton(AF_INET, targetSpec, &addr_test) != 1) {
                fprintf(stderr, "\033[31mError: Could not resolve '%s' and it is not a valid IP.\n\033[0m", targetSpec);
                return 1;
            }
            strncpy(startIp, targetSpec, sizeof(startIp));
        }
        strncpy(endIp, startIp, sizeof(endIp));
    }
    
    printf("\033[97m");
    printf("[.] Scanning Target: %s\n", targetSpec);
    if (!g_isPingOnly) {
        printf("[.] PORT(s): %s\n", portSpec == DEFAULT_PORTS ? "TOP 123" : portSpec);
    } else {
        printf("[.] Ping-only scan mode\n");
    }
    printf("[.] Threads: %d   Rechecks: %d   Timeout: %d\n", g_threadLimit, g_rechecks, g_ctimeout);
    if (!g_pingEnabled) printf("[.] Ping disabled (-Pn flag used)\n");
    printf("\033[0m\n");

    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
    if (!setup_ip_targets(startIp, endIp)) { fprintf(stderr, "Invalid IP range setup.\n"); return 1; }
    if (!g_isPingOnly && !parse_ports(portSpec)) { fprintf(stderr, "Invalid port specification.\n"); return 1; }
    atomic_init(&g_pingProgress, 0);
    atomic_init(&g_portProgress, 0);

    pthread_t *threads = malloc(sizeof(pthread_t) * g_threadLimit);
    if (g_pingEnabled) {
        ProgressCtx pingCtx = {.label = "Ping", .counter = &g_pingProgress, .total = g_ipCount};
        atomic_init(&pingCtx.stopFlag, 0);
        pthread_t pingProgThread;
        int usePingProgress = g_ipCount > 0;
        atomic_init(&g_taskIndex, 0);
        if (usePingProgress) pthread_create(&pingProgThread, NULL, progress_worker, &pingCtx);
        for (int i = 0; i < g_threadLimit; i++) pthread_create(&threads[i], NULL, worker_ping, NULL);
        for (int i = 0; i < g_threadLimit; i++) pthread_join(threads[i], NULL);
        if (usePingProgress) { atomic_store(&pingCtx.stopFlag, 1); pthread_join(pingProgThread, NULL); }
    } else {
        // If ping is disabled, mark all hosts as "responded" to allow port scan
        for(int i=0; i<g_ipCount; i++) atomic_store(&g_ipResults[i].responded, 1);
    }

    if (!g_isPingOnly) {
        long totalPorts = (long)g_ipCount * (long)g_portCount;
        ProgressCtx portCtx = {.label = "Ports", .counter = &g_portProgress, .total = (int)totalPorts};
        atomic_init(&portCtx.stopFlag, 0);
        pthread_t portProgThread;
        int usePortProgress = totalPorts > 0;
        atomic_init(&g_taskIndex, 0);
        if (usePortProgress) pthread_create(&portProgThread, NULL, progress_worker, &portCtx);
        for (int i = 0; i < g_threadLimit; i++) pthread_create(&threads[i], NULL, worker_port, NULL);
        for (int i = 0; i < g_threadLimit; i++) pthread_join(threads[i], NULL);
        if (usePortProgress) { atomic_store(&portCtx.stopFlag, 1); pthread_join(portProgThread, NULL); printf("\n"); }
    }
    free(threads);

    clock_gettime(CLOCK_MONOTONIC,&t1);
    double elapsed=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    int first_output = 1;
    for (int i = 0; i < g_ipCount; i++) {
        if (g_ipResults[i].detailCount > 0) {
            if (!first_output) printf("\033[97m------------------\033[0m\n");
            for (int j = 0; j < g_ipResults[i].detailCount; j++) printf("%s\n", g_ipResults[i].details[j]);
            first_output = 0;
        }
    }

    printf("\033[33m\nSummary:\n\033[0m");
    for (int i = 0; i < g_ipCount; i++) {
        IPResult *r = &g_ipResults[i];
        if (r->openCount > 0) {
            if (g_isPingOnly) {
                if (r->netbiosName[0]) printf("%s (%s) responded to ping\n", r->ip, r->netbiosName);
                else printf("%s responded to ping\n", r->ip);
            } else {
                qsort(r->openPorts, r->openCount, sizeof(int), cmp_int);
                if (r->netbiosName[0]) printf("%s (%s): ", r->ip, r->netbiosName);
                else printf("%s: ", r->ip);
                for (int j = 0; j < r->openCount; j++) printf("%d%s", r->openPorts[j], j < r->openCount - 1 ? "," : "");
                printf("\n");
            }
        }
    }
    
    printf("\nScan Duration: %.2f s\n",elapsed);
    
    // Cleanup
    if (g_ports) free(g_ports);
    for (int i = 0; i < g_ipCount; i++) {
        for (int j = 0; j < g_ipResults[i].detailCount; j++) free(g_ipResults[i].details[j]);
        free(g_ipResults[i].details);
        free(g_ipResults[i].openPorts);
        pthread_mutex_destroy(&g_ipResults[i].cs);
    }
    free(g_ipResults);

    return 0;
}
