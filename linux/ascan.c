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
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdatomic.h>
#include <ctype.h>
#include <netdb.h>

// Default configuration
static int g_threadLimit    = 100;
static int g_ctimeout       = 300; // msec
static int g_rechecks       = 0;
static int g_pingEnabled    = 1;
static int g_isPingOnly     = 0;
static int g_netbiosEnabled = 0;

// Top 120 common ports as default
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
    char netbiosName[256];
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


static int cmp_int(const void *a, const void *b) {
    int ia = *(const int*)a;
    int ib = *(const int*)b;
    return ia - ib;
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
    g_ports = malloc(cnt * sizeof(int));
    memcpy(g_ports, tmp, cnt * sizeof(int));
    g_portCount = cnt;
    free(tmp);
    return 1;
}

// Parse IP range, support shorthand last octet
static int parse_ip_range(const char *spec) {
    char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
    char *dash = strchr(spec, '-');
    if (!dash) {
        snprintf(a, sizeof(a), "%s", spec);
        snprintf(b, sizeof(b), "%s", spec);
    } else {
        size_t L = dash - spec;
        if (L >= sizeof(a)) return 0;
        memcpy(a, spec, L); a[L] = '\0';
        snprintf(b, sizeof(b), "%s", dash + 1);
        if (!strchr(b, '.')) {
            char tmp[INET_ADDRSTRLEN];
            strncpy(tmp, a, sizeof(tmp));
            char *last = strrchr(tmp, '.'); if (!last) return 0;
            *last = '\0';
            snprintf(b, sizeof(b), "%s.%s", tmp, dash + 1);
        }
    }
    struct in_addr ia, ib;
    if (inet_pton(AF_INET, a, &ia) != 1) return 0;
    if (inet_pton(AF_INET, b, &ib) != 1) return 0;
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

enum { ICMP_SZ = 8 + 32 };

// Ping thread
static void *worker_ping(void *_) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { perror("socket(ICMP)"); return NULL; }
    struct timeval tv = { g_ctimeout/1000, (g_ctimeout%1000)*1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Declare your ICMP packet space and header pointer **once**
    char    pkt[ICMP_SZ];
    struct icmp *hdr = (struct icmp*)pkt;

    while (1) {
        int idx = atomic_fetch_add(&g_taskIndex, 1);
        if (idx >= g_ipCount) break;

        // Build ICMP echo request in pkt/hdr
        memset(pkt, 0, ICMP_SZ);
        hdr->icmp_type    = ICMP_ECHO;
        hdr->icmp_code    = 0;
        hdr->icmp_id      = htons(getpid() & 0xFFFF);
        hdr->icmp_seq     = htons(idx & 0xFFFF);
        memset(hdr->icmp_data, 0xA5, ICMP_SZ - sizeof(struct icmp));
        hdr->icmp_cksum   = 0;
        hdr->icmp_cksum   = checksum(hdr, ICMP_SZ);

        // Destination socket address
        struct sockaddr_in dst = { .sin_family = AF_INET };
        inet_pton(AF_INET, g_ipResults[idx].ip, &dst.sin_addr);

        // Send the request
        sendto(sock, pkt, ICMP_SZ, 0, (struct sockaddr*)&dst, sizeof(dst));

        // Receive the reply
        char buf[1500];
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
    
        while (1) {
            int n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr*)&peer, &plen);
            if (n <= 0) {
                // either timed out (n < 0 && errno==EAGAIN/EWOULDBLOCK)
                // or some error – give up
                break;
            }
    
            // strip off IP header
            struct iphdr  *ip   = (void*)buf;
            unsigned ihl        = ip->ihl * 4;
            if ((unsigned)n < ihl + sizeof(struct icmphdr))
                continue;        // too small to even hold ICMP
    
            struct icmphdr *icm = (void*)(buf + ihl);
            // only care about our Echo Reply with our id+seq
            if (icm->type == ICMP_ECHOREPLY
             && icm->un.echo.id       == hdr->icmp_id
             && icm->un.echo.sequence == hdr->icmp_seq)
            {
                atomic_store(&g_ipResults[idx].responded, 1);
                if (g_isPingOnly) {
                    char m[64];
                    snprintf(m,sizeof(m), "%s responded to ping",
                             g_ipResults[idx].ip);
                    add_detail(idx, m);
                    add_open(idx, 0);
                }
                break;  // we got our reply, stop loop
            }
            // else: it was someone else's reply (or an ICMP error), keep reading
        }
    }

    close(sock);
    return NULL;
}



// Port scan thread
// Port scan worker thread (with retries)
static void *worker_port(void *_) {
    int total = g_ipCount * g_portCount;
    while (1) {
        int t = atomic_fetch_add(&g_taskIndex, 1);
        if (t >= total) break;

        int idx  = t / g_portCount;
        int port = g_ports[t % g_portCount];
        if (!atomic_load(&g_ipResults[idx].responded)) continue;

        char banner[512];
        char msg[1024];
        int open_success = 0;

        // Try up to (1 + rechecks) times
        for (int attempt = 0; attempt <= g_rechecks; attempt++) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;

            // Non‐blocking connect
            fcntl(sock, F_SETFL, O_NONBLOCK);
            struct sockaddr_in sa = {
                .sin_family = AF_INET,
                .sin_port   = htons(port)
            };
            inet_pton(AF_INET, g_ipResults[idx].ip, &sa.sin_addr);
            connect(sock, (void*)&sa, sizeof(sa));

            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(sock, &wf);
            struct timeval tvc = {
                g_ctimeout / 1000,
                (g_ctimeout % 1000) * 1000
            };

            if (select(sock + 1, NULL, &wf, NULL, &tvc) > 0) {
                int err = 0;
                socklen_t el = sizeof(err);
                if (!getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &el) && err == 0) {
                    // Connected: grab banner/status line
                    struct timeval rto = {
                        g_ctimeout / 1000,
                        (g_ctimeout % 1000) * 1000
                    };
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));
                    int flags = fcntl(sock, F_GETFL, 0);
                    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);

                    memset(banner, 0, sizeof(banner));
                    if (port == 80 || port == 8080 || port == 8000) {
                        char req[256];
                        snprintf(req, sizeof(req),
                                 "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                                 g_ipResults[idx].ip);
                        send(sock, req, strlen(req), 0);

                        int tot = 0;
                        char c;
                        while (tot < (int)sizeof(banner) - 1 &&
                               recv(sock, &c, 1, 0) > 0) {
                            if (c == '\n' || c == '\r') break;
                            banner[tot++] = c;
                        }
                        banner[tot] = '\0';
                    } else {
                        int n = recv(sock, banner, sizeof(banner) - 1, 0);
                        if (n > 0) {
                            banner[n] = '\0';
                            char *p = strpbrk(banner, "\r\n");
                            if (p) *p = '\0';
                        }
                    }

                    // Build message and record success
                    if (banner[0]) {
                        snprintf(msg, sizeof(msg), "%s:%d open. %s",
                                 g_ipResults[idx].ip, port, banner);
                    } else {
                        snprintf(msg, sizeof(msg), "%s:%d open",
                                 g_ipResults[idx].ip, port);
                    }
                    add_open(idx, port);
                    add_detail(idx, msg);
                    open_success = 1;
                }
            }
            close(sock);
            if (open_success) break;  // no need to retry
        }
    }
    return NULL;
}


int main(int argc, char **argv) {
    char *ipRange = NULL, *portRange = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-T") && i+1 < argc) g_threadLimit    = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i+1 < argc) g_ctimeout      = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-r") && i+1 < argc) g_rechecks      = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-Pn"))              g_pingEnabled   = 0;
        else if (!strcmp(argv[i], "-i"))                g_isPingOnly    = 1;
        else if (!strcmp(argv[i], "-h")) {
            printf("Usage: %s <ip-range> [port-range] [-T threads] [-t timeout_ms] "
                            "[-r rechecks] [-Pn] [-i] [-h]\n", argv[0]);
            printf("  ipRange:   Single IP or range (e.g., 192.168.1.1-100 or 192.168.1.1-192.168.1.100)\n");
            printf("  portRange: Single port, range (80-90), or comma-separated list (22,80,443)\n");
            printf("  -T:        Set thread limit (default: 100)\n");
            printf("  -t:        Set port scan timeout in msec (default: 300)\n");
            printf("  -r:        Set extra rechecks for unanswered ports (default: 0)\n");
            printf("  -Pn:       Disable ping (skip host availability check)\n");
            printf("  -i:        Perform ping scan only (skip port scan)\n");
            printf("  -h:        Display this help message\n");
            return 0;
        } else if (!ipRange) ipRange   = argv[i];
        else if (!portRange) portRange = argv[i];
        else { fprintf(stderr, "Unexpected arg %s\n", argv[i]); return 1; }
    }
    if (!ipRange) { fprintf(stderr, "IP range required\n"); return 1; }
    if (!portRange) portRange = (char*)DEFAULT_PORTS;

    // ASCII logo & colors
    printf("\033[36m");
    printf(" _____     _   _____             \n");
    printf("|  _  |___| |_|   __|___ ___ ___ \n");
    printf("|     |  _|  _|__   |  _| .'|   |\n");
    printf("|__|__|_| |_| |_____|___|__,|_|_|\n");
    printf("\033[32mArtScan by @art3x         ver 1.1\033[0m\n");
    printf("\033[97m");
    printf("[.] Scanning IP(s): %s\n", ipRange);
    if (!g_isPingOnly) {
      if (portRange == DEFAULT_PORTS)
        printf("[.] PORT(s): TOP 123\n");
      else
        printf("[.] PORT(s): %s\n", portRange);
    } else {
      printf("[.] Ping-only scan mode\n");
    }
    printf("[.] Threads: %d   Rechecks: %d   Timeout: %d\n",
           g_threadLimit, g_rechecks, g_ctimeout);
    printf("\033[0m");
    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
    if (!parse_ip_range(ipRange)) { fprintf(stderr, "Invalid IP range\n"); return 1; }
    if (!g_isPingOnly && !parse_ports(portRange)) { fprintf(stderr, "Invalid ports\n"); return 1; }

    pthread_t *threads = malloc(sizeof(pthread_t) * g_threadLimit);
    // Ping phase
    atomic_init(&g_taskIndex, 0);
    for (int i = 0; i < g_threadLimit; i++) pthread_create(&threads[i], NULL, worker_ping, NULL);
    for (int i = 0; i < g_threadLimit; i++) pthread_join(threads[i], NULL);

    // Port phase
    if (!g_isPingOnly) {
        atomic_init(&g_taskIndex, 0);
        for (int i = 0; i < g_threadLimit; i++) pthread_create(&threads[i], NULL, worker_port, NULL);
        for (int i = 0; i < g_threadLimit; i++) pthread_join(threads[i], NULL);
    }
    
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double elapsed=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    // Output details
    int isRange = strchr(ipRange, '-') != NULL;
    for (int i = 0; i < g_ipCount; i++) {
        if (g_ipResults[i].detailCount > 0) {
            for (int j = 0; j < g_ipResults[i].detailCount; j++)
                printf("%s\n", g_ipResults[i].details[j]);
            if (isRange && i < g_ipCount - 1) printf("\033[97m------------------\033[0m\n");
        }
    }
    // Summary
    printf("\033[33m\nSummary:\n\033[0m");
    for (int i = 0; i < g_ipCount; i++) {
        if (g_ipResults[i].openCount > 0) {
            // Sort the openPorts array in ascending order
            qsort(
                g_ipResults[i].openPorts,
                g_ipResults[i].openCount,
                sizeof(int),
                cmp_int
            );

            // Print IP and its sorted ports
            printf("%s: ", g_ipResults[i].ip);
            for (int j = 0; j < g_ipResults[i].openCount; j++) {
                printf("%d%s",
                    g_ipResults[i].openPorts[j],
                    j < g_ipResults[i].openCount - 1 ? "," : ""
                );
            }
            printf("\n");
        }
    }
    printf("\nScan Duration: %.2f s\n",elapsed);
    return 0;
}