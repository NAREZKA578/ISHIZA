/*
 * nwaccel.c — высокопроизводительное ядро для netwatch (чистый C, Linux + Windows/MinGW).
 *
 * Что ускоряет по сравнению с pure-Python:
 *   1. ICMP flood-пинг: N сокетов + non-blocking sendmmsg/recvmmsg (или send/recv),
 *      вместо Python-цикла «отправил → ждёт ответ» (последовательный ping).
 *   2. Пакетная DNS-разрешалка: все хосты резолвятся параллельно в пуле pthread,
 *      вместо последовательного getaddrinfo() в основном потоке.
 *
 * Собран как обычная бинарь (не shared lib) — ноль ABI-рисков, вызов через
 * subprocess, вывод в JSON (парсится stdlib json).
 *
 * Build (Linux):   gcc -O2 -pthread -o nwaccel nwaccel.c -lm
 * Build (Windows, MinGW-w64):  gcc -O2 -Wall -static -o nwaccel.exe nwaccel.c \
 *                              -lwsock32 -lws2_32 -liphlpapi -lmswsock -lm
 *                              (или просто: build.bat)
 * Usage:  ./nwaccel ping <host> --count N --interval MS --size B [--df] [--ttl T]
 *         ./nwaccel dns  <h1,h2,...> [--timeout SEC] [--threads N]
 */
#ifdef _WIN32
/* ---- Win32 / MinGW: winsock2 вместо POSIX-сокетов, winpthreads из MinGW ---- */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <pthread.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <math.h>
#endif

#ifdef RECVMMSG
#  define NW_MMSG 1
#else
#  define NW_MMSG 0
#endif

/* ---------------- портовые мелочи ---------------- */

#ifdef _WIN32
typedef SOCKET nw_sock_t;
#  define NW_SOCKERR   WSAGetLastError()
#  define NW_INVALID   INVALID_SOCKET
#  define NW_CLOSESOCK closesocket
#  define NW_MSGDONTWAIT 0            /* сокет уже non-blocking */
#  define NW_PID       ((int)GetCurrentProcessId())
   /* winsock не отдаёт IPv4-заголовок в raw-сокетах: ICMP-заголовок с offset 0 */
#  define NW_ICMP_OFF  0
#  define ICMP_ECHO      8
#  define ICMP_ECHOREPLY 0
static int nw_rbuf(SOCKET s, int bytes) {
    return setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&bytes, sizeof(bytes));
}
static int nw_ttl(SOCKET s, int ttl) {
    return setsockopt(s, IPPROTO_IP, IP_TTL, (const char *)&ttl, sizeof(ttl));
}
static int nw_df(SOCKET s, int on) { (void)s; (void)on; return 0; } /* no-op на windows */
static void nw_fdset(fd_set *rf, SOCKET fd) { FD_SET((u_int)fd, rf); }
#else
typedef int nw_sock_t;
#  define NW_SOCKERR   errno
#  define NW_INVALID   (-1)
#  define NW_CLOSESOCK close
#  define NW_MSGDONTWAIT MSG_DONTWAIT
#  define NW_PID       getpid()
#  define NW_ICMP_OFF  ((int)sizeof(struct iphdr))
static int nw_rbuf(int fd, int bytes) {
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bytes, sizeof(bytes)) == 0) return 0;
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
}
static int nw_ttl(int fd, int ttl) {
    return setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
}
static int nw_df(int fd, int on) {
    int val = on ? 2 /*IP_PMTUDISC_DO*/ : 0;
    return setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
}
static void nw_fdset(fd_set *rf, int fd) { FD_SET(fd, rf); }
#endif

/* ---------------- утилиты ---------------- */

static double mono_ms(void) {
#ifdef _WIN32
    static LARGE_INTEGER qpc = {0};
    LARGE_INTEGER t;
    if (!qpc.QuadPart) QueryPerformanceFrequency(&qpc);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1000.0 / (double)qpc.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
#endif
}

#ifdef _WIN32
/* --- слой совместимости: winsock-специфичные мелочи --- */
static const char *nw_strerror(int e) {
    static char buf[64];
    LPVOID msg = NULL;
    if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
                       | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, (DWORD)e, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       (char *)&msg, 0, NULL) && msg) {
        snprintf(buf, sizeof(buf), "%s", (const char *)msg);
        LocalFree(msg);
        return buf;
    }
    snprintf(buf, sizeof(buf), "WSA error %d", e);
    return buf;
}

static void nw_usleep(unsigned us) {
    if (us >= 2000) Sleep(us / 1000);
    else { double t0 = mono_ms(); while (mono_ms() - t0 < (double)us / 1000.0) { /* spin */ } }
}

static int nw_set_nonblock(nw_sock_t s) {
    u_long nb = 1;
    return ioctlsocket(s, FIONBIO, &nb);
}

static ssize_t nw_recv(nw_sock_t s, void *buf, size_t len, int flags) {
    return recv(s, (char *)buf, (int)len, flags);
}

static void nw_net_cleanup(void) { WSACleanup(); }

static void nw_inet_ntop_sa(const struct sockaddr *sa, char *out, size_t outlen) {
    DWORD n = (DWORD)outlen;
    int sl = (sa->sa_family == AF_INET) ? (int)sizeof(struct sockaddr_in)
                                        : (int)sizeof(struct sockaddr_in6);
    if (WSAAddressToStringA((SOCKADDR *)sa, sl, NULL, out, &n) != 0)
        snprintf(out, outlen, "?");
}
#else /* POSIX */
static const char *nw_strerror(int e) { return strerror(e); }
static void nw_usleep(unsigned us) { usleep(us); }
static int nw_set_nonblock(nw_sock_t fd) { return fcntl(fd, F_SETFL, O_NONBLOCK); }
static ssize_t nw_recv(nw_sock_t fd, void *buf, size_t len, int flags) { return recv(fd, buf, len, flags); }
__attribute__((unused)) static void nw_net_cleanup(void) {}
static void nw_inet_ntop_sa(const struct sockaddr *sa, char *out, size_t outlen) {
    const void *addr = (sa->sa_family == AF_INET)
        ? (const void *)&((const struct sockaddr_in *)sa)->sin_addr
        : (const void *)&((const struct sockaddr_in6 *)sa)->sin6_addr;
    if (!inet_ntop(sa->sa_family, addr, out, (socklen_t)outlen))
        snprintf(out, outlen, "?");
}
#endif

static uint16_t icmp_cksum(const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t sum = 0;
    while (len > 1) { sum += (uint32_t)(p[0] | (p[1] << 8)); p += 2; len -= 2; }
    if (len) sum += *p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static int cmp_dbl(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void json_escape_str(FILE *out, const char *s) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out);  break;
            default:
                if (*p < 0x20) fprintf(out, "\\u%04x", *p);
                else fputc(*p, out);
        }
    }
    fputc('"', out);
}

/* ---------------- ICMP flood-ping ---------------- */

/* единое представление ICMP echo-заголовка (16-байтный layout одинаков на обеих ОС) */
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t cksum;
    uint16_t id;
    uint16_t seq;
} nw_icmphdr_t;
#define NW_ICMP_HDR ((int)sizeof(nw_icmphdr_t))

typedef struct {
    uint16_t ident;
    uint32_t seq;
    double   t_send;
} pending_t;

#define PENDING_CAP 8192

static void build_echo_pkt(uint8_t *buf, size_t pktlen, uint16_t ident,
                           uint32_t seq, double tsend) {
    nw_icmphdr_t *h = (nw_icmphdr_t *)buf;
    memset(buf, 0, pktlen);
    h->type = ICMP_ECHO;
    h->code = 0;
    h->cksum = 0;
    h->id = htons(ident);
    /* seq кодируем 32-битным счётчиком: поле seq = младшие 16 бит */
    h->seq = htons((uint16_t)seq);
    /* после заголовка: timestamp (double) + заполнитель */
    size_t off = NW_ICMP_HDR;
    if (pktlen >= off + sizeof(double)) memcpy(buf + off, &tsend, sizeof(double));
    for (size_t i = off + sizeof(double); i < pktlen; i++)
        buf[i] = (uint8_t)((i * 7 + 13) % 251);
    h->cksum = icmp_cksum(buf, pktlen);
}

static int parse_echo_reply(const uint8_t *data, ssize_t n, uint16_t ident,
                            uint32_t *oseq) {
    int off = NW_ICMP_OFF;
    if (n < (ssize_t)(off + NW_ICMP_HDR)) return 0;
    const nw_icmphdr_t *h = (const nw_icmphdr_t *)(data + off);
    if (h->type != ICMP_ECHOREPLY) return 0;
    if (ntohs(h->id) != ident) return 0;
    *oseq = (uint32_t)ntohs(h->seq);
    return 1;
}

static int cmd_ping(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "usage: ping <host> [opts]\n"); return 2; }
    const char *host = argv[0];
    int count = 100, interval_ms = 10, size = 56, df = 0, ttl = 0, sockets = 1;
    double deadline_ms = 0;
    for (int i = 1; i < argc; i++) {
        #define NEEDVAL() do { if (i + 1 >= argc) { fprintf(stderr, "missing value for %s\n", argv[i]); return 2; } } while (0)
        if      (!strcmp(argv[i], "--count"))    { NEEDVAL(); count = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--interval")) { NEEDVAL(); interval_ms = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--size"))     { NEEDVAL(); size = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--df"))       { df = 1; }
        else if (!strcmp(argv[i], "--ttl"))      { NEEDVAL(); ttl = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--sockets"))  { NEEDVAL(); sockets = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--deadline")) { NEEDVAL(); deadline_ms = atof(argv[++i]); }
        else { fprintf(stderr, "unknown opt: %s\n", argv[i]); return 2; }
    }
    if (count < 1) count = 1;
    if (count > 1000000) count = 1000000;
    if (sockets < 1) sockets = 1;
    if (sockets > 64) sockets = 64;
    if (size < 16) size = 16;
    if (size > 60000) size = 60000;

    /* резолв */
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;
    int gai = getaddrinfo(host, NULL, &hints, &res);
    if (gai != 0) {
        printf("{\"mode\":\"ping\",\"error\":\"dns_failure\",\"detail\":");
        json_escape_str(stdout, gai_strerror(gai));
        printf(",\"received\":0,\"sent\":0}\n");
        return 0;
    }
    struct sockaddr_in dest = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);

    /* сокеты */
    nw_sock_t *fds = calloc(sockets, sizeof(nw_sock_t));
    size_t pktlen = NW_ICMP_HDR + (size_t)size;
    if (pktlen < NW_ICMP_HDR + sizeof(double))
        pktlen = NW_ICMP_HDR + sizeof(double);
    uint8_t *pktbuf = malloc(pktlen);
    uint32_t seq_base = ((uint32_t)NW_PID << 12) ^ ((uint32_t)clock() & 0xFFF);
    seq_base &= 0xFFFF; /* держимся 16 бит, чтобы seq не переполнялся часто */
    double t_start = mono_ms();
    long next_seq = seq_base;
    long sent = 0, recv_cnt = 0;

    /* таблица ожидающих ответов: индекс = seq - seq_base */
    pending_t *pend = calloc(PENDING_CAP, sizeof(pending_t));
    double *rtts = malloc(sizeof(double) * (size_t)(count > 0 ? count : 1));
    int rtt_n = 0;
    uint16_t ident = (uint16_t)(NW_PID & 0xFFFF);

    for (int s = 0; s < sockets; s++) {
        fds[s] = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (fds[s] == NW_INVALID) {
            printf("{\"mode\":\"ping\",\"error\":\"raw_not_allowed\",\"detail\":");
            json_escape_str(stdout, nw_strerror(NW_SOCKERR));
            printf(",\"received\":0,\"sent\":0,\"duration_ms\":%.1f}\n", mono_ms() - t_start);
            return 0; /* не root / нет CAP_NET_RAW / нет админ-прав на Windows */
        }
        int rcvbuf = 4 * 1024 * 1024; /* 4MB — flood-пины не должны терять ответы */
        nw_rbuf(fds[s], rcvbuf);
        nw_set_nonblock(fds[s]);
        if (ttl) nw_ttl(fds[s], ttl);
        if (df)  nw_df(fds[s], 1);
    }

    /* цикл отправки+приёма */
    int err_net_unreach = 0, err_msg_too_big = 0;
    double t_end = t_start + (deadline_ms > 0 ? deadline_ms
                       : (double)count * interval_ms + 2000.0);
    uint8_t rbuf[65536];
#ifndef _WIN32
    int maxfd = -1; /* posix-хелпер для select */
#endif

    while (1) {
        double now = mono_ms();
        if (now >= t_end) break;

        /* 1) сначала дренируем входящие ответы — снижает риск потери в ring-buffer */
        fd_set rf; FD_ZERO(&rf);
        for (int s = 0; s < sockets; s++) nw_fdset(&rf, fds[s]);
#ifdef _WIN32
        struct timeval tv = {0, 0};
        select(0, &rf, NULL, NULL, &tv);   /* WinSock: nfds игнорируется */
#else
        struct timeval tv = {0, 0};
        maxfd = -1;
        for (int s = 0; s < sockets; s++) if (fds[s] > maxfd) maxfd = fds[s];
        select(maxfd + 1, &rf, NULL, NULL, &tv);
#endif
        for (int s = 0; s < sockets; s++) {
            if (!FD_ISSET((u_int)fds[s], &rf)) continue;
            for (;;) {
                ssize_t n = nw_recv(fds[s], rbuf, sizeof(rbuf), NW_MSGDONTWAIT);
                if (n <= 0) break; /* EAGAIN/EWOULDBLOCK — очередь пуста */
                uint32_t rsq;
                if (!parse_echo_reply(rbuf, n, ident, &rsq)) continue;
                size_t idx = (rsq - seq_base) % PENDING_CAP;
                if (pend[idx].seq != rsq) continue; /* перезаписано/мусор */
                double rtt = mono_ms() - pend[idx].t_send;
                pend[idx].seq = 0xFFFFFFFFu;
                if (rtt_n < count) rtts[rtt_n++] = rtt;
                recv_cnt++;
            }
        }

        /* 2) отправить следующий пакет по интервалу */
        now = mono_ms();
        while (sent < count &&
               now >= t_start + (double)sent * interval_ms) {
            uint32_t sq = (uint32_t)(next_seq++);
            build_echo_pkt(pktbuf, pktlen, ident, sq, now);
            ssize_t w = sendto(fds[sent % sockets], (const char *)pktbuf, (int)pktlen, 0,
                               (struct sockaddr *)&dest, sizeof(dest));
            if (w < 0) {
                int e = NW_SOCKERR;
                if (e == ENOBUFS || e == EAGAIN) { /* темп слишком высок */
                    nw_usleep(200);
                    continue;
                }
                if (e == ENETUNREACH || e == EHOSTUNREACH) { err_net_unreach = 1; break; }
                if (e == EMSGSIZE) { err_msg_too_big = 1; break; }
                /* прочее — пропускаем */
            } else {
                size_t idx = (sq - seq_base) % PENDING_CAP;
                pend[idx].ident = ident;
                pend[idx].seq = sq;
                pend[idx].t_send = now;
                sent++;
            }
        }
        if (err_net_unreach || err_msg_too_big) break;

        /* 3) короткое ожидание активности */
        FD_ZERO(&rf);
        for (int s = 0; s < sockets; s++) nw_fdset(&rf, fds[s]);
        struct timeval tv2 = {0, 200000}; /* 200ms — короткая кванта планировщика */
#ifdef _WIN32
        if (select(0, &rf, NULL, NULL, &tv2) <= 0) continue;
#else
        maxfd = -1;
        for (int s = 0; s < sockets; s++) if (fds[s] > maxfd) maxfd = fds[s];
        if (select(maxfd + 1, &rf, NULL, NULL, &tv2) <= 0) continue;
#endif
    }

    /* статистика */
    double min = 0, max = 0, avg = 0, mdev = 0, p50 = 0, p95 = 0;
    if (rtt_n > 0) {
        double *sorted = malloc(sizeof(double) * rtt_n);
        memcpy(sorted, rtts, sizeof(double) * rtt_n);
        qsort(sorted, rtt_n, sizeof(double), cmp_dbl);
        min = sorted[0]; max = sorted[rtt_n - 1];
        for (int i = 0; i < rtt_n; i++) avg += sorted[i];
        avg /= rtt_n;
        for (int i = 0; i < rtt_n; i++) mdev += fabs(sorted[i] - avg);
        mdev /= rtt_n;
        p50 = sorted[(size_t)(rtt_n * 0.50 > 0 ? rtt_n * 0.50 : 0)];
        size_t i95 = (size_t)(rtt_n * 0.95); if (i95 >= (size_t)rtt_n) i95 = rtt_n - 1;
        p95 = sorted[i95];
        free(sorted);
    }
    const char *err = NULL;
    if (err_net_unreach) err = "net_unreach";
    else if (err_msg_too_big) err = "msg_too_big";

    printf("{\"mode\":\"ping\",\"engine\":\"c\",\"target\":");
    json_escape_str(stdout, host);
    printf(",\"ip\":");
    char ipstr[INET_ADDRSTRLEN]; nw_inet_ntop_sa((struct sockaddr *)&dest, ipstr, sizeof(ipstr));
    json_escape_str(stdout, ipstr);
    printf(",\"sent\":%ld,\"received\":%ld,\"loss_pct\":%.2f",
           sent, recv_cnt, sent ? (sent - recv_cnt) * 100.0 / sent : 100.0);
    printf(",\"min_ms\":%.3f,\"avg_ms\":%.3f,\"max_ms\":%.3f,\"mdev_ms\":%.3f",
           min, avg, max, mdev);
    printf(",\"p50_ms\":%.3f,\"p95_ms\":%.3f,\"samples\":%d", p50, p95, rtt_n);
    printf(",\"duration_ms\":%.1f", mono_ms() - t_start);
    if (err) { printf(",\"error\":"); json_escape_str(stdout, err); }
    printf("}\n");
    fflush(stdout);

    free(rtts); free(pend); free(pktbuf);
    for (int s = 0; s < sockets; s++) if (fds[s] != NW_INVALID) NW_CLOSESOCK(fds[s]);
    free(fds);
    return 0;
}

/* ---------------- пакетный DNS-resolver ---------------- */

typedef struct {
    const char *host;
    char ips[4][INET6_ADDRSTRLEN];
    int  n_ips;
    int  status;      /* 0 ok, иначе код getaddrinfo */
    double ms;
} dns_job_t;

typedef struct {
    dns_job_t *jobs;
    int n;
    int pos;
    pthread_mutex_t mtx;
} dns_queue_t;

static void *dns_worker(void *arg) {
    dns_queue_t *q = (dns_queue_t *)arg;
    for (;;) {
        pthread_mutex_lock(&q->mtx);
        int idx = q->pos++;
        pthread_mutex_unlock(&q->mtx);
        if (idx >= q->n) return NULL;
        dns_job_t *job = &q->jobs[idx];
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        double t0 = mono_ms();
        int rc = getaddrinfo(job->host, NULL, &hints, &res);
        job->ms = mono_ms() - t0;
        job->status = rc;
        if (rc == 0) {
            for (struct addrinfo *p = res; p && job->n_ips < 4; p = p->ai_next) {
                char buf[INET6_ADDRSTRLEN];
                nw_inet_ntop_sa(p->ai_addr, buf, sizeof(buf));
                if (buf[0] && strcmp(buf, "?") != 0) {
                    snprintf(job->ips[job->n_ips], INET6_ADDRSTRLEN, "%s", buf);
                    job->n_ips++;
                }
            }
            freeaddrinfo(res);
        }
    }
}

/* ---------------- main ---------------- */

#ifdef _WIN32
static char *nw_strdup(const char *s) { return _strdup(s); }
#else
static char *nw_strdup(const char *s) { return strdup(s); }
#endif

static int cmd_dns(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "usage: dns <h1,h2,...> [--threads N]\n"); return 2; }
    const char *csv = argv[0];
    int threads = 16;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
        else { fprintf(stderr, "unknown opt: %s\n", argv[i]); return 2; }
    }
    /* парсим список */
    int cap = 64, n = 0;
    char **hosts = malloc(cap * sizeof(char *));
    char *dup = nw_strdup(csv);
    for (char *tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
        while (*tok == ' ') tok++;
        if (!*tok) continue;
        if (n == cap) { cap *= 2; hosts = realloc(hosts, cap * sizeof(char *)); }
        hosts[n++] = tok;
    }
    if (threads > n) threads = n;
    if (threads < 1) threads = 1;

    dns_job_t *jobs = calloc(n, sizeof(dns_job_t));
    for (int i = 0; i < n; i++) jobs[i].host = hosts[i];

    dns_queue_t q = { .jobs = jobs, .n = n, .pos = 0 };
    pthread_mutex_init(&q.mtx, NULL);

    pthread_t *pool = malloc(sizeof(pthread_t) * threads);
    for (int t = 0; t < threads; t++) pthread_create(&pool[t], NULL, dns_worker, &q);
    for (int t = 0; t < threads; t++) pthread_join(pool[t], NULL);
    free(pool);
    pthread_mutex_destroy(&q.mtx);

    int ok = 0;
    double slowest = 0;
    printf("{\"mode\":\"dns\",\"engine\":\"c\",\"results\":[");
    for (int i = 0; i < n; i++) {
        if (i) fputc(',', stdout);
        printf("{\"host\":"); json_escape_str(stdout, jobs[i].host);
        printf(",\"ok\":%s,\"ms\":%.2f,\"ips\":[", jobs[i].status == 0 ? "true" : "false", jobs[i].ms);
        for (int k = 0; k < jobs[i].n_ips; k++) {
            if (k) fputc(',', stdout);
            json_escape_str(stdout, jobs[i].ips[k]);
        }
        printf("]");
        if (jobs[i].status != 0) {
            printf(",\"error\":");
            json_escape_str(stdout, gai_strerror(jobs[i].status));
        }
        printf("}");
        if (jobs[i].status == 0) ok++;
        if (jobs[i].ms > slowest) slowest = jobs[i].ms;
    }
    printf("],\"total\":%d,\"ok\":%d,\"failed\":%d,\"slowest_ms\":%.2f}\n",
           n, ok, n - ok, slowest);
    fflush(stdout);
    free(jobs); free(hosts); free(dup);
    return 0;
}

/* ---------------- main ---------------- */

int main(int argc, char **argv) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif
    int rc = 2;
    if (argc < 2) {
        fprintf(stderr,
            "nwaccel — C-ядро netwatch\n"
            "  nwaccel ping <host> [--count N] [--interval MS] [--size B] [--df] [--ttl T] [--sockets K] [--deadline MS]\n"
            "  nwaccel dns  <h1,h2,...> [--threads N]\n");
        rc = 2;
    } else if (!strcmp(argv[1], "ping")) rc = cmd_ping(argc - 2, argv + 2);
    else if (!strcmp(argv[1], "dns"))    rc = cmd_dns(argc - 2, argv + 2);
    else { fprintf(stderr, "unknown command: %s\n", argv[1]); rc = 2; }
#ifdef _WIN32
    nw_net_cleanup();
#endif
    return rc;
}
