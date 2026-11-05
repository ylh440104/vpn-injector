package com.inj;

/**
 * Thin bridge to the syscalls the Java socket API does not expose.
 *
 * Everything CVE-2026-98432 touches sits behind setsockopt(IP_OPTIONS) and
 * getsockopt(IP_OPTIONS): the first allocates the ip_options_rcu that a request
 * socket ends up holding, the second is the read that trusts optlen. Neither is
 * reachable from java.net, so they live here.
 */
public final class Native {

    static {
        System.loadLibrary("injnative");
    }

    private Native() {
    }

    /** Attach a 40 byte record route option to an existing socket. Returns 0 or -errno. */
    public static native int applyOptions(int fd, int tag);

    /** Read the options back, returned as "len=N hexbytes" or an error string. */
    public static native String readOptions(int fd);

    /**
     * Create a listening socket on addr:port.
     *
     * Returns {fd, 0} on success, or {-1, errno} on failure. The raw fd comes
     * back because the caller has to setsockopt(IP_OPTIONS) on it: the whole
     * bug hangs off the options object that a TCP child inherits from its
     * listener, and java.net.ServerSocket cannot carry options at all.
     */
    public static native int[] makeListener(String addr, int port);

    /** UDP socket carrying its own options object, as a control case. */
    public static native int[] makeUdp(int tag);

    /**
     * Allocate count options objects with tag == index, then read every one
     * back and report anomalies.
     *
     * A clean slab run reports mismatched=0 badlen=0 dup=0. A duplicate free
     * shows up as a socket whose tag is not its own, or the same tag twice.
     */
    public static native String probeHeap(int count);

    public static native int closeFd(int fd);
}