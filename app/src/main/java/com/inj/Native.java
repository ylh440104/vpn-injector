package com.inj;

/**
 * Thin bridge to the syscalls the Java socket API does not expose.
 *
 * Everything CVE-2026-98432 touches sits behind setsockopt(IP_OPTIONS) and
 * getsockopt(IP_OPTIONS): the first allocates the ip_options_rcu that ends up
 * on a request socket, the second is the read that trusts optlen. Neither is
 * reachable from java.net, so they live here.
 */
public final class Native {

    static {
        System.loadLibrary("injnative");
    }

    private Native() {
    }

    /** Attach a 40 byte record route option to an existing socket. */
    public static native int applyOptions(int fd, int tag);

    /** Read the options back, returned as "len=N hexbytes". */
    public static native String readOptions(int fd);

    /** Bind and listen on 10.7.7.1:port, returning the fd. */
    public static native int[] makeListener(int port);

    /** UDP socket carrying its own options object, as a control case. */
    public static native int[] makeUdp(int tag);

    public static native int closeFd(int fd);
}