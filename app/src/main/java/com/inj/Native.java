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
     * Returns "OK fd=N addr:port" on success, or a string naming the syscall
     * that failed together with its errno. The address is explicit because the
     * tun endpoint only exists inside the VPN, and a wrong guess has to be
     * distinguishable from a port conflict.
     */
    public static native String makeListener(String addr, int port);

    /** UDP socket carrying its own options object, as a control case. */
    public static native int[] makeUdp(int tag);

    public static native int closeFd(int fd);
}