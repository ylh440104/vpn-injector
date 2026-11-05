package com.inj;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Owns a tun device, a listener on the tunnel endpoint, and a control channel
 * back to the machine that builds packets.
 *
 * No routes are added. The kernel installs its own connected route for the
 * interface address, which is enough: the endpoint stays a local address, so a
 * packet written to the tun is processed by ip_rcv and delivered to the local
 * socket exactly as if it had arrived on a physical interface. Adding an
 * explicit route over the subnet instead made endpoint traffic get pulled into
 * the tun read side and never reach the socket.
 *
 * The read side is forwarded back over the control channel rather than dropped.
 * The kernel's replies go to the forged source address, which has no owner, so
 * the only way to see them and to answer with a matching ACK is to hand them
 * back to the machine that is building the packets.
 *
 * Control protocol:
 *   server -> app   4 byte big-endian length, then that many bytes of IPv4
 *   app -> server   1 byte 0x06 to acknowledge an injected packet
 *                   1 byte 0x07 followed by a 4 byte length and the packet,
 *                   for every packet read back from the tun
 */
public class InjService extends VpnService {

    static final String ACTION_START = "com.inj.START";
    static final String ACTION_STOP = "com.inj.STOP";

    private static final String TAG = "InjService";

    private static final String TUN_ADDRESS = "10.7.7.1";
    private static final int TUN_PREFIX = 24;
    private static final int TUN_MTU = 1500;

    private static final int LISTEN_PORT = 47100;
    private static final int LISTEN_BACKLOG = 128;

    private static final String CLOUD_HOST = "5.180.98.79";
    private static final int CLOUD_PORT = 45700;
    private static final int CONNECT_TIMEOUT_MS = 10000;

    private static final int MAX_PACKET = 4096;
    private static final int ACK_BYTE = 0x06;
    private static final int OUT_BYTE = 0x07;

    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "inj";

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong injected = new AtomicLong();
    private final AtomicLong drained = new AtomicLong();

    private ParcelFileDescriptor tun;
    private ServerSocket listener;
    private Thread pump;
    private Thread drainer;
    private Thread acceptor;

    private volatile OutputStream controlOut;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();

        if (ACTION_STOP.equals(action)) {
            stopAll();
            stopSelf();
            return START_NOT_STICKY;
        }

        startForeground(NOTIFICATION_ID, buildNotification());

        if (running.compareAndSet(false, true)) {
            pump = new Thread(this::pumpLoop, "tun-pump");
            pump.setDaemon(true);
            pump.start();
        }
        return START_STICKY;
    }

    private void pumpLoop() {
        Socket control = null;

        try {
            Builder builder = new Builder();
            builder.setSession("inj");
            builder.addAddress(TUN_ADDRESS, TUN_PREFIX);
            builder.setMtu(TUN_MTU);
            if (Build.VERSION.SDK_INT >= 29) {
                builder.setBlocking(true);
            }

            tun = builder.establish();
            if (tun == null) {
                Log.e(TAG, "establish returned null: no consent, or another VPN is active");
                return;
            }
            Log.i(TAG, "tun up, fd=" + tun.getFd() + ", address " + TUN_ADDRESS + "/" + TUN_PREFIX);

            listener = new ServerSocket();
            listener.setReuseAddress(true);
            listener.bind(new InetSocketAddress(
                    InetAddress.getByName(TUN_ADDRESS), LISTEN_PORT), LISTEN_BACKLOG);
            Log.i(TAG, "listener bound " + TUN_ADDRESS + ":" + LISTEN_PORT);

            acceptor = new Thread(this::acceptLoop, "tun-accept");
            acceptor.setDaemon(true);
            acceptor.start();

            control = new Socket();
            control.connect(new InetSocketAddress(CLOUD_HOST, CLOUD_PORT), CONNECT_TIMEOUT_MS);
            control.setTcpNoDelay(true);

            InputStream frame = control.getInputStream();
            OutputStream out = control.getOutputStream();
            controlOut = out;
            Log.i(TAG, "control channel established");

            drainer = new Thread(this::drainLoop, "tun-drain");
            drainer.setDaemon(true);
            drainer.start();

            OutputStream sink = new FileOutputStream(tun.getFileDescriptor());

            byte[] lengthField = new byte[4];
            byte[] packet = new byte[MAX_PACKET];

            while (running.get()) {
                if (!readFully(frame, lengthField, 4)) {
                    Log.w(TAG, "control channel closed, keeping tun alive for observation");
                    break;
                }

                int length = ((lengthField[0] & 0xff) << 24)
                        | ((lengthField[1] & 0xff) << 16)
                        | ((lengthField[2] & 0xff) << 8)
                        | (lengthField[3] & 0xff);

                if (length < 20 || length > MAX_PACKET) {
                    Log.w(TAG, "rejecting frame with length " + length);
                    break;
                }

                if (!readFully(frame, packet, length)) {
                    break;
                }

                try {
                    sink.write(packet, 0, length);
                    sink.flush();
                    long n = injected.incrementAndGet();
                    if (n % 20 == 1) {
                        Log.i(TAG, "injected #" + n + " len=" + length
                                + " drained=" + drained.get());
                    }
                } catch (Exception we) {
                    Log.e(TAG, "tun write failed at #" + (injected.get() + 1), we);
                    break;
                }

                out.write(ACK_BYTE);
                out.flush();
            }
        } catch (Exception e) {
            Log.e(TAG, "pump stopped", e);
        } finally {
            closeQuietly(control);
            controlOut = null;
            Log.i(TAG, "pump finished, injected=" + injected.get()
                    + " drained=" + drained.get() + ", tun still up");
        }
    }

    /** Forwards everything the kernel sends toward the forged source back to the server. */
    private void drainLoop() {
        try {
            FileInputStream source = new FileInputStream(tun.getFileDescriptor());
            byte[] buf = new byte[MAX_PACKET];
            while (running.get()) {
                int n = source.read(buf);
                if (n <= 0) {
                    break;
                }
                long count = drained.incrementAndGet();
                if (count <= 3) {
                    Log.i(TAG, "tun read #" + count + " len=" + n + " proto="
                            + (n > 9 ? (buf[9] & 0xff) : -1));
                }

                OutputStream out = controlOut;
                if (out != null) {
                    try {
                        byte[] len = new byte[4];
                        len[0] = (byte) ((n >> 24) & 0xff);
                        len[1] = (byte) ((n >> 16) & 0xff);
                        len[2] = (byte) ((n >> 8) & 0xff);
                        len[3] = (byte) (n & 0xff);
                        synchronized (out) {
                            out.write(OUT_BYTE);
                            out.write(len);
                            out.write(buf, 0, n);
                            out.flush();
                        }
                    } catch (Exception ignored) {
                        controlOut = null;
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "drain loop ended: " + e);
        }
    }

    private void acceptLoop() {
        while (running.get()) {
            Socket s = null;
            try {
                s = listener.accept();
                Log.i(TAG, "ACCEPT from " + s.getInetAddress().getHostAddress()
                        + ":" + s.getPort());
            } catch (Exception e) {
                if (!running.get()) {
                    break;
                }
            } finally {
                closeQuietly(s);
            }
        }
    }

    private static boolean readFully(InputStream in, byte[] dst, int count) throws Exception {
        int offset = 0;
        while (offset < count) {
            int n = in.read(dst, offset, count - offset);
            if (n <= 0) {
                return false;
            }
            offset += n;
        }
        return true;
    }

    private void stopAll() {
        running.set(false);
        closeQuietly(listener);
        listener = null;
        closeQuietly(tun);
        tun = null;

        Thread a = acceptor;
        acceptor = null;
        if (a != null) {
            a.interrupt();
        }
        Thread d = drainer;
        drainer = null;
        if (d != null) {
            d.interrupt();
        }
    }

    private static void closeQuietly(AutoCloseable c) {
        if (c == null) {
            return;
        }
        try {
            c.close();
        } catch (Exception ignored) {
        }
    }

    private Notification buildNotification() {
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "Tunnel", NotificationManager.IMPORTANCE_LOW);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
            b = new Notification.Builder(this, CHANNEL_ID);
        } else {
            b = new Notification.Builder(this);
        }

        return b.setContentTitle("Inj tunnel")
                .setContentText(TUN_ADDRESS + "/" + TUN_PREFIX)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setOngoing(true)
                .build();
    }

    @Override
    public void onDestroy() {
        stopAll();
        super.onDestroy();
    }
}