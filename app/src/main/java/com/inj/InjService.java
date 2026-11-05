package com.inj;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Owns a tun device, a listener bound inside that tun, and a control channel
 * back to the machine that builds packets.
 *
 * Packets written to the tun write end are handed to the kernel as if they had
 * arrived on the interface, so the listener sees them through the ordinary
 * receive path. That is the whole point: it gives us TCP segments with an
 * arbitrary source address, source port and sequence number without needing
 * CAP_NET_RAW on this device.
 *
 * The route is scoped to the tunnel subnet. A default route would swallow the
 * control channel's own traffic and deadlock the session.
 */
public class InjService extends VpnService {

    static final String ACTION_START = "com.inj.START";
    static final String ACTION_STOP = "com.inj.STOP";

    private static final String TAG = "InjService";

    private static final String TUN_ADDRESS = "10.7.7.1";
    private static final int TUN_PREFIX = 24;
    private static final String TUN_SUBNET = "10.7.7.0";
    private static final int TUN_MTU = 1500;

    /** Listener that absorbing the injected SYNs. */
    private static final int LISTEN_PORT = 47100;
    private static final int LISTEN_BACKLOG = 128;

    private static final String CLOUD_HOST = "5.180.98.79";
    private static final int CLOUD_PORT = 45700;
    private static final int CONNECT_TIMEOUT_MS = 10000;

    private static final int MAX_PACKET = 4096;
    private static final int ACK_BYTE = 0x06;

    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "inj";

    private final AtomicBoolean running = new AtomicBoolean(false);

    private ParcelFileDescriptor tun;
    private ServerSocket listener;
    private Thread pump;
    private Thread acceptor;

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
            builder.addRoute(TUN_SUBNET, TUN_PREFIX);
            builder.setMtu(TUN_MTU);
            if (Build.VERSION.SDK_INT >= 29) {
                builder.setBlocking(true);
            }

            tun = builder.establish();
            if (tun == null) {
                Log.e(TAG, "establish returned null: no consent, or another VPN is active");
                return;
            }
            Log.i(TAG, "tun up, fd=" + tun.getFd() + ", route " + TUN_SUBNET + "/" + TUN_PREFIX);

            // The listener must be bound after establish(), otherwise the
            // address does not exist yet and bind() fails with EADDRNOTAVAIL.
            listener = new ServerSocket();
            listener.setReuseAddress(true);
            listener.bind(new InetSocketAddress(
                    InetAddress.getByName(TUN_ADDRESS), LISTEN_PORT), LISTEN_BACKLOG);
            Log.i(TAG, "listener bound " + TUN_ADDRESS + ":" + LISTEN_PORT);

            acceptor = new Thread(this::acceptLoop, "tun-accept");
            acceptor.setDaemon(true);
            acceptor.start();

            OutputStream sink = new FileOutputStream(tun.getFileDescriptor());

            control = new Socket();
            control.connect(new InetSocketAddress(CLOUD_HOST, CLOUD_PORT), CONNECT_TIMEOUT_MS);
            control.setTcpNoDelay(true);

            InputStream frame = control.getInputStream();
            OutputStream ack = control.getOutputStream();
            Log.i(TAG, "control channel established");

            byte[] lengthField = new byte[4];
            byte[] packet = new byte[MAX_PACKET];

            while (running.get()) {
                if (!readFully(frame, lengthField, 4)) {
                    Log.w(TAG, "control channel closed");
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

                sink.write(packet, 0, length);
                sink.flush();

                ack.write(ACK_BYTE);
                ack.flush();
                Log.i(TAG, "injected " + length + " bytes");
            }
        } catch (Exception e) {
            Log.e(TAG, "pump stopped", e);
        } finally {
            closeQuietly(control);
            stopAll();
            running.set(false);
        }
    }

    /** Drains the listener so the accept queue never fills and stalls the SYN path. */
    private void acceptLoop() {
        while (running.get()) {
            Socket s = null;
            try {
                s = listener.accept();
                Log.i(TAG, "accepted from " + s.getInetAddress().getHostAddress()
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
        closeQuietly(listener);
        listener = null;
        closeQuietly(tun);
        tun = null;

        Thread a = acceptor;
        acceptor = null;
        if (a != null) {
            a.interrupt();
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