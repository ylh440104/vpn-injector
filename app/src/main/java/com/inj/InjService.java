package com.inj;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Owns a VpnService tun device and relays pre-built IPv4 packets from the
 * control server straight into it.  Anything written to the tun write-end is
 * handed to the kernel as if it had arrived on that interface, which is how we
 * reach the TCP receive path without CAP_NET_RAW.
 */
public class InjService extends VpnService {

    static final String ACTION_START = "com.inj.START";
    static final String ACTION_STOP = "com.inj.STOP";

    private static final String TAG = "InjService";

    /** Tunnel endpoint. Ranges outside 10.0.0.0/8 clash with nothing we need. */
    private static final String TUN_ADDRESS = "10.7.7.1";
    private static final int TUN_PREFIX = 24;
    private static final int TUN_MTU = 1500;

    /** Control channel back to the box that builds the packets. */
    private static final String CLOUD_HOST = "5.180.98.79";
    private static final int CLOUD_PORT = 45700;
    private static final int CONNECT_TIMEOUT_MS = 8000;

    private static final int MAX_PACKET = 4096;

    private ParcelFileDescriptor tun;
    private Thread pump;
    private volatile boolean running;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();

        if (ACTION_STOP.equals(action)) {
            shutdown();
            stopSelf();
            return START_NOT_STICKY;
        }

        startForeground(NOTIFICATION_ID, buildNotification());

        if (!running) {
            running = true;
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
            builder.addRoute("0.0.0.0", 0);
            builder.setMtu(TUN_MTU);
            if (Build.VERSION.SDK_INT >= 29) {
                builder.setBlocking(true);
            }

            tun = builder.establish();
            if (tun == null) {
                Log.e(TAG, "establish() returned null, consent missing or another VPN active");
                return;
            }
            Log.i(TAG, "tun up, fd=" + tun.getFd());

            OutputStream sink = new FileOutputStream(tun.getFileDescriptor());

            control = new Socket();
            control.connect(new InetSocketAddress(CLOUD_HOST, CLOUD_PORT), CONNECT_TIMEOUT_MS);
            control.setTcpNoDelay(true);
            InputStream in = control.getInputStream();
            OutputStream ack = control.getOutputStream();
            Log.i(TAG, "control channel connected");

            byte[] lengthField = new byte[4];
            byte[] packet = new byte[MAX_PACKET];

            while (running) {
                if (!readFully(in, lengthField, 4)) {
                    Log.w(TAG, "control channel closed");
                    break;
                }
                int length = ((lengthField[0] & 0xff) << 24)
                        | ((lengthField[1] & 0xff) << 16)
                        | ((lengthField[2] & 0xff) << 8)
                        | (lengthField[3] & 0xff);

                if (length < 20 || length > MAX_PACKET) {
                    Log.w(TAG, "bad frame length " + length);
                    break;
                }
                if (!readFully(in, packet, length)) {
                    break;
                }

                sink.write(packet, 0, length);
                sink.flush();

                ack.write(ACK);
                ack.flush();
            }
        } catch (Exception e) {
            Log.e(TAG, "pump failed", e);
        } finally {
            closeQuietly(control);
            shutdown();
        }
    }

    private static final int ACK = 0x06;

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

    private void shutdown() {
        running = false;
        closeQuietly(tun);
        tun = null;
        if (pump != null) {
            pump.interrupt();
            pump = null;
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

    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "inj";

    private Notification buildNotification() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "Tunnel", NotificationManager.IMPORTANCE_LOW);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }

        Notification.Builder b = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);

        return b.setContentTitle("Inj tunnel")
                .setContentText(TUN_ADDRESS + "/" + TUN_PREFIX)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setOngoing(true)
                .build();
    }

    @Override
    public void onDestroy() {
        shutdown();
        super.onDestroy();
    }
}