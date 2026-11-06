package com.inj;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    private static final int REQ_VPN = 1001;
    private static final String TAG = "InjNative";

    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(64, 160, 64, 64);

        status = new TextView(this);
        status.setTextSize(18f);
        status.setText("starting...");
        root.addView(status);

        android.widget.Button vpn = new android.widget.Button(this);
        vpn.setText("Start as VPN (internet via HK)");
        vpn.setOnClickListener(v -> launchForward());
        root.addView(vpn);

        setContentView(root);
    }

    @Override
    protected void onResume() {
        super.onResume();
        prepareAndStart();
    }

    private void prepareAndStart() {
        Intent consent = VpnService.prepare(this);
        if (consent != null) {
            status.setText("requesting VPN consent");
            startActivityForResult(consent, REQ_VPN);
        } else {
            launchService();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            launchService();
        } else {
            status.setText("VPN consent denied");
        }
    }

    /**
     * Exercise the native layer once the service is up.
     *
     * Loading the library at this point means a missing or mismatched .so shows
     * up as a line of text rather than as an unexplained crash in the middle of
     * a race test. Reading the options back also confirms the setsockopt round
     * trip works on this kernel before anything relies on it.
     */
    private String nativeCheck() {
        StringBuilder sb = new StringBuilder();

        try {
            int[] made = Native.makeUdp(0xdeadbeef);
            if (made == null) {
                sb.append("makeUdp failed");
            } else {
                int fd = made[0];
                sb.append("udp fd=").append(fd).append('\n');
                sb.append("read: ").append(Native.readOptions(fd)).append('\n');
                Native.closeFd(fd);
            }
        } catch (Throwable t) {
            sb.append("native error: ").append(t);
        }

        return sb.toString();
    }

    /**
     * Left as a placeholder.
     *
     * The listener probe moved into InjService because the tun address only
     * exists after establish() returns; running it from the activity raced the
     * VPN coming up and produced EADDRNOTAVAIL for an address that was merely
     * not there yet.
     */
    private String listenerCheck() {
        return "";
    }

    private void launchService() {
        launch(false);
    }

    /** Start the service in forwarding mode so it behaves as a real VPN. */
    private void launchForward() {
        launch(true);
    }

    private void launch(boolean forward) {
        if (forward) {
            // Switching modes needs a clean tunnel: Android only allows one
            // active VPN, and the old service would keep its fd.
            stopService(new Intent(this, InjService.class));
            try {
                Thread.sleep(400);
            } catch (InterruptedException ignored) {
            }
        }
        Intent i = new Intent(this, InjService.class);
        i.setAction(InjService.ACTION_START);
        i.putExtra(InjService.EXTRA_FORWARD, forward);
        startForegroundService(i);
        if (forward) {
            status.setText("forward mode: all traffic via HK");
            return;
        }

        String probe = nativeCheck() + listenerCheck();
        Log.i(TAG, probe);
        status.setText("service started\n" + probe);

        // Also drop the result where a shell can read it. The log ring buffer
        // on this device is short enough that a probe logged at startup is gone
        // by the time anyone looks, and a silent failure here would be
        // indistinguishable from the probe never running.
        try {
            java.io.FileOutputStream f = new java.io.FileOutputStream(
                    new java.io.File(getFilesDir(), "nativecheck.txt"));
            f.write(probe.getBytes("UTF-8"));
            f.close();
        } catch (Exception ignored) {
        }
    }
}