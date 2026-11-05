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
     * Hand the native layer a listener that already carries an options object.
     *
     * The Java ServerSocket cannot take IP_OPTIONS, but the whole point of the
     * bug is that the object hangs off the socket's inet_opt and gets inherited
     * by children. Building the listener in C is the only way to get a socket
     * whose options object is reachable from the TCP path at all.
     */
    private String listenerCheck() {
        StringBuilder sb = new StringBuilder();

        try {
            int[] made = Native.makeListener(47101);
            if (made == null) {
                sb.append("makeListener failed\n");
            } else {
                sb.append("listener fd=").append(made[0]).append('\n');
                sb.append("before: ").append(Native.readOptions(made[0])).append('\n');

                int rc = Native.applyOptions(made[0], 0x11223344);
                sb.append("applyOptions rc=").append(rc).append('\n');

                sb.append("after: ").append(Native.readOptions(made[0])).append('\n');
            }
        } catch (Throwable t) {
            sb.append("listener error: ").append(t);
        }

        return sb.toString();
    }

    private void launchService() {
        Intent i = new Intent(this, InjService.class);
        i.setAction(InjService.ACTION_START);
        startForegroundService(i);

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