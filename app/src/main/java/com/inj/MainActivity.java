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

    private void launchService() {
        Intent i = new Intent(this, InjService.class);
        i.setAction(InjService.ACTION_START);
        startForegroundService(i);

        String probe = nativeCheck();
        Log.i(TAG, probe);
        status.setText("service started\n" + probe);
    }
}