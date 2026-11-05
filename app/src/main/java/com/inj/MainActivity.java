package com.inj;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    private static final int REQ_VPN = 1001;

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
     * Prove the native layer works before any of it is trusted.
     *
     * A failed System.loadLibrary shows up here as a message instead of as an
     * unexplained crash deep inside a race test, and the option bytes coming
     * back out of getsockopt() confirm the whole setsockopt round trip works on
     * this kernel.
     */
    private String nativeCheck() {
        StringBuilder sb = new StringBuilder();
        try {
            int[] made = Native.makeUdp(0xdeadbeef);
            if (made == null) {
                sb.append("makeUdp failed errno=").append(android.system.Os.getErrno()).append("
");
            } else {
                int fd = made[0];
                sb.append("udp fd=").append(fd).append("
");
                sb.append("read: ").append(Native.readOptions(fd)).append("
");
                Native.closeFd(fd);
            }
        } catch (Throwable t) {
            sb.append("native error: ").append(t).append("
");
        }
        return sb.toString();
    }

    private void launchService() {
        Intent i = new Intent(this, InjService.class);
        i.setAction(InjService.ACTION_START);
        startForegroundService(i);
        String probe = nativeCheck();
        android.util.Log.i("InjNative", probe);
        status.setText("service started
" + probe);
    }
}