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

    private void launchService() {
        Intent i = new Intent(this, InjService.class);
        i.setAction(InjService.ACTION_START);
        startForegroundService(i);
        status.setText("service started, watch logcat tag InjService");
    }
}