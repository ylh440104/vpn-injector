package com.inj;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.Button;
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
        root.setPadding(48, 96, 48, 48);

        status = new TextView(this);
        status.setText("Idle.\n\nVpnService will take over the system VPN slot.\nAny running VPN app (e.g. Clash) will be replaced.");

        Button start = new Button(this);
        start.setText("Start tunnel");
        start.setOnClickListener(v -> prepareAndStart());

        Button stop = new Button(this);
        stop.setText("Stop tunnel");
        stop.setOnClickListener(v -> {
            Intent i = new Intent(this, InjService.class);
            i.setAction(InjService.ACTION_STOP);
            startService(i);
            status.setText("Stopped.");
        });

        root.addView(status);
        root.addView(start);
        root.addView(stop);
        setContentView(root);
    }

    private void prepareAndStart() {
        Intent consent = VpnService.prepare(this);
        if (consent != null) {
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
            status.setText("VPN consent denied.");
        }
    }

    private void launchService() {
        Intent i = new Intent(this, InjService.class);
        i.setAction(InjService.ACTION_START);
        startForegroundService(i);
        status.setText("Tunnel starting.\nLocal address 10.7.7.1/24\nCloud 5.180.98.79:45700");
    }
}