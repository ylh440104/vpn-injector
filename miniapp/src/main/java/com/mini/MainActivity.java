package com.mini;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    static final int REQ = 1;

    private TextView tv;
    private final Handler h = new Handler();

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            tv.setText("status: " + MiniVpn.status
                    + "\nrounds: " + MiniVpn.rounds.get()
                    + "\nconnect ok : " + MiniVpn.connOk.get()
                    + "\nconnect rst: " + MiniVpn.connRst.get());
            h.postDelayed(this, 500);
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        ll.setPadding(pad, pad, pad, pad);
        tv = new TextView(this);
        tv.setTextSize(12);
        ll.addView(tv);
        setContentView(ll);

        Intent prep = VpnService.prepare(this);
        if (prep != null) {
            startActivityForResult(prep, REQ);
        } else {
            startService(new Intent(this, MiniVpn.class));
        }
        h.post(tick);
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req == REQ) {
            startService(new Intent(this, MiniVpn.class));
        }
    }
}
