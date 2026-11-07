package com.mini;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Just a dashboard. Requests VPN consent once, starts MiniVpn, then shows the
 * counters so we can tell whether the forged RSTs are reaching the request
 * socket at all.
 */
public class MainActivity extends Activity {

    private static final int REQ_VPN = 1;

    private TextView tv;
    private final Handler handler = new Handler();

    private final Runnable ticker = new Runnable() {
        @Override
        public void run() {
            long rounds = MiniVpn.rounds.get();
            long ok = MiniVpn.okCount.get();
            long rst = MiniVpn.rstCount.get();
            long err = MiniVpn.errCount.get();
            long total = ok + rst;
            long pct = total == 0 ? 0 : (rst * 100 / total);

            tv.setText("status : " + MiniVpn.status
                    + "\nrounds : " + rounds
                    + "\nconnect ok  : " + ok
                    + "\nconnect rst : " + rst
                    + "\ntun write err: " + err
                    + "\nreset ratio : " + pct + "%");
            handler.postDelayed(this, 500);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        tv = new TextView(this);
        tv.setTextSize(13);
        tv.setPadding(0, 0, 0, pad);
        root.addView(tv);

        ScrollView scroller = new ScrollView(this);
        scroller.addView(root);
        setContentView(scroller);

        Intent prep = VpnService.prepare(this);
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN);
        } else {
            startService(new Intent(this, MiniVpn.class));
        }
        handler.post(ticker);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQ_VPN) {
            startService(new Intent(this, MiniVpn.class));
        }
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacks(ticker);
        super.onDestroy();
    }
}