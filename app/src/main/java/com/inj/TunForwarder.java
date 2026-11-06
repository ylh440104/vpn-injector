package com.inj;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Minimal tun2socks: reads IP packets from the tunnel, terminates TCP in user
 * space and forwards the payload through a Shadowsocks stream, and relays DNS
 * over the underlying network so name resolution keeps working.
 *
 * The stack is deliberately small. The tunnel is a memory buffer, so segments
 * are not lost or reordered, which means no retransmission, no congestion
 * control and no reassembly are needed - just sequence bookkeeping so the
 * kernel on the other side of the tunnel stays happy.
 */
final class TunForwarder {
    private static final int IPV4_TCP = 6;
    private static final int IPV4_UDP = 17;

    private static final int FIN = 0x01;
    private static final int SYN = 0x02;
    private static final int RST = 0x04;
    private static final int PSH = 0x08;
    private static final int ACK = 0x10;

    private final String server;
    private final int serverPort;
    private final String password;
    private final String dnsServer;
    private final FileInputStream in;
    private final FileOutputStream out;
    private final Map<Integer, TcpFlow> flows = new ConcurrentHashMap<>();
    private final AtomicInteger portSeq = new AtomicInteger(20000);
    private volatile boolean running = true;

    TunForwarder(FileInputStream in, FileOutputStream out,
                 String server, int serverPort, String password, String dnsServer) {
        this.in = in;
        this.out = out;
        this.server = server;
        this.serverPort = serverPort;
        this.password = password;
        this.dnsServer = dnsServer;
    }

    void stop() {
        running = false;
        for (TcpFlow f : flows.values()) {
            f.close();
        }
        flows.clear();
    }

    void run() {
        byte[] buf = new byte[4096];
        while (running) {
            int n;
            try {
                n = in.read(buf);
            } catch (IOException e) {
                break;
            }
            if (n <= 0) {
                break;
            }
            try {
                handle(buf, n);
            } catch (Exception ignored) {
            }
        }
    }

    void handle(byte[] p, int len) throws IOException {
        if (len < 20 || (p[0] >> 4) != 4) {
            return;
        }
        int ihl = (p[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl) {
            return;
        }
        int proto = p[9] & 0xFF;
        int dstStart = 16;

        if (proto == IPV4_UDP) {
            // DNS waits on a real socket, so it must not stall the tunnel loop
            // that also carries the injected packets.
            final byte[] copy = new byte[len];
            System.arraycopy(p, 0, copy, 0, len);
            final int udpOff = ihl;
            new Thread(() -> {
                try {
                    handleUdp(copy, copy.length, udpOff);
                } catch (Exception ignored) {
                }
            }, "dns").start();
            return;
        }
        if (proto != IPV4_TCP) {
            return;
        }

        int tcpOff = ihl;
        if (len < tcpOff + 20) {
            return;
        }
        int srcPort = ((p[tcpOff] & 0xFF) << 8) | (p[tcpOff + 1] & 0xFF);
        int dstPort = ((p[tcpOff + 2] & 0xFF) << 8) | (p[tcpOff + 3] & 0xFF);
        long seq = readU32(p, tcpOff + 4);
        int dataOff = ((p[tcpOff + 12] >> 4) & 0x0F) * 4;
        int flags = p[tcpOff + 13] & 0xFF;
        int payloadOff = tcpOff + dataOff;
        int payloadLen = len - payloadOff;
        if (payloadLen < 0) {
            payloadLen = 0;
        }

        byte[] srcIp = new byte[4];
        byte[] dstIp = new byte[4];
        System.arraycopy(p, 12, srcIp, 0, 4);
        System.arraycopy(p, dstStart, dstIp, 0, 4);

        int key = hashKey(srcPort, dstPort, dstIp);
        TcpFlow flow = flows.get(key);

        if ((flags & SYN) != 0 && (flags & ACK) == 0) {
            TcpFlow fresh = new TcpFlow(this, key, srcIp, srcPort, dstIp, dstPort, seq + 1);
            flows.put(key, fresh);
            fresh.start();
            return;
        }
        if (flow == null) {
            sendTcp(srcIp, dstIp, dstPort, srcPort, 1, seq + payloadLen, RST | ACK, null, 0);
            return;
        }
        flow.onSegment(seq, flags, p, payloadOff, payloadLen);
    }

    private void handleUdp(byte[] p, int len, int ihl) throws IOException {
        int udpOff = ihl;
        if (len < udpOff + 8) {
            return;
        }
        int srcPort = ((p[udpOff] & 0xFF) << 8) | (p[udpOff + 1] & 0xFF);
        int dstPort = ((p[udpOff + 2] & 0xFF) << 8) | (p[udpOff + 3] & 0xFF);
        int udpLen = ((p[udpOff + 4] & 0xFF) << 8) | (p[udpOff + 5] & 0xFF);
        int payloadLen = udpLen - 8;
        if (payloadLen <= 0 || udpOff + udpLen > len) {
            return;
        }
        if (dstPort != 53) {
            // Everything else is dropped on purpose: browsers fall back to TCP.
            return;
        }
        byte[] query = new byte[payloadLen];
        System.arraycopy(p, udpOff + 8, query, 0, payloadLen);

        byte[] srcIp = new byte[4];
        byte[] dstIp = new byte[4];
        System.arraycopy(p, 12, srcIp, 0, 4);
        System.arraycopy(p, 16, dstIp, 0, 4);

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(4000);
            InetAddress dns = InetAddress.getByName(dnsServer);
            socket.send(new DatagramPacket(query, query.length, dns, 53));
            byte[] resp = new byte[1500];
            DatagramPacket reply = new DatagramPacket(resp, resp.length);
            socket.receive(reply);
            byte[] answer = new byte[reply.getLength()];
            System.arraycopy(resp, 0, answer, 0, answer.length);
            sendUdp(dstIp, srcIp, dstPort, srcPort, answer);
        } catch (IOException ignored) {
        }
    }

    private static int hashKey(int srcPort, int dstPort, byte[] dstIp) {
        int h = dstIp[0] << 24 | dstIp[1] << 16 | dstIp[2] << 8 | dstIp[3];
        return h * 31 + srcPort;
    }

    static long readU32(byte[] b, int off) {
        return ((long) (b[off] & 0xFF) << 24)
                | ((b[off + 1] & 0xFF) << 16)
                | ((b[off + 2] & 0xFF) << 8)
                | (b[off + 3] & 0xFF);
    }

    synchronized void sendTcp(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort,
                             long seq, long ack, int flags, byte[] payload, int payloadLen)
            throws IOException {
        byte[] pkt = buildTcp(srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload, payloadLen);
        out.write(pkt);
    }

    synchronized void sendUdp(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort,
                              byte[] payload) throws IOException {
        int total = 20 + 8 + payload.length;
        byte[] p = new byte[total];
        p[0] = 0x45;
        p[2] = (byte) (total >> 8);
        p[3] = (byte) total;
        p[8] = 64;
        p[9] = (byte) IPV4_UDP;
        System.arraycopy(srcIp, 0, p, 12, 4);
        System.arraycopy(dstIp, 0, p, 16, 4);
        writeChecksum(p, 0, 20, 0);
        int off = 20;
        p[off] = (byte) (srcPort >> 8);
        p[off + 1] = (byte) srcPort;
        p[off + 2] = (byte) (dstPort >> 8);
        p[off + 3] = (byte) dstPort;
        int udpLen = 8 + payload.length;
        p[off + 4] = (byte) (udpLen >> 8);
        p[off + 5] = (byte) udpLen;
        System.arraycopy(payload, 0, p, off + 8, payload.length);
        out.write(p);
    }

    static byte[] buildTcp(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort,
                           long seq, long ack, int flags, byte[] payload, int payloadLen) {
        int total = 20 + 20 + payloadLen;
        byte[] p = new byte[total];
        p[0] = 0x45;
        p[2] = (byte) (total >> 8);
        p[3] = (byte) total;
        p[8] = 64;
        p[9] = (byte) IPV4_TCP;
        System.arraycopy(srcIp, 0, p, 12, 4);
        System.arraycopy(dstIp, 0, p, 16, 4);
        writeChecksum(p, 0, 20, 0);

        int o = 20;
        p[o] = (byte) (srcPort >> 8);
        p[o + 1] = (byte) srcPort;
        p[o + 2] = (byte) (dstPort >> 8);
        p[o + 3] = (byte) dstPort;
        writeU32(p, o + 4, seq);
        writeU32(p, o + 8, ack);
        p[o + 12] = 0x50;
        p[o + 13] = (byte) flags;
        p[o + 14] = (byte) 0xFF;
        p[o + 15] = (byte) 0xFF;
        if (payloadLen > 0 && payload != null) {
            System.arraycopy(payload, 0, p, o + 20, payloadLen);
        }
        writeChecksum(p, o, 20 + payloadLen, 6);
        return p;
    }

    private static void writeU32(byte[] p, int off, long v) {
        p[off] = (byte) (v >> 24);
        p[off + 1] = (byte) (v >> 16);
        p[off + 2] = (byte) (v >> 8);
        p[off + 3] = (byte) v;
    }

    private static void writeChecksum(byte[] p, int off, int len, int protocol) {
        p[off + 16] = 0;
        p[off + 17] = 0;
        long sum = 0;
        if (off == 0) {
            for (int i = 0; i < len; i += 2) {
                sum += ((p[i] & 0xFF) << 8) | (p[i + 1] & 0xFF);
            }
        } else {
            // Pseudo header for TCP/UDP.
            for (int i = 12; i < 20; i += 2) {
                sum += ((p[i] & 0xFF) << 8) | (p[i + 1] & 0xFF);
            }
            sum += protocol;
            sum += len;
            for (int i = off; i < off + len; i += 2) {
                int hi = p[i] & 0xFF;
                int lo = (i + 1 < p.length) ? (p[i + 1] & 0xFF) : 0;
                sum += (hi << 8) | lo;
            }
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        int ck = (int) (~sum & 0xFFFF);
        p[off + 16] = (byte) (ck >> 8);
        p[off + 17] = (byte) ck;
    }

    int nextPort() {
        return portSeq.incrementAndGet() & 0x7FFF;
    }

    /** One TCP connection on the tunnel, mirrored to one Shadowsocks stream. */
    static final class TcpFlow {
        private final TunForwarder owner;
        private final int key;
        private final byte[] clientIp;
        private final int clientPort;
        private final byte[] serverIp;
        private final int serverPort;
        private long sendSeq;
        private long recvSeq;
        private volatile SsTunnel tunnel;
        private volatile boolean closed;

        TcpFlow(TunForwarder owner, int key, byte[] clientIp, int clientPort,
                byte[] serverIp, int serverPort, long clientNextSeq) {
            this.owner = owner;
            this.key = key;
            this.clientIp = clientIp;
            this.clientPort = clientPort;
            this.serverIp = serverIp;
            this.serverPort = serverPort;
            this.recvSeq = clientNextSeq;
            this.sendSeq = 1 + (System.nanoTime() & 0x7FFFFFF);
        }

        void close() {
            closed = true;
            SsTunnel t = tunnel;
            if (t != null) {
                t.close();
            }
        }

        void start() {
            new Thread(this::handshake, "flow-" + clientPort).start();
        }

        private void handshake() {
            String host = (clientIp[0] & 0xFF) + "." + (clientIp[1] & 0xFF) + "."
                    + (clientIp[2] & 0xFF) + "." + (clientIp[3] & 0xFF);
            try {
                SsTunnel t = SsTunnel.open(owner.server, owner.serverPort, owner.password,
                        host, serverPort, 8000);
                tunnel = t;
                owner.sendTcp(serverIp, clientIp, serverPort, clientPort,
                        sendSeq, recvSeq, SYN | ACK, null, 0);
                sendSeq++;
                pump();
            } catch (IOException e) {
                try {
                    owner.sendTcp(serverIp, clientIp, serverPort, clientPort,
                            sendSeq, recvSeq, RST | ACK, null, 0);
                } catch (IOException ignored) {
                }
                owner.flows.remove(key);
            }
        }

        private void pump() {
            byte[] buf = new byte[16384];
            try {
                while (!closed) {
                    int n = tunnel.read(buf);
                    if (n < 0) {
                        break;
                    }
                    owner.sendTcp(serverIp, clientIp, serverPort, clientPort,
                            sendSeq, recvSeq, PSH | ACK, buf, n);
                    sendSeq += n;
                }
                owner.sendTcp(serverIp, clientIp, serverPort, clientPort,
                        sendSeq, recvSeq, FIN | ACK, null, 0);
                sendSeq++;
            } catch (IOException ignored) {
            }
        }

        void onSegment(long seq, int flags, byte[] p, int off, int len) {
            if (closed) {
                return;
            }
            if ((flags & RST) != 0) {
                close();
                owner.flows.remove(key);
                return;
            }
            if (len > 0 && seq == recvSeq) {
                SsTunnel t = tunnel;
                if (t == null) {
                    return;
                }
                try {
                    t.write(p, off, len);
                    recvSeq += len;
                    owner.sendTcp(serverIp, clientIp, serverPort, clientPort,
                            sendSeq, recvSeq, ACK, null, 0);
                } catch (IOException e) {
                    close();
                }
            }
            if ((flags & FIN) != 0) {
                try {
                    owner.sendTcp(serverIp, clientIp, serverPort, clientPort,
                            sendSeq, recvSeq + 1, FIN | ACK, null, 0);
                } catch (IOException ignored) {
                }
                close();
                owner.flows.remove(key);
            }
        }
    }
}