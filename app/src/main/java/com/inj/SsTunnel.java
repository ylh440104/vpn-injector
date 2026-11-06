package com.inj;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * One Shadowsocks stream to the server, carrying one TCP connection.
 *
 * The first chunk the client sends is the SOCKS-style target address followed
 * by payload, which the server reads to decide where to connect.
 */
final class SsTunnel {
    private final Socket socket;
    private final SsAead aead;
    private final InputStream rawIn;
    private final OutputStream rawOut;
    private boolean decrypted;

    private SsTunnel(Socket socket, SsAead aead) throws IOException {
        this.socket = socket;
        this.aead = aead;
        this.rawIn = new BufferedInputStream(socket.getInputStream(), 16384);
        this.rawOut = new BufferedOutputStream(socket.getOutputStream(), 16384);
    }

    static SsTunnel open(String server, int port, String password,
                         String host, int dstPort, int timeoutMs) throws IOException {
        Socket s = new Socket();
        try {
            s.setTcpNoDelay(true);
            s.connect(new InetSocketAddress(server, port), timeoutMs);

            SsAead aead = new SsAead(password);
            SsTunnel t = new SsTunnel(s, aead);

            byte[] addr = encodeAddress(host, dstPort);
            byte[] salt = aead.openOutgoing();
            t.rawOut.write(salt);
            t.rawOut.write(aead.seal(addr, 0, addr.length));
            t.rawOut.flush();
            return t;
        } catch (IOException e) {
            try {
                s.close();
            } catch (IOException ignored) {
            }
            throw e;
        }
    }

    /** SOCKS5 address encoding: type, address, big endian port. */
    private static byte[] encodeAddress(String host, int port) throws IOException {
        byte[] addrBytes;
        byte type;
        byte[] literal = ipv4Bytes(host);
        if (literal != null) {
            type = 1;
            addrBytes = literal;
        } else {
            byte[] name = host.getBytes(StandardCharsets.UTF_8);
            if (name.length > 255) {
                throw new IOException("hostname too long");
            }
            type = 3;
            addrBytes = new byte[1 + name.length];
            addrBytes[0] = (byte) name.length;
            System.arraycopy(name, 0, addrBytes, 1, name.length);
        }
        byte[] out = new byte[1 + addrBytes.length + 2];
        out[0] = type;
        System.arraycopy(addrBytes, 0, out, 1, addrBytes.length);
        int p = 1 + addrBytes.length;
        out[p] = (byte) (port >> 8);
        out[p + 1] = (byte) port;
        return out;
    }

    private static byte[] ipv4Bytes(String host) {
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            try {
                int v = Integer.parseInt(parts[i]);
                if (v < 0 || v > 255) {
                    return null;
                }
                out[i] = (byte) v;
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return out;
    }

    /** Encrypt and queue payload; flush is left to the caller's cadence. */
    void write(byte[] buf, int off, int len) throws IOException {
        while (len > 0) {
            int n = Math.min(len, 0x3FFF);
            rawOut.write(aead.seal(buf, off, n));
            off += n;
            len -= n;
        }
        rawOut.flush();
    }

    void writeFlush() throws IOException {
        rawOut.flush();
    }

    /** Returns payload bytes, or -1 at end of stream. */
    int read(byte[] dst) throws IOException {
        if (!decrypted) {
            aead.readSalt(rawIn);
            decrypted = true;
        }
        int len = aead.openLength(rawIn);
        if (len <= 0) {
            return -1;
        }
        byte[] body = aead.openBody(rawIn, len);
        int n = Math.min(body.length, dst.length);
        System.arraycopy(body, 0, dst, 0, n);
        return n;
    }

    void shutdownOutput() {
        try {
            socket.shutdownOutput();
        } catch (IOException ignored) {
        }
    }

    void close() {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }
}