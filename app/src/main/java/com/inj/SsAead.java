package com.inj;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Shadowsocks AEAD stream layer, aes-256-gcm.
 *
 * AES/GCM is available from API 21 on, while ChaCha20-Poly1305 only appears in
 * API 28, so this keeps the client usable on older devices. The wire format is
 * the standard one: each direction starts with a 32 byte salt, then payloads
 * arrive as [encrypted 2 byte length][tag][encrypted body][tag], with the
 * nonce incremented once per chunk.
 */
final class SsAead {
    private static final int KEY_LEN = 32;
    private static final int NONCE_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final int TAG_LEN = 16;
    private static final int MAX_CHUNK = 0x3FFF;

    private final byte[] masterKey;
    private final SecureRandom random = new SecureRandom();

    /** One direction of a connection: salt already sent, nonce advancing. */
    private static final class Ctx {
        final byte[] key;
        final byte[] nonce = new byte[NONCE_LEN];
        Ctx(byte[] key) { this.key = key; }
    }

    private Ctx out;
    private Ctx in;

    SsAead(String password) {
        this.masterKey = evpBytesToKey(password);
    }

    private static byte[] evpBytesToKey(String password) {
        byte[] pass = password.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] out = new byte[KEY_LEN];
        byte[] prev = new byte[0];
        int filled = 0;
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            while (filled < KEY_LEN) {
                md5.reset();
                md5.update(prev);
                md5.update(pass);
                prev = md5.digest();
                int n = Math.min(prev.length, KEY_LEN - filled);
                System.arraycopy(prev, 0, out, filled, n);
                filled += n;
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("md5 unavailable", e);
        }
        return out;
    }

    private static byte[] subkey(byte[] master, byte[] salt) {
        byte[] info = "ss-subkey".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(salt, "HmacSHA1"));
            byte[] prk = mac.doFinal(master);
            mac.init(new SecretKeySpec(prk, "HmacSHA1"));
            mac.update(info);
            mac.update((byte) 1);
            return Arrays.copyOf(mac.doFinal(), KEY_LEN);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("hkdf failed", e);
        }
    }

    private static Cipher cipher(Ctx c, int mode) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(c.key, "AES"),
                new GCMParameterSpec(TAG_BITS, c.nonce));
        return cipher;
    }

    private static void bump(byte[] nonce) {
        for (int i = 0; i < nonce.length; i++) {
            if (++nonce[i] != 0) {
                break;
            }
        }
    }

    /** First outgoing chunk must be preceded by the salt. */
    byte[] openOutgoing() {
        byte[] salt = new byte[KEY_LEN];
        random.nextBytes(salt);
        out = new Ctx(subkey(masterKey, salt));
        return salt;
    }

    byte[] seal(byte[] plain, int off, int len) throws IOException {
        if (len > MAX_CHUNK) {
            throw new IOException("chunk too large: " + len);
        }
        try {
            byte[] outBuf = new byte[2 + TAG_LEN + len + TAG_LEN];
            byte[] lenField = new byte[]{(byte) (len >> 8), (byte) len};
            cipher(out, Cipher.ENCRYPT_MODE).doFinal(lenField, 0, 2, outBuf, 0);
            bump(out.nonce);
            cipher(out, Cipher.ENCRYPT_MODE).doFinal(plain, off, len, outBuf, 2 + TAG_LEN);
            bump(out.nonce);
            return outBuf;
        } catch (GeneralSecurityException e) {
            throw new IOException("seal failed", e);
        }
    }

    void readSalt(InputStream in) throws IOException {
        byte[] salt = new byte[KEY_LEN];
        readFully(in, salt);
        this.in = new Ctx(subkey(masterKey, salt));
    }

    int openLength(InputStream stream) throws IOException {
        byte[] buf = new byte[2 + TAG_LEN];
        readFully(stream, buf);
        try {
            byte[] len = cipher(in, Cipher.DECRYPT_MODE).doFinal(buf);
            bump(in.nonce);
            return ((len[0] & 0xff) << 8) | (len[1] & 0xff);
        } catch (GeneralSecurityException e) {
            throw new IOException("bad length chunk", e);
        }
    }

    byte[] openBody(InputStream stream, int len) throws IOException {
        byte[] buf = new byte[len + TAG_LEN];
        readFully(stream, buf);
        try {
            byte[] body = cipher(in, Cipher.DECRYPT_MODE).doFinal(buf);
            bump(in.nonce);
            return body;
        } catch (GeneralSecurityException e) {
            throw new IOException("bad body chunk", e);
        }
    }

    private static void readFully(InputStream in, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) {
                throw new IOException("eof");
            }
            off += n;
        }
    }
}