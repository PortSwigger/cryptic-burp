package com.crypticburp.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Does the actual encrypt and decrypt work, and is safe to call from more than
 * one thread. The key and its settings live in a single volatile snapshot, so
 * the Swing config thread and Burp's editor threads can read them at the same
 * time without locking on every message.
 *
 * <p>Handles either a fixed IV or a fresh random IV per message that gets
 * prepended to the ciphertext (see {@link IvMode#PREPENDED}). The key and IV
 * bytes are never written to the log.
 */
public final class CryptoService {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** A frozen copy of the key and settings, so readers always see one consistent set. */
    private static final class State {
        final CipherSpec cipher;
        final Encoding encoding;
        final SecretKeySpec keySpec;
        final byte[] ivBytes;
        final IvMode ivMode;
        final boolean ready;
        final String status;

        State(CipherSpec cipher, Encoding encoding, SecretKeySpec keySpec,
              byte[] ivBytes, IvMode ivMode, boolean ready, String status) {
            this.cipher = cipher;
            this.encoding = encoding;
            this.keySpec = keySpec;
            this.ivBytes = ivBytes;
            this.ivMode = ivMode;
            this.ready = ready;
            this.status = status;
        }
    }

    private volatile State state =
            new State(CipherSpec.AES_CBC, Encoding.BASE64, null, null, IvMode.FIXED, false, "No key configured");

    public void configure(CipherSpec cipher, Encoding encoding, KeyFormat keyFormat,
                          String key, String iv, boolean ivSameAsKey) {
        configure(cipher, encoding, keyFormat, key, iv, ivSameAsKey, IvMode.FIXED);
    }

    public void configure(CipherSpec cipher, Encoding encoding, KeyFormat keyFormat,
                          String key, String iv, boolean ivSameAsKey, IvMode ivMode) {
        try {
            byte[] keyBytes = keyFormat.toBytes(key);
            if (keyBytes.length == 0) {
                this.state = new State(cipher, encoding, null, null, ivMode, false, "Key is empty");
                return;
            }
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, cipher.keyAlgorithm());

            boolean fixedIv = cipher.usesIv() && ivMode == IvMode.FIXED;
            byte[] ivBytes = new byte[0];
            if (fixedIv) {
                ivBytes = ivSameAsKey ? keyBytes : keyFormat.toBytes(iv);
                if (ivBytes.length == 0) {
                    this.state = new State(cipher, encoding, null, null, ivMode, false,
                            "IV is required for " + cipher.displayName());
                    return;
                }
            }

            String ivStatus;
            if (!cipher.usesIv()) {
                ivStatus = "";
            } else if (ivMode == IvMode.PREPENDED) {
                ivStatus = ", iv prepended (" + cipher.ivLength() + " bytes)";
            } else {
                ivStatus = ", iv " + ivBytes.length + " bytes";
            }
            String status = String.format("Ready: %s, key %d bytes%s",
                    cipher.displayName(), keyBytes.length, ivStatus);
            this.state = new State(cipher, encoding, keySpec, ivBytes, ivMode, true, status);
        } catch (CryptoException e) {
            this.state = new State(cipher, encoding, null, null, ivMode, false, e.getMessage());
        } catch (Exception e) {
            this.state = new State(cipher, encoding, null, null, ivMode, false, "Invalid key/IV");
        }
    }

    public boolean isReady() {
        return state.ready;
    }

    public String status() {
        return state.status;
    }

    public String decrypt(String encoded, Padding padding) throws CryptoException {
        State s = state;
        if (!s.ready) {
            throw new CryptoException("crypto is not configured");
        }
        if (encoded == null || encoded.isEmpty()) {
            throw new CryptoException("no ciphertext");
        }
        byte[] blob = s.encoding.decode(encoded);

        byte[] iv = s.ivBytes;
        byte[] ciphertext = blob;
        if (s.cipher.usesIv() && s.ivMode == IvMode.PREPENDED) {
            int ivLen = s.cipher.ivLength();
            if (blob.length < ivLen) {
                throw new CryptoException("ciphertext too short to contain a prepended IV");
            }
            iv = Arrays.copyOfRange(blob, 0, ivLen);
            ciphertext = Arrays.copyOfRange(blob, ivLen, blob.length);
        }

        try {
            Cipher cipher = Cipher.getInstance(s.cipher.transformation(padding));
            initCipher(cipher, Cipher.DECRYPT_MODE, s, iv);
            byte[] plain = cipher.doFinal(ciphertext);
            if (s.cipher.needsManualPadding(padding)) {
                plain = padding.strip(plain);
            }
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CryptoException("decryption failed (check key, mode, padding, encoding)");
        }
    }

    public String encrypt(String plaintext, Padding padding) throws CryptoException {
        State s = state;
        if (!s.ready) {
            throw new CryptoException("crypto is not configured");
        }
        byte[] plain = plaintext.getBytes(StandardCharsets.UTF_8);
        if (s.cipher.needsManualPadding(padding)) {
            plain = padding.pad(plain, s.cipher.blockSize());
        }

        boolean prepend = s.cipher.usesIv() && s.ivMode == IvMode.PREPENDED;
        byte[] iv = s.ivBytes;
        if (prepend) {
            iv = new byte[s.cipher.ivLength()];
            RANDOM.nextBytes(iv);
        }

        try {
            Cipher cipher = Cipher.getInstance(s.cipher.transformation(padding));
            initCipher(cipher, Cipher.ENCRYPT_MODE, s, iv);
            byte[] ciphertext = cipher.doFinal(plain);
            byte[] out = prepend ? concat(iv, ciphertext) : ciphertext;
            return s.encoding.encode(out);
        } catch (Exception e) {
            throw new CryptoException("encryption failed (check key, mode, padding)");
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static void initCipher(Cipher cipher, int mode, State s, byte[] iv) throws Exception {
        if (s.cipher.isAead()) {
            cipher.init(mode, s.keySpec, new GCMParameterSpec(128, iv));
        } else if (!s.cipher.usesIv()) {
            cipher.init(mode, s.keySpec);
        } else {
            cipher.init(mode, s.keySpec, new IvParameterSpec(iv));
        }
    }
}
