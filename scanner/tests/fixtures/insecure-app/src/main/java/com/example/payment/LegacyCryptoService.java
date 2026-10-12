package com.example.payment;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Deliberately insecure. Fixture for ECDAT integration tests.
 * Every finding here is intentional - do not "fix" it.
 */
public class LegacyCryptoService {

    // Hardcoded key: CWE-798
    private static final String AES_KEY = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";

    private static final String RSA_PRIVATE_KEY_PEM =
        "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIIEowIBAAKCAQEAxK3vT8sPqL2mZx9wYt7bR4vN6cH1jK0pQ8sT3uV5wX7yZ9aB\n" +
        "-----END RSA PRIVATE KEY-----";

    // ECB mode, MD5 hashing, DES - all broken
    public String encryptCard(String pan) throws Exception {
        SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(pan.getBytes()));
    }

    public String legacyEncrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("12345678".getBytes(), "DES"));
        return cipher.doFinal(data.getBytes()) != null ? "ok" : null;
    }

    public String fingerprint(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public String strongFingerprint(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(input.getBytes()));
    }

    public java.security.KeyPair generateRsaKeys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);
        return gen.generateKeyPair();
    }

    public SecretKey generateAesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }

    public String getPem() {
        return RSA_PRIVATE_KEY_PEM;
    }
}
