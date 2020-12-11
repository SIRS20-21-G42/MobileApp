package com.example.sirsapp;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

import javax.crypto.BadPaddingException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TOTP {
    private final Cryptography crypto;
    private byte[] secret;

    private static final int DIGITS = 6;
    private static final int MOD = 1_000_000; // = 10^6 digits
    public static final int TIME_STEP = 30;

    public TOTP(Cryptography crypto) {
        this.crypto = crypto;

        try {
            this.secret = this.crypto.getFromFile(Cryptography.AUTH_SHARED_KEY_FILE);
        } catch (IOException | BadPaddingException e) {
            throw new RuntimeException("Couldn't get shared secret");
        }
    }

    /**
     * Get the secret in use
     *
     * @return the secret
     */
    public byte[] getSecret() {
        return this.secret;
    }

    /**
     * Check if TOTP has already been seeded with a secret
     *
     * @return if secret is already defined
     */
    public boolean isInitialized() {
        return this.secret != null;
    }

    /**
     * Compute HMAC-SHA256 of text with key
     *
     * @param key: the bytes to use as HMAC key
     * @param text: the text to be authenticated
     * @return the corresponding 32-byte hash
     */
    private byte[] hmac(byte[] key, byte[] text) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec macKey = new SecretKeySpec(key, "RAW");
            mac.init(macKey);
            return mac.doFinal(text);
        } catch(NoSuchAlgorithmException e) {
            // Ignore
            return null;
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid key");
        }
    }

    /**
     * Convert an hex string to bytes (supported 00 byte-padded string)
     *
     * @param hex: the string to convert
     * @return the corresponding bytes
     */
    private static byte[] hex2Bytes(String hex){
        // Add byte in case hex starts with byte 00
        byte[] array = new BigInteger("10" + hex,16).toByteArray();

        // Copy all bytes except the first
        byte[] ret = new byte[array.length - 1];

        if (ret.length >= 0) {
            System.arraycopy(array, 1, ret, 0, ret.length);
        }
        return ret;
    }

    /**
     * Generate a TOTP for the current timestamp
     *
     * @return the TOTP for the current timestep
     */
    public String generate() {
        long T = System.currentTimeMillis() / (TIME_STEP * 1000);
        StringBuilder step = new StringBuilder(Long.toHexString(T).toUpperCase());

        while(step.length() < 16) {
            step.insert(0, "0");
        }

        byte[] msg = hex2Bytes(step.toString());

        byte[] hash = hmac(this.secret, msg);

        // Get 4 least significant bits of HMAC
        int offset = hash[hash.length - 1] & 0xf;
        int P = (((((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)) | ((hash[offset + 2] & 0xff) << 8)) | (hash[offset + 3] & 0xff));

        StringBuilder OTP = new StringBuilder(Integer.toString(Math.floorMod(P, MOD)));

        while(OTP.length() < DIGITS) {
            OTP.insert(0, "0");
        }

        return OTP.toString();
    }
}
