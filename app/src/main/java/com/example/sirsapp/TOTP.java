package com.example.sirsapp;

import java.math.BigInteger;
import java.time.Instant;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static java.lang.Math.pow;

public class TOTP {
    private static final int DIGITS = 6;
    private static final int MOD = 1000000; // = 10^6 digits
    private static final int TIME_STEP = 30;

    /**
     * Store the {@param key} in the keyStore for later usage
     *
     * @param key: the shared secret between prover and verifier
     */
    public static void init(String key) {
        try {
            Criptography.saveTOTPSecret(key);
        } catch (Exception e) {
            // FIXME: Properly handle the exception
            e.printStackTrace();
        }
    }

    /**
     * Compute HMAC of with SHA256
     *
     * @param key: the bytes to use as HMAC key
     * @param text: the text to be authenticated
     * @return the corresponding 32-byte hash
     */
    private static byte[] hmac(byte[] key, byte[] text) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec macKey = new SecretKeySpec(key, "RAW");
            mac.init(macKey);
            return mac.doFinal(text);
        } catch(Exception e) {
            e.printStackTrace();
            return null;
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
    public static String generate() {
        long T = Instant.now().getEpochSecond() / TIME_STEP;
        StringBuilder step = new StringBuilder(Long.toHexString(T).toUpperCase());

        while(step.length() < 16) {
            step.insert(0, "0");
        }

        byte[] msg = hex2Bytes(step.toString());

        byte[] hash;
        try {
            hash = hmac(Criptography.getTOTPSecret(), msg);
        } catch (Exception e) {
            // FIXME: Properly handle the exception
            e.printStackTrace();
            return null;
        }

        // Get 4 least significant bits of HMAC
        int offset = hash[hash.length - 1] & 0xf;
        int P = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | (hash[offset + 3]);

        StringBuilder OTP = new StringBuilder(Integer.toString(P % MOD));

        while(OTP.length() < DIGITS) {
            OTP.insert(0, "0");
        }

        return step.toString();
    }
}
