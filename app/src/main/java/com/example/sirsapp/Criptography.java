package com.example.sirsapp;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Criptography {

    private static final int ASYM_KEY_SIZE = 2048;

    public static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    public static final String APP_ASYMK_ALIAS = "app_asymKeys";

    public static final String APP_SECRETK_ALIAS = "app_secretK";

    public static final String AUTH_CERT_ALIAS = "authCert";


    public Criptography(){

    }

    public static KeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);

        keyPairGen.initialize(new KeyGenParameterSpec.Builder(
                APP_ASYMK_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setKeySize(ASYM_KEY_SIZE)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build());

        return keyPairGen.generateKeyPair();
    }

    public static KeyPair getKeyPair() throws Exception{
        //Load key entry from key store
        KeyStore keySt = KeyStore.getInstance(ANDROID_KEY_STORE);
        keySt.load(null);
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keySt
                .getEntry(APP_ASYMK_ALIAS, null);

        //Return secret key entry or return a new secret key
        if (privateKeyEntry != null) {
            PrivateKey key = privateKeyEntry.getPrivateKey();

            // Get public key from certificate
            PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();

            // Return a key pair
            return new KeyPair(publicKey, key);
        } else return generateKeyPair();
    }

    public static SecretKey generateSecretKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        //Get instance of keyStore
        KeyGenerator keyGen = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

        //Specify key properties
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(APP_SECRETK_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build();
        keyGen.init(keyGenParameterSpec);

        //Generate secretK
        return keyGen.generateKey();

    }

    public static SecretKey getSecretKey() throws Exception{
        //Load key entry from key store
        KeyStore keySt = KeyStore.getInstance(ANDROID_KEY_STORE);
        keySt.load(null);
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keySt
                .getEntry(APP_SECRETK_ALIAS, null);

        //Return secret key entry or return a new secret key
        if (secretKeyEntry != null)
            return secretKeyEntry.getSecretKey();
        else return generateSecretKey();
    }

    private static Certificate readCert(Context context, int certResourceId) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {

        // read certificate resource
        InputStream certInput = context.getResources().openRawResource(certResourceId);

        Certificate cert;
        try {
            // generate a certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = cf.generateCertificate(certInput);

            //Load certificate into keyStore
            KeyStore ks = KeyStore.getInstance(ANDROID_KEY_STORE);
            ks.load(null);
            ks.setCertificateEntry(AUTH_CERT_ALIAS, cert);
        } finally {
            certInput.close();
        }
        return cert;
    }

    public static PublicKey getKeyFromCertificate(Context context, int certResourceId){
        //TODO-Refactor method to use alias of key store
        try {
            Certificate cert = readCert(context, certResourceId);
            return cert.getPublicKey();
        } catch (Exception e){
            return null;
        }
    }

    public static void generateCSR(){

    }
}
