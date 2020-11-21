package com.example.sirsapp;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.jcajce.JcaPEMWriter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.spongycastle.util.io.pem.PemObject;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class Criptography {

    private static final int ASYM_KEY_SIZE = 2048;
    private static final int SYM_KEY_SIZE = 256;
    public static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    //public static final String APP_ASYMK_ALIAS = "app_asymKeys";
    public static final String APP_SECRETK_ALIAS = "app_secretK";
    public static final String APP_CERT_ALIAS = "app_cert";
    public static final String AUTH_CERT_ALIAS = "authCert";
    public static final String CA_CERT_ALIAS = "caCert";
    private static final String PRIVATE_KEY_FILE = "priv.key";
    private static final String PUBLIC_KEY_FILE = "pub.key";
    public static final String APP_CSR_FILE = "app.csr";
    public static final String APP_CERT_FILE = "app.crt";
    public static final String AUTH_CERT_FILE = "auth.crt";
    public static final String CA_CERT_FILE = "ca.crt";
    private static final int TAG_BITS = 128;
    private static final int BLOCK_SIZE = 12; // GCM has block-size of 12 bytes


    public Criptography(){

    }

    public static KeyPair generateKeyPair(Context context) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA);

        keyPairGen.initialize(ASYM_KEY_SIZE);

        KeyPair keys = keyPairGen.generateKeyPair();

        SecretKey secretKey = getSecretKeyFromKeyStore();

        //save keys to files
        saveToFile(context, PRIVATE_KEY_FILE, keys.getPrivate().getEncoded(), secretKey);
        saveToFile(context, PUBLIC_KEY_FILE, keys.getPublic().getEncoded(), secretKey);

        return keys;
    }

    public static KeyPair getKeyPair(Context context) throws Exception{
        File filePriv = new File(context.getFilesDir(), PRIVATE_KEY_FILE);
        File filePub = new File(context.getFilesDir(), PUBLIC_KEY_FILE);

        if (filePriv.exists() && filePub.exists()){
            //load file
            SecretKey secretKey = getSecretKeyFromKeyStore();
            PrivateKey privKey = getPrivateKeyFromFile(getFromFile(context, PRIVATE_KEY_FILE, secretKey));
            PublicKey pubKey = getPublicKeyFromFile(getFromFile(context, PUBLIC_KEY_FILE, secretKey));
            return new KeyPair(pubKey, privKey);
        } else {
            //generate file
            return generateKeyPair(context);
        }
    }

    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        //Get instance of keyStore
        KeyGenerator keyGen = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES);

        keyGen.init(SYM_KEY_SIZE);

        //Generate secretK
        return keyGen.generateKey();

    }

    public static SecretKey getSecretKeyFromKeyStore() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException, CertificateException, IOException, UnrecoverableEntryException {
        //Get secretKey from keystore or create one
        KeyStore keySt = KeyStore.getInstance(ANDROID_KEY_STORE);
        keySt.load(null);
        //TODO-REMOVEMEkeySt.deleteEntry(APP_SECRETK_ALIAS);
        if (keySt.containsAlias(APP_SECRETK_ALIAS)) {
            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keySt
                    .getEntry(APP_SECRETK_ALIAS, null);
            return secretKeyEntry.getSecretKey();
        } else{
            KeyGenerator keyGen = KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

            keyGen.init(new KeyGenParameterSpec.Builder(
                    APP_SECRETK_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(SYM_KEY_SIZE)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build());

            //Generate secretK
            return keyGen.generateKey();
        }

    }

    public static Certificate readCert(Context context, int certResourceId, String alias) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {

        // read certificate resource
        InputStream certInput = context.getResources().openRawResource(certResourceId);

        X509Certificate cert;
        try {
            // generate a certificate
            cert = (X509Certificate) CertificateFactory.getInstance(
                    "X.509").generateCertificate(new BufferedInputStream(certInput));

            KeyStore ks = KeyStore.getInstance(ANDROID_KEY_STORE);
            ks.load(null);
            ks.deleteEntry(alias);
            ks.setEntry(alias, new KeyStore.TrustedCertificateEntry(cert), null);
        } finally {
            certInput.close();
        }
        return cert;
    }

    public static Certificate getCertificate(String alias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        KeyStore keySt = KeyStore.getInstance(ANDROID_KEY_STORE);
        keySt.load(null);
        KeyStore.TrustedCertificateEntry certificateEntry = (KeyStore.TrustedCertificateEntry) keySt.getEntry(alias, null);
        if (certificateEntry != null) {
            return certificateEntry.getTrustedCertificate();
        } else return null;
    }

    public static PublicKey getKeyFromCertificate(String alias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        Certificate certificate = getCertificate(alias);

        //Return certificate or return null if entry doesn't exist
        if (certificate != null) {
            return certificate.getPublicKey();
        } else return null;
    }

    public static PublicKey getKeyFromCertificate(Context context, int certResourceId) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableEntryException {
        Certificate cert = readCert(context, certResourceId, AUTH_CERT_ALIAS);
        return cert.getPublicKey();
    }

    public static byte[] generateCSR(String username, KeyPair keyPair) throws OperatorCreationException, IOException {
        // Certificate Signature Algorithm
        String sigAlg = "SHA256withRSA";
        // all the basic information
        String params = "O=app-" + username;

        // CN and public
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name(params), keyPair.getPublic());
        // Signature Algorithm
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(sigAlg);
        csBuilder.setProvider(new BouncyCastleProvider());

        ContentSigner signer = csBuilder.setProvider(new BouncyCastleProvider()).build(keyPair.getPrivate());
        // generates a binary coded format PKCS10 (ber / der)
        PKCS10CertificationRequest p10 = p10Builder.build(signer);

        // convert binary format for the certificate format (csr)
        PemObject pemObject = new PemObject("CERTIFICATE REQUEST", p10.getEncoded());
        StringWriter str = new StringWriter();
        JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(str);
        jcaPEMWriter.writeObject(pemObject);
        jcaPEMWriter.close();
        str.close();

        return str.toString().getBytes();
    }

    public static byte[] cipherRSA(byte[] m, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(m);
    }

    public static byte[] decipherRSA(byte[] m, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(m);
    }

    public static byte[] cipherAES(byte[] m, SecretKey secK) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secK);
        System.out.println("Input Length - " + m.length);
        return cipher.doFinal(m);
    }

    public static byte[] decipherAES(byte[] m, SecretKey secK) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secK);
        return cipher.doFinal(m);
    }

    public static byte[] digestSHA256(byte[] m) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(m);
        return messageDigest.digest();
    }

    public static byte[] sign(byte[] m, PrivateKey privKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, KeyStoreException, CertificateException, IOException, UnrecoverableEntryException, NoSuchProviderException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(privKey);
        s.update(m);
        return s.sign();
    }




    //---------------------------------------------------------------------------------------------

    public static void saveToFile(Context context, String filename, byte[] text, SecretKey secretKey) throws Exception {
        File path = new File(context.getFilesDir(), filename);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        path.createNewFile();

        FileOutputStream file = new FileOutputStream(path);
        file.write(cipher.getIV());
        file.write(cipher.doFinal(text));
        file.close();
    }

    public static void saveToFileNoEncryption(Context context, String filename, byte[] text) throws Exception {
        File path = new File(context.getFilesDir(), filename);

        path.createNewFile();

        FileOutputStream file = new FileOutputStream(path);
        file.write(text);
        file.close();
    }

    public static byte[] getFromFile(Context context, String filename, SecretKey secretKey) throws Exception {
        File path = new File(context.getFilesDir(), filename);

        if (!path.exists()) {
            throw new FileNotFoundException();
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        byte[] iv = new byte[BLOCK_SIZE];
        byte[] data = new byte[(int) path.length() - BLOCK_SIZE];

        FileInputStream file = new FileInputStream(path);
        file.read(iv);
        file.read(data);
        file.close();

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_BITS, iv));
        return cipher.doFinal(data);
    }

    public static byte[] getFromFileNoEncryption(Context context, String filename) throws Exception {
        File path = new File(context.getFilesDir(), filename);

        byte[] data = new byte[(int) path.length()];

        FileInputStream file = new FileInputStream(path);
        file.read(data);
        file.close();

        return data;
    }

    public static PrivateKey getPrivateKeyFromFile(byte[] key) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static PublicKey getPublicKeyFromFile(byte[] key) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

}
