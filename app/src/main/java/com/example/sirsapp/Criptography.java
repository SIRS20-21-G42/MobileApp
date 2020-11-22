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
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
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
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Criptography {

    private static final int ASYM_KEY_SIZE = 2048;
    private static final int SYM_KEY_SIZE = 256;
    public static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    public static final String APP_SECRETK_ALIAS = "app_secretK";
    private static final String PRIVATE_KEY_FILE = "priv.key";
    private static final String PUBLIC_KEY_FILE = "pub.key";
    public static final String APP_CSR_FILE = "app.csr";
    public static final String APP_CERT_FILE = "app.crt";
    private static final int TAG_BITS = 128;
    private static final int BLOCK_SIZE = 12; // GCM has block-size of 12 bytes
    private static final String AUTH_SHARED_KEY_FILE = "auth_shared.key";


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

    public static Certificate readCertificateFromFile(Context context, String fileName) throws Exception {

        // read certificate resource
        byte[] certBytes =  getFromFileNoEncryption(context, fileName);
        InputStream certIn = new ByteArrayInputStream(certBytes);

        X509Certificate cert;
        try {
            // generate a certificate
            cert = (X509Certificate) CertificateFactory.getInstance(
                    "X.509").generateCertificate(certIn);

        } finally {
            certIn.close();
        }
        return cert;
    }

    public static Certificate readCertificateFromResource(Context context, int certResourceId) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {

        // read certificate resource
        InputStream certInput = context.getResources().openRawResource(certResourceId);

        X509Certificate cert;
        try {
            // generate a certificate
            cert = (X509Certificate) CertificateFactory.getInstance(
                    "X.509").generateCertificate(certInput);

        } finally {
            certInput.close();
        }
        return cert;
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
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(m);
    }

    public static byte[] decipherRSA(byte[] m, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(m);
    }

    public static byte[] cipherAES(byte[] m, SecretKey secK, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(secK.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(m);
    }

    public static byte[] decipherAES(byte[] m, SecretKey secK, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(secK.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(m);
    }

    public static byte[] generateIv(){
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    public static byte[] sign(byte[] m, PrivateKey privKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(privKey);
        s.update(m);
        return s.sign();
    }

    public static boolean verify(byte[] m, byte[] signature, PublicKey pubKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pubKey);
        s.update(m);
        return s.verify(signature);
    }

    public static BigInteger generateDiffieHellmanParam(Context context, BigInteger paramA, BigInteger n, BigInteger g) throws Exception {
        // generate secret b
        Random randomGenerator = new Random();
        BigInteger b = new BigInteger(1024, randomGenerator); // secret key b (private) (on client)

        // calculate public B
        BigInteger paramB = g.modPow(b, n); // calculated public client key (B=g^b(modp))

        // calculate shared secret
        BigInteger sharedSecret = paramA.modPow(b, n);

        // generate AES key
        byte[] sharedKey = sharedSecret.toByteArray();
        // AES supports 128 bit keys. So, just take first 16 bits of DH generated key.
        byte[] byteKey = new byte[16];
        for(int i = 0; i < 16; i++) {
            byteKey[i] = sharedKey[i];
        }

        // convert given key to AES format
        Key key = new SecretKeySpec(byteKey, "AES");

        // save key
        saveToFile(context, AUTH_SHARED_KEY_FILE, key.getEncoded(), getSecretKeyFromKeyStore());

        return paramB;
    }



//-----------------------------------------Files--------------------------------------------------//



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
