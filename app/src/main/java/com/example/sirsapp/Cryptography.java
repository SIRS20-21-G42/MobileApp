package com.example.sirsapp;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.jcajce.JcaPEMWriter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.spongycastle.util.io.pem.PemObject;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cryptography {
    private final SecretKey key;
    private final Context context;

    public static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    public static final String APP_CERT_FILE = "app.crt";
    public static final String APP_CSR_FILE = "app.csr";
    public static final String APP_SECRETK_ALIAS = "app_secretK";
    public static final String AUTH_SHARED_KEY_FILE = "auth_shared.key";
    private static final int ASYM_KEY_SIZE = 2048;
    private static final int BLOCK_SIZE = 12; // GCM has block-size of 12 bytes
    private static final String PUBLIC_KEY_FILE = "pub.key";
    private static final String PRIVATE_KEY_FILE = "priv.key";
    private static final int SYM_KEY_SIZE = 256;
    private static final int TAG_BITS = 128;

    /**
     * Create a new instance of the Criptography class
     *
     * @param context: the application context
     * @throws Exception for now throws all the occurred exceptions
     */
    public Cryptography(Context context) throws Exception {
        // FIXME: properly handle the exceptions
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

        this.context = context;

        if (keyStore.containsAlias(APP_SECRETK_ALIAS)) {
            this.key = ((KeyStore.SecretKeyEntry) keyStore.getEntry(APP_SECRETK_ALIAS, null)).getSecretKey();
        } else {
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            KeyGenParameterSpec spec = new KeyGenParameterSpec
                    .Builder(APP_SECRETK_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build();

            generator.init(spec);

            this.key = generator.generateKey();
        }
    }

    /**
     * Get the current application context
     *
     * @return the application context
     */
    public Context getContext() {
        return this.context;
    }

    /**
     * Cipher text with AES CBC (PKCS5Padding)
     *
     * @param m: message to be ciphered
     * @param secK: key to cipher the message with
     * @param iv: iv to cipher the message with
     * @return ciphered message
     * @throws Exception for now throws all the occurred exceptions
     */
    public static byte[] cipherAES(byte[] m, SecretKey secK, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(secK.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(m);
    }

    /**
     * Decipher text with AES CBC (PKCS5Padding)
     *
     * @param m: message to be deciphered
     * @param secK: key to decipher the message with
     * @param iv: iv to decipher the message with
     * @return deciphered message
     * @throws Exception for now throws all the occurred exceptions
     */
    public static byte[] decipherAES(byte[] m, SecretKey secK, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(secK.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(m);
    }

    /**
     * Creates a key store and inserts the certificate in it
     *
     * @param caCert: CA certificate
     * @return created keystore
     * @throws Exception for now throws all the occurred exceptions
     */
    public static KeyStore createKeyStore(Certificate caCert) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null);

        //setting the certificate of the ca
        ks.setEntry("caCert", new KeyStore.TrustedCertificateEntry(caCert), null);

        return ks;
    }

    /**
     * Generate a 16 byte random IV
     *
     * @return generated IV
     */
    public static byte[] generateIV(){
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Sign a message with the private key given (SHA256withRSA)
     *
     * @param m: message to be signed
     * @param privKey: key to sign the message with
     * @return signed message
     * @throws Exception for now throws all the occurred exceptions
     */
    public static byte[] sign(byte[] m, PrivateKey privKey) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(privKey);
        s.update(m);
        return s.sign();
    }

    /**
     * Verify the signature of a message with the public key given (SHA256withRSA)
     *
     * @param m: message that was signed
     * @param signature: signature to be verified
     * @param pubKey: public key to verify the signature of the message with
     * @return true if signature is correct
     * @throws Exception for now throws all the occurred exceptions
     */
    public static boolean verify(byte[] m, byte[] signature, PublicKey pubKey) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pubKey);
        s.update(m);
        return s.verify(signature);
    }

    /**
     * Generate Bob's public Diffie Hellman parameter and save the shared secret generated to a file
     *
     * @param paramA: DH parameter A
     * @param n: DH parameter N
     * @param g: DH parameter g
     * @return DH parameter B
     * @throws Exception for now throws all the occurred exceptions
     */
    public BigInteger generateDiffieHellmanParam(BigInteger paramA, BigInteger n, BigInteger g) throws Exception {
        // generate secret b
        Random randomGenerator = new Random();
        BigInteger b = new BigInteger(2048, randomGenerator); // secret key b (private) (on client)

        // calculate public B
        BigInteger paramB = g.modPow(b, n); // calculated public client key (B=g^b(modp))

        // calculate shared secret
        BigInteger sharedSecret = paramA.modPow(b, n);

        // generate shared key
        byte[] sharedKey = sharedSecret.toByteArray();

        // save shared secret
        saveToFile(AUTH_SHARED_KEY_FILE, sharedKey);

        return paramB;
    }

    /**
     * Gets a private key from a byte array
     *
     * @param key: bytes of the key
     * @return private key from the bytes
     * @throws Exception for now throws all the occurred exceptions
     */
    public static PrivateKey getPrivateKey(byte[] key) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    /**
     * Gets a public key from a byte array
     *
     * @param key: bytes of the key
     * @return public key from the bytes
     * @throws Exception for now throws all the occurred exceptions
     */
    public static PublicKey getPublicKey(byte[] key) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    /**
     * Generates a key pair and stores both keys in separate files
     *
     * @return key pair generated
     * @throws Exception for now throws all the occurred exceptions
     */
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA);

        keyPairGen.initialize(ASYM_KEY_SIZE);

        KeyPair keys = keyPairGen.generateKeyPair();

        //save keys to files
        saveToFile(PRIVATE_KEY_FILE, keys.getPrivate().getEncoded());
        saveToFile(PUBLIC_KEY_FILE, keys.getPublic().getEncoded());

        return keys;
    }

    /**
     * Gets the key pair from the files or generates a new key pair if the files don't exist
     *
     * @return key pair obtained
     * @throws Exception for now throws all the occurred exceptions
     */
    public KeyPair getKeyPair() throws Exception{
        File filePriv = new File(context.getFilesDir(), PRIVATE_KEY_FILE);
        File filePub = new File(context.getFilesDir(), PUBLIC_KEY_FILE);

        if (filePriv.exists() && filePub.exists()){
            //load file
            PrivateKey privKey = getPrivateKey(getFromFile(PRIVATE_KEY_FILE));
            PublicKey pubKey = getPublicKey(getFromFile(PUBLIC_KEY_FILE));
            return new KeyPair(pubKey, privKey);
        } else {
            //generate file
            return generateKeyPair();
        }
    }

    /**
     * Generates a secret key
     *
     * @return secret key generated
     * @throws Exception for now throws all the occurred exceptions
     */
    public static SecretKey generateSecretKey() throws Exception {
        //Get instance of keyStore
        KeyGenerator keyGen = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES);

        keyGen.init(SYM_KEY_SIZE);

        //Generate secretK
        return keyGen.generateKey();
    }

    /**
     * Reads a certificate from a filename given
     *
     * @param fileName: name of the file with the certificate to be read
     * @return certificate read from file
     * @throws Exception for now throws all the occurred exceptions
     */
    public Certificate readCertificateFromFile(String fileName) throws Exception {

        // read certificate resource
        byte[] certBytes =  getFromFileNoEncryption(fileName);
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

    /**
     * Reads a certificate from a resource
     *
     * @param certResourceId: id of the resource of the certificate to be read
     * @return certificate read from the resource
     * @throws Exception for now throws all the occurred exceptions
     */
    public Certificate readCertificateFromResource(int certResourceId) throws Exception {

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

    /**
     * Generates a CSR for a given key pair
     *
     * @param username: username to be used as Organization in the CSR
     * @param keyPair: key pair for which the CSR will be made
     * @return byte array of the generated CSR
     * @throws Exception for now throws all the occurred exceptions
     */
    public static byte[] generateCSR(String username, KeyPair keyPair) throws Exception {
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

    /**
     * Generate teh SHA-256 digest of the message
     *
     * @param message: the message to create digest
     * @return the digest of the given message
     */
    public static byte[] digest(byte[] message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            return digest.digest(message);
        } catch(NoSuchAlgorithmException e) {
            throw new RuntimeException("Unknown algorithm in digest");
        }
    }

    /**
     * Cipher text with RSA (PKCS1Padding)
     *
     * @param m: message to be ciphered
     * @param key: key to cipher the message with
     * @return ciphered message
     * @throws Exception for now throws all the occurred exceptions
     */
    public static byte[] cipherRSA(byte[] m, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(m);
    }

    /**
     * Decipher text with RSA (PKCS1Padding)
     *
     * @param m: message to be deciphered
     * @param key: key to decipher the message with
     * @return deciphered message
     * @throws Exception for now throws all the occurred exceptions
     */
    public static byte[] decipherRSA(byte[] m, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(m);
    }

    /**
     * Save information to the given filename, that will be ciphered with the app key
     *
     * @param filename: the filename to store the information
     * @param text: the information to store
     * @throws Exception for now throws all the occurred exceptions
     */
    public void saveToFile(String filename, byte[] text) throws Exception {
        File path = new File(context.getFilesDir(), filename);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, this.key);

        path.createNewFile();

        FileOutputStream file = new FileOutputStream(path);
        file.write(cipher.getIV());
        file.write(cipher.doFinal(text));
        file.close();
    }

    /**
     * Saves a message to a file with no encryption
     *
     * @param filename: name of the file to store the message in
     * @param text: text to store in the file
     * @throws Exception for now throws all the occurred exceptions
     */
    public void saveToFileNoEncryption(String filename, byte[] text) throws Exception {
        File path = new File(context.getFilesDir(), filename);

        path.createNewFile();

        FileOutputStream file = new FileOutputStream(path);
        file.write(text);
        file.close();
    }

    /**
     * Decipher and return the information stored in the given file
     *
     * @param filename: the file containing the information
     * @return the information on the file
     * @throws Exception for now throws all the occurred exceptions
     */
    public byte[] getFromFile(String filename) throws Exception {
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

        cipher.init(Cipher.DECRYPT_MODE, this.key, new GCMParameterSpec(TAG_BITS, iv));
        return cipher.doFinal(data);
    }

    /**
     * Gets a message from a file
     *
     * @param filename: name of the file to load the message from
     * @return content of the file
     * @throws Exception for now throws all the occurred exceptions
     */
    public byte[] getFromFileNoEncryption(String filename) throws Exception {
        File path = new File(context.getFilesDir(), filename);

        byte[] data = new byte[(int) path.length()];

        FileInputStream file = new FileInputStream(path);
        file.read(data);
        file.close();

        return data;
    }
}
