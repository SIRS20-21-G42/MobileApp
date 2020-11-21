package com.example.sirsapp;

import android.content.Context;
import android.os.Bundle;
import android.os.StrictMode;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class RegisterActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_register);
    }

    public void registerUser(View view){

        closeKeyboard();

        String username = ((EditText) findViewById(R.id.usernameEditText)).getText().toString();
        if (!validateUsername(username))
            return;
        try {
            //get pubK and privK of the app
            KeyPair keys = Criptography.getKeyPair(getApplicationContext());

            Certificate caCert = Criptography.readCert(getApplicationContext(), R.raw.ca, "ca");

            //generate CSR for pubK and get certificate(need to communicate with CA)
            if (!checkFile(Criptography.APP_CSR_FILE))
                Criptography.saveToFileNoEncryption(getApplicationContext(), Criptography.APP_CSR_FILE, Criptography.generateCSR(username, keys));
            boolean success = Communications.getCertificateFromCA(getApplicationContext(), Criptography.APP_CSR_FILE, caCert);
            if (!success){
                outputError("An error occurred, please try again");
            }

            System.out.println("DONE");

            //TODO- get auth server pubK from certificate
            //PublicKey authKey = Criptography.getKeyFromCertificate(Criptography.AUTH_CERT_ALIAS);
            //if (authKey == null)
            //   authKey = Criptography.getKeyFromCertificate(getApplicationContext(), R.raw.authcert);

            //generate secK
            //SecretKey secretK = Criptography.generateSecretKey();

            //calculate {secK || ts || username}authPubK +  {appCert || {sha256(secK, ts, username)}appPrivK}secK
            //String message = calculateFirstMessage(username, keys, secretK);

            //TODO-REMOVEMEtest(username, keys);

            //TODO-send message

            //TODO-validate response message

            //TODO-generate DH params

            //calculate {ts || username || B || {sha256(ts, username, B)}privK}secK

            //TODO-send message

            //TODO-receive server response and validate it

        } catch (Exception e) {
            outputError("An error occurred, please try again");
            System.out.println("ERROR!");
            e.printStackTrace();
            return;
        }
    }

    private boolean checkFile(String filename) {
        File file = new File(getApplicationContext().getFilesDir(), filename);
        return file.exists();
    }

    private void test(String username, KeyPair keys) throws InvalidKeyException, NoSuchAlgorithmException, CertificateException, KeyStoreException, SignatureException, NoSuchProviderException, UnrecoverableEntryException, IOException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        //TODO-REMOVEME
        byte[] messageCiphered = Criptography.sign(username.getBytes(), keys.getPrivate());
        System.out.println(Base64.getEncoder().encodeToString(messageCiphered));
        //byte[] messageDeciphered = Criptography.decipherRSA(messageCiphered, keys.getPrivate());
        //System.out.println(new String(messageDeciphered));
    }

    private String calculateFirstMessage(String username, KeyPair keys, SecretKey secK) throws Exception{
        //calculate {secK || ts || username}authPubK +  {appCert || {sha256(secK, ts, username)}appPrivK}secK
        long ts = System.currentTimeMillis() / 1000L;
        PrivateKey privKey= keys.getPrivate();
        PublicKey pubKey= keys.getPublic();
        //Certificate appCert = Criptography.getCertificate(Criptography.APP_CERT_ALIAS);

        JSONObject requestJson = new JSONObject();

        //Calculate {secK || ts || username}authPubK
        JSONObject plainMessageJson = new JSONObject();
        plainMessageJson.put("secretKey", Base64.getEncoder().encodeToString(secK.getEncoded()));
        plainMessageJson.put("ts", "" + ts);
        plainMessageJson.put("username", username);

        //Cipher plainMessage with authPubK
        //byte[] messageCiphered = Criptography.cipherRSA(plainMessageJson.toString().getBytes(), Criptography.getKeyFromCertificate(Criptography.AUTH_CERT_ALIAS));
        //requestJson.put("message", Base64.getEncoder().encodeToString(messageCiphered));

        //Calculate appCert || {sha256(secK, ts, username)}appPrivK || {sha256(appCert)}privK
        JSONObject plainCertificateJson = new JSONObject();
        //plainCertificateJson.put("certificate", appCert.toString());
        byte[] signatureMessage = Criptography.sign(plainMessageJson.toString().getBytes(), privKey);
        plainCertificateJson.put("messageSignature", Base64.getEncoder().encodeToString(signatureMessage));

        //Cipher plainCertificate with secK and put on request
        byte[] certEncoded = Criptography.cipherAES(plainCertificateJson.toString().getBytes(), secK);
        requestJson.put("certificate", Base64.getEncoder().encodeToString(certEncoded));
        return  requestJson.toString();
    }

    private boolean validateUsername(String username) {
        if (username == null || username.equals("")) {
            outputError("Please specify a username");
            return false;
        } else if (!username.matches("[A-Za-z0-9_]+") || username.length() > 20) {
            outputError("Invalid username");
            return false;
        }
        return true;
    }

    private void closeKeyboard() {
        View view = this.getCurrentFocus();
        if (view != null){
            InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
            imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
        }
    }

    private void outputError(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }

}