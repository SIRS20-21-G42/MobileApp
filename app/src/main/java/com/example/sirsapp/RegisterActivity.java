package com.example.sirsapp;

import android.content.Context;
import android.os.Bundle;
import android.os.StrictMode;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class RegisterActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_register);
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitNetwork().build();
        StrictMode.setThreadPolicy(policy);
    }

    public void registerUser(View view){

        closeKeyboard();

        String username = ((EditText) findViewById(R.id.usernameEditText)).getText().toString();
        if (!validateUsername(username))
            return;
        try {
            // get pubK and privK of the app
            KeyPair keys = Criptography.getKeyPair(getApplicationContext());

            Certificate caCert = Criptography.readCertificateFromResource(getApplicationContext(), R.raw.ca);

            // generate CSR for pubK and get certificate(need to communicate with CA)
            if (!checkFile(Criptography.APP_CSR_FILE))
                Criptography.saveToFileNoEncryption(getApplicationContext(), Criptography.APP_CSR_FILE, Criptography.generateCSR(username, keys));

            if (!checkFile(Criptography.APP_CERT_FILE)) {
                boolean success = Communications.getCertificateFromCA(getApplicationContext(), Criptography.APP_CSR_FILE, caCert);
                if (!success) {
                    outputError("An error occurred, please try again");
                    return;
                }
            }

            // get auth server pubK from certificate
            Certificate authCert = Criptography.readCertificateFromResource(getApplicationContext(), R.raw.auth);

            // generate secK for auth communication
            SecretKey secretK = Criptography.generateSecretKey();

            // get app certificate
            Certificate appCert = Criptography.readCertificateFromFile(getApplicationContext(), Criptography.APP_CERT_FILE);

            // calculate {secK || ts || username}authPubK +  {appCert || {sha256(secK, ts, username)}appPrivK}secK
            JSONObject message = calculateFirstMessage(username, keys, secretK, authCert.getPublicKey(), appCert);



            // Send message to Auth
            JSONObject response = Communications.sendMesageToAuth(message);


            BigInteger paramB = handleFirstResponse(response, secretK, authCert.getPublicKey());
            if (paramB == null){
                outputError("An error occurred, please try again");
                return;
            }

            // calculate {ts || username || B || {sha256(ts, username, B)}privK}secK
            message = calculateSecondMessage(username, keys, secretK, paramB, authCert.getPublicKey());

            // Send message to Auth
            response = Communications.sendMesageToAuth(message);

            // validate server response
            if (!handleSecondResponse(response, secretK, authCert.getPublicKey())){
                outputError("An error occurred, please try again");
                return;
            }

            Criptography.saveToFileNoEncryption(getApplicationContext(), "username.txt", username.getBytes());

            System.out.println("DONE");

        } catch (Exception e) {
            outputError("An error occurred, please try again");
            System.out.println("ERROR!");
            e.printStackTrace();
            return;
        }
    }

    private JSONObject calculateFirstMessage(String username, KeyPair keys, SecretKey secK, PublicKey authKey, Certificate appCert) throws Exception{
        // calculate {ts || username || secK}authPubK +  {appCert || {sha256(secK, ts, username)}appPrivK}secK

        long ts = System.currentTimeMillis() / 1000L;
        PrivateKey privKey= keys.getPrivate();

        JSONObject requestJson = new JSONObject();
        JSONObject requestContentJson = new JSONObject();

        // calculate {ts || username || secK}authPubK
        JSONObject part1Json = new JSONObject();
        part1Json.put("ts", "" + ts);
        part1Json.put("username", username);
        String secretKEnc = Base64.getEncoder().encodeToString(secK.getEncoded());
        part1Json.put("secretKey", secretKEnc);

        // cipher part1 with authPubK
        byte[] messageCiphered = Criptography.cipherRSA(part1Json.toString().getBytes(), authKey);
        requestContentJson.put("part1", Base64.getEncoder().encodeToString(messageCiphered));

        // calculate appCert || {sha256(secK, ts, username)}appPrivK
        JSONObject part2Json = new JSONObject();
        part2Json.put("certificate", Base64.getEncoder().encodeToString(appCert.getEncoded()));
        String stringToSign = ts + username + secretKEnc;
        byte[] signatureMessage = Criptography.sign(stringToSign.getBytes(), privKey);
        part2Json.put("signature", Base64.getEncoder().encodeToString(signatureMessage));

        // generate new iv
        byte[] iv = Criptography.generateIv();

        // cipher plainCertificate with secK and put on request
        byte[] part2Encoded = Criptography.cipherAES(part2Json.toString().getBytes(), secK, iv);
        requestContentJson.put("part2", Base64.getEncoder().encodeToString(part2Encoded));
        requestContentJson.put("iv", Base64.getEncoder().encodeToString(iv));

        requestJson.put("reg", requestContentJson);
        System.out.println(requestJson.toString());
        return  requestJson;
    }

    private BigInteger handleFirstResponse(JSONObject response, SecretKey secK, PublicKey authPubkey) throws Exception {
        String contentEncoded = response.getString("content");

        // get iv used to encrypt the content
        byte[] requestIv = Base64.getDecoder().decode(response.getString("iv"));

        // decode content
        byte[] contentDecoded = Criptography.decipherAES(Base64.getDecoder().decode(contentEncoded), secK, requestIv);

        JSONObject content = new JSONObject(new String(contentDecoded, StandardCharsets.UTF_8));

        String ts = content.getString("ts");
        String g = content.getString("g");
        String n = content.getString("N");
        String paramA = content.getString("A");
        String signature = content.getString("signature");

        // verify signature
        String stringToVerify = ts + g + n + paramA;
        boolean success = checkRequest(stringToVerify, signature, ts, authPubkey);
        if (!success)
            return null;

        return Criptography.generateDiffieHellmanParam(getApplicationContext(), new BigInteger(paramA), new BigInteger(n), new BigInteger(g));
    }

    private JSONObject calculateSecondMessage(String username, KeyPair keys, SecretKey secK, BigInteger paramB, PublicKey authKey) throws Exception{
        // calculate {ts || username || B || {sha256(ts, username, B)}privK}secK

        long ts = System.currentTimeMillis() / 1000L;
        PrivateKey privKey= keys.getPrivate();

        JSONObject requestJson = new JSONObject();
        JSONObject requestContentJson = new JSONObject();

        // calculate ts || username || B
        JSONObject content = new JSONObject();
        content.put("ts", "" + ts);
        content.put("username", username);
        content.put("B", paramB.toString());

        // calculate {sha256(ts, username, B)}privK
        String stringToSign = ts + username + paramB;
        byte[] signatureMessage = Criptography.sign(stringToSign.getBytes(), privKey);
        content.put("signature", Base64.getEncoder().encodeToString(signatureMessage));

        // generate new iv
        byte[] iv = Criptography.generateIv();

        // cipher content with secK
        byte[] messageCiphered = Criptography.cipherAES(content.toString().getBytes(), secK, iv);
        requestContentJson.put("content", Base64.getEncoder().encodeToString(messageCiphered));
        requestContentJson.put("iv", Base64.getEncoder().encodeToString(iv));

        requestJson.put("reg", requestContentJson);
        System.out.println(requestJson);
        return  requestJson;
    }

    private boolean handleSecondResponse(JSONObject response, SecretKey secK, PublicKey authPubkey) throws Exception {
        String contentEncoded = response.getString("content");

        // get iv used to encrypt the content
        byte[] requestIv = Base64.getDecoder().decode(response.getString("iv"));

        // decode content
        byte[] contentDecoded = Criptography.decipherAES(Base64.getDecoder().decode(contentEncoded), secK, requestIv);

        JSONObject content = new JSONObject(new String(contentDecoded, StandardCharsets.UTF_8));

        String ts = content.getString("ts");
        String resp = content.getString("resp");
        String signature = content.getString("signature");

        // verify signature
        String stringToVerify = ts + resp;
        boolean success = checkRequest(stringToVerify, signature, ts, authPubkey);
        if (!success)
            return false;

        System.out.println("here");
        return resp.equals("OK");
    }

    private boolean checkRequest(String stringToVerify, String signature, String ts, PublicKey authPubkey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // verify signature
        boolean success = Criptography.verify(stringToVerify.getBytes(), Base64.getDecoder().decode(signature), authPubkey);
        if (!success)
            return false;

        // verify ts limit
        long currentTs = System.currentTimeMillis() / 1000L;
        Date currentDate = new java.util.Date(currentTs*1000);
        Date reqTs = new Date(Long.parseLong(ts)*1000);
        Calendar c = Calendar.getInstance();
        c.setTime(currentDate);

        // set upper limit of 1 minute
        c.add(Calendar.MINUTE, 1);
        Date upperLimit = c.getTime();

        // set lower limit of 2 minutes
        c.add(Calendar.MINUTE, -2);
        Date bottomLimit = c.getTime();

        if (upperLimit.before(reqTs) || bottomLimit.after(reqTs)){
            return false;
        }
        return true;
    }

    private boolean checkFile(String filename) {
        File file = new File(getApplicationContext().getFilesDir(), filename);
        return file.exists();
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