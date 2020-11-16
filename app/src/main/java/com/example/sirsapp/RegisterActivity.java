package com.example.sirsapp;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

import java.io.File;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

import javax.crypto.SecretKey;

public class RegisterActivity extends AppCompatActivity {
    private Cryptography crypto;
    private Communications comms;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        try {
            this.crypto = new Cryptography(getApplicationContext());
        } catch (Exception e) {
            // FIXME: Properly handle exception
            e.printStackTrace();
            throw new RuntimeException("Couldn't initialize crypto instance");
        }

        this.comms = new Communications(this.crypto);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_register);
    }

    public void registerUser(View view) {
        new Thread(() -> { registerAsyncUser(view); }).start();
    }

    public void registerAsyncUser(View view){

        closeKeyboard();

        String username = ((EditText) findViewById(R.id.usernameEditText)).getText().toString();
        if (!validateUsername(username))
            return;
        try {
            // get pubK and privK of the app
            KeyPair keys = this.crypto.getKeyPair();

            Certificate caCert = this.crypto.readCertificateFromResource(R.raw.ca);

            // generate CSR for pubK and get certificate(need to communicate with CA)
            if (!checkFile(Cryptography.APP_CSR_FILE))
                this.crypto.saveToFileNoEncryption(Cryptography.APP_CSR_FILE, Cryptography.generateCSR(username, keys));

            if (!checkFile(Cryptography.APP_CERT_FILE)) {
                boolean success = this.comms.getCertificateFromCA(Cryptography.APP_CSR_FILE, caCert);
                if (!success) {
                    outputError("An error occurred, please try again");
                    return;
                }
            }

            // get auth server pubK from certificate
            Certificate authCert = this.crypto.readCertificateFromResource(R.raw.auth);

            // generate secK for auth communication
            SecretKey secretK = Cryptography.generateSecretKey();

            // get app certificate
            Certificate appCert = this.crypto.readCertificateFromFile(Cryptography.APP_CERT_FILE);

            // calculate timestamp for messages
            long ts = System.currentTimeMillis() / 1000L;

            // calculate {secK || ts || username}authPubK +  {appCert || {sha256(secK, ts, username)}appPrivK}secK
            JSONObject message = calculateFirstMessage(username, keys, secretK, authCert.getPublicKey(), appCert, ts);

            // create auth connection
            Socket connection = Communications.newAuthConnection();

            // Send message to Auth
            JSONObject response = Communications.sendMessageToAuth(connection, message, false);


            BigInteger paramB = handleFirstResponse(response, secretK, authCert.getPublicKey());
            if (paramB == null){
                outputError("An error occurred, please try again");
                return;
            }

            // calculate {ts || username || B || {sha256(ts, username, B)}privK}secK
            message = calculateSecondMessage(username, keys, secretK, paramB, ts);


            // Send message to Auth
            response = Communications.sendMessageToAuth(connection, message, true);


            // validate server response
            if (!handleSecondResponse(response, secretK, authCert.getPublicKey())){
                outputError("An error occurred, please try again");
                return;
            }

            this.crypto.saveToFileNoEncryption("username.txt", username.getBytes());

            Intent intent = new Intent(this, DrawerActivity.class);

            startActivity(intent);
            finish();

        } catch (Exception e) {
            outputError("An error occurred, please try again");
            System.out.println("ERROR!");
            e.printStackTrace();
        }
    }

    /**
     * Calculate de json containing the first message to send to auth
     *      {ts || username || secK}authPubK +  {appCert || {sha256(secK, ts, username)}appPrivK}secK
     *
     * @param username: username received for register
     * @param keys: the application key pair
     * @param secK: the generated secret key for the communication
     * @param appCert: the application certificate
     * @return json with the application's first message to auth
     * @throws Exception for now throws all the occurred exceptions
     */
    private JSONObject calculateFirstMessage(String username, KeyPair keys, SecretKey secK, PublicKey authKey, Certificate appCert, long ts) throws Exception{
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
        byte[] messageCiphered = Cryptography.cipherRSA(part1Json.toString().getBytes(), authKey);
        requestContentJson.put("part1", Base64.getEncoder().encodeToString(messageCiphered));

        // calculate appCert || {sha256(secK, ts, username)}appPrivK
        JSONObject part2Json = new JSONObject();
        part2Json.put("certificate", Base64.getEncoder().encodeToString(appCert.getEncoded()));
        String stringToSign = ts + username + secretKEnc;
        byte[] signatureMessage = Cryptography.sign(stringToSign.getBytes(), privKey);
        part2Json.put("signature", Base64.getEncoder().encodeToString(signatureMessage));

        // generate new iv
        byte[] iv = Cryptography.generateIV();

        // cipher part2 with secK and put on request
        byte[] part2Encoded = Cryptography.cipherAES(part2Json.toString().getBytes(), secK, iv);
        requestContentJson.put("part2", Base64.getEncoder().encodeToString(part2Encoded));

        // add iv to request
        requestContentJson.put("iv", Base64.getEncoder().encodeToString(iv));

        requestJson.put("reg", requestContentJson);
        return  requestJson;
    }

    /**
     * Interpret the first response received from auth
     *
     * @param response: json with the response from the auth
     * @param secK: the generated secret key for the communication
     * @param authPubkey: the public key of the auth
     * @return public application DH parameter
     * @throws Exception for now throws all the occurred exceptions
     */
    private BigInteger handleFirstResponse(JSONObject response, SecretKey secK, PublicKey authPubkey) throws Exception {
        String contentEncoded = response.getString("content");

        // get iv used to encrypt the content
        byte[] requestIv = Base64.getDecoder().decode(response.getString("iv"));

        // decode content
        byte[] contentDecoded = Cryptography.decipherAES(Base64.getDecoder().decode(contentEncoded), secK, requestIv);

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

        return this.crypto.generateDiffieHellmanParam(new BigInteger(paramA), new BigInteger(n), new BigInteger(g));
    }

    /**
     * Calculate de json containing the second message to send to auth:
     *      {ts || username || B || {sha256(ts, username, B)}privK}secK
     *
     * @param username: username received for register
     * @param keys: the application key pair
     * @param secK: the generated secret key for the communication
     * @param paramB: the application's public DH parameter
     * @return json with the application's second message to auth
     * @throws Exception for now throws all the occurred exceptions
     */
    private JSONObject calculateSecondMessage(String username, KeyPair keys, SecretKey secK, BigInteger paramB, long ts) throws Exception{
        PrivateKey privKey= keys.getPrivate();

        JSONObject requestContentJson = new JSONObject();

        // calculate ts || username || B
        JSONObject content = new JSONObject();
        content.put("ts", "" + ts);
        content.put("username", username);
        content.put("B", paramB.toString());

        // calculate {sha256(ts, username, B)}privK
        String stringToSign = ts + username + paramB;
        byte[] signatureMessage = Cryptography.sign(stringToSign.getBytes(), privKey);
        content.put("signature", Base64.getEncoder().encodeToString(signatureMessage));

        // generate new iv
        byte[] iv = Cryptography.generateIV();

        // cipher content with secK
        byte[] messageCiphered = Cryptography.cipherAES(content.toString().getBytes(), secK, iv);
        requestContentJson.put("content", Base64.getEncoder().encodeToString(messageCiphered));

        // add iv to request
        requestContentJson.put("iv", Base64.getEncoder().encodeToString(iv));

        return  requestContentJson;
    }

    /**
     * Interpret the second response received from auth
     *
     * @param response: json with the response from the auth
     * @param secK: the generated secret key for the communication
     * @param authPubkey: the public key of the auth
     * @return true if the response is accepted, false otherwise
     * @throws Exception for now throws all the occurred exceptions
     */
    private boolean handleSecondResponse(JSONObject response, SecretKey secK, PublicKey authPubkey) throws Exception {
        String contentEncoded = response.getString("content");

        // get iv used to encrypt the content
        byte[] requestIv = Base64.getDecoder().decode(response.getString("iv"));

        // decode content
        byte[] contentDecoded = Cryptography.decipherAES(Base64.getDecoder().decode(contentEncoded), secK, requestIv);

        JSONObject content = new JSONObject(new String(contentDecoded, StandardCharsets.UTF_8));

        String ts = content.getString("ts");
        String resp = content.getString("resp");
        String signature = content.getString("signature");

        // verify signature
        String stringToVerify = ts + resp;
        boolean success = checkRequest(stringToVerify, signature, ts, authPubkey);
        if (!success)
            return false;

        return resp.equals("OK");
    }

    /**
     * Verify if the received response can be accepted
     *
     * @param stringToVerify: string with the contents of the signature
     * @param signature: signature received in the response
     * @param ts: timestamp received in the response
     * @param authPubkey: the public key of the auth
     * @return true if the signature is correct and the response timestamp is within the boundary limits
     * @throws Exception for now throws all the occurred exceptions
     */
    private boolean checkRequest(String stringToVerify, String signature, String ts, PublicKey authPubkey) throws Exception {
        // verify signature
        boolean success = Cryptography.verify(stringToVerify.getBytes(), Base64.getDecoder().decode(signature), authPubkey);
        if (!success)
            return false;

        // get current ts
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

        // verify ts limits
        return !upperLimit.before(reqTs) && !bottomLimit.after(reqTs);
    }

    /**
     * Verify is a file exists
     *
     * @param filename: name of the file to be checked
     * @return true if the file exists, false otherwise
     */
    private boolean checkFile(String filename) {
        File file = new File(getApplicationContext().getFilesDir(), filename);
        return file.exists();
    }

    /**
     * Verify the username
     *
     * @param username: username to be verified
     * @return true if the username can be accepted, false otherwise
     */
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

    /**
     * Close the keyboard on the screen
     *
     */
    private void closeKeyboard() {
        View view = this.getCurrentFocus();
        if (view != null){
            InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
            imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
        }
    }

    /**
     * Prints an error to the screen
     *
     * @param s: string to be printed to the screen
     */
    private void outputError(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }

}