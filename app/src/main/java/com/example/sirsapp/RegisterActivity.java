package com.example.sirsapp;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.Toast;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;

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
            //generate pubK and privK
            KeyPair keys = Criptography.getKeyPair();

            //TODO-generate CSR for pubK(need to communicate with CA)

            //get auth server pubK from certificate
            PublicKey authKey = Criptography.getKeyFromCertificate(view.getContext(), R.raw.Authcert);

            //generate secK
            SecretKey secretK = Criptography.getSecretKey();

        } catch (Exception e) {
            outputError("An error occurred, please try again");
            return;
        }



        //calculate {secK || ts || username || sha256(secK, ts, username)}authPubK +  {appCert || {sha256(appCert)}privK}secK

        //send message

        //validate response message

        //generate DH params

        //calculate {ts || username || {sha256(ts, username)}privK}secK

        //send message
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