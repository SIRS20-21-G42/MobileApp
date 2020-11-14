package com.example.sirsapp;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.Toast;

import java.security.KeyPair;

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

        //generate pubK and privK
        KeyPair keys = Criptography.generateKeyPair();
        if (keys == null) {
            Toast.makeText(this, "An error occurred, please try again", Toast.LENGTH_LONG).show();
            return ;
        }

        //generate certificate for pubK

        //get auth server pubK from certificate

        //generate secK

        //calculate {secK || ts || username || sha256(secK, ts, username)}authPubK +  {appCert || {sha256(appCert)}privK}secK

        //send message

        //validate response message

        //generate DH params

        //calculate {ts || username || {sha256(ts, username)}privK}secK
    }

    private boolean validateUsername(String username) {
        if (username == null || username.equals("")) {
            Toast.makeText(this, "Please specify a username", Toast.LENGTH_LONG).show();
            return false;
        } else if (!username.matches("[A-Za-z0-9_]+") || username.length() > 20) {
            Toast.makeText(this, "Invalid username", Toast.LENGTH_LONG).show();
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
}