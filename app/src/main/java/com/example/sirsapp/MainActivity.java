package com.example.sirsapp;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Intent intent;
        if ( logged() ) {
            intent = new Intent(this, DrawerActivity.class);
        } else {
            intent = new Intent(this, RegisterActivity.class);
        }
        startActivity(intent);
        finish();
    }

    private boolean logged() {
        //TODO- Check if user file exists and load information
        return false;
    }
}