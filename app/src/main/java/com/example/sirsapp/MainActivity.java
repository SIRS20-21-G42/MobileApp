package com.example.sirsapp;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;

import java.io.File;

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

    /**
     * Checks if a user is logged in
     *
     * @return true if the user is logged in, false otherwise
     */
    private boolean logged() {
        // if username file exists, then register has been completed
        return checkFile("username.txt");
    }

    /**
     * Checks if a file with a given filename exists
     *
     * @param filename: name of the file to be checked
     * @return true if the file with the given filename exists, false otherwise
     */
    private boolean checkFile(String filename) {
        File file = new File(getApplicationContext().getFilesDir(), filename);
        return file.exists();
    }
}