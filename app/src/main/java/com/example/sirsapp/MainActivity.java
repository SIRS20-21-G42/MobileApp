package com.example.sirsapp;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.os.StrictMode;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;

public class MainActivity extends AppCompatActivity {
    public static final String USERNAME_FILE = "username.txt";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Intent intent;
        String username = getUsername();

        if (username != null) {
            intent = new Intent(this, DrawerActivity.class);

            Bundle bundle = new Bundle();
            bundle.putString("username", username);

            intent.putExtras(bundle);
        } else {
            intent = new Intent(this, RegisterActivity.class);
        }

        startActivity(intent);
        finish();
    }

    /**
     * Get the current username
     *
     * @return the current username or null if not logged
     */
    private String getUsername() {
        File file = new File(getApplicationContext().getFilesDir(), USERNAME_FILE);

        if (file.exists()) {
            try {
                return new BufferedReader(new InputStreamReader(new FileInputStream(file))).readLine();
            } catch (FileNotFoundException e) {
                throw new RuntimeException("File not found");
            } catch (IOException e) {
                return null;
            }
        }

        return null;
    }
}