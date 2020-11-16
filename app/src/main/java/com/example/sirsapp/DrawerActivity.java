package com.example.sirsapp;

import androidx.appcompat.app.AppCompatActivity;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.navigation.NavController;
import androidx.navigation.Navigation;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;

import android.os.Bundle;
import android.widget.TextView;

import com.google.android.material.navigation.NavigationView;

import java.util.HashSet;
import java.util.Set;

public class DrawerActivity extends AppCompatActivity {
    private TOTP totp;
    private Communications comms;
    private NavController navController;
    private DrawerLayout drawerLayout;
    private AppBarConfiguration appBarConfig;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_drawer);

        Cryptography crypto;
        try {
            crypto = new Cryptography(getApplicationContext());
        } catch (Exception e) {
            // FIXME: Properly handle exception
            e.printStackTrace();
            throw new RuntimeException("Couldn't initialize crypto instance");
        }

        this.comms = new Communications(crypto);
        this.totp = new TOTP(crypto);

        navController = Navigation.findNavController(this, R.id.fragment);
        drawerLayout = findViewById(R.id.drawer_layout);

        NavigationView navView = findViewById(R.id.navView);
        NavigationUI.setupWithNavController(navView, navController);

        Set<Integer> topLevelDestinations = new HashSet<>();
        topLevelDestinations.add(R.id.authenticationCodeFragment);
        topLevelDestinations.add(R.id.authorizationFragment);
        topLevelDestinations.add(R.id.safeLocalFragment);
        appBarConfig = new AppBarConfiguration.Builder(topLevelDestinations).setOpenableLayout(drawerLayout).build();
        NavigationUI.setupActionBarWithNavController(this, navController, appBarConfig);

        this.totp.init("aaaaaaaaaaaaaaa");
        new Thread(this::generateOTP).start();
    }

    private void generateOTP() {

        while(true) {
            try {
                String totp = this.totp.generate();

                runOnUiThread(() -> ((TextView) findViewById(R.id.OTPCode)).setText(totp));

                Thread.sleep(30 * 1000);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public boolean onSupportNavigateUp() {
        navController = Navigation.findNavController(this, R.id.fragment);
        return NavigationUI.navigateUp(navController, appBarConfig) || super.onSupportNavigateUp();
    }
}