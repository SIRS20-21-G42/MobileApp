package com.example.sirsapp;

import androidx.appcompat.app.AppCompatActivity;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.navigation.NavController;
import androidx.navigation.Navigation;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;

import android.os.Bundle;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.google.android.material.navigation.NavigationView;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

public class DrawerActivity extends AppCompatActivity {
    private static final int SLEEP_TIME = 100;

    private TOTP totp;
    private Communications comms;
    private String current = "QUEREMOS O 20";
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

        if (!this.totp.isInitialized()) {
            // TODO: Get the secret from RegistrationActivity
            // (it is done with Bundle)
            this.totp.init("aaaaaaaaaaaaaaa");
        }

        new Thread(this::generateOTP).start();
    }

    /**
     * Update progress bar and code
     *
     * @param progress: the seconds elapsed since last code calculation
     */
    private void updateOTPCode(int progress) {
        runOnUiThread(() -> {
            try {
                ((TextView) findViewById(R.id.OTPCode)).setText(this.current);
                ((ProgressBar) findViewById(R.id.codeProgress)).setProgress(progress);
            } catch (NullPointerException e) {
                // FIXME: ignore???
            }
        });
    }

    /**
     * Generate TOTP codes and show them in the UI
     */
    private void generateOTP() {
        while(true) {
            try {
                this.current = this.totp.generate();

                int progress;
                while ((progress = (int) (Instant.now().getEpochSecond() % TOTP.TIME_STEP)) != 0) {
                    this.updateOTPCode(progress);
                    Thread.sleep(SLEEP_TIME);
                }
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