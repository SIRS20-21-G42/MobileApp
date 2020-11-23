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

import org.json.JSONObject;

import java.net.Socket;
import java.util.HashSet;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

public class DrawerActivity extends AppCompatActivity {
    private static final int SLEEP_TIME = 100;
    private static final long POLL_PERIOD = 5;

    private TOTP totp;
    private String current = "QUEREMOS O 20";

    private Timer timer;
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

        this.totp = new TOTP(crypto);

        navController = Navigation.findNavController(this, R.id.fragment);
        drawerLayout = findViewById(R.id.drawer_layout);

        NavigationView navView = findViewById(R.id.navView);
        NavigationUI.setupWithNavController(navView, navController);

        // Run as daemon
        this.timer = new Timer(true);

        this.timer.schedule(new TimerTask() {
            @Override
            public void run() {
                // Poll auth server
                try {
                    Socket socket = Communications.openConnection(Communications.AUTH_HOSTNAME, Communications.AUTH_PORT);
                    JSONObject message = new JSONObject();
                    message.put("HELLO", "WORLD");
                    Communications.sendMessage(socket, message);
                    System.out.println(Communications.getMessage(socket));
                    Communications.closeConnection(socket);
                } catch (Exception e) {
                    System.err.println("********************");
                    e.printStackTrace();
                }
            }
        }, 0, POLL_PERIOD * 60 * 1000);

        Set<Integer> topLevelDestinations = new HashSet<>();
        topLevelDestinations.add(R.id.authenticationCodeFragment);
        topLevelDestinations.add(R.id.authorizationFragment);
        topLevelDestinations.add(R.id.safeLocalFragment);
        appBarConfig = new AppBarConfiguration.Builder(topLevelDestinations).setOpenableLayout(drawerLayout).build();
        NavigationUI.setupActionBarWithNavController(this, navController, appBarConfig);

        if (!this.totp.isInitialized()) {
            throw new RuntimeException("Couldn't get secret from crypto");
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
                while ((progress = (int) ((System.currentTimeMillis() / 1000L) % TOTP.TIME_STEP)) != 0) {
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