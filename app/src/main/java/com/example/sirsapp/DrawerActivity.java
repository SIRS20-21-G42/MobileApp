package com.example.sirsapp;

import androidx.appcompat.app.AppCompatActivity;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.fragment.app.Fragment;
import androidx.navigation.NavController;
import androidx.navigation.Navigation;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;

import android.os.Bundle;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.example.sirsapp.ui.Authorization.AuthorizationItem;
import com.google.android.material.navigation.NavigationView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DrawerActivity extends AppCompatActivity {
    private static final int SLEEP_TIME = 100;
    private static final long POLL_PERIOD = 1;

    private TOTP totp;
    private Cryptography crypto;
    private String current = "QUEREMOS O 20";
    private String username;

    private Timer timer;
    private NavController navController;
    private DrawerLayout drawerLayout;
    private AppBarConfiguration appBarConfig;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_drawer);

        Bundle bundle = getIntent().getExtras();
        if (bundle == null || (this.username = bundle.getString("username")) == null) {
            throw new RuntimeException("Couldn't get current user");
        }

        try {
            this.crypto = new Cryptography(getApplicationContext());
        } catch (Exception e) {
            // FIXME: Properly handle exception
            e.printStackTrace();
            throw new RuntimeException("Couldn't initialize crypto instance");
        }

        this.totp = new TOTP(this.crypto);

        navController = Navigation.findNavController(this, R.id.fragment);
        drawerLayout = findViewById(R.id.drawer_layout);

        NavigationView navView = findViewById(R.id.navView);
        NavigationUI.setupWithNavController(navView, navController);

        // Run as daemon
        this.timer = new Timer(true);

        this.timer.schedule(new TimerTask() {
            @Override
            public void run() {
                pollAuthRequests();
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

    /**
     * Poll auth for pending authorization requests (with custom protocol)
     */
    private void pollAuthRequests() {
        try {
            Socket socket = Communications.openConnection(Communications.AUTH_HOSTNAME, Communications.AUTH_PORT);
            JSONObject message = new JSONObject();
            message.put("username", username);

            long ts = System.currentTimeMillis() / 1000L;

            JSONObject content = new JSONObject();
            content.put("username", username);
            content.put("ts", ts);
            content.put("signature", Base64.getEncoder().encodeToString(Cryptography.sign((username + ts).getBytes(), crypto.getKeyPair().getPrivate())));

            byte[] iv = Cryptography.generateIV();
            byte[] key = Cryptography.digest(totp.getSecret());

            SecretKey secK = new SecretKeySpec(key, 0, key.length, "AES");

            message.put("content", Base64.getEncoder().encodeToString(Cryptography.cipherAES(content.toString().getBytes(), secK, iv)));

            message.put("iv", Base64.getEncoder().encodeToString(iv));

            JSONObject request = new JSONObject();
            request.put("list", message);

            Communications.sendMessage(socket, request);

            JSONObject response = Communications.getMessage(socket);

            Communications.closeConnection(socket);

            iv = Base64.getDecoder().decode(response.getString("iv"));

            // Authorization requests
            response = new JSONObject(
                    new String(
                            Cryptography.decipherAES(
                                    Base64.getDecoder().decode(response.getString("content")), secK, iv)));

            // Check integrity
            String hash = response.getString("response").replace("\\", "");
            if (!response.getString("hash").equals(Base64.getEncoder().encodeToString(Cryptography.digest(hash.getBytes())))) {
                System.err.println("Got tampered response while asking for pending authorization requests");
                return;
            }

            JSONArray pending = response.getJSONObject("response").getJSONArray("list");

            List<AuthorizationItem> list = new ArrayList<>();

            // Convert to AuthorizationItem
            for (int i = 0; i < pending.length(); i++) {
                JSONArray entry = pending.getJSONArray(i);
                list.add(new AuthorizationItem(entry.getString(0), entry.getString(1)));
            }

            synchronized (authorizationFragment.lock) {
                authorizationFragment.list = list;
                try {
                    // FIXME: NOT WORKING
                    runOnUiThread(() -> {
                        ((authorizationFragment) getSupportFragmentManager().findFragmentById(R.id.authorizationFragment)).updateView();
                    });
                } catch(NullPointerException e) {
                    return;
                }
            }
        } catch (Exception e) {
            // FIXME: Properly handle the exception
            e.printStackTrace();
        }
    }

    /**
     * Send response to Auth server to accept/decline a request (with custom protocol)
     *
     * @param hash: the hash of the request to accept/decline
     * @param accepted: whether the request was accepted by the user or not
     */
    public void answerAuthRequest(String hash, boolean accepted, int position) {
        try {
            Socket socket = Communications.openConnection(Communications.AUTH_HOSTNAME, Communications.AUTH_PORT);

            JSONObject message = new JSONObject();
            message.put("username", username);

            long ts = System.currentTimeMillis() / 1000L;

            JSONObject content = new JSONObject();
            String status = (accepted ? "OK" : "NO");
            content.put("resp", status);
            content.put("ts", ts);
            content.put("hash", hash);
            content.put("signature", Base64.getEncoder().encodeToString(Cryptography.sign((ts + status + hash).getBytes(), crypto.getKeyPair().getPrivate())));

            byte[] iv = Cryptography.generateIV();
            byte[] key = Cryptography.digest(totp.getSecret());

            SecretKey secK = new SecretKeySpec(key, 0, key.length, "AES");

            message.put("content", Base64.getEncoder().encodeToString(Cryptography.cipherAES(content.toString().getBytes(), secK, iv)));
            message.put("iv", Base64.getEncoder().encodeToString(iv));

            JSONObject request = new JSONObject();
            request.put("auth", message);

            Communications.sendMessage(socket, request);

            JSONObject response = Communications.getMessage(socket);

            Communications.closeConnection(socket);

            iv = Base64.getDecoder().decode(response.getString("iv"));

            response = new JSONObject(
                    new String(
                            Cryptography.decipherAES(
                                    Base64.getDecoder().decode(response.getString("content")), secK, iv)));

            PublicKey authKey = this.crypto.readCertificateFromResource(R.raw.auth).getPublicKey();

            String toVerify = response.getString("resp") + response.getString("ts");

            Cryptography.verify(toVerify.getBytes(), Base64.getDecoder().decode(response.getString("signature")), authKey);

            if (!response.getString("resp").equals("OK")) {
                // TODO: Retry?
                System.err.println("Could not " + (accepted ? "accept" : "decline") + " the authorization request with hash " + hash);
            }

            authorizationFragment.list.remove(position);

        } catch (Exception e) {
            // FIXME: Properly handle the exception
            e.printStackTrace();
        }
    }

    @Override
    public boolean onSupportNavigateUp() {
        navController = Navigation.findNavController(this, R.id.fragment);
        return NavigationUI.navigateUp(navController, appBarConfig) || super.onSupportNavigateUp();
    }
}