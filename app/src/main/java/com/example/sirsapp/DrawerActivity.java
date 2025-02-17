package com.example.sirsapp;

import androidx.appcompat.app.AppCompatActivity;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.navigation.NavController;
import androidx.navigation.Navigation;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;

import android.content.Context;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.example.sirsapp.ui.Authorization.AuthorizationItem;
import com.google.android.material.navigation.NavigationView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DrawerActivity extends AppCompatActivity {
    private static final int SLEEP_TIME = 100;
    private static final long POLL_PERIOD = 1;
    private static final String SAFE_WIFIS_FILE = "wifis.txt";

    private TOTP totp;
    private Cryptography crypto;
    private String current = "QUEREMOS O 20";
    private String username;

    private Timer timer;
    private NavController navController;
    private DrawerLayout drawerLayout;
    private AppBarConfiguration appBarConfig;

    private Set<String> wifiIds;
    private String previousLocalCheck;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_drawer);

        Bundle bundle = getIntent().getExtras();
        if (bundle == null || (this.username = bundle.getString("username")) == null) {
            throw new RuntimeException("Couldn't get current user");
        }

        this.crypto = new Cryptography(getApplicationContext());

        this.totp = new TOTP(this.crypto);

        navController = Navigation.findNavController(this, R.id.fragment);
        drawerLayout = findViewById(R.id.drawer_layout);

        NavigationView navView = findViewById(R.id.navView);
        NavigationUI.setupWithNavController(navView, navController);

        // initialize wifi checks
        try {
            this.wifiIds = getSafeWifiSet();
            this.previousLocalCheck = checkCurrentWifi();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Run as daemon
        this.timer = new Timer(true);

        this.timer.schedule(new TimerTask() {
            @Override
            public void run() {
                pollAuthRequests();
                try {
                    checkLocalStatus();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, 0, POLL_PERIOD * 10 * 1000);

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
     * Gets the stored safe wifis
     *
     * @return set of safe wifis
     * @throws IOException if an I/O error occurs
     */
    private HashSet<String> getSafeWifiSet() throws IOException {
        File file = new File(getApplicationContext().getFilesDir(), SAFE_WIFIS_FILE);

        if (file.exists()) {
            try {
                String wifis = new String(crypto.getFromFile(SAFE_WIFIS_FILE), StandardCharsets.UTF_8);

                return new HashSet<>(Arrays.asList(wifis.split(",")));
            } catch (BadPaddingException e) {
                throw new RuntimeException("Tampered wifi file");
            }
        }

        return new HashSet<>();
    }

    /**
     * adds a new safe wifi to the set and updates the local storage
     *
     * @param wifiId : id of the wifi to be added
     * @throws IOException if file couldn't be opened
     */
    public void addSafeWifi(int wifiId) throws IOException {
        if (this.wifiIds.add("" + wifiId)){
            this.crypto.saveToFile(SAFE_WIFIS_FILE, String.join(",", this.wifiIds).getBytes());
        }
    }

    /**
     * removes a new safe wifi from the set and updates the local storage
     *
     * @param wifiId : id of the wifi to be removed
     * @throws IOException if file couldn't be opened
     */
    public void removeSafeWifi(int wifiId) throws IOException {
        if (this.wifiIds.remove("" + wifiId)){
            this.crypto.saveToFile(SAFE_WIFIS_FILE, String.join(",", this.wifiIds).getBytes());
        }

    }

    /**
     * gets the status of the current wifi
     *
     * @return "SAFE" if the wifi is safe, "UNSAFE" otherwise
     */
    public String checkCurrentWifi() {
        int wifiId = getWifiId();
        if (this.wifiIds.contains("" + wifiId))
            return "SAFE";
        else
            return "UNSAFE";
    }

    /**
     * gets the current wifi id
     *
     * @return current wifi id
     */
    public int getWifiId() {
        WifiManager wifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();
        return wifiInfo.getNetworkId();
    }

    /**
     * checks if the local status has changed and if so, updates the auth
     *
     * @throws Exception for now throws all the occurred exceptions
     */
    private void checkLocalStatus() throws Exception {
        if (checkCurrentWifi().equals("SAFE")) {
            updateLocalStatus("OK");
            this.previousLocalCheck = "SAFE";
        } else if (this.previousLocalCheck.equals("SAFE")){
            updateLocalStatus("NO");
            this.previousLocalCheck = "UNSAFE";
        }
    }

    /**
     * sends the local status to the auth
     *
     * @param new_status: new status to send to the auth
     * @return true if successfully sent to auth, false otherwise
     * @throws Exception for now throws all the occurred exceptions
     */
    public boolean updateLocalStatus(String new_status) throws Exception {
        // username || {username || ts || {sha(...)}appPrivK}secretK
        Socket socket = Communications.openConnection(Communications.AUTH_HOSTNAME, Communications.AUTH_PORT);
        long ts = System.currentTimeMillis() / 1000L;
        JSONObject request = new JSONObject();
        JSONObject message = new JSONObject();
        JSONObject content = new JSONObject();

        content.put("username", this.username);
        content.put("ts", "" + ts);
        content.put("safe", new_status);
        String to_sign = this.username + ts + new_status;
        String signature = Base64.getEncoder().encodeToString(Cryptography.sign(to_sign.getBytes(), this.crypto.getKeyPair().getPrivate()));
        content.put("signature", signature);

        byte[] iv = Cryptography.generateIV();
        byte[] key = Cryptography.digest(totp.getSecret());
        SecretKey secK = new SecretKeySpec(key, 0, key.length, "AES");

        message.put("username", this.username);
        message.put("content", Base64.getEncoder().encodeToString(Cryptography.cipherAES(content.toString().getBytes(), secK, iv)));
        message.put("iv", Base64.getEncoder().encodeToString(iv));

        request.put("location", message);

        Communications.sendMessage(socket, request);

        JSONObject response = Communications.getMessage(socket);

        Communications.closeConnection(socket);

        iv = Base64.getDecoder().decode(response.getString("iv"));

        // Authorization requests
        response = new JSONObject(
                new String(
                        Cryptography.decipherAES(
                                Base64.getDecoder().decode(response.getString("content")), secK, iv)));

        String to_verify = response.getString("resp") + response.getString("ts");
        // Check integrity
        if (!Cryptography.verify(to_verify.getBytes(), Base64.getDecoder().decode(response.getString("signature")), this.crypto.readCertificateFromResource(R.raw.auth).getPublicKey()))
            return false;
        return response.getString("ts").equals("" + ts) && response.getString("resp").equals("OK");

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
                // Just ignore because the view is not visible
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
            } catch (InterruptedException e) {
                // Ignore
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
                    runOnUiThread(() -> {
                        try {
                            ((authorizationFragment) getSupportFragmentManager().findFragmentById(R.id.authorizationFragment)).updateView();
                        } catch(NullPointerException e) {
                            // Ignore
                        }
                    });
            }
        } catch (JSONException | SignatureException | IOException e) {
            try {
                runOnUiThread(() ->
                        Toast.makeText(getApplicationContext(), "An error occurred, please try again later!", Toast.LENGTH_LONG).show()
                );
            } catch (NullPointerException f) {
                // Ignore
            }
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid key");
        } catch (BadPaddingException e) {
            throw new RuntimeException("Invalid padding");
        }
    }

    /**
     * Send response to Auth server to accept/decline a request (with custom protocol)
     *
     * @param hash: the hash of the request to accept/decline
     * @param accepted: whether the request was accepted by the user or not
     */
    public boolean answerAuthRequest(String hash, boolean accepted, int position) {
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
                return false;
            }

            if (position != -1)
                authorizationFragment.list.remove(position);
            return true;
        } catch (IOException | JSONException | SignatureException e) {
            try {
                runOnUiThread(() ->
                        Toast.makeText(getApplicationContext(), "An error occurred, please try again later!", Toast.LENGTH_LONG).show()
                );
            } catch (NullPointerException f) {
                // Ignore
            }
            return false;
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid key");
        } catch (BadPaddingException e) {
            throw new RuntimeException("Invalid padding");
        }
    }

    @Override
    public boolean onSupportNavigateUp() {
        navController = Navigation.findNavController(this, R.id.fragment);
        return NavigationUI.navigateUp(navController, appBarConfig) || super.onSupportNavigateUp();
    }
}