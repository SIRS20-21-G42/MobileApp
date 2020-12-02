package com.example.sirsapp.ui.Authorization;

import java.text.SimpleDateFormat;
import java.util.Calendar;

public class AuthorizationItem {
    // base item to be represented in the screen

    private final String hash;
    private final String date;

    public AuthorizationItem(String hash, String ts) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(Long.parseLong(ts) * 1000);

        this.date = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(calendar.getTime());
        this.hash = hash;
    }

    public String getHash() {
        return this.hash;
    }

    public String getDate() {
        return this.date;
    }
}
