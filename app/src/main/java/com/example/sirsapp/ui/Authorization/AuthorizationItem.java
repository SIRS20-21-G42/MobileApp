package com.example.sirsapp.ui.Authorization;

import java.text.SimpleDateFormat;
import java.util.Calendar;

/**
 * represents an item to be displayed on the authorization list
 */
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

    /**
     * gets the hash of the item
     *
     * @return hash of the item
     */
    public String getHash() {
        return this.hash;
    }

    /**
     * gets the date of the item
     *
     * @return date of the item
     */
    public String getDate() {
        return this.date;
    }
}
