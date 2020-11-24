package com.example.sirsapp.ui.Authorization;

public class AuthorizationItem {
    // base item to be represented in the screen

    private String hash;

    public AuthorizationItem(String hash) {
        this.hash = hash;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }
}
