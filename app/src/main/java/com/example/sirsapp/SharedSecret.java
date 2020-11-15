package com.example.sirsapp;

import javax.crypto.SecretKey;

public class SharedSecret implements SecretKey {
    private byte[] secret;

    public SharedSecret(String secret) {
        this.secret = secret.getBytes();
    }

    @Override
    public void destroy() {
        this.secret = null;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SharedSecret && ((SharedSecret) o).getEncoded().equals(this.secret);
    }

    @Override
    public String getAlgorithm() {
        return "Diffie-Hellman";
    }

    @Override
    public byte[] getEncoded() throws IllegalStateException {
        if(this.secret != null){
          return this.secret;
        }

        throw new IllegalStateException();
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public int hashCode() {
        return this.secret.hashCode();
    }

    @Override
    public boolean isDestroyed() {
        return this.secret == null;
    }
}
