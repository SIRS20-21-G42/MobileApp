package com.example.sirsapp;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class Criptography {

    private static final int KEY_SIZE = 2048;

    private static final String KEY_GENERATION_ALG = "RSA";


    public Criptography(){

    }

    public static KeyPair generateKeyPair(){
        try{
            KeyPairGenerator keyPairGenerator = null;
            keyPairGenerator = KeyPairGenerator.getInstance(Criptography.KEY_GENERATION_ALG);

            keyPairGenerator.initialize(Criptography.KEY_SIZE);

            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            return null;
        }
    }

    public static void generateCertificate(){

    }
}
