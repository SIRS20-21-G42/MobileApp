package com.example.sirsapp;

import android.content.Context;

import org.jetbrains.annotations.NotNull;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class Communications {

    public static final String HOSTNAME = "192.168.1.78";
    private static final String attachmentName = "csr";
    private static final String attachmentFileName = "app.csr";
    private static final String crlf = "\r\n";
    private static final String twoHyphens = "--";
    private static final String boundary =  "*****";

    public Communications(){

    }

    public static boolean getCertificateFromCA(Context context, String csrFilename, Certificate caCert) throws Exception {
        //Load certificate into keyStore to use for TLS
        KeyStore ks = createKeyStore(caCert);

        //setup parameters for connection
        HttpsURLConnection httpsConn = setupHttpsURLConnection(ks);

        //send request
        sendCARequest(context, csrFilename, httpsConn);

        //get response
        int responseCode = httpsConn.getResponseCode();
        System.out.println(responseCode);
        if (responseCode == HttpURLConnection.HTTP_OK) {
            getCAResponse(context, httpsConn);
            return true;
        }

        return false;

    }

    private static KeyStore createKeyStore(Certificate caCert) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null);

        //setting the certificate of the ca
        ks.setEntry("caCert", new KeyStore.TrustedCertificateEntry(caCert), null);

        return ks;
    }

    private static HttpsURLConnection setupHttpsURLConnection(KeyStore ks) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        //Creating a TrustManager and initializing with the KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(ks);

        SSLContext cont = SSLContext.getInstance("TLS");
        cont.init(null, tmf.getTrustManagers(), null);

        URL url = new URL("https://" + HOSTNAME + ":8080/sign");
        HttpsURLConnection httpsConn = (HttpsURLConnection) url.openConnection();
        httpsConn.setSSLSocketFactory(cont.getSocketFactory());

        //Setting a verifier to allow connections to the host
        httpsConn.setHostnameVerifier((hostname, sslSession) -> {
            return hostname.equals(HOSTNAME);
        });
        httpsConn.setUseCaches(false);
        httpsConn.setDoOutput(true);
        return httpsConn;
    }

    private static void sendCARequest(Context context, String csrFilename, HttpsURLConnection httpsConn) throws Exception {
        //Setting the headers of the request
        httpsConn.setRequestMethod("POST");
        httpsConn.setRequestProperty("Connection", "Keep-Alive");
        httpsConn.setRequestProperty("Cache-Control", "no-cache");
        httpsConn.setRequestProperty(
                "Content-Type", "multipart/form-data;boundary=" + boundary);

        DataOutputStream request = new DataOutputStream(
                httpsConn.getOutputStream());

        //writing the content of the request
        request.writeBytes(twoHyphens + boundary + crlf);
        request.writeBytes("Content-Disposition: form-data; name=\"" +
                attachmentName + "\";filename=\"" +
                attachmentFileName + "\"" + crlf);
        request.writeBytes(crlf);

        //Reading the file and writing the request
        byte [] csr = Criptography.getFromFileNoEncryption(context, csrFilename);
        request.write(csr);

        //End of the request
        request.writeBytes(crlf);
        request.writeBytes(twoHyphens + boundary +
                twoHyphens + crlf);

        request.flush();
        request.close();
    }

    private static void getCAResponse(Context context, HttpsURLConnection httpsConn) throws IOException {
        String fileName = Criptography.APP_CERT_FILE;
        String disposition = httpsConn.getHeaderField("Content-Disposition");

        if (disposition != null) {
            //Extracts file name from header field
            int index = disposition.indexOf("filename=");
            if (index > 0) {
                fileName = disposition.substring(index + 10,
                        disposition.length() - 1);
            }
        }

        //Opens input stream from the HTTPS connection
        InputStream inputStream = httpsConn.getInputStream();

        //Opens an output stream to save into file
        File path = new File(context.getFilesDir(), fileName);

        path.createNewFile();

        FileOutputStream outputStream = new FileOutputStream(path);

        //Save file
        int bytesRead = -1;
        byte[] buffer = new byte[4096];
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }

        outputStream.close();
        inputStream.close();
    }

}
