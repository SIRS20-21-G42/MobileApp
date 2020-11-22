package com.example.sirsapp;

import android.content.Context;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class Communications {

    private static final String HOSTNAME = "192.168.1.78";
    private static final int AUTH_PORT = 1337;
    private static final String attachmentName = "csr";
    private static final String attachmentFileName = "app.csr";
    private static final String crlf = "\r\n";
    private static final String twoHyphens = "--";
    private static final String boundary =  "*****";

    public Communications(){

    }

    /**
     * Sends the json message to auth
     *
     * @param request: json with the request to send
     * @return json with the response from auth
     * @throws Exception for now throws all the occurred exceptions
     */
    public static JSONObject sendMesageToAuth(JSONObject request) throws Exception {
        Socket socket = new Socket(HOSTNAME, AUTH_PORT);
        DataOutputStream outStream = new DataOutputStream(socket.getOutputStream());

        //Send request
        outStream.write(request.toString().getBytes());
        outStream.write("\n".getBytes());

        outStream.close();

        //Read response
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String response = reader.readLine();

        reader.close();

        return new JSONObject(response);
    }

    /**
     * Sends a CSR to the CA and gets a certificate, storing it in a file
     *
     * @param context: context of the application
     * @param csrFilename: name of the file containing the CSR
     * @param caCert: CA certificate
     * @return true if the certificate was received correctly
     * @throws Exception for now throws all the occurred exceptions
     */
    public static boolean getCertificateFromCA(Context context, String csrFilename, Certificate caCert) throws Exception {
        // create keystore with ca certificate to use for connection
        KeyStore ks = createKeyStore(caCert);
        if (ks == null)
            return false;

        // setup the HTTPS connection to ca
        HttpsURLConnection conn = setupHttpsURLConnection(ks);
        if (conn == null)
            return false;

        // send the request to the CA
        sendCARequest(context, csrFilename, conn);

        // check request response code
        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK)
            return false;

        // get response from the CA
        getCAResponse(context, conn);
        return true;

    }

    /**
     * Creates a key store and inserts the certificate in it
     *
     * @param caCert: CA certificate
     * @return created keystore
     * @throws Exception for now throws all the occurred exceptions
     */
    private static KeyStore createKeyStore(Certificate caCert) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null);

        //setting the certificate of the ca
        ks.setEntry("caCert", new KeyStore.TrustedCertificateEntry(caCert), null);

        return ks;
    }

    /**
     * Sets up the parameters for the HTTPS connection
     *
     * @param ks: key store to use for the trusted certificates in the connection
     * @return connection created
     * @throws Exception for now throws all the occurred exceptions
     */
    private static HttpsURLConnection setupHttpsURLConnection(KeyStore ks) throws Exception {
        // Creating a TrustManager and initializing with the KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(ks);

        SSLContext cont = SSLContext.getInstance("TLS");
        cont.init(null, tmf.getTrustManagers(), null);

        URL url = new URL("https://" + HOSTNAME + ":8080/sign");
        HttpsURLConnection httpsConn = (HttpsURLConnection) url.openConnection();
        httpsConn.setSSLSocketFactory(cont.getSocketFactory());

        // Setting a verifier to allow connections to the host
        httpsConn.setHostnameVerifier((hostname, sslSession) -> hostname.equals(HOSTNAME));
        httpsConn.setUseCaches(false);
        httpsConn.setDoOutput(true);
        return httpsConn;
    }

    /**
     * Sends a request to the CA
     *
     * @param context: context of the application
     * @param csrFilename: name of the file containing the CSR
     * @param httpsConn: connection object with the connection parameters setup
     * @throws Exception for now throws all the occurred exceptions
     */
    private static void sendCARequest(Context context, String csrFilename, HttpsURLConnection httpsConn) throws Exception {
        // Setting the headers of the request
        httpsConn.setRequestMethod("POST");
        httpsConn.setRequestProperty("Connection", "Keep-Alive");
        httpsConn.setRequestProperty("Cache-Control", "no-cache");
        httpsConn.setRequestProperty(
                "Content-Type", "multipart/form-data;boundary=" + boundary);

        DataOutputStream request = new DataOutputStream(httpsConn.getOutputStream());

        // Writing the content of the request
        request.writeBytes(twoHyphens + boundary + crlf);
        request.writeBytes("Content-Disposition: form-data; name=\"" +
                attachmentName + "\";filename=\"" +
                attachmentFileName + "\"" + crlf);
        request.writeBytes(crlf);

        // Reading the file and writing the request
        byte [] csr = Criptography.getFromFileNoEncryption(context, csrFilename);
        request.write(csr);

        // End of the request
        request.writeBytes(crlf);
        request.writeBytes(twoHyphens + boundary +
                twoHyphens + crlf);

        request.flush();
        request.close();
    }

    /**
     * Gets the response from the CA and stores the certificate in a file if successful request
     *
     * @param context: context of the application
     * @param httpsConn: connection created with the CA
     * @throws Exception for now throws all the occurred exceptions
     */
    private static void getCAResponse(Context context, HttpsURLConnection httpsConn) throws Exception {
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
