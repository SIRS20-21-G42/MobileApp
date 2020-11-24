package com.example.sirsapp;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
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
    private final Cryptography crypto;

    public static final String AUTH_HOSTNAME = "192.168.1.70";
    public static final int AUTH_PORT = 1337;
    public static final String CA_HOSTNAME = "192.168.1.70";
    public static final int CA_PORT        = 8081;
    private static final String attachmentName = "csr";
    private static final String attachmentFileName = "app.csr";
    private static final String crlf = "\r\n";
    private static final String twoHyphens = "--";
    private static final String boundary =  "*****";

    public Communications(Cryptography crypto) {
        this.crypto = crypto;
    }

    /**
     * Create a new socket for the given hostname and port (with TCP No Delay)
     *
     * @param hostname: the address of the host to connect to
     * @param port: the port in the host to connect to
     * @return an open socket to hostname:port
     * @throws Exception for now throws all the occurred exceptions
     */
    public static Socket openConnection(String hostname, int port) throws Exception {
        Socket socket = new Socket(hostname, port);

        socket.setTcpNoDelay(true);

        return socket;
    }

    /**
     * Close the given socket
     *
     * @param socket: the socket to close
     * @throws IOException if an I/O error occurs when closing the socket
     */
    public static void closeConnection(Socket socket) throws IOException {
        socket.close();
    }

    /**
     * Send a message through the given socket
     *
     * @param socket: the socket used to send the message
     * @param message: the message to send through the socket
     * @throws IOException if an I/O error occurs when creating the output stream or if the socket is not connected
     */
    public static void sendMessage(Socket socket, JSONObject message) throws IOException {
        DataOutputStream output = new DataOutputStream(socket.getOutputStream());

        output.write(message.toString().getBytes());
        output.write('\n');
        output.flush();
    }

    /**
     * Get message from the  given socket
     *
     * @param socket: the socket to read the message from
     * @return the JSON object corresponding to the received message
     * @throws IOException 	if an I/O error occurs when creating the input stream, the socket is closed, the socket is not connected, or the socket input has been shutdown
     * @throws JSONException if the message is not JSON parsable
     */
    public static JSONObject getMessage(Socket socket) throws IOException, JSONException {
        BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        String response = input.readLine();
        return new JSONObject(response);
    }

    /**
     * Sends a CSR to the CA and gets a certificate, storing it in a file
     *
     * @param csrFilename: name of the file containing the CSR
     * @param caCert: CA certificate
     * @return true if the certificate was received correctly
     * @throws Exception for now throws all the occurred exceptions
     */
    public boolean getCertificateFromCA(String csrFilename, Certificate caCert) throws Exception {
        // create keystore with ca certificate to use for connection
        KeyStore ks = Cryptography.createKeyStore(caCert);
        if (ks == null)
            return false;

        // setup the HTTPS connection to ca
        HttpsURLConnection conn = setupHttpsURLConnection(ks);
        if (conn == null)
            return false;

        // send the request to the CA
        sendCARequest(csrFilename, conn);

        // check request response code
        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK)
            return false;

        // get response from the CA
        getCAResponse(conn);
        return true;

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

        URL url = new URL("https://" + CA_HOSTNAME + ":" + CA_PORT + "/sign");
        HttpsURLConnection httpsConn = (HttpsURLConnection) url.openConnection();
        httpsConn.setSSLSocketFactory(cont.getSocketFactory());

        // Setting a verifier to allow connections to the host
        httpsConn.setHostnameVerifier((hostname, sslSession) -> hostname.equals(CA_HOSTNAME));
        httpsConn.setUseCaches(false);
        httpsConn.setDoOutput(true);
        return httpsConn;
    }

    /**
     * Sends a request to the CA
     *
     * @param csrFilename: name of the file containing the CSR
     * @param httpsConn: connection object with the connection parameters setup
     * @throws Exception for now throws all the occurred exceptions
     */
    private void sendCARequest(String csrFilename, HttpsURLConnection httpsConn) throws Exception {
        // Setting the headers of the request
        httpsConn.setRequestMethod("POST");
        httpsConn.setRequestProperty("Connection", "Keep-Alive");
        httpsConn.setRequestProperty("Cache-Control", "no-cache");
        httpsConn.setRequestProperty(
                "Content-Type", "multipart/form-data;boundary=" + boundary);
        httpsConn.setConnectTimeout(5000);

        DataOutputStream request = new DataOutputStream(httpsConn.getOutputStream());

        // Writing the content of the request
        request.writeBytes(twoHyphens + boundary + crlf);
        request.writeBytes("Content-Disposition: form-data; name=\"" +
                attachmentName + "\";filename=\"" +
                attachmentFileName + "\"" + crlf);
        request.writeBytes(crlf);

        // Reading the file and writing the request
        byte [] csr = this.crypto.getFromFileNoEncryption(csrFilename);
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
     * @param httpsConn: connection created with the CA
     * @throws Exception for now throws all the occurred exceptions
     */
    private void getCAResponse(HttpsURLConnection httpsConn) throws Exception {
        String fileName = Cryptography.APP_CERT_FILE;
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
        File path = new File(this.crypto.getContext().getFilesDir(), fileName);

        path.createNewFile();

        FileOutputStream outputStream = new FileOutputStream(path);

        //Save file
        int bytesRead;
        byte[] buffer = new byte[4096];
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }

        outputStream.close();
        inputStream.close();
    }
}
