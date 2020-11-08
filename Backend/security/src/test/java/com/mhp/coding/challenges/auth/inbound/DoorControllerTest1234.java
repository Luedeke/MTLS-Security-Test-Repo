package com.mhp.coding.challenges.auth.inbound;

import lombok.SneakyThrows;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.junit.Test;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class DoorControllerTest1234 {

    private static final String DOOR_ENDPOINT = "https://127.0.0.1:8090/v1/door";

    private static final String DOOR_TO_CHANGE = "{\"id\":1,\"state\":\"UNLOCKED\"}";
    private static final String RESPONSE_DOOR_TO_CHANGE = "\"id\":1,\"type\":\"fireproof\"," +
            "\"location\":\"Basement 5.3\",\"state\":\"UNLOCKED\"";

    @SneakyThrows
    @Test
    public void test_get_all_doors_accept_admin_role() throws Exception {

        // #Arrange
        HttpGet request = new HttpGet(DOOR_ENDPOINT);
        HttpClient httpClient = getSSLHttpClientWithAdminRole();

        // #Act
        HttpResponse response = httpClient.execute(request);

        // #Assert
        assertEquals(200, response.getStatusLine().getStatusCode());
        String content = EntityUtils.toString(response.getEntity());
        assertTrue(content.contains("fireproof"));
        assertTrue(content.contains("Office 3.1.3"));
        assertTrue(content.contains("Office 3.1.2"));
    }

    @SneakyThrows
    @Test
    public void test_get_all_doors_accept_user_role() throws Exception {

        // #Arrange
        HttpGet request = new HttpGet(DOOR_ENDPOINT);
        HttpClient httpClient = getSSLHttpClientWithUserRole();

        // #Act
        HttpResponse response = httpClient.execute(request);

        // #Assert
        assertEquals(200, response.getStatusLine().getStatusCode());
        String content = EntityUtils.toString(response.getEntity());
        assertTrue(content.contains("fireproof"));
        assertTrue(content.contains("Office 3.1.3"));
        assertTrue(content.contains("Office 3.1.2"));
    }

    @SneakyThrows
    @Test
    public void test_change_door_state_accept_admin_role() throws Exception {
        // #Arrange
        HttpPost request = new HttpPost(DOOR_ENDPOINT);
        request.addHeader("content-type", "application/json");
        StringEntity jsonEntity = new StringEntity(DOOR_TO_CHANGE);
        request.setEntity(jsonEntity);

        // #Act
        HttpClient sslHttpClient = getSSLHttpClientWithAdminRole();
        HttpResponse response = sslHttpClient.execute(request);

        // #Assert
        assertEquals(200, response.getStatusLine().getStatusCode());
        String content = EntityUtils.toString(response.getEntity());
        assertTrue(content.contains(RESPONSE_DOOR_TO_CHANGE));
    }

    @SneakyThrows
    @Test
    public void test_change_door_state_revoke_user_role() throws Exception {
        // #Arrange
        HttpPost request = new HttpPost(DOOR_ENDPOINT);
        request.addHeader("content-type", "application/json");
        StringEntity jsonEntity = new StringEntity(DOOR_TO_CHANGE);
        request.setEntity(jsonEntity);

        // #Act
        HttpClient httpClient = getSSLHttpClientWithUserRole();
        HttpResponse response = httpClient.execute(request);

        // #Assert
        assertEquals(403, response.getStatusLine().getStatusCode());
    }

    @SneakyThrows
    @Test
    public void test_change_door_state_revoke_unknown_certificate() throws Exception {
        // #Arrange
        HttpPost request = new HttpPost(DOOR_ENDPOINT);
        request.addHeader("content-type", "application/json");
        StringEntity jsonEntity = new StringEntity(DOOR_TO_CHANGE);
        request.setEntity(jsonEntity);

        // #Act
        HttpClient httpClient = getSSLHttpClientWithUnknownUserCertificate();
        HttpResponse response = httpClient.execute(request);

        // #Assert
        assertEquals(401, response.getStatusLine().getStatusCode());
    }


    @SneakyThrows
    @Test(expected=SSLHandshakeException.class)
    public void test_get_all_doors_accept_all_cert_should_fail() throws Exception {
        String keyPassphrase = "123456";
        KeyStore keyStore = KeyStore.getInstance("JKS");
        String keyStoreUser = "C:/Users/Nils-Desktop/Google Drive/MHP/coding-challenges/" +
                "Backend/security/src/main/resources/client-user.jks";
        String keyStoreUserNB = "C:/Users/Nils-NB/Google Drive/MHP/coding-challenges/" +
                "Backend/security/src/main/resources/client-user.jks";
        keyStore.load(new FileInputStream(keyStoreUser), keyPassphrase.toCharArray());

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        HttpClient httpClient = HttpClients.custom().setSSLContext(sc).build();
        // This should fail, if MTLS is active
        httpClient.execute(new HttpGet(DOOR_ENDPOINT));
    }

    private HttpClient getSSLHttpClientWithAdminRole() throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, KeyManagementException, UnrecoverableKeyException {
        String adminKeySTore = "C:/Users/Nils-Desktop/Google Drive/MHP/coding-challenges/" +
                "Backend/security/src/main/resources/client-admin.jks";
        String keyStoreUserNB = "C:/Users/Nils-NB/Google Drive/MHP/coding-challenges/" +
                "Backend/security/src/main/resources/client-user.jks";

        // truststore
        /*
        KeyStore trustStore = KeyStore.getInstance("JKS";
        trustStore.load(new FileInputStream(adminKeySTore), "123456".toCharArray());
        String alg = KeyManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory fac = TrustManagerFactory.getInstance(alg);
        fac.init(trustStore);
        */


        KeyStore myTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        myTrustStore.load(new FileInputStream(keyStoreUserNB), "password".toCharArray());

        String keyPassphrase = "123456";
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(keyStoreUserNB), keyPassphrase.toCharArray());

        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(new SSLContextBuilder()
                .loadTrustMaterial(myTrustStore, new TrustSelfSignedStrategy())
                .loadKeyMaterial(keyStore, keyPassphrase.toCharArray()).build(),
                NoopHostnameVerifier.INSTANCE);

        return HttpClients.custom().setSSLSocketFactory(socketFactory).build();
    }

    private HttpClient getSSLHttpClientWithUserRole() throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, KeyManagementException, UnrecoverableKeyException {
        String keyPassphrase = "123456";
        KeyStore keyStore = KeyStore.getInstance("JKS");
        String userKeyStore = "C:/Users/Nils-Desktop/Google Drive/MHP/coding-challenges/" +
                "Backend/security/src/main/resources/client-user.jks";
        keyStore.load(new FileInputStream(userKeyStore), keyPassphrase.toCharArray());


        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(new SSLContextBuilder()
                .loadTrustMaterial(null, new TrustSelfSignedStrategy())
                .loadKeyMaterial(keyStore, keyPassphrase.toCharArray()).build(),
                NoopHostnameVerifier.INSTANCE);

        return HttpClients.custom().setSSLSocketFactory(socketFactory).build();
    }

    /**
     * nt-gateway.jks contains Server Cert,
     * but Server.jks not contains nt-gateway.cert
     */
    private HttpClient getSSLHttpClientWithUnknownUserCertificate() throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, KeyManagementException, UnrecoverableKeyException {
        String keyPassphrase = "123456";
        KeyStore keyStore = KeyStore.getInstance("JKS");
        String userKeyStore = "C:/Users/Nils-Desktop/Google Drive/MHP/coding-challenges/" +
                "Backend/security/src/main/resources/nt-gateway.jks";
        keyStore.load(new FileInputStream(userKeyStore), keyPassphrase.toCharArray());


        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(new SSLContextBuilder()
                .loadTrustMaterial(null, new TrustSelfSignedStrategy())
                .loadKeyMaterial(keyStore, keyPassphrase.toCharArray()).build(),
                NoopHostnameVerifier.INSTANCE);

        return HttpClients.custom().setSSLSocketFactory(socketFactory).build();
    }
}
