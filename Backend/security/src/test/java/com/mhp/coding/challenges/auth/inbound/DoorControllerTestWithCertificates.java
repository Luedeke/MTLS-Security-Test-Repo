package com.mhp.coding.challenges.auth.inbound;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
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

public class DoorControllerTestWithCertificates {

    private static final String DOOR_ENDPOINT = "https://127.0.0.1:8090/v1/door";

    private static final String HEADER_CONTENT_TYPE = "content-type";
    private static final String HEADER_CONTENT_TYPE_APPLICATION_JSON = "application/json";

    private static final String DOOR_TO_CHANGE = "{\"id\":1,\"state\":\"UNLOCKED\"}";
    private static final String RESPONSE_DOOR_TO_CHANGE = "\"id\":1,\"type\":\"fireproof\"," +
            "\"location\":\"Basement 5.3\",\"state\":\"UNLOCKED\"";

    private static final String KEY_PASSPHRASE = "123456";

    // Keystores for 3 different Roles
    private static final String USER_KEY_STORE = "C:/Users/Nils-Desktop/Google Drive/MHP/coding-challenges/" +
            "Backend/security/src/main/resources/client-user.jks";
    private static final String USER_KEY_STORE_NB = "C:/Users/Nils-NB/Google Drive/MHP/coding-challenges/" +
            "Backend/security/src/main/resources/client-user.jks";

    private static final String ADMIN_KEYS_TORE = "C:/Users/Nils-Desktop/Google Drive/MHP/coding-challenges/" +
            "Backend/security/src/main/resources/client-admin.jks";

    private static final String GATEWAY_KEY_STORE = "C:/Users/Nils-Desktop/Google Drive/MHP/coding-challenges/" +
            "Backend/security/src/main/resources/nt-gateway.jks";

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

    @Test
    public void test_change_door_state_accept_admin_role() throws Exception {
        // #Arrange
        HttpPost request = new HttpPost(DOOR_ENDPOINT);
        request.addHeader(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON);
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

    @Test
    public void test_change_door_state_revoke_user_role() throws Exception {
        // #Arrange
        HttpPost request = new HttpPost(DOOR_ENDPOINT);
        request.addHeader(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON);
        StringEntity jsonEntity = new StringEntity(DOOR_TO_CHANGE);
        request.setEntity(jsonEntity);

        // #Act
        HttpClient httpClient = getSSLHttpClientWithUserRole();
        HttpResponse response = httpClient.execute(request);

        // #Assert
        assertEquals(403, response.getStatusLine().getStatusCode());
    }

    @Test(expected=SSLHandshakeException.class)
    public void test_change_door_state_revoke_unknown_certificate() throws Exception {
        // #Arrange
        HttpPost request = new HttpPost(DOOR_ENDPOINT);
        request.addHeader(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON);
        StringEntity jsonEntity = new StringEntity(DOOR_TO_CHANGE);
        request.setEntity(jsonEntity);

        // #Act
        HttpClient httpClient = getSSLHttpClientWithUnknownUserCertificate();
        httpClient.execute(request);
    }

    @Test(expected=SSLHandshakeException.class)
    public void test_get_all_doors_accept_all_cert_should_fail() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(USER_KEY_STORE), KEY_PASSPHRASE.toCharArray());

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
        String keyStoreUserNB = "C:/Users/Nils-NB/Google Drive/MHP/coding-challenges/" +
                "Backend/security/src/main/resources/client-admin.jks";
        return getHttpClient(ADMIN_KEYS_TORE);
    }


    private HttpClient getSSLHttpClientWithUserRole() throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, KeyManagementException, UnrecoverableKeyException {
        return getHttpClient(USER_KEY_STORE);
    }

    /**
     * nt-gateway.jks contains Server Cert,
     * but Server.jks not contains nt-gateway.cert
     */
    private HttpClient getSSLHttpClientWithUnknownUserCertificate() throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, KeyManagementException, UnrecoverableKeyException {
        String userKeyStoreNB = "C:/Users/Nils-NB/Google Drive/MHP/coding-challenges/" +
                "Backend/security/src/main/resources/nt-gateway.jks";
        return getHttpClient(GATEWAY_KEY_STORE);
    }

    private HttpClient getHttpClient(String adminKeySTore) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException,
            KeyManagementException, UnrecoverableKeyException {

        //KeyStore for Client
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(adminKeySTore), KEY_PASSPHRASE.toCharArray());
        // TrustStore for Client
        KeyStore myTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        myTrustStore.load(new FileInputStream(adminKeySTore), KEY_PASSPHRASE.toCharArray());

        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(new SSLContextBuilder()
                .loadTrustMaterial(myTrustStore, new TrustSelfSignedStrategy())
                .loadKeyMaterial(keyStore, KEY_PASSPHRASE.toCharArray()).build(),
                NoopHostnameVerifier.INSTANCE);

        return HttpClients.custom().setSSLSocketFactory(socketFactory).build();
    }
}
