package com.mhp.coding.challenges.auth.inbound;

import lombok.SneakyThrows;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.junit.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;

public class DoorControllerTest2 {

    private static final String DOOR_TO_CHANGE = "{\"id\":1,\"state\":\"UNLOCKED\"}";

    @SneakyThrows
    @Test
    public void test_get_all_doors() throws Exception {
        // #Arrange
        HttpGet request = new HttpGet("http://127.0.0.1:8090/v1/door");

        // #Act
        CloseableHttpClient httpClient = HttpClientBuilder.create()
                .build();
        CloseableHttpResponse response = httpClient.execute(request);

        // #Assert
        assertEquals(403, response.getStatusLine().getStatusCode());
    }

    @Test
    public void test_change_door_state() throws Exception {
        // #Arrange
        HttpPost request = new HttpPost("http://127.0.0.1:8090/v1/door");
        request.addHeader("content-type", "application/json");
        StringEntity jsonEntity = new StringEntity(DOOR_TO_CHANGE);
        request.setEntity(jsonEntity);

        // #Act
        CloseableHttpClient httpClient = HttpClientBuilder.create()
                .build();
        CloseableHttpResponse response = httpClient.execute(request);

        // #Assert
        assertEquals(403, response.getStatusLine().getStatusCode());
    }
}
