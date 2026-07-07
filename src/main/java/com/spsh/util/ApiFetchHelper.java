package com.spsh.util;

import java.io.IOException;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;

import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;

import org.apache.hc.core5.util.Timeout;
import org.json.JSONObject;

public class ApiFetchHelper {

    public static final String ENV_KEY_INTERNAL_COMMUNICATION_API_KEY = "INTERNAL_COMMUNICATION_API_KEY";

    public static String fetchApiData(String url, String userSub) throws IOException {

        String apiKey = System.getenv(ENV_KEY_INTERNAL_COMMUNICATION_API_KEY);
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IOException(String.format("Environment variable %s is not set or is empty.",
                    ENV_KEY_INTERNAL_COMMUNICATION_API_KEY));
        }

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost request = new HttpPost(url);
            request.setHeader("Content-Type", "application/json");
            request.setHeader("api-key", apiKey);
            StringEntity requestBody = new StringEntity(String.format("{\"sub\":\"%s\"}", userSub));
            request.setEntity(requestBody);

            return httpClient.execute(request, response -> {
                int statusCode = response.getCode();
                if (statusCode >= 200 && statusCode < 300) {
                    HttpEntity entity = response.getEntity();
                    return entity != null ? EntityUtils.toString(entity) : null;
                } else {
                    throw new IOException("Unexpected response status: " + statusCode);
                }
            });
        }
    }

    public static String fetchApiData(final String url,
                                      final String body,
                                      final int timeoutMs) throws IOException {
        final var apiKey = System.getenv(ENV_KEY_INTERNAL_COMMUNICATION_API_KEY);
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IOException(String.format("Environment variable %s is not set or is empty.",
                    ENV_KEY_INTERNAL_COMMUNICATION_API_KEY));
        }

        final var requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.ofMilliseconds(timeoutMs))
                .setResponseTimeout(Timeout.ofMilliseconds(timeoutMs))
                .build();

        try (final var httpClient = HttpClients.custom().setDefaultRequestConfig(requestConfig).build()) {
            final var request = new HttpPost(url);
            request.setHeader("Content-Type", "application/json");
            request.setHeader("api-key", apiKey);
            request.setEntity(new StringEntity(body));

            return httpClient.execute(request, response -> {
                int statusCode = response.getCode();
                if (statusCode >= 200 && statusCode < 300) {
                    final var entity = response.getEntity();

                    if (entity == null) {
                        throw new IOException("Couldn't fetch data from server");
                    }

                    return EntityUtils.toString(entity);
                } else {
                    throw new IOException("Unexpected response status: " + statusCode);
                }
            });
        }
    }

    public static String getTokenDataBody(final String keycloakUserId) {
        JSONObject payloadObj = new JSONObject();
        payloadObj.put("keycloakUserId", keycloakUserId);

        return payloadObj.toString();
    }

    public static String getRoleDataBody(final String keycloakUserId, String clientName) {
        JSONObject payloadObj = new JSONObject();
        payloadObj.put("keycloakUserId", keycloakUserId);
        payloadObj.put("clientName", clientName);

        return payloadObj.toString();
    }
}