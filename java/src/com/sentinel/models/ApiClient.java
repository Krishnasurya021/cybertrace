package com.sentinel.models;

import java.time.LocalDateTime;

/**
 * SENTINEL OOPJ - ApiClient Entity
 * Encapsulates cryptographic API credentials for connected applications.
 * Ensures API secrets are hashed and never exposed in cleartext.
 */
public class ApiClient {
    private final int clientId;
    private final String applicationId;
    private final String apiKey;
    private final String apiSecretHash;
    private final String apiSecretPreview; // e.g. "sec_live_...2b5e"
    private boolean isActive;
    private final LocalDateTime createdAt;
    private LocalDateTime lastUsedAt;

    public ApiClient(int clientId, String applicationId, String apiKey, String apiSecretHash, String apiSecretPreview) {
        this.clientId = clientId;
        this.applicationId = applicationId;
        this.apiKey = apiKey;
        this.apiSecretHash = apiSecretHash;
        this.apiSecretPreview = apiSecretPreview;
        this.isActive = true;
        this.createdAt = LocalDateTime.now();
    }

    public int getClientId() { return clientId; }
    public String getApplicationId() { return applicationId; }
    public String getApiKey() { return apiKey; }
    public String getApiSecretHash() { return apiSecretHash; }
    public String getApiSecretPreview() { return apiSecretPreview; }
    public boolean isActive() { return isActive; }
    public void setActive(boolean active) { isActive = active; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getLastUsedAt() { return lastUsedAt; }
    public void markUsed() { this.lastUsedAt = LocalDateTime.now(); }

    @Override
    public String toString() {
        return String.format("ApiClient[app=%s, key='%s', preview='%s', active=%s]",
                applicationId, apiKey, apiSecretPreview, isActive);
    }
}
