package com.sentinel.models;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * SENTINEL OOPJ - Application Entity
 * Demonstrates Encapsulation, Immutability patterns, and Collections.
 * Represents an external website, portal, or web application registered with SENTINEL.
 */
public class Application {
    private final String applicationId;
    private String name;
    private String url;
    private String appType;       // Website, Web Application, Mobile Application, API, Portal
    private String ownerEmail;
    private String environment;   // Production, Staging, Development
    private String status;        // ACTIVE, SUSPENDED, MAINTENANCE
    private final LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private final List<ApiClient> apiClients;

    public Application(String applicationId, String name, String url, String appType, String ownerEmail, String environment) {
        if (applicationId == null || applicationId.trim().isEmpty()) {
            throw new IllegalArgumentException("Application ID cannot be empty");
        }
        this.applicationId = applicationId;
        this.name = name;
        this.url = url;
        this.appType = appType;
        this.ownerEmail = ownerEmail;
        this.environment = environment != null ? environment : "Production";
        this.status = "ACTIVE";
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
        this.apiClients = new ArrayList<>();
    }

    public String getApplicationId() { return applicationId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; this.updatedAt = LocalDateTime.now(); }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; this.updatedAt = LocalDateTime.now(); }
    public String getAppType() { return appType; }
    public void setAppType(String appType) { this.appType = appType; }
    public String getOwnerEmail() { return ownerEmail; }
    public void setOwnerEmail(String ownerEmail) { this.ownerEmail = ownerEmail; }
    public String getEnvironment() { return environment; }
    public void setEnvironment(String environment) { this.environment = environment; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }

    public void addApiClient(ApiClient client) {
        if (client != null) {
            this.apiClients.add(client);
        }
    }

    public List<ApiClient> getApiClients() {
        return Collections.unmodifiableList(apiClients);
    }

    @Override
    public String toString() {
        return String.format("Application[id=%s, name='%s', type='%s', env='%s', status='%s']",
                applicationId, name, appType, environment, status);
    }
}
