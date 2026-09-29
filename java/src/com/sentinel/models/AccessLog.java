package com.sentinel.models;

import java.time.LocalDateTime;

/**
 * OOP Principle: ENCAPSULATION
 * Represents an individual access telemetry log event.
 */
public class AccessLog {
    private int logId;
    private Session session;
    private User user;
    private IPAddress ipAddress;
    private Resource resource;
    private LocalDateTime timestamp;
    private String httpMethod;
    private String action;
    private String status; // SUCCESS, FAILED, BLOCKED
    private int failedAttempts;
    private int responseCode;
    private int responseTimeMs;

    public AccessLog(int logId, Session session, User user, IPAddress ipAddress, Resource resource, 
                     LocalDateTime timestamp, String httpMethod, String action, String status, 
                     int failedAttempts, int responseCode, int responseTimeMs) {
        this.logId = logId;
        this.session = session;
        this.user = user;
        this.ipAddress = ipAddress;
        this.resource = resource;
        this.timestamp = timestamp;
        this.httpMethod = httpMethod;
        this.action = action;
        this.status = status;
        this.failedAttempts = failedAttempts;
        this.responseCode = responseCode;
        this.responseTimeMs = responseTimeMs;
    }

    public int getLogId() { return logId; }
    public Session getSession() { return session; }
    public User getUser() { return user; }
    public IPAddress getIpAddress() { return ipAddress; }
    public Resource getResource() { return resource; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getHttpMethod() { return httpMethod; }
    public String getAction() { return action; }
    public String getStatus() { return status; }
    public int getFailedAttempts() { return failedAttempts; }
    public int getResponseCode() { return responseCode; }
    public int getResponseTimeMs() { return responseTimeMs; }

    public boolean isFailed() {
        return "FAILED".equalsIgnoreCase(status) || "BLOCKED".equalsIgnoreCase(status);
    }

    @Override
    public String toString() {
        return String.format("Log[%d: %s | User=%s | IP=%s | Res=%s | Status=%s | Failed=%d]",
            logId, timestamp, user.getUsername(), ipAddress.getIpAddress(), resource.getPath(), status, failedAttempts);
    }
}
