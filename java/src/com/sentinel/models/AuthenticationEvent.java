package com.sentinel.models;

import java.time.LocalDateTime;

/**
 * SENTINEL OOPJ - AuthenticationEvent
 * Represents an ingested authentication event metadata packet.
 * 
 * STRICT ARCHITECTURAL PRINCIPLE:
 * SENTINEL NEVER requests, receives, stores, or processes passwords.
 * This class has NO password fields by design.
 */
public class AuthenticationEvent {
    private final int eventId;
    private final String applicationId;
    private final LocalDateTime timestamp;
    private final String usernameIdentifier;
    private final String eventType;              // LOGIN_ATTEMPT, MFA_CHALLENGE, etc.
    private final String authenticationResult;  // SUCCESS, FAILURE, UNKNOWN_ACCOUNT, LOCKED_ACCOUNT, MFA_FAILURE, etc.
    private final String sourceIp;
    private final String deviceType;
    private final String userAgent;
    private final String resource;
    private final String sessionId;
    
    // Evaluated by Risk Engine
    private String riskLevel;   // LOW, MEDIUM, HIGH, CRITICAL
    private int riskScore;      // 0 to 100
    private String status;      // SAFE, MONITORING, SUSPICIOUS, ALERT, CRITICAL_ALERT
    private String failureReason;
    private String triggeredRules; // JSON array string

    public AuthenticationEvent(int eventId, String applicationId, LocalDateTime timestamp,
                               String usernameIdentifier, String eventType, String authenticationResult,
                               String sourceIp, String deviceType, String userAgent, String resource,
                               String sessionId) {
        this.eventId = eventId;
        this.applicationId = applicationId;
        this.timestamp = timestamp != null ? timestamp : LocalDateTime.now();
        this.usernameIdentifier = usernameIdentifier;
        this.eventType = eventType != null ? eventType : "LOGIN_ATTEMPT";
        this.authenticationResult = authenticationResult;
        this.sourceIp = sourceIp;
        this.deviceType = deviceType != null ? deviceType : "Desktop";
        this.userAgent = userAgent != null ? userAgent : "Unknown Browser";
        this.resource = resource != null ? resource : "/login";
        this.sessionId = sessionId;
        this.riskLevel = "LOW";
        this.riskScore = 5;
        this.status = "SAFE";
    }

    public int getEventId() { return eventId; }
    public String getApplicationId() { return applicationId; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getUsernameIdentifier() { return usernameIdentifier; }
    public String getEventType() { return eventType; }
    public String getAuthenticationResult() { return authenticationResult; }
    public String getSourceIp() { return sourceIp; }
    public String getDeviceType() { return deviceType; }
    public String getUserAgent() { return userAgent; }
    public String getResource() { return resource; }
    public String getSessionId() { return sessionId; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }
    public String getTriggeredRules() { return triggeredRules; }
    public void setTriggeredRules(String triggeredRules) { this.triggeredRules = triggeredRules; }

    @Override
    public String toString() {
        return String.format("AuthenticationEvent[#%d, app=%s, user=%s, res=%s, ip=%s, risk=%s(%d)]",
                eventId, applicationId, usernameIdentifier, authenticationResult, sourceIp, riskLevel, riskScore);
    }
}
