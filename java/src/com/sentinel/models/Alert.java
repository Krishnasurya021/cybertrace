package com.sentinel.models;

import java.time.LocalDateTime;

/**
 * OOP Principle: ENCAPSULATION
 * Represents an actionable cybersecurity incident or anomaly alert.
 */
public class Alert {
    private int alertId;
    private AccessLog log;
    private SecurityRule rule;
    private String riskLevel; // LOW, MEDIUM, HIGH, CRITICAL
    private String title;
    private String description;
    private String status; // OPEN, INVESTIGATING, RESOLVED
    private LocalDateTime createdAt;

    public Alert(int alertId, AccessLog log, SecurityRule rule, String riskLevel, String title, String description) {
        this.alertId = alertId;
        this.log = log;
        this.rule = rule;
        this.riskLevel = riskLevel;
        this.title = title;
        this.description = description;
        this.status = "OPEN";
        this.createdAt = LocalDateTime.now();
    }

    public int getAlertId() { return alertId; }
    public AccessLog getLog() { return log; }
    public SecurityRule getRule() { return rule; }
    public String getRiskLevel() { return riskLevel; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public LocalDateTime getCreatedAt() { return createdAt; }

    @Override
    public String toString() {
        return String.format("Alert[#%d | %s | %s | %s]", alertId, riskLevel, title, description);
    }
}
