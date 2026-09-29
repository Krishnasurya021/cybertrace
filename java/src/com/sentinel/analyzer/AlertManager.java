package com.sentinel.analyzer;

import com.sentinel.models.Alert;
import com.sentinel.models.AuthenticationEvent;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * SENTINEL OOPJ - AlertManager
 * Manages incident alerting lifecycle, dispatching, and investigation triage.
 * Uses Java Collections framework and Lambda Streams.
 */
public class AlertManager {
    private final List<Alert> alerts;
    private int alertSequence = 1;

    public AlertManager() {
        this.alerts = new ArrayList<>();
    }

    public Alert createAlertIfHighRisk(AuthenticationEvent event, String triggeredRulesJson, int failedAttempts, int accountsAttempted) {
        if (event.getRiskScore() < 50) {
            return null; // Only HIGH (>=50) and CRITICAL (>=75) trigger formal alerts
        }

        String title = event.getRiskScore() >= 75
                ? "CRITICAL: High-Risk Authentication Pattern Detected"
                : "SECURITY ALERT: Suspicious Authentication Activity";

        String desc = String.format("Origin %s triggered risk score %d/100 on application %s for identity '%s'.",
                event.getSourceIp(), event.getRiskScore(), event.getApplicationId(), event.getUsernameIdentifier());

        Alert alert = new Alert(
                alertSequence++,
                event.getEventId(),
                0, // user id mapping
                0, // ip id mapping
                1, // primary rule id
                event.getRiskLevel(),
                title,
                desc,
                "OPEN"
        );

        alerts.add(alert);
        return alert;
    }

    public List<Alert> getAllAlerts() {
        return Collections.unmodifiableList(alerts);
    }

    public List<Alert> getOpenAlerts() {
        return alerts.stream()
                .filter(a -> "OPEN".equalsIgnoreCase(a.getStatus()) || "INVESTIGATING".equalsIgnoreCase(a.getStatus()))
                .collect(Collectors.toList());
    }

    public void updateAlertStatus(int alertId, String newStatus, String notes) {
        for (Alert a : alerts) {
            if (a.getAlertId() == alertId) {
                a.setStatus(newStatus);
                a.setInvestigatorNotes(notes);
                if ("RESOLVED".equalsIgnoreCase(newStatus)) {
                    a.setResolvedAt(LocalDateTime.now());
                }
                break;
            }
        }
    }
}
