package com.sentinel.strategies;

import com.sentinel.models.*;
import java.util.ArrayList;
import java.util.List;

/**
 * OOP Principle: POLYMORPHISM & INTERFACE IMPLEMENTATION
 * Rule-Based Anomaly Detector implementing DMGT propositional logic checks.
 */
public class RuleBasedDetector implements AnomalyDetectionStrategy {
    private List<SecurityRule> activeRules;
    private int alertSequence = 1000;

    public RuleBasedDetector() {
        this.activeRules = new ArrayList<>();
        // Default DMGT rules
        activeRules.add(new SecurityRule(1, "BRUTE_FORCE_RULE", "Brute Force Login", 
            "Triggered when failed attempts > 5", "failed_attempts > 5", "HIGH"));
        activeRules.add(new SecurityRule(4, "PRIVILEGE_VIOLATION_RULE", "Restricted Access", 
            "Triggered when non-admin accesses restricted asset", "restricted AND role != ADMIN", "HIGH"));
        activeRules.add(new SecurityRule(7, "CREDENTIAL_STUFFING_RULE", "Credential Stuffing", 
            "Triggered on multi-user proxy failure burst", "failed > 5 AND proxy = TRUE", "CRITICAL"));
    }

    @Override
    public List<Alert> detect(List<AccessLog> logs) {
        List<Alert> alerts = new ArrayList<>();

        for (AccessLog log : logs) {
            // Rule 1: Brute force check
            if (log.getFailedAttempts() > 5) {
                SecurityRule rule = activeRules.get(0);
                String risk = log.getIpAddress().isKnownProxy() ? "CRITICAL" : "HIGH";
                alerts.add(new Alert(
                    ++alertSequence, log, rule, risk, 
                    "Brute Force Attempt Detected",
                    String.format("User '%s' had %d consecutive failed login attempts from IP %s.", 
                        log.getUser().getUsername(), log.getFailedAttempts(), log.getIpAddress().getIpAddress())
                ));
            }

            // Rule 2: Restricted asset access check
            if (log.getResource().isRestricted() && !"ADMIN".equals(log.getUser().getRole())) {
                SecurityRule rule = activeRules.get(1);
                alerts.add(new Alert(
                    ++alertSequence, log, rule, "HIGH",
                    "Unauthorized Restricted Resource Probing",
                    String.format("Non-admin user '%s' (%s) attempted unauthorized access to restricted resource '%s'.",
                        log.getUser().getUsername(), log.getUser().getRole(), log.getResource().getPath())
                ));
            }
        }

        return alerts;
    }

    @Override
    public String getDetectorName() {
        return "DMGT Propositional Rule-Based Detector";
    }
}
