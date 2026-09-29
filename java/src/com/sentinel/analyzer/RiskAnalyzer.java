package com.sentinel.analyzer;

import com.sentinel.models.AuthenticationEvent;
import com.sentinel.models.RiskScore;

import java.util.HashMap;
import java.util.Map;

/**
 * SENTINEL OOPJ - RiskAnalyzer
 * Evaluates multi-signal risk scores and patterns for authentication events.
 * Demonstrates Strategy Pattern, Encapsulation, and Polymorphic Behavior.
 */
public class RiskAnalyzer {

    private final Map<String, Integer> weights;

    public RiskAnalyzer() {
        this.weights = new HashMap<>();
        // Default weights matching SENTINEL spec
        weights.put("single_failure", 10);
        weights.put("unknown_account", 10);
        weights.put("mfa_failure", 20);
        weights.put("failed_attempts_5", 25);
        weights.put("multiple_usernames_4", 35);
        weights.put("high_frequency_10", 25);
        weights.put("restricted_resource", 30);
        weights.put("previous_high_risk", 30);
        weights.put("brute_force_success", 35);
    }

    public void setWeight(String key, int weight) {
        weights.put(key, Math.max(0, Math.min(100, weight)));
    }

    public RiskScore analyze(AuthenticationEvent event, int recentFails, int distinctUsers, int freq1m, boolean priorRisk) {
        int baseScore = 5;
        int resultPenalty = 0;
        int failedAttemptsPenalty = 0;
        int unknownAccountPenalty = 0;
        int usernameVarietyPenalty = 0;
        int frequencyPenalty = 0;
        int resourcePenalty = 0;
        int previousRiskPenalty = 0;

        String res = event.getAuthenticationResult();

        // 1. Result penalty
        if ("FAILURE".equalsIgnoreCase(res)) {
            resultPenalty = weights.getOrDefault("single_failure", 10);
        } else if ("UNKNOWN_ACCOUNT".equalsIgnoreCase(res)) {
            unknownAccountPenalty = weights.getOrDefault("unknown_account", 10);
        } else if ("MFA_FAILURE".equalsIgnoreCase(res)) {
            resultPenalty = weights.getOrDefault("mfa_failure", 20);
        }

        // 2. Failed attempts velocity
        if (recentFails >= 5) {
            failedAttemptsPenalty = weights.getOrDefault("failed_attempts_5", 25);
        }

        // 3. Username variety (Account Enumeration)
        if (distinctUsers >= 4) {
            usernameVarietyPenalty = weights.getOrDefault("multiple_usernames_4", 35);
        }

        // 4. Request frequency
        if (freq1m >= 10) {
            frequencyPenalty = weights.getOrDefault("high_frequency_10", 25);
        }

        // 5. Restricted resource
        String r = event.getResource() != null ? event.getResource().toLowerCase() : "";
        if (r.contains("admin") || r.contains("root") || r.contains("keys")) {
            resourcePenalty = weights.getOrDefault("restricted_resource", 30);
        }

        // 6. Prior high risk
        if (priorRisk) {
            previousRiskPenalty = weights.getOrDefault("previous_high_risk", 30);
        }

        int totalScore = Math.min(100, Math.max(0, baseScore + resultPenalty + failedAttemptsPenalty +
                unknownAccountPenalty + usernameVarietyPenalty + frequencyPenalty + resourcePenalty + previousRiskPenalty));

        String level;
        String status;
        if (totalScore >= 75) {
            level = "CRITICAL";
            status = "CRITICAL_ALERT";
        } else if (totalScore >= 50) {
            level = "HIGH";
            status = "ALERT";
        } else if (totalScore >= 25) {
            level = "MEDIUM";
            status = "SUSPICIOUS";
        } else {
            level = "LOW";
            status = "SUCCESS".equalsIgnoreCase(res) ? "SAFE" : "MONITORING";
        }

        event.setRiskScore(totalScore);
        event.setRiskLevel(level);
        event.setStatus(status);

        return new RiskScore(
                0, event.getEventId(), event.getApplicationId(),
                resultPenalty, failedAttemptsPenalty, unknownAccountPenalty,
                usernameVarietyPenalty, frequencyPenalty, resourcePenalty,
                previousRiskPenalty, totalScore, level
        );
    }
}
