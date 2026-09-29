package com.sentinel.models;

import java.time.LocalDateTime;

/**
 * SENTINEL OOPJ - RiskScore
 * Detailed multi-signal mathematical breakdown of a calculated risk score.
 */
public class RiskScore {
    private final int scoreId;
    private final int eventId;
    private final String applicationId;
    private final int resultPenalty;
    private final int failedAttemptsPenalty;
    private final int unknownAccountPenalty;
    private final int usernameVarietyPenalty;
    private final int frequencyPenalty;
    private final int resourcePenalty;
    private final int previousRiskPenalty;
    private final int totalScore;
    private final String riskLevel;
    private final LocalDateTime calculatedAt;

    public RiskScore(int scoreId, int eventId, String applicationId,
                     int resultPenalty, int failedAttemptsPenalty, int unknownAccountPenalty,
                     int usernameVarietyPenalty, int frequencyPenalty, int resourcePenalty,
                     int previousRiskPenalty, int totalScore, String riskLevel) {
        this.scoreId = scoreId;
        this.eventId = eventId;
        this.applicationId = applicationId;
        this.resultPenalty = resultPenalty;
        this.failedAttemptsPenalty = failedAttemptsPenalty;
        this.unknownAccountPenalty = unknownAccountPenalty;
        this.usernameVarietyPenalty = usernameVarietyPenalty;
        this.frequencyPenalty = frequencyPenalty;
        this.resourcePenalty = resourcePenalty;
        this.previousRiskPenalty = previousRiskPenalty;
        this.totalScore = totalScore;
        this.riskLevel = riskLevel;
        this.calculatedAt = LocalDateTime.now();
    }

    public int getScoreId() { return scoreId; }
    public int getEventId() { return eventId; }
    public String getApplicationId() { return applicationId; }
    public int getResultPenalty() { return resultPenalty; }
    public int getFailedAttemptsPenalty() { return failedAttemptsPenalty; }
    public int getUnknownAccountPenalty() { return unknownAccountPenalty; }
    public int getUsernameVarietyPenalty() { return usernameVarietyPenalty; }
    public int getFrequencyPenalty() { return frequencyPenalty; }
    public int getResourcePenalty() { return resourcePenalty; }
    public int getPreviousRiskPenalty() { return previousRiskPenalty; }
    public int getTotalScore() { return totalScore; }
    public String getRiskLevel() { return riskLevel; }
    public LocalDateTime getCalculatedAt() { return calculatedAt; }

    @Override
    public String toString() {
        return String.format("RiskScore[total=%d, level=%s, penalties=(res:%d, fails:%d, unk:%d, users:%d, freq:%d)]",
                totalScore, riskLevel, resultPenalty, failedAttemptsPenalty, unknownAccountPenalty, usernameVarietyPenalty, frequencyPenalty);
    }
}
