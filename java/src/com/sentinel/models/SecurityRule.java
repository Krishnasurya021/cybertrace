package com.sentinel.models;

/**
 * OOP Principle: ENCAPSULATION
 * Represents a security rule derived from DMGT propositional logic.
 */
public class SecurityRule {
    private int ruleId;
    private String ruleCode;
    private String ruleName;
    private String description;
    private String logicalExpression;
    private String riskLevel; // LOW, MEDIUM, HIGH, CRITICAL

    public SecurityRule(int ruleId, String ruleCode, String ruleName, String description, String logicalExpression, String riskLevel) {
        this.ruleId = ruleId;
        this.ruleCode = ruleCode;
        this.ruleName = ruleName;
        this.description = description;
        this.logicalExpression = logicalExpression;
        this.riskLevel = riskLevel;
    }

    public int getRuleId() { return ruleId; }
    public String getRuleCode() { return ruleCode; }
    public String getRuleName() { return ruleName; }
    public String getDescription() { return description; }
    public String getLogicalExpression() { return logicalExpression; }
    public String getRiskLevel() { return riskLevel; }

    @Override
    public String toString() {
        return String.format("Rule[%s (%s): %s]", ruleCode, riskLevel, logicalExpression);
    }
}
