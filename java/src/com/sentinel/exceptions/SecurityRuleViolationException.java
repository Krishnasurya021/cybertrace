package com.sentinel.exceptions;

/**
 * OOP Principle: EXCEPTION HANDLING (CHECKED EXCEPTION)
 * Thrown when an access log violates a hard security proposition or critical policy.
 */
public class SecurityRuleViolationException extends Exception {
    private String ruleCode;
    private String riskLevel;

    public SecurityRuleViolationException(String message, String ruleCode, String riskLevel) {
        super(message);
        this.ruleCode = ruleCode;
        this.riskLevel = riskLevel;
    }

    public String getRuleCode() {
        return ruleCode;
    }

    public String getRiskLevel() {
        return riskLevel;
    }
}
