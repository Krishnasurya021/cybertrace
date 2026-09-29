package com.sentinel.analyzer;

import com.sentinel.models.Alert;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * OOP Principle: SINGLE RESPONSIBILITY PRINCIPLE (SRP)
 * Formats and generates structured security intelligence reports.
 */
public class ReportGenerator {

    public static String generateTextReport(LogAnalyzer analyzer) {
        StringBuilder sb = new StringBuilder();
        sb.append("=================================================================\n");
        sb.append("SENTINEL SOC - EXECUTIVE SECURITY INTELLIGENCE REPORT\n");
        sb.append("Generated At: ").append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\n");
        sb.append("=================================================================\n\n");

        sb.append(String.format("Total Logs Analyzed: %d\n", analyzer.getLogs().size()));
        sb.append(String.format("Total Alerts Generated: %d\n", analyzer.getGeneratedAlerts().size()));

        // Count by risk
        long criticalCount = analyzer.getGeneratedAlerts().stream().filter(a -> "CRITICAL".equals(a.getRiskLevel())).count();
        long highCount = analyzer.getGeneratedAlerts().stream().filter(a -> "HIGH".equals(a.getRiskLevel())).count();
        long medCount = analyzer.getGeneratedAlerts().stream().filter(a -> "MEDIUM".equals(a.getRiskLevel())).count();

        sb.append(String.format("  - CRITICAL: %d\n", criticalCount));
        sb.append(String.format("  - HIGH:     %d\n", highCount));
        sb.append(String.format("  - MEDIUM:   %d\n", medCount));

        sb.append("\nTop Failed Logins by IP Origin:\n");
        for (Map.Entry<String, Integer> entry : analyzer.getFailedLoginsByIP().entrySet()) {
            sb.append(String.format("  * IP %-18s -> %d failed attempts\n", entry.getKey(), entry.getValue()));
        }

        sb.append("\nRecent Security Incidents:\n");
        List<Alert> alerts = analyzer.getGeneratedAlerts();
        for (int i = 0; i < Math.min(5, alerts.size()); i++) {
            Alert a = alerts.get(i);
            sb.append(String.format("  [%s] #%d: %s\n        %s\n", 
                a.getRiskLevel(), a.getAlertId(), a.getTitle(), a.getDescription()));
        }

        sb.append("\n========================= END OF REPORT =========================\n");
        return sb.toString();
    }
}
