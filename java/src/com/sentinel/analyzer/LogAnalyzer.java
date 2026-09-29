package com.sentinel.analyzer;

import com.sentinel.models.*;
import com.sentinel.strategies.AnomalyDetectionStrategy;
import java.util.*;

/**
 * OOP Principle: COMPOSITION, COLLECTIONS & STRATEGY EXECUTION
 * Coordinates log ingestion, anomaly detector invocation, and telemetry aggregation.
 */
public class LogAnalyzer {
    private List<AccessLog> logs;
    private List<Alert> generatedAlerts;
    private AnomalyDetectionStrategy detectionStrategy;

    public LogAnalyzer(AnomalyDetectionStrategy detectionStrategy) {
        this.logs = new ArrayList<>();
        this.generatedAlerts = new ArrayList<>();
        this.detectionStrategy = detectionStrategy;
    }

    public void addLog(AccessLog log) {
        this.logs.add(log);
    }

    public void addLogs(List<AccessLog> newLogs) {
        this.logs.addAll(newLogs);
    }

    /**
     * Polymorphic Strategy Switch
     */
    public void setDetectionStrategy(AnomalyDetectionStrategy strategy) {
        this.detectionStrategy = strategy;
    }

    public List<Alert> runAnalysis() {
        System.out.println("Executing Anomaly Strategy: " + detectionStrategy.getDetectorName());
        List<Alert> newAlerts = detectionStrategy.detect(this.logs);
        this.generatedAlerts.addAll(newAlerts);
        return newAlerts;
    }

    /**
     * Demonstrates Collections Sorting: Sort logs by timestamp descending or failed attempts
     */
    public List<AccessLog> getLogsSortedByFailedAttempts() {
        List<AccessLog> sortedList = new ArrayList<>(logs);
        sortedList.sort((a, b) -> Integer.compare(b.getFailedAttempts(), a.getFailedAttempts()));
        return sortedList;
    }

    public Map<String, Integer> getFailedLoginsByIP() {
        Map<String, Integer> failMap = new HashMap<>();
        for (AccessLog log : logs) {
            if (log.isFailed()) {
                String ip = log.getIpAddress().getIpAddress();
                failMap.put(ip, failMap.getOrDefault(ip, 0) + 1);
            }
        }
        return failMap;
    }

    public List<AccessLog> getLogs() { return logs; }
    public List<Alert> getGeneratedAlerts() { return generatedAlerts; }
}
