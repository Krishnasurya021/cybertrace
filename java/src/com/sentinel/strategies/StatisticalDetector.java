package com.sentinel.strategies;

import com.sentinel.models.*;
import java.util.*;

/**
 * OOP Principle: POLYMORPHISM & INTERFACE IMPLEMENTATION
 * Statistical Anomaly Detector calculating Mean, Standard Deviation, and Z-Score in Java.
 */
public class StatisticalDetector implements AnomalyDetectionStrategy {
    private double zThreshold;
    private int alertSequence = 2000;

    public StatisticalDetector(double zThreshold) {
        this.zThreshold = zThreshold;
    }

    @Override
    public List<Alert> detect(List<AccessLog> logs) {
        List<Alert> alerts = new ArrayList<>();
        if (logs.isEmpty()) return alerts;

        // 1. Group failed logins by IP address
        Map<String, Integer> ipFailureCounts = new HashMap<>();
        Map<String, List<AccessLog>> ipLogsMap = new HashMap<>();

        for (AccessLog log : logs) {
            String ip = log.getIpAddress().getIpAddress();
            ipLogsMap.computeIfAbsent(ip, k -> new ArrayList<>()).add(log);
            if (log.isFailed()) {
                ipFailureCounts.put(ip, ipFailureCounts.getOrDefault(ip, 0) + 1);
            }
        }

        // 2. Compute Mean and Standard Deviation
        List<Integer> counts = new ArrayList<>(ipFailureCounts.values());
        if (counts.size() < 2) return alerts;

        double sum = 0;
        for (int c : counts) sum += c;
        double mean = sum / counts.size();

        double varianceSum = 0;
        for (int c : counts) {
            varianceSum += Math.pow(c - mean, 2);
        }
        double stdDev = Math.sqrt(varianceSum / (counts.size() - 1));

        if (stdDev == 0) return alerts;

        // 3. Compute Z-Scores and generate alerts
        for (Map.Entry<String, Integer> entry : ipFailureCounts.entrySet()) {
            double zScore = (entry.getValue() - mean) / stdDev;
            if (zScore >= zThreshold) {
                String risk = (zScore >= 3.5) ? "CRITICAL" : "HIGH";
                AccessLog representativeLog = ipLogsMap.get(entry.getKey()).get(0);
                SecurityRule statRule = new SecurityRule(99, "STAT_ZSCORE_RULE", "Statistical Outlier Detection",
                    "Z-score exceeds configured standard deviation threshold", "|z| >= " + zThreshold, risk);

                alerts.add(new Alert(
                    ++alertSequence, representativeLog, statRule, risk,
                    "Statistical Anomaly: Outlier Failure Burst",
                    String.format("IP %s experienced %d failures (μ=%.1f, σ=%.1f, Z-Score=+%.2f). Exceeds |z|>=%.1f threshold.",
                        entry.getKey(), entry.getValue(), mean, stdDev, zScore, zThreshold)
                ));
            }
        }

        return alerts;
    }

    @Override
    public String getDetectorName() {
        return "Statistical Z-Score Detector";
    }
}
