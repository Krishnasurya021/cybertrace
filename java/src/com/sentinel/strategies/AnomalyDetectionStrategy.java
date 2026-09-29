package com.sentinel.strategies;

import com.sentinel.models.AccessLog;
import com.sentinel.models.Alert;
import java.util.List;

/**
 * OOP Principle: INTERFACE & STRATEGY PATTERN (ABSTRACTION & POLYMORPHISM)
 * Contract for interchangeable anomaly detection engines.
 */
public interface AnomalyDetectionStrategy {
    
    /**
     * Inspects a collection of access logs and produces security alerts.
     * @param logs Telemetry logs to analyze
     * @return List of generated alerts
     */
    List<Alert> detect(List<AccessLog> logs);

    /**
     * Returns human-readable name of the detector.
     */
    String getDetectorName();
}
