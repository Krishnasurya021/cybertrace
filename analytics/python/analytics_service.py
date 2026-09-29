#!/usr/bin/env python3
"""
SENTINEL — Universal Authentication Security & Access Log Monitoring Platform
Module: Python Statistical Analytics Microservice
Provides /analytics/analyze endpoint for SIEM / SOC anomaly inference.

SECURITY PRINCIPLE:
Strictly sanitizes input. NEVER accepts, processes, or returns passwords.
"""

import math
import json
from typing import Dict, List, Any

def compute_statistics(values: List[float]) -> Dict[str, float]:
    """Calculates Mean, Median, and Bessel-corrected Sample Standard Deviation."""
    if not values:
        return {'mean': 0.0, 'median': 0.0, 'std_dev': 0.0, 'count': 0}
    
    n = len(values)
    mean_val = sum(values) / n
    
    # Median
    sorted_v = sorted(values)
    mid = n // 2
    median_val = (sorted_v[mid - 1] + sorted_v[mid]) / 2.0 if n % 2 == 0 else sorted_v[mid]
    
    # Std Dev
    if n > 1:
        variance = sum((x - mean_val) ** 2 for x in values) / (n - 1)
        std_val = math.sqrt(variance)
    else:
        std_val = 0.0
        
    return {
        'mean': round(mean_val, 2),
        'median': round(median_val, 2),
        'std_dev': round(std_val, 2),
        'count': n
    }

def analyze_event_statistics(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes sanitized authentication statistics and returns anomaly score,
    anomaly type, and detailed mathematical explanation.
    """
    # CRITICAL SECURITY GUARD
    forbidden_keys = {'password', 'pwd', 'pass', 'admin_password', 'secret'}
    if any(k.lower() in forbidden_keys for k in payload.keys()):
        raise ValueError("Security Policy Violation: Passwords must NEVER be sent to SENTINEL Analytics.")

    observed_metric = float(payload.get('observed_value', 0))
    metric_name = payload.get('metric_name', 'FAILURE_FREQUENCY')
    baseline_samples = [float(x) for x in payload.get('baseline_samples', [])]
    entity_id = payload.get('entity_id', 'UNKNOWN_ENTITY')

    if not baseline_samples:
        # Default fallback baselines if none provided
        baseline_samples = [1.0, 2.0, 1.0, 3.0, 2.0, 1.0, 4.0, 2.0]

    stats = compute_statistics(baseline_samples)
    mean = stats['mean']
    std_dev = stats['std_dev']

    if std_dev > 0:
        z_score = round((observed_metric - mean) / std_dev, 2)
    else:
        z_score = 0.0

    # Calculate Anomaly Score (0 to 100)
    anomaly_score = min(100, max(0, int(abs(z_score) * 25)))
    
    # Anomaly classification
    if abs(z_score) >= 3.5:
        anomaly_type = 'CRITICAL_STATISTICAL_OUTLIER'
        explanation = f"Extreme deviation: observed {observed_metric} for {entity_id} is {abs(z_score)} standard deviations from mean ({mean})."
    elif abs(z_score) >= 2.5:
        anomaly_type = 'SIGNIFICANT_STATISTICAL_SPIKE'
        explanation = f"Statistically significant anomaly: observed {observed_metric} ({abs(z_score)}σ above mean baseline of {mean})."
    elif abs(z_score) >= 1.8:
        anomaly_type = 'MODERATE_VARIANCE'
        explanation = f"Moderate deviation from baseline: observed {observed_metric} (z-score: {z_score})."
    else:
        anomaly_type = 'NORMAL_VARIANCE'
        explanation = f"Observed metric {observed_metric} conforms to standard historical baseline."

    return {
        'entity_id': entity_id,
        'metric_name': metric_name,
        'observed_value': observed_metric,
        'baseline_statistics': stats,
        'z_score': z_score,
        'anomaly_score': anomaly_score,
        'anomaly_type': anomaly_type,
        'explanation': explanation
    }

if __name__ == '__main__':
    sample_req = {
        'entity_id': '192.0.2.10',
        'metric_name': 'FAILURE_BURST',
        'observed_value': 14,
        'baseline_samples': [1, 2, 0, 1, 3, 2, 1, 2, 0, 1]
    }
    result = analyze_event_statistics(sample_req)
    print("=== Python Analytics Microservice Test ===")
    print(json.dumps(result, indent=2))
