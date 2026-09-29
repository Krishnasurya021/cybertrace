#!/usr/bin/env python3
"""
SENTINEL — Universal Authentication Security & Access Log Monitoring Platform
Module: Python Statistical Anomaly Detector
Implements formal statistical anomaly detection on cybersecurity authentication logs.
Calculates Mean, Median, Standard Deviation, and Z-Scores to flag statistical outliers.

Mathematical Formulation:
1. Sample Mean (μ): μ = (1 / N) * Σ x_i
2. Sample Standard Deviation (σ): σ = sqrt( (1 / (N - 1)) * Σ (x_i - μ)^2 )
3. Sample Median: middle value of sorted distribution
4. Z-Score (Standardized Metric): z = (x - μ) / σ

IMPORTANT SECURITY GUARANTEE:
Zero passwords involved. Evaluates authentication event statistics only.
"""

import sys
import os
import math
import json
import sqlite3
import argparse
from typing import List, Dict, Any, Tuple

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'sentinel.db')

def calculate_mean(values: List[float]) -> float:
    """Calculates sample arithmetic mean."""
    if not values:
        return 0.0
    return sum(values) / len(values)

def calculate_median(values: List[float]) -> float:
    """Calculates sample median."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    mid = n // 2
    if n % 2 == 0:
        return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0
    return sorted_vals[mid]

def calculate_std_dev(values: List[float], mean: float) -> float:
    """Calculates sample standard deviation (with Bessel's correction N-1)."""
    if len(values) < 2:
        return 0.0
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)

def calculate_z_score(value: float, mean: float, std_dev: float) -> float:
    """Calculates standard Z-score: (value - mean) / std_dev."""
    if std_dev == 0:
        return 0.0
    return (value - mean) / std_dev

class StatisticalAnomalyDetector:
    """
    Computes statistical baselines for authentication patterns and detects anomalies.
    """
    def __init__(self, z_threshold: float = 2.2):
        self.z_threshold = z_threshold

    def analyze_database_logs(self, conn: sqlite3.Connection) -> Dict[str, Any]:
        cursor = conn.cursor()

        # 1. Failed Login Counts per Source IP
        ip_fail_rows = cursor.execute("""
            SELECT source_ip, COUNT(event_id) as fail_count
            FROM authentication_events
            WHERE authentication_result IN ('FAILURE', 'UNKNOWN_ACCOUNT', 'MFA_FAILURE')
            GROUP BY source_ip
        """).fetchall()

        fail_counts = [float(r[1]) for r in ip_fail_rows]
        mean_fails = calculate_mean(fail_counts)
        median_fails = calculate_median(fail_counts)
        std_fails = calculate_std_dev(fail_counts, mean_fails)

        # 2. Session Durations (seconds)
        session_rows = cursor.execute("""
            SELECT session_id, username_identifier, duration_seconds
            FROM sessions
            WHERE duration_seconds > 0
        """).fetchall()

        durations = [float(r[2]) for r in session_rows]
        mean_dur = calculate_mean(durations)
        median_dur = calculate_median(durations)
        std_dur = calculate_std_dev(durations, mean_dur)

        # 3. Request Volumes per User
        user_req_rows = cursor.execute("""
            SELECT username_identifier, COUNT(event_id) as total_reqs
            FROM authentication_events
            GROUP BY username_identifier
        """).fetchall()

        user_reqs = [float(r[1]) for r in user_req_rows]
        mean_user_reqs = calculate_mean(user_reqs)
        median_user_reqs = calculate_median(user_reqs)
        std_user_reqs = calculate_std_dev(user_reqs, mean_user_reqs)

        # 4. Hourly Distribution (0-23 hours)
        hourly_rows = cursor.execute("""
            SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hr, COUNT(*) as count
            FROM authentication_events
            GROUP BY hr
            ORDER BY hr ASC
        """).fetchall()

        hourly_counts = [float(r[1]) for r in hourly_rows]
        mean_hourly = calculate_mean(hourly_counts)
        std_hourly = calculate_std_dev(hourly_counts, mean_hourly)

        anomalies = []

        # Check Failed Logins per IP
        for r in ip_fail_rows:
            ip_addr, count = r[0], float(r[1])
            z = calculate_z_score(count, mean_fails, std_fails)
            if abs(z) >= self.z_threshold:
                risk = 'CRITICAL' if abs(z) >= 3.5 else ('HIGH' if abs(z) >= 2.8 else 'MEDIUM')
                anomalies.append({
                    'dimension': 'FAILED_LOGIN_BURST',
                    'entity_type': 'IP_ADDRESS',
                    'entity_name': ip_addr,
                    'observed_value': count,
                    'mean': round(mean_fails, 2),
                    'median': round(median_fails, 2),
                    'std_dev': round(std_fails, 2),
                    'z_score': round(z, 2),
                    'risk_level': risk,
                    'explanation': f"Source IP {ip_addr} logged {int(count)} failures ({abs(z):.2f}σ above mean baseline of {mean_fails:.1f})."
                })

        # Check User Request Velocity
        for r in user_req_rows:
            uname, count = r[0], float(r[1])
            z = calculate_z_score(count, mean_user_reqs, std_user_reqs)
            if abs(z) >= self.z_threshold:
                risk = 'HIGH' if abs(z) >= 2.8 else 'MEDIUM'
                anomalies.append({
                    'dimension': 'REQUEST_VELOCITY_ANOMALY',
                    'entity_type': 'USER_IDENTIFIER',
                    'entity_name': uname,
                    'observed_value': count,
                    'mean': round(mean_user_reqs, 2),
                    'median': round(median_user_reqs, 2),
                    'std_dev': round(std_user_reqs, 2),
                    'z_score': round(z, 2),
                    'risk_level': risk,
                    'explanation': f"Account identifier {uname} generated {int(count)} authentication attempts ({abs(z):.2f}σ above mean baseline of {mean_user_reqs:.1f})."
                })

        return {
            'threshold_applied': self.z_threshold,
            'total_anomalies_flagged': len(anomalies),
            'baselines': {
                'failed_logins_per_ip': {
                    'mean': round(mean_fails, 2),
                    'median': round(median_fails, 2),
                    'std_dev': round(std_fails, 2),
                    'sample_size': len(fail_counts)
                },
                'session_duration_seconds': {
                    'mean': round(mean_dur, 2),
                    'median': round(median_dur, 2),
                    'std_dev': round(std_dur, 2),
                    'sample_size': len(durations)
                },
                'requests_per_user': {
                    'mean': round(mean_user_reqs, 2),
                    'median': round(median_user_reqs, 2),
                    'std_dev': round(std_user_reqs, 2),
                    'sample_size': len(user_reqs)
                },
                'hourly_events': {
                    'mean': round(mean_hourly, 2),
                    'std_dev': round(std_hourly, 2)
                }
            },
            'anomalies': anomalies
        }

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SENTINEL Statistical Anomaly Detector')
    parser.add_argument('--threshold', type=float, default=2.2, help='Z-score threshold')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    args = parser.parse_args()

    conn = sqlite3.connect(DB_PATH)
    detector = StatisticalAnomalyDetector(z_threshold=args.threshold)
    res = detector.analyze_database_logs(conn)
    conn.close()

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print("=== SENTINEL Statistical Anomaly Detection Results ===")
        print(f"Threshold: |z| >= {res['threshold_applied']}")
        print(f"Total Anomalies Flagged: {res['total_anomalies_flagged']}")
        for a in res['anomalies']:
            print(f"  [{a['risk_level']}] {a['dimension']}: {a['entity_name']} -> z={a['z_score']} ({a['explanation']})")
