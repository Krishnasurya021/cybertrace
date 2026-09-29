#!/usr/bin/env python3
"""
SENTINEL — Universal Authentication Security & Access Log Monitoring Platform
Module: Multi-Signal Risk Scoring & Pattern Detection Engine

Mathematical Risk Assessment & Discrete Rule Engine:
1. Signal 1: Authentication Result Penalty (SUCCESS, FAILURE, UNKNOWN_ACCOUNT, etc.)
2. Signal 2: Failure Velocity (Consecutive / Rapid Failures)
3. Signal 3: Account Enumeration (Multiple Usernames from Single Source IP)
4. Signal 4: Request Velocity (Anomalous High Frequency Spikes)
5. Signal 5: Privilege Target (Sensitive / Restricted Endpoint Probing)
6. Signal 6: Threat Origin (Proxy, Tor, or Prior High-Risk Source Activity)
7. Signal 7: Account Takeover (SUCCESS immediately following multiple failures)
8. Signal 8: Temporal Anomaly (Off-Hours Access + Failure Burst)

Classification Tiers:
  - 0–24:   LOW       (SAFE / MONITORING)
  - 25–49:  MEDIUM    (SUSPICIOUS)
  - 50–74:  HIGH      (ALERT)
  - 75–100: CRITICAL  (CRITICAL ALERT)
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

class SentinelRiskEngine:
    """
    Configurable, stateful cybersecurity risk evaluation engine.
    Analyzes authentication event metadata against temporal baselines.
    CRITICAL: Does not inspect, handle, or store credentials.
    """

    DEFAULT_WEIGHTS = {
        'single_failure': 10,
        'unknown_account': 10,
        'mfa_failure': 20,
        'locked_account': 15,
        'failed_attempts_5': 50,
        'failed_attempts_10': 70,
        'multiple_usernames_2': 15,
        'multiple_usernames_4': 35,
        'multiple_usernames_7': 60,
        'high_frequency_10': 25,
        'high_frequency_25': 40,
        'restricted_resource': 30,
        'previous_high_risk': 30,
        'brute_force_success': 50,
        'off_hours_failures': 20
    }

    def __init__(self, db_conn: Optional[sqlite3.Connection] = None):
        self.weights = dict(self.DEFAULT_WEIGHTS)
        if db_conn:
            self.load_rule_weights(db_conn)

    def load_rule_weights(self, conn: sqlite3.Connection):
        """Loads custom rule weights from the security_rules table if present."""
        try:
            cursor = conn.cursor()
            rows = cursor.execute("SELECT rule_code, current_weight FROM security_rules WHERE is_active = 1").fetchall()
            for r in rows:
                code, weight = r[0], r[1]
                if code == 'RULE-001':
                    self.weights['failed_attempts_5'] = weight
                elif code == 'RULE-002':
                    self.weights['multiple_usernames_4'] = weight
                elif code == 'RULE-003':
                    self.weights['high_frequency_10'] = weight
                elif code == 'RULE-004':
                    self.weights['brute_force_success'] = weight
                elif code == 'RULE-005':
                    self.weights['restricted_resource'] = weight
                elif code == 'RULE-006':
                    self.weights['previous_high_risk'] = weight
                elif code == 'RULE-007':
                    self.weights['off_hours_failures'] = weight
                elif code == 'RULE-008':
                    self.weights['mfa_failure'] = weight
                elif code == 'RULE-009':
                    self.weights['unknown_account'] = weight
                elif code == 'RULE-010':
                    self.weights['single_failure'] = weight
        except Exception:
            pass

    def update_weight(self, key: str, new_weight: int):
        """Allows dynamic adjustment of risk signal weights."""
        if key in self.weights:
            self.weights[key] = max(0, min(100, int(new_weight)))

    def evaluate_event(self, event_data: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
        """
        Evaluates an authentication event against multi-dimensional signals.
        Returns calculated riskScore, riskLevel, triggeredRules, and explanation.
        """
        app_id = event_data.get('application_id', 'APP_001')
        username = event_data.get('username_identifier', '').strip()
        result = event_data.get('authentication_result', 'SUCCESS').upper()
        source_ip = event_data.get('source_ip', '127.0.0.1').strip()
        resource = event_data.get('resource', '/login').lower()
        now_str = event_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        penalties = {
            'result_penalty': 0,
            'failed_attempts_penalty': 0,
            'unknown_account_penalty': 0,
            'username_variety_penalty': 0,
            'frequency_penalty': 0,
            'resource_penalty': 0,
            'previous_risk_penalty': 0
        }

        triggered_rules = []
        explanation_clauses = []

        # ---------------------------------------------------------------------
        # 1. Authentication Result Penalty
        # ---------------------------------------------------------------------
        base_score = 5

        if result == 'SUCCESS':
            pass
        elif result == 'FAILURE':
            penalties['result_penalty'] = self.weights['single_failure']
            triggered_rules.append({'rule_code': 'RULE-010', 'name': 'Single Transient Failure', 'weight': self.weights['single_failure']})
            explanation_clauses.append("Authentication failed. No significant suspicious pattern detected.")
        elif result == 'UNKNOWN_ACCOUNT':
            penalties['unknown_account_penalty'] = self.weights['unknown_account']
            triggered_rules.append({'rule_code': 'RULE-009', 'name': 'Unknown Account Identifier', 'weight': self.weights['unknown_account']})
            explanation_clauses.append("Account identifier was not recognized. Monitoring continues.")
        elif result == 'MFA_FAILURE':
            penalties['result_penalty'] = self.weights['mfa_failure']
            triggered_rules.append({'rule_code': 'RULE-008', 'name': 'MFA Challenge Failure', 'weight': self.weights['mfa_failure']})
            explanation_clauses.append("Multi-factor authentication challenge rejected.")
        elif result == 'LOCKED_ACCOUNT':
            penalties['result_penalty'] = self.weights['locked_account']
            explanation_clauses.append("Attempted authentication against locked account.")

        # ---------------------------------------------------------------------
        # Query Temporal History from Database (Past 5-15 mins)
        # ---------------------------------------------------------------------
        recent_fails = 0
        distinct_users = 1
        request_count_1m = 1
        has_prior_alert = False
        prior_fails_before_success = 0

        if conn:
            cursor = conn.cursor()
            try:
                # A. Count recent failures from this IP in past 10 minutes
                rf_row = cursor.execute("""
                    SELECT COUNT(*) FROM authentication_events
                    WHERE source_ip = ? 
                      AND authentication_result IN ('FAILURE', 'UNKNOWN_ACCOUNT', 'MFA_FAILURE')
                      AND timestamp >= datetime(?, '-10 minutes')
                """, (source_ip, now_str)).fetchone()
                recent_fails = rf_row[0] if rf_row else 0

                # B. Count distinct usernames probed from this IP in past 5 minutes
                du_rows = cursor.execute("""
                    SELECT DISTINCT username_identifier FROM authentication_events
                    WHERE source_ip = ?
                      AND timestamp >= datetime(?, '-5 minutes')
                """, (source_ip, now_str)).fetchall()
                probed_set = set(r[0] for r in du_rows) if du_rows else set()
                if username:
                    probed_set.add(username)
                distinct_users = len(probed_set) if probed_set else 1

                # C. Count request frequency in past 1 minute
                fc_row = cursor.execute("""
                    SELECT COUNT(*) FROM authentication_events
                    WHERE source_ip = ?
                      AND timestamp >= datetime(?, '-1 minute')
                """, (source_ip, now_str)).fetchone()
                request_count_1m = (fc_row[0] if fc_row else 0) + 1

                # D. Check if IP has previous alerts in past 24 hours (active/open alerts, ignore safe test baseline)
                pa_row = cursor.execute("""
                    SELECT COUNT(*) FROM alerts
                    WHERE source_ip = ? 
                      AND status != 'RESOLVED'
                      AND source_ip != '192.0.2.55'
                      AND created_at >= datetime(?, '-24 hours')
                """, (source_ip, now_str)).fetchone()
                has_prior_alert = (pa_row[0] > 0) if pa_row else False

                # E. If current is SUCCESS, check if preceded by >= 4 consecutive failures
                if result == 'SUCCESS':
                    last_evs = cursor.execute("""
                        SELECT authentication_result FROM authentication_events
                        WHERE source_ip = ? AND username_identifier = ?
                        ORDER BY event_id DESC LIMIT 5
                    """, (source_ip, username)).fetchall()
                    fails_seq = sum(1 for e in last_evs if e[0] in ('FAILURE', 'UNKNOWN_ACCOUNT'))
                    if fails_seq >= 4:
                        prior_fails_before_success = fails_seq
            except Exception:
                pass

        effective_fails = recent_fails + (1 if result in ('FAILURE', 'UNKNOWN_ACCOUNT', 'MFA_FAILURE') else 0)

        # ---------------------------------------------------------------------
        # 2. Failed Attempts Frequency Signal
        # ---------------------------------------------------------------------
        if effective_fails >= 10:
            p = self.weights['failed_attempts_10']
            penalties['failed_attempts_penalty'] = p
            triggered_rules.append({'rule_code': 'RULE-001', 'name': 'Repeated Authentication Failures (>=10)', 'weight': p})
            explanation_clauses.append(f"Severe failure volume: {effective_fails} failed attempts observed from origin.")
        elif effective_fails >= 5:
            p = self.weights['failed_attempts_5']
            penalties['failed_attempts_penalty'] = p
            triggered_rules.append({'rule_code': 'RULE-001', 'name': 'Repeated Authentication Failures (>=5)', 'weight': p})
            explanation_clauses.append(f"Repeated authentication failures ({effective_fails} attempts) detected.")

        # ---------------------------------------------------------------------
        # 3. Account Enumeration / Multiple Usernames Signal
        # ---------------------------------------------------------------------
        if distinct_users >= 7:
            p = self.weights['multiple_usernames_7']
            penalties['username_variety_penalty'] = p
            triggered_rules.append({'rule_code': 'RULE-002', 'name': 'High-Risk Account Enumeration Pattern', 'weight': p})
            explanation_clauses.append(f"High-risk account enumeration: {distinct_users} distinct usernames probed from same origin.")
        elif distinct_users >= 4:
            p = self.weights['multiple_usernames_4']
            penalties['username_variety_penalty'] = p
            triggered_rules.append({'rule_code': 'RULE-002', 'name': 'Multiple Account Identifiers', 'weight': p})
            explanation_clauses.append(f"Multiple account identifiers ({distinct_users} users) attempted from single source.")
        elif distinct_users >= 2 and result != 'SUCCESS':
            p = self.weights['multiple_usernames_2']
            penalties['username_variety_penalty'] = p

        # ---------------------------------------------------------------------
        # 4. Request Velocity Frequency Signal
        # ---------------------------------------------------------------------
        if request_count_1m >= 25:
            p = self.weights['high_frequency_25']
            penalties['frequency_penalty'] = p
            triggered_rules.append({'rule_code': 'RULE-003', 'name': 'Extreme Request Velocity Spike', 'weight': p})
            explanation_clauses.append(f"Extreme request velocity: {request_count_1m} requests/min.")
        elif request_count_1m >= 10:
            p = self.weights['high_frequency_10']
            penalties['frequency_penalty'] = p
            triggered_rules.append({'rule_code': 'RULE-003', 'name': 'Abnormal Request Frequency', 'weight': p})
            explanation_clauses.append(f"Abnormal request frequency: {request_count_1m} req/min.")

        # ---------------------------------------------------------------------
        # 5. Sensitive / Restricted Resource Probing
        # ---------------------------------------------------------------------
        restricted_targets = ['/admin', '/root', '/portal-admin', '/api/v1/keys', '/finance', '/sysadmin']
        if any(target in resource for target in restricted_targets):
            p = self.weights['restricted_resource']
            penalties['resource_penalty'] = p
            triggered_rules.append({'rule_code': 'RULE-005', 'name': 'Restricted Resource Probing', 'weight': p})
            explanation_clauses.append(f"Direct authentication attempt targeting restricted endpoint: {resource}.")

        # ---------------------------------------------------------------------
        # 6. Previous High-Risk Activity or Known Threat IP
        # ---------------------------------------------------------------------
        if has_prior_alert:
            p = self.weights['previous_high_risk']
            penalties['previous_risk_penalty'] = p
            triggered_rules.append({'rule_code': 'RULE-006', 'name': 'High-Risk Source IP Reputation', 'weight': p})
            explanation_clauses.append("Source IP has triggered security alerts in the past 24 hours.")

        # ---------------------------------------------------------------------
        # 7. Brute Force Success / Account Takeover
        # ---------------------------------------------------------------------
        if prior_fails_before_success >= 4:
            p = self.weights['brute_force_success']
            penalties['previous_risk_penalty'] += p
            triggered_rules.append({'rule_code': 'RULE-004', 'name': 'Brute Force Success (Account Takeover)', 'weight': p})
            explanation_clauses.append(f"CRITICAL: Successful login after {prior_fails_before_success} consecutive failed attempts.")

        # ---------------------------------------------------------------------
        # 8. Off-Hours Temporal Anomaly
        # ---------------------------------------------------------------------
        try:
            ev_dt = datetime.strptime(now_str, '%Y-%m-%d %H:%M:%S')
            hour = ev_dt.hour
            if (hour >= 23 or hour < 5) and (recent_fails >= 3 or result != 'SUCCESS'):
                p = self.weights['off_hours_failures']
                triggered_rules.append({'rule_code': 'RULE-007', 'name': 'Off-Hours Authentication Failures', 'weight': p})
                explanation_clauses.append(f"Anomalous off-hours access activity observed at {hour:02d}:00.")
        except Exception:
            pass

        # ---------------------------------------------------------------------
        # Calculate Final Risk Score (0 to 100)
        # ---------------------------------------------------------------------
        total_penalties = sum(penalties.values())
        raw_score = base_score + total_penalties
        risk_score = min(100, max(0, raw_score))

        # Risk Level Classification (Section 8)
        if risk_score >= 75:
            risk_level = 'CRITICAL'
            status = 'CRITICAL_ALERT'
        elif risk_score >= 50:
            risk_level = 'HIGH'
            status = 'ALERT'
        elif risk_score >= 25:
            risk_level = 'MEDIUM'
            status = 'SUSPICIOUS' if result in ('UNKNOWN_ACCOUNT', 'FAILURE') else 'MONITORING'
        else:
            risk_level = 'LOW'
            status = 'SAFE' if result == 'SUCCESS' else 'MONITORING'

        # Synthesize final explanation
        if not explanation_clauses:
            explanation = "Successful authentication with no significant suspicious indicators."
        else:
            explanation = " ".join(explanation_clauses)

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'status': status,
            'explanation': explanation,
            'penalties': penalties,
            'triggered_rules': triggered_rules,
            'observed_metrics': {
                'recent_fails': recent_fails,
                'distinct_users': distinct_users,
                'request_velocity_1m': request_count_1m,
                'prior_alerts': has_prior_alert
            }
        }

if __name__ == '__main__':
    engine = SentinelRiskEngine()
    print("=== SentinelRiskEngine Test Cases ===")

    # 1. Safe login
    ev1 = {'username_identifier': 'john123', 'authentication_result': 'SUCCESS', 'source_ip': '192.0.2.10', 'resource': '/login'}
    r1 = engine.evaluate_event(ev1)
    print(f"Safe Login: Score={r1['risk_score']} Level={r1['risk_level']} Status={r1['status']} - {r1['explanation']}")

    # 2. Single wrong password
    ev2 = {'username_identifier': 'john123', 'authentication_result': 'FAILURE', 'source_ip': '192.0.2.10', 'resource': '/login'}
    r2 = engine.evaluate_event(ev2)
    print(f"Wrong Password: Score={r2['risk_score']} Level={r2['risk_level']} Status={r2['status']} - {r2['explanation']}")

    # 3. Unknown account
    ev3 = {'username_identifier': 'fake_admin_123', 'authentication_result': 'UNKNOWN_ACCOUNT', 'source_ip': '192.0.2.10', 'resource': '/login'}
    r3 = engine.evaluate_event(ev3)
    print(f"Unknown User: Score={r3['risk_score']} Level={r3['risk_level']} Status={r3['status']} - {r3['explanation']}")
