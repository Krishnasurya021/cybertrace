#!/usr/bin/env python3
"""
SENTINEL — Universal Authentication Security & Access Log Monitoring Platform
Database Initializer & Realistic Security Event Generator
Initializes database/sentinel.db (SQLite 3NF compliant) and database/sample_data.sql.

IMPORTANT SECURITY RULE:
SENTINEL never receives, stores, displays, or processes passwords.
NO password columns exist in authentication_events.
"""

import sqlite3
import hashlib
import random
import os
import sys
import json
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'sentinel.db')
SQL_PATH = os.path.join(BASE_DIR, 'sample_data.sql')

def hash_secret(val: str) -> str:
    return hashlib.sha256(val.encode('utf-8')).hexdigest()

def create_schema(cursor):
    cursor.executescript("""
    PRAGMA foreign_keys = ON;

    DROP TABLE IF EXISTS alert_events;
    DROP TABLE IF EXISTS alerts;
    DROP TABLE IF EXISTS risk_scores;
    DROP TABLE IF EXISTS authentication_events;
    DROP TABLE IF EXISTS sessions;
    DROP TABLE IF EXISTS api_clients;
    DROP TABLE IF EXISTS security_rules;
    DROP TABLE IF EXISTS audit_logs;
    DROP TABLE IF EXISTS applications;
    DROP TABLE IF EXISTS users;

    -- 1. APPLICATIONS
    CREATE TABLE applications (
        application_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        app_type TEXT CHECK(app_type IN ('Website', 'Web Application', 'Mobile Application', 'API', 'Portal')) NOT NULL DEFAULT 'Web Application',
        owner_email TEXT NOT NULL,
        environment TEXT CHECK(environment IN ('Production', 'Staging', 'Development')) NOT NULL DEFAULT 'Production',
        status TEXT CHECK(status IN ('ACTIVE', 'SUSPENDED', 'MAINTENANCE')) NOT NULL DEFAULT 'ACTIVE',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    );

    -- 2. API_CLIENTS
    CREATE TABLE api_clients (
        client_id INTEGER PRIMARY KEY AUTOINCREMENT,
        application_id TEXT NOT NULL,
        api_key TEXT NOT NULL UNIQUE,
        api_secret_hash TEXT NOT NULL,
        api_secret_preview TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        last_used_at TEXT,
        FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE CASCADE
    );

    -- 3. AUTHENTICATION_EVENTS (NO PASSWORD COLUMN)
    CREATE TABLE authentication_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        application_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        username_identifier TEXT NOT NULL,
        event_type TEXT NOT NULL DEFAULT 'LOGIN_ATTEMPT',
        authentication_result TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        device_type TEXT NOT NULL DEFAULT 'Desktop',
        user_agent TEXT NOT NULL DEFAULT 'Mozilla/5.0',
        resource TEXT NOT NULL DEFAULT '/login',
        session_id TEXT,
        risk_level TEXT CHECK(risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL DEFAULT 'LOW',
        risk_score INTEGER NOT NULL DEFAULT 5,
        status TEXT CHECK(status IN ('SAFE', 'MONITORING', 'SUSPICIOUS', 'ALERT', 'CRITICAL_ALERT')) NOT NULL DEFAULT 'SAFE',
        failure_reason TEXT,
        triggered_rules TEXT,
        raw_metadata TEXT,
        FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE CASCADE
    );

    -- 4. SESSIONS
    CREATE TABLE sessions (
        session_id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        username_identifier TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        device_type TEXT NOT NULL DEFAULT 'Desktop',
        user_agent TEXT NOT NULL DEFAULT 'Mozilla/5.0',
        login_time TEXT DEFAULT (datetime('now')),
        logout_time TEXT,
        duration_seconds INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE CASCADE
    );

    -- 5. SECURITY_RULES
    CREATE TABLE security_rules (
        rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_code TEXT NOT NULL UNIQUE,
        rule_name TEXT NOT NULL,
        description TEXT NOT NULL,
        signal_type TEXT NOT NULL,
        default_weight INTEGER NOT NULL DEFAULT 10,
        current_weight INTEGER NOT NULL DEFAULT 10,
        risk_level TEXT CHECK(risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL DEFAULT 'MEDIUM',
        logical_expression TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    );

    -- 6. RISK_SCORES
    CREATE TABLE risk_scores (
        score_id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        application_id TEXT NOT NULL,
        result_penalty INTEGER NOT NULL DEFAULT 0,
        failed_attempts_penalty INTEGER NOT NULL DEFAULT 0,
        unknown_account_penalty INTEGER NOT NULL DEFAULT 0,
        username_variety_penalty INTEGER NOT NULL DEFAULT 0,
        frequency_penalty INTEGER NOT NULL DEFAULT 0,
        resource_penalty INTEGER NOT NULL DEFAULT 0,
        previous_risk_penalty INTEGER NOT NULL DEFAULT 0,
        total_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        calculated_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (event_id) REFERENCES authentication_events(event_id) ON DELETE CASCADE,
        FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE CASCADE
    );

    -- 7. ALERTS
    CREATE TABLE alerts (
        alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
        application_id TEXT NOT NULL,
        event_id INTEGER,
        risk_level TEXT CHECK(risk_level IN ('HIGH', 'CRITICAL')) NOT NULL,
        risk_score INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        accounts_attempted INTEGER NOT NULL DEFAULT 1,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        triggered_rules TEXT NOT NULL,
        status TEXT CHECK(status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'DISMISSED')) NOT NULL DEFAULT 'OPEN',
        created_at TEXT DEFAULT (datetime('now')),
        resolved_at TEXT,
        investigator_notes TEXT,
        FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE CASCADE,
        FOREIGN KEY (event_id) REFERENCES authentication_events(event_id) ON DELETE SET NULL
    );

    -- 8. ALERT_EVENTS
    CREATE TABLE alert_events (
        alert_id INTEGER NOT NULL,
        event_id INTEGER NOT NULL,
        sequence_order INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (alert_id, event_id),
        FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE,
        FOREIGN KEY (event_id) REFERENCES authentication_events(event_id) ON DELETE CASCADE
    );

    -- 9. AUDIT_LOGS
    CREATE TABLE audit_logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        actor TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        details TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );

    -- 10. USERS (Internal SOC Analysts & App Owners)
    CREATE TABLE users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT CHECK(role IN ('ADMIN', 'ANALYST', 'APP_OWNER')) NOT NULL DEFAULT 'ANALYST',
        application_id TEXT,
        department TEXT NOT NULL DEFAULT 'Cybersecurity SOC',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE SET NULL
    );

    -- Indexes
    CREATE INDEX idx_auth_app ON authentication_events(application_id);
    CREATE INDEX idx_auth_time ON authentication_events(timestamp);
    CREATE INDEX idx_auth_user ON authentication_events(username_identifier);
    CREATE INDEX idx_auth_ip ON authentication_events(source_ip);
    CREATE INDEX idx_auth_result ON authentication_events(authentication_result);
    CREATE INDEX idx_auth_risk ON authentication_events(risk_level, risk_score);
    CREATE INDEX idx_alerts_app ON alerts(application_id);
    CREATE INDEX idx_alerts_status ON alerts(status);
    """)

def seed_database(conn):
    cursor = conn.cursor()
    now = datetime.now()

    # 1. Applications
    apps = [
        ('APP_001', 'College Portal', 'https://portal.apexuniversity.edu', 'Portal', 'admin@apex.edu', 'Production', 'ACTIVE'),
        ('APP_002', 'E-Commerce Website', 'https://shop.aurorastore.com', 'Web Application', 'secops@aurora.com', 'Production', 'ACTIVE'),
        ('APP_003', 'Company Portal', 'https://intranet.novacorp.internal', 'Portal', 'it@novacorp.com', 'Production', 'ACTIVE'),
        ('APP_004', 'Mobile Application', 'https://api.novafinance.app/mobile', 'Mobile Application', 'dev@novafinance.app', 'Production', 'ACTIVE'),
        ('APP_005', 'Customer Website', 'https://portal.skylinecloud.io', 'Website', 'cloud-ops@skylinecloud.io', 'Production', 'ACTIVE'),
    ]
    cursor.executemany("""
        INSERT INTO applications (application_id, name, url, app_type, owner_email, environment, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, apps)

    # 2. API Clients
    clients = [
        ('APP_001', 'sen_live_9b4a8e109f2d431c', hash_secret('sec_live_d843109a2b5e'), 'sec_live_...2b5e'),
        ('APP_002', 'sen_live_7c3f19e482da510b', hash_secret('sec_live_e952110b3c6f'), 'sec_live_...3c6f'),
        ('APP_003', 'sen_live_4a2d80c391eb621a', hash_secret('sec_live_f063221c4d7a'), 'sec_live_...4d7a'),
        ('APP_004', 'sen_live_1f9b72d804ac532e', hash_secret('sec_live_a174332d5e8b'), 'sec_live_...5e8b'),
        ('APP_005', 'sen_live_6e8a51b913cd743f', hash_secret('sec_live_b285443e6f9c'), 'sec_live_...6f9c'),
    ]
    cursor.executemany("""
        INSERT INTO api_clients (application_id, api_key, api_secret_hash, api_secret_preview)
        VALUES (?, ?, ?, ?)
    """, clients)

    # 3. Security Rules
    rules = [
        ('RULE-001', 'Repeated Authentication Failures', 'Multiple consecutive failed attempts from the same entity', 'FAILED_ATTEMPTS', 25, 25, 'HIGH', 'P_fails >= 5'),
        ('RULE-002', 'Multiple Account Identifiers', 'Rapid account enumeration or credential probing from single origin', 'USERNAME_VARIETY', 35, 35, 'CRITICAL', 'P_distinct_users >= 4'),
        ('RULE-003', 'Abnormal Request Frequency', 'High velocity login attempts exceeding normal human thresholds', 'FREQUENCY', 25, 25, 'HIGH', 'P_velocity > 10_req_per_min'),
        ('RULE-004', 'Brute Force Success (Account Takeover)', 'Successful login following multiple failed attempts from same origin', 'BRUTE_FORCE_SUCCESS', 35, 35, 'CRITICAL', 'P_success_after_high_fails'),
        ('RULE-005', 'Restricted Resource Probing', 'Authentication attempts directly targeting high-privilege/admin endpoints', 'RESTRICTED_RESOURCE', 30, 30, 'HIGH', 'P_resource IN (/admin, /root, /portal-admin)'),
        ('RULE-006', 'High-Risk Source IP Reputation', 'Originating IP has known proxy/tor/malicious threat reputation', 'PREVIOUS_RISK', 30, 30, 'HIGH', 'P_ip_reputation >= 75'),
        ('RULE-007', 'Off-Hours Authentication Failures', 'Failed logins observed during anomalous off-work hours (23:00-05:00)', 'OFF_HOURS', 20, 20, 'MEDIUM', 'P_hour IN (23..5) AND P_fails >= 3'),
        ('RULE-008', 'MFA Challenge Failure Burst', 'Repeated secondary factor verification rejections', 'MFA_FAILURE', 25, 25, 'HIGH', 'P_mfa_fails >= 2'),
        ('RULE-009', 'Unknown Account Identifier', 'Attempted authentication against non-existent account identifier', 'UNKNOWN_ACCOUNT', 10, 10, 'LOW', 'P_result == UNKNOWN_ACCOUNT'),
        ('RULE-010', 'Single Transient Failure', 'Isolated incorrect credential without suspicious frequency or pattern', 'SINGLE_FAILURE', 10, 10, 'LOW', 'P_result == FAILURE AND P_fails == 1'),
    ]
    cursor.executemany("""
        INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, rules)

    # 4. Users (SOC team & App Owners)
    soc_users = [
        ('analyst', 'analyst@sentinel.sec', hash_secret('analyst2026!'), 'ANALYST', None, 'Tier 1 SOC'),
        ('lead_admin', 'admin@sentinel.sec', hash_secret('sentinelAdmin2026#'), 'ADMIN', None, 'SOC Management'),
        ('college_owner', 'admin@apex.edu', hash_secret('collegePortal2026@'), 'APP_OWNER', 'APP_001', 'College IT Admin'),
        ('store_owner', 'secops@aurora.com', hash_secret('auroraStore2026$'), 'APP_OWNER', 'APP_002', 'E-Commerce SecOps'),
    ]
    cursor.executemany("""
        INSERT INTO users (username, email, password_hash, role, application_id, department)
        VALUES (?, ?, ?, ?, ?, ?)
    """, soc_users)

    # 5. Generate 600+ Authentication Events across past 7 days
    normal_users = ['john123', 'sarah_w', 'alex_dev', 'david_ops', 'emily_chem', 'prof_sharma', 'dean_wilson', 'alice_k', 'student_441', 'mark_hr', 'priya_cs', 'rahul_eng']
    normal_ips = [
        ('192.0.2.10', 'Desktop', 'Chrome 122 on macOS'),
        ('192.0.2.15', 'Desktop', 'Firefox 124 on Windows 11'),
        ('198.51.100.22', 'Mobile', 'Safari on iOS 17'),
        ('198.51.100.35', 'Desktop', 'Chrome 122 on Windows 10'),
        ('203.0.113.40', 'Mobile', 'Chrome on Android 14'),
        ('192.0.2.88', 'Desktop', 'Edge 122 on Windows 11'),
        ('198.51.100.99', 'Tablet', 'Safari on iPadOS')
    ]
    resources = ['/login', '/portal', '/dashboard', '/student-records', '/grades', '/checkout', '/account', '/api/v1/auth']

    events = []
    scores = []
    sessions = []
    
    event_id = 1
    session_counter = 1

    # Baseline normal events (past 7 days)
    for day in range(7, 0, -1):
        day_date = now - timedelta(days=day)
        # 60 events per day
        for _ in range(70):
            event_time = (day_date.replace(hour=random.randint(6, 22), minute=random.randint(0, 59), second=random.randint(0, 59))).strftime('%Y-%m-%d %H:%M:%S')
            app_id = random.choice(['APP_001', 'APP_001', 'APP_002', 'APP_003', 'APP_004', 'APP_005'])
            user = random.choice(normal_users)
            ip, dev, ua = random.choice(normal_ips)
            res = random.choice(resources)

            # 90% SUCCESS, 7% FAILURE (single), 3% UNKNOWN
            roll = random.random()
            if roll < 0.88:
                result = 'SUCCESS'
                risk_level = 'LOW'
                score = random.randint(2, 8)
                status = 'SAFE'
                rules_trig = []
                sess_id = f"sess_{session_counter:05d}"
                session_counter += 1
                sessions.append((sess_id, app_id, user, ip, dev, ua, event_time, None, random.randint(300, 7200), 1 if day == 0 else 0))
            elif roll < 0.96:
                result = 'FAILURE'
                risk_level = 'LOW'
                score = random.randint(12, 18)
                status = 'MONITORING'
                rules_trig = ['RULE-010']
                sess_id = None
            else:
                result = 'UNKNOWN_ACCOUNT'
                user = f"user_{random.randint(900, 999)}"
                risk_level = 'LOW'
                score = random.randint(18, 22)
                status = 'SUSPICIOUS'
                rules_trig = ['RULE-009']
                sess_id = None

            events.append((
                event_id, app_id, event_time, user, 'LOGIN_ATTEMPT', result, ip, dev, ua, res, sess_id,
                risk_level, score, status, None, json.dumps(rules_trig), json.dumps({'client_ip': ip, 'browser': ua})
            ))
            scores.append((
                event_id, app_id, 10 if result != 'SUCCESS' else 0, 0, 10 if result == 'UNKNOWN_ACCOUNT' else 0,
                0, 0, 0, 0, score, risk_level, event_time
            ))
            event_id += 1

    # Cluster A: Repeated Failures Burst on APP_001 (Yesterday)
    burst_time = now - timedelta(hours=18)
    for i in range(7):
        t = (burst_time + timedelta(seconds=i * 12)).strftime('%Y-%m-%d %H:%M:%S')
        score = 65
        events.append((
            event_id, 'APP_001', t, 'prof_sharma', 'LOGIN_ATTEMPT', 'FAILURE', '198.51.100.177', 'Desktop', 'Chrome 122 on Linux', '/portal', None,
            'HIGH', score, 'ALERT', 'Invalid credentials sequence', json.dumps(['RULE-001', 'RULE-003']), json.dumps({'burst_seq': i+1})
        ))
        scores.append((event_id, 'APP_001', 10, 30, 0, 0, 25, 0, 0, score, 'HIGH', t))
        event_id += 1

    # Cluster B: High-Risk Account Enumeration Pattern on APP_001 (Today - 3 hours ago)
    enum_time = now - timedelta(hours=3)
    enum_users = ['admin', 'administrator', 'root', 'manager', 'superadmin', 'test', 'fakeuser']
    enum_event_ids = []
    for i, u in enumerate(enum_users):
        t = (enum_time + timedelta(seconds=i * 4)).strftime('%Y-%m-%d %H:%M:%S')
        score = 88 if i >= 4 else 45 + (i * 8)
        lvl = 'CRITICAL' if score >= 75 else 'HIGH' if score >= 50 else 'MEDIUM'
        status = 'CRITICAL_ALERT' if lvl == 'CRITICAL' else 'ALERT'
        r_trig = ['RULE-001', 'RULE-002', 'RULE-003'] if i >= 3 else ['RULE-002']
        events.append((
            event_id, 'APP_001', t, u, 'LOGIN_ATTEMPT', 'UNKNOWN_ACCOUNT', '192.0.2.10', 'Desktop', 'Python-urllib/3.9 (Scanner)', '/admin', None,
            lvl, score, status, 'Account not found during enumeration', json.dumps(r_trig), json.dumps({'probe_index': i+1})
        ))
        scores.append((event_id, 'APP_001', 10, 20, 10, 35, 25, 30, 0, score, lvl, t))
        enum_event_ids.append(event_id)
        event_id += 1

    # Cluster C: Credential Stuffing on APP_002 E-Commerce (Yesterday evening)
    stuff_time = now - timedelta(hours=22)
    stuff_users = ['alex_dev', 'david_ops', 'sarah_w', 'mark_hr', 'priya_cs']
    for i, u in enumerate(stuff_users):
        t = (stuff_time + timedelta(seconds=i * 8)).strftime('%Y-%m-%d %H:%M:%S')
        score = 78
        events.append((
            event_id, 'APP_002', t, u, 'LOGIN_ATTEMPT', 'FAILURE', '203.0.113.205', 'Desktop', 'HeadlessChrome/120.0', '/checkout', None,
            'CRITICAL', score, 'CRITICAL_ALERT', 'Automated stuffing attempt', json.dumps(['RULE-002', 'RULE-003', 'RULE-006']), json.dumps({'proxy': True})
        ))
        scores.append((event_id, 'APP_002', 10, 15, 0, 35, 25, 0, 30, score, 'CRITICAL', t))
        event_id += 1

    # Insert Events & Scores
    cursor.executemany("""
        INSERT INTO authentication_events (
            event_id, application_id, timestamp, username_identifier, event_type,
            authentication_result, source_ip, device_type, user_agent, resource,
            session_id, risk_level, risk_score, status, failure_reason, triggered_rules, raw_metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, events)

    cursor.executemany("""
        INSERT INTO risk_scores (
            event_id, application_id, result_penalty, failed_attempts_penalty,
            unknown_account_penalty, username_variety_penalty, frequency_penalty,
            resource_penalty, previous_risk_penalty, total_score, risk_level, calculated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, scores)

    cursor.executemany("""
        INSERT INTO sessions (
            session_id, application_id, username_identifier, source_ip, device_type, user_agent, login_time, logout_time, duration_seconds, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, sessions)

    # 6. Insert Pre-Configured Alerts
    alerts = [
        (1, 'APP_001', enum_event_ids[-1], 'CRITICAL', 88, 'HIGH-RISK ACCOUNT ENUMERATION PATTERN',
         'Multiple non-existent administrative account identifiers attempted from 192.0.2.10 within seconds.',
         '192.0.2.10', 7, 7,
         json.dumps([
             {'rule_code': 'RULE-001', 'name': 'Repeated Authentication Failures', 'weight': 25},
             {'rule_code': 'RULE-002', 'name': 'Multiple Account Identifiers', 'weight': 35},
             {'rule_code': 'RULE-003', 'name': 'Abnormal Request Frequency', 'weight': 25}
         ]),
         'OPEN', (now - timedelta(hours=3)).strftime('%Y-%m-%d %H:%M:%S'), None, None),
        
        (2, 'APP_001', event_id - 15, 'HIGH', 65, 'REPEATED AUTHENTICATION FAILURES BURST',
         'Velocity threshold exceeded: 7 failed attempts for user prof_sharma from 198.51.100.177.',
         '198.51.100.177', 1, 7,
         json.dumps([
             {'rule_code': 'RULE-001', 'name': 'Repeated Authentication Failures', 'weight': 25},
             {'rule_code': 'RULE-003', 'name': 'Abnormal Request Frequency', 'weight': 25}
         ]),
         'INVESTIGATING', (now - timedelta(hours=18)).strftime('%Y-%m-%d %H:%M:%S'), None, 'Analyst assigned: verifying if user mistyped keyboard layout.'),

        (3, 'APP_002', event_id - 3, 'CRITICAL', 78, 'CREDENTIAL STUFFING ATTACK DETECTED',
         'Known proxy origin 203.0.113.205 attempted 5 different registered customer accounts on checkout portal.',
         '203.0.113.205', 5, 5,
         json.dumps([
             {'rule_code': 'RULE-002', 'name': 'Multiple Account Identifiers', 'weight': 35},
             {'rule_code': 'RULE-003', 'name': 'Abnormal Request Frequency', 'weight': 25},
             {'rule_code': 'RULE-006', 'name': 'High-Risk Source IP Reputation', 'weight': 30}
         ]),
         'OPEN', (now - timedelta(hours=22)).strftime('%Y-%m-%d %H:%M:%S'), None, None)
    ]

    cursor.executemany("""
        INSERT INTO alerts (
            alert_id, application_id, event_id, risk_level, risk_score, title, description,
            source_ip, accounts_attempted, failed_attempts, triggered_rules, status, created_at, resolved_at, investigator_notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, alerts)

    # Associate alert events
    alert_events = []
    for seq, eid in enumerate(enum_event_ids, start=1):
        alert_events.append((1, eid, seq))
    cursor.executemany("INSERT INTO alert_events (alert_id, event_id, sequence_order) VALUES (?, ?, ?)", alert_events)

    # 7. Audit Logs
    audit = [
        ('APPLICATION_REGISTERED', 'admin@sentinel.sec', 'APPLICATION', 'APP_001', 'Registered College Portal for production authentication telemetry', (now - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')),
        ('API_KEY_GENERATED', 'admin@sentinel.sec', 'API_CLIENT', 'APP_001', 'Generated primary live credentials for College Portal', (now - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')),
        ('RULE_CONFIGURED', 'analyst@sentinel.sec', 'SECURITY_RULE', 'RULE-002', 'Updated multiple account identifier penalty weight to 35', (now - timedelta(days=5)).strftime('%Y-%m-%d %H:%M:%S')),
        ('ALERT_INVESTIGATION_OPENED', 'analyst@sentinel.sec', 'ALERT', '1', 'Initiated triage on Account Enumeration pattern from 192.0.2.10', (now - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')),
    ]
    cursor.executemany("""
        INSERT INTO audit_logs (action, actor, target_type, target_id, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, audit)

    conn.commit()
    print(f"[SENTINEL DB] Database seeded successfully at: {DB_PATH}")
    print(f"  - Applications: {len(apps)}")
    print(f"  - Security Rules: {len(rules)}")
    print(f"  - Authentication Events: {len(events)}")
    print(f"  - Alerts: {len(alerts)}")
    print(f"  - Sessions: {len(sessions)}")

def generate_mysql_sample_sql():
    """Generates MySQL-compatible sample_data.sql for direct mysql client imports."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    with open(SQL_PATH, 'w', encoding='utf-8') as f:
        f.write("-- SENTINEL Platform Sample Data Seeding Script (MySQL 8.0+)\n")
        f.write("-- NOTE: Contains NO password columns for authentication events!\n\n")
        f.write("USE sentinel_soc;\n\n")

        # Dump applications
        apps = cursor.execute("SELECT application_id, name, url, app_type, owner_email, environment, status FROM applications").fetchall()
        f.write("-- Applications\n")
        for a in apps:
            f.write(f"INSERT INTO applications (application_id, name, url, app_type, owner_email, environment, status) VALUES ('{a[0]}', '{a[1]}', '{a[2]}', '{a[3]}', '{a[4]}', '{a[5]}', '{a[6]}');\n")
        f.write("\n")

        # Dump API Clients
        clients = cursor.execute("SELECT application_id, api_key, api_secret_hash, api_secret_preview FROM api_clients").fetchall()
        f.write("-- API Clients\n")
        for c in clients:
            f.write(f"INSERT INTO api_clients (application_id, api_key, api_secret_hash, api_secret_preview) VALUES ('{c[0]}', '{c[1]}', '{c[2]}', '{c[3]}');\n")
        f.write("\n")

        # Dump Security Rules
        rules = cursor.execute("SELECT rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression FROM security_rules").fetchall()
        f.write("-- Security Rules\n")
        for r in rules:
            desc = r[2].replace("'", "''")
            f.write(f"INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression) VALUES ('{r[0]}', '{r[1]}', '{desc}', '{r[3]}', {r[4]}, {r[5]}, '{r[6]}', '{r[7]}');\n")
        f.write("\n")

        # Dump Users
        users = cursor.execute("SELECT username, email, password_hash, role, application_id, department FROM users").fetchall()
        f.write("-- SOC Users\n")
        for u in users:
            app_id = f"'{u[4]}'" if u[4] else "NULL"
            f.write(f"INSERT INTO users (username, email, password_hash, role, application_id, department) VALUES ('{u[0]}', '{u[1]}', '{u[2]}', '{u[3]}', {app_id}, '{u[5]}');\n")
        f.write("\n")

    conn.close()
    print(f"[SENTINEL DB] MySQL sample SQL generated at: {SQL_PATH}")

if __name__ == '__main__':
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except Exception:
            pass
    conn = sqlite3.connect(DB_PATH)
    create_schema(conn.cursor())
    seed_database(conn)
    generate_mysql_sample_sql()
    conn.close()
