-- ============================================================================
-- SENTINEL — Universal Authentication Security & Access Log Monitoring Platform
-- Module: DBMS (Relational Database Schema)
-- Engine: MySQL 8.0+ / MariaDB Compatible
-- Normalization: 3NF (Third Normal Form)
-- ============================================================================
-- IMPORTANT SECURITY REQUIREMENT:
-- SENTINEL receives authentication EVENT METADATA only.
-- SENTINEL MUST NEVER store, receive, display, or process actual passwords.
-- There is NO password column in authentication_events.
-- ============================================================================

CREATE DATABASE IF NOT EXISTS sentinel_soc;
USE sentinel_soc;

-- Drop tables in reverse dependency order
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

-- ----------------------------------------------------------------------------
-- 1. APPLICATIONS TABLE (Connected external websites, portals, and apps)
-- ----------------------------------------------------------------------------
CREATE TABLE applications (
    application_id VARCHAR(32) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    url VARCHAR(255) NOT NULL,
    app_type ENUM('Website', 'Web Application', 'Mobile Application', 'API', 'Portal') NOT NULL DEFAULT 'Web Application',
    owner_email VARCHAR(120) NOT NULL,
    environment ENUM('Production', 'Staging', 'Development') NOT NULL DEFAULT 'Production',
    status ENUM('ACTIVE', 'SUSPENDED', 'MAINTENANCE') NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_app_status (status),
    INDEX idx_app_type (app_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- 2. API_CLIENTS TABLE (Cryptographic API credentials for connected apps)
-- ----------------------------------------------------------------------------
CREATE TABLE api_clients (
    client_id INT AUTO_INCREMENT PRIMARY KEY,
    application_id VARCHAR(32) NOT NULL,
    api_key VARCHAR(64) NOT NULL UNIQUE,
    api_secret_hash VARCHAR(128) NOT NULL,
    api_secret_preview VARCHAR(32) NOT NULL, -- e.g. "sec_live_...9f"
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NULL DEFAULT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE CASCADE,
    INDEX idx_api_key (api_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- 3. AUTHENTICATION_EVENTS TABLE (Ingested authentication event telemetry)
-- CRITICAL: NO PASSWORD COLUMN ALLOWED!
-- ----------------------------------------------------------------------------
CREATE TABLE authentication_events (
    event_id INT AUTO_INCREMENT PRIMARY KEY,
    application_id VARCHAR(32) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    username_identifier VARCHAR(100) NOT NULL,
    event_type ENUM('LOGIN_ATTEMPT', 'MFA_CHALLENGE', 'SESSION_STARTED', 'SESSION_ENDED', 'ACCOUNT_LOCKOUT') NOT NULL DEFAULT 'LOGIN_ATTEMPT',
    authentication_result ENUM('SUCCESS', 'FAILURE', 'UNKNOWN_ACCOUNT', 'LOCKED_ACCOUNT', 'MFA_FAILURE', 'MFA_SUCCESS', 'SESSION_STARTED', 'SESSION_ENDED') NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    device_type VARCHAR(50) NOT NULL DEFAULT 'Desktop',
    user_agent VARCHAR(255) NOT NULL DEFAULT 'Unknown Browser',
    resource VARCHAR(255) NOT NULL DEFAULT '/login',
    session_id VARCHAR(64) NULL,
    risk_level ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'LOW',
    risk_score INT NOT NULL DEFAULT 5, -- 0 to 100
    status ENUM('SAFE', 'MONITORING', 'SUSPICIOUS', 'ALERT', 'CRITICAL_ALERT') NOT NULL DEFAULT 'SAFE',
    failure_reason VARCHAR(255) NULL,
    triggered_rules TEXT NULL, -- JSON array of rule codes
    raw_metadata TEXT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE CASCADE,
    INDEX idx_auth_app_id (application_id),
    INDEX idx_auth_timestamp (timestamp),
    INDEX idx_auth_user (username_identifier),
    INDEX idx_auth_ip (source_ip),
    INDEX idx_auth_result (authentication_result),
    INDEX idx_auth_risk (risk_level, risk_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- 4. SESSIONS TABLE (Active and historical sessions reported by apps)
-- ----------------------------------------------------------------------------
CREATE TABLE sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    application_id VARCHAR(32) NOT NULL,
    username_identifier VARCHAR(100) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    device_type VARCHAR(50) NOT NULL DEFAULT 'Desktop',
    user_agent VARCHAR(255) NOT NULL DEFAULT 'Unknown Browser',
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    logout_time TIMESTAMP NULL DEFAULT NULL,
    duration_seconds INT NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE CASCADE,
    INDEX idx_sessions_app (application_id),
    INDEX idx_sessions_user (username_identifier),
    INDEX idx_sessions_ip (source_ip),
    INDEX idx_sessions_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- 5. SECURITY_RULES TABLE (Configurable detection rules and signal weights)
-- ----------------------------------------------------------------------------
CREATE TABLE security_rules (
    rule_id INT AUTO_INCREMENT PRIMARY KEY,
    rule_code VARCHAR(40) NOT NULL UNIQUE,
    rule_name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    signal_type VARCHAR(50) NOT NULL,
    default_weight INT NOT NULL DEFAULT 10,
    current_weight INT NOT NULL DEFAULT 10,
    risk_level ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    logical_expression VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_rules_code (rule_code),
    INDEX idx_rules_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- 6. RISK_SCORES TABLE (Detailed signal contribution breakdown per event)
-- ----------------------------------------------------------------------------
CREATE TABLE risk_scores (
    score_id INT AUTO_INCREMENT PRIMARY KEY,
    event_id INT NOT NULL,
    application_id VARCHAR(32) NOT NULL,
    result_penalty INT NOT NULL DEFAULT 0,
    failed_attempts_penalty INT NOT NULL DEFAULT 0,
    unknown_account_penalty INT NOT NULL DEFAULT 0,
    username_variety_penalty INT NOT NULL DEFAULT 0,
    frequency_penalty INT NOT NULL DEFAULT 0,
    resource_penalty INT NOT NULL DEFAULT 0,
    previous_risk_penalty INT NOT NULL DEFAULT 0,
    total_score INT NOT NULL,
    risk_level ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES authentication_events(event_id) ON DELETE CASCADE,
    FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE CASCADE,
    INDEX idx_scores_event (event_id),
    INDEX idx_scores_level (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- 7. ALERTS TABLE (High and Critical security incidents flagged by engine)
-- ----------------------------------------------------------------------------
CREATE TABLE alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    application_id VARCHAR(32) NOT NULL,
    event_id INT NULL,
    risk_level ENUM('HIGH', 'CRITICAL') NOT NULL,
    risk_score INT NOT NULL,
    title VARCHAR(150) NOT NULL,
    description TEXT NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    accounts_attempted INT NOT NULL DEFAULT 1,
    failed_attempts INT NOT NULL DEFAULT 0,
    triggered_rules TEXT NOT NULL, -- JSON array of rules
    status ENUM('OPEN', 'INVESTIGATING', 'RESOLVED', 'DISMISSED') NOT NULL DEFAULT 'OPEN',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL DEFAULT NULL,
    investigator_notes TEXT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES authentication_events(event_id) ON DELETE SET NULL,
    INDEX idx_alerts_app (application_id),
    INDEX idx_alerts_risk (risk_level),
    INDEX idx_alerts_status (status),
    INDEX idx_alerts_ip (source_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- 8. ALERT_EVENTS TABLE (Associates an incident with its historical events)
-- ----------------------------------------------------------------------------
CREATE TABLE alert_events (
    alert_id INT NOT NULL,
    event_id INT NOT NULL,
    sequence_order INT NOT NULL DEFAULT 1,
    PRIMARY KEY (alert_id, event_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES authentication_events(event_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- 9. AUDIT_LOGS TABLE (Platform administrative actions and key rotations)
-- ----------------------------------------------------------------------------
CREATE TABLE audit_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(60) NOT NULL,
    actor VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id VARCHAR(100) NOT NULL,
    details TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- 10. USERS TABLE (Internal SENTINEL SOC analysts & application owners)
-- ----------------------------------------------------------------------------
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('ADMIN', 'ANALYST', 'APP_OWNER') NOT NULL DEFAULT 'ANALYST',
    application_id VARCHAR(32) NULL, -- Scoped for APP_OWNER role
    department VARCHAR(60) NOT NULL DEFAULT 'Cybersecurity SOC',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id) REFERENCES applications(application_id) ON DELETE SET NULL,
    INDEX idx_users_username (username),
    INDEX idx_users_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
