-- SENTINEL Platform Sample Data Seeding Script (MySQL 8.0+)
-- NOTE: Contains NO password columns for authentication events!

USE sentinel_soc;

-- Applications
INSERT INTO applications (application_id, name, url, app_type, owner_email, environment, status) VALUES ('APP_001', 'College Portal', 'https://portal.apexuniversity.edu', 'Portal', 'admin@apex.edu', 'Production', 'ACTIVE');
INSERT INTO applications (application_id, name, url, app_type, owner_email, environment, status) VALUES ('APP_002', 'E-Commerce Website', 'https://shop.aurorastore.com', 'Web Application', 'secops@aurora.com', 'Production', 'ACTIVE');
INSERT INTO applications (application_id, name, url, app_type, owner_email, environment, status) VALUES ('APP_003', 'Company Portal', 'https://intranet.novacorp.internal', 'Portal', 'it@novacorp.com', 'Production', 'ACTIVE');
INSERT INTO applications (application_id, name, url, app_type, owner_email, environment, status) VALUES ('APP_004', 'Mobile Application', 'https://api.novafinance.app/mobile', 'Mobile Application', 'dev@novafinance.app', 'Production', 'ACTIVE');
INSERT INTO applications (application_id, name, url, app_type, owner_email, environment, status) VALUES ('APP_005', 'Customer Website', 'https://portal.skylinecloud.io', 'Website', 'cloud-ops@skylinecloud.io', 'Production', 'ACTIVE');

-- API Clients
INSERT INTO api_clients (application_id, api_key, api_secret_hash, api_secret_preview) VALUES ('APP_001', 'sen_live_9b4a8e109f2d431c', 'c6a229d01fc630c1df0991a11cd1829dbe88d43b432aad6bfb50297812de7b5a', 'sec_live_...2b5e');
INSERT INTO api_clients (application_id, api_key, api_secret_hash, api_secret_preview) VALUES ('APP_002', 'sen_live_7c3f19e482da510b', 'f4983959885f674229dbbb538808c81b4fa65c5d9dfb3a5c0073ce0b04380cbc', 'sec_live_...3c6f');
INSERT INTO api_clients (application_id, api_key, api_secret_hash, api_secret_preview) VALUES ('APP_003', 'sen_live_4a2d80c391eb621a', 'c7d68b8a7f819109374e7c02d183ee33612dd00fd6f660535feb5ff2be648d8e', 'sec_live_...4d7a');
INSERT INTO api_clients (application_id, api_key, api_secret_hash, api_secret_preview) VALUES ('APP_004', 'sen_live_1f9b72d804ac532e', 'ed0023a76a105017df5da6701bfa8127b4159087de43e0b3e12260457f10c39f', 'sec_live_...5e8b');
INSERT INTO api_clients (application_id, api_key, api_secret_hash, api_secret_preview) VALUES ('APP_005', 'sen_live_6e8a51b913cd743f', '47ce2c88b6d17cae7c3d3817c50e697936e19f9b3422ac99b20c80992e0e84bd', 'sec_live_...6f9c');

-- Security Rules
INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression) VALUES ('RULE-001', 'Repeated Authentication Failures', 'Multiple consecutive failed attempts from the same entity', 'FAILED_ATTEMPTS', 25, 25, 'HIGH', 'P_fails >= 5');
INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression) VALUES ('RULE-002', 'Multiple Account Identifiers', 'Rapid account enumeration or credential probing from single origin', 'USERNAME_VARIETY', 35, 35, 'CRITICAL', 'P_distinct_users >= 4');
INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression) VALUES ('RULE-003', 'Abnormal Request Frequency', 'High velocity login attempts exceeding normal human thresholds', 'FREQUENCY', 25, 25, 'HIGH', 'P_velocity > 10_req_per_min');
INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression) VALUES ('RULE-004', 'Brute Force Success (Account Takeover)', 'Successful login following multiple failed attempts from same origin', 'BRUTE_FORCE_SUCCESS', 35, 35, 'CRITICAL', 'P_success_after_high_fails');
INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression) VALUES ('RULE-005', 'Restricted Resource Probing', 'Authentication attempts directly targeting high-privilege/admin endpoints', 'RESTRICTED_RESOURCE', 30, 30, 'HIGH', 'P_resource IN (/admin, /root, /portal-admin)');
INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression) VALUES ('RULE-006', 'High-Risk Source IP Reputation', 'Originating IP has known proxy/tor/malicious threat reputation', 'PREVIOUS_RISK', 30, 30, 'HIGH', 'P_ip_reputation >= 75');
INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression) VALUES ('RULE-007', 'Off-Hours Authentication Failures', 'Failed logins observed during anomalous off-work hours (23:00-05:00)', 'OFF_HOURS', 20, 20, 'MEDIUM', 'P_hour IN (23..5) AND P_fails >= 3');
INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression) VALUES ('RULE-008', 'MFA Challenge Failure Burst', 'Repeated secondary factor verification rejections', 'MFA_FAILURE', 25, 25, 'HIGH', 'P_mfa_fails >= 2');
INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression) VALUES ('RULE-009', 'Unknown Account Identifier', 'Attempted authentication against non-existent account identifier', 'UNKNOWN_ACCOUNT', 10, 10, 'LOW', 'P_result == UNKNOWN_ACCOUNT');
INSERT INTO security_rules (rule_code, rule_name, description, signal_type, default_weight, current_weight, risk_level, logical_expression) VALUES ('RULE-010', 'Single Transient Failure', 'Isolated incorrect credential without suspicious frequency or pattern', 'SINGLE_FAILURE', 10, 10, 'LOW', 'P_result == FAILURE AND P_fails == 1');

-- SOC Users
INSERT INTO users (username, email, password_hash, role, application_id, department) VALUES ('analyst', 'analyst@sentinel.sec', 'e9b3176bf243b4f90f16f2a19ccc522bda5695334c8ef8c2267149dad6e884e0', 'ANALYST', NULL, 'Tier 1 SOC');
INSERT INTO users (username, email, password_hash, role, application_id, department) VALUES ('lead_admin', 'admin@sentinel.sec', '3f44ca205d98876207409cd5dd4ddbc975d34e25935bb20f64cc35163b9b0910', 'ADMIN', NULL, 'SOC Management');
INSERT INTO users (username, email, password_hash, role, application_id, department) VALUES ('college_owner', 'admin@apex.edu', '91c327bd3edb21448a2dab7be0ac7c7c75a4527409e47692b44fca99eca70970', 'APP_OWNER', 'APP_001', 'College IT Admin');
INSERT INTO users (username, email, password_hash, role, application_id, department) VALUES ('store_owner', 'secops@aurora.com', 'b40bed44d4d13dd0985ddc39eb871802ac315ced0870dfc5d7a4292ec897382b', 'APP_OWNER', 'APP_002', 'E-Commerce SecOps');

