-- ============================================================================
-- SENTINEL - Intelligent Access Log Monitoring & Anomaly Detection System
-- Module: DBMS (Curriculum SQL Anomaly Detection Queries)
-- Demonstrating: JOIN, GROUP BY, HAVING, ORDER BY, Subqueries, Aggregate Functions
-- ============================================================================

USE sentinel_soc;

-- ----------------------------------------------------------------------------
-- QUERY 1: Find users with more than 5 failed login attempts
-- Concepts: JOIN, GROUP BY, HAVING, Aggregate COUNT(), Subquery / Condition
-- ----------------------------------------------------------------------------
SELECT 
    u.user_id,
    u.username,
    u.email,
    u.role,
    u.department,
    COUNT(al.log_id) AS total_failed_attempts,
    MAX(al.timestamp) AS last_failed_attempt
FROM users u
JOIN access_logs al ON u.user_id = al.user_id
WHERE al.status = 'FAILED' AND al.action LIKE '%LOGIN%'
GROUP BY u.user_id, u.username, u.email, u.role, u.department
HAVING COUNT(al.log_id) > 5
ORDER BY total_failed_attempts DESC;

-- ----------------------------------------------------------------------------
-- QUERY 2: Find suspicious IP addresses (High failure rate, proxy/VPN flag, or high risk)
-- Concepts: JOIN, CASE expression, Aggregate functions (SUM, AVG), HAVING
-- ----------------------------------------------------------------------------
SELECT 
    ip.ip_id,
    ip.ip_address,
    ip.country,
    ip.city,
    ip.risk_score,
    COUNT(al.log_id) AS total_requests,
    SUM(CASE WHEN al.status = 'FAILED' THEN 1 ELSE 0 END) AS failed_requests,
    ROUND(SUM(CASE WHEN al.status = 'FAILED' THEN 1.0 ELSE 0.0 END) / COUNT(al.log_id) * 100, 2) AS failure_percentage
FROM ip_addresses ip
JOIN access_logs al ON ip.ip_id = al.ip_id
GROUP BY ip.ip_id, ip.ip_address, ip.country, ip.city, ip.risk_score
HAVING (failed_requests >= 5 AND failure_percentage > 40.0) OR ip.risk_score >= 70
ORDER BY failure_percentage DESC, total_requests DESC;

-- ----------------------------------------------------------------------------
-- QUERY 3: Find non-admin users attempting to access restricted resources
-- Concepts: Multi-table INNER JOIN, WHERE clause filters, String pattern matching
-- ----------------------------------------------------------------------------
SELECT 
    al.log_id,
    al.timestamp,
    u.username,
    u.role AS user_role,
    r.resource_name,
    r.path AS resource_path,
    r.required_role,
    al.status,
    ip.ip_address
FROM access_logs al
JOIN users u ON al.user_id = u.user_id
JOIN resources r ON al.resource_id = r.resource_id
JOIN ip_addresses ip ON al.ip_id = ip.ip_id
WHERE r.is_restricted = TRUE 
  AND u.role != 'ADMIN'
ORDER BY al.timestamp DESC;

-- ----------------------------------------------------------------------------
-- QUERY 4: Find users with unusually long sessions
-- Concepts: Subqueries, Statistical comparison, Aggregate AVG & STDDEV, Comparison
-- ----------------------------------------------------------------------------
SELECT 
    s.session_id,
    u.username,
    u.role,
    s.login_time,
    s.logout_time,
    s.duration_seconds,
    ROUND(s.duration_seconds / 3600.0, 2) AS duration_hours,
    ip.ip_address
FROM sessions s
JOIN users u ON s.user_id = u.user_id
JOIN ip_addresses ip ON s.ip_id = ip.ip_id
WHERE s.duration_seconds > (
    -- Subquery: Dynamic threshold exceeding 2 standard deviations above the mean duration
    SELECT AVG(duration_seconds) + (1.5 * STDDEV(duration_seconds))
    FROM sessions
    WHERE duration_seconds > 0
)
ORDER BY s.duration_seconds DESC;

-- ----------------------------------------------------------------------------
-- QUERY 5: Find multiple distinct users accessing the system from the same IP address
-- Concepts: Self-referential or aggregate grouping, COUNT(DISTINCT ...), HAVING
-- (Indicates potential shared proxy, botnet proxy node, or credential stuffing)
-- ----------------------------------------------------------------------------
SELECT 
    ip.ip_address,
    ip.country,
    ip.city,
    COUNT(DISTINCT al.user_id) AS distinct_users_count,
    GROUP_CONCAT(DISTINCT u.username ORDER BY u.username SEPARATOR ', ') AS associated_users,
    COUNT(al.log_id) AS total_events
FROM access_logs al
JOIN ip_addresses ip ON al.ip_id = ip.ip_id
JOIN users u ON al.user_id = u.user_id
GROUP BY ip.ip_address, ip.country, ip.city
HAVING COUNT(DISTINCT al.user_id) > 2
ORDER BY distinct_users_count DESC;

-- ----------------------------------------------------------------------------
-- QUERY 6: Find access activity occurring during unusual/off-hours (23:00 to 05:00)
-- Concepts: Date/Time scalar functions (HOUR, TIME), Multi-table JOIN
-- ----------------------------------------------------------------------------
SELECT 
    al.log_id,
    al.timestamp,
    HOUR(al.timestamp) AS access_hour,
    u.username,
    u.department,
    r.resource_name,
    al.action,
    al.status,
    ip.ip_address
FROM access_logs al
JOIN users u ON al.user_id = u.user_id
JOIN resources r ON al.resource_id = r.resource_id
JOIN ip_addresses ip ON al.ip_id = ip.ip_id
WHERE HOUR(al.timestamp) >= 23 OR HOUR(al.timestamp) < 5
ORDER BY al.timestamp DESC;

-- ----------------------------------------------------------------------------
-- QUERY 7: Find the top most frequently accessed resources and their error counts
-- Concepts: Aggregate COUNT(), Conditional SUM(), GROUP BY, ORDER BY, LIMIT
-- ----------------------------------------------------------------------------
SELECT 
    r.resource_id,
    r.resource_name,
    r.path,
    r.classification,
    COUNT(al.log_id) AS total_hits,
    SUM(CASE WHEN al.status = 'SUCCESS' THEN 1 ELSE 0 END) AS successful_hits,
    SUM(CASE WHEN al.status != 'SUCCESS' THEN 1 ELSE 0 END) AS failed_or_blocked_hits
FROM resources r
LEFT JOIN access_logs al ON r.resource_id = al.resource_id
GROUP BY r.resource_id, r.resource_name, r.path, r.classification
ORDER BY total_hits DESC
LIMIT 10;

-- ----------------------------------------------------------------------------
-- QUERY 8: Find users with the highest number of access attempts (Velocity analysis)
-- Concepts: Aggregates, Window/Ranking or Top-N sorting, Percentage of total
-- ----------------------------------------------------------------------------
SELECT 
    u.user_id,
    u.username,
    u.role,
    u.department,
    COUNT(al.log_id) AS total_access_attempts,
    COUNT(DISTINCT al.ip_id) AS distinct_ips_used,
    COUNT(DISTINCT al.resource_id) AS distinct_resources_accessed
FROM users u
JOIN access_logs al ON u.user_id = al.user_id
GROUP BY u.user_id, u.username, u.role, u.department
ORDER BY total_access_attempts DESC
LIMIT 10;

-- ----------------------------------------------------------------------------
-- QUERY 9: Failed-login activity grouped by IP address and geographic location
-- Concepts: Multi-table JOIN, GROUP BY multiple columns, Aggregate filters
-- ----------------------------------------------------------------------------
SELECT 
    ip.ip_address,
    ip.country,
    ip.city,
    COUNT(al.log_id) AS failed_login_count,
    COUNT(DISTINCT al.user_id) AS targeted_accounts_count,
    MIN(al.timestamp) AS first_attempt,
    MAX(al.timestamp) AS latest_attempt
FROM access_logs al
JOIN ip_addresses ip ON al.ip_id = ip.ip_id
WHERE al.status = 'FAILED' AND al.action LIKE '%LOGIN%'
GROUP BY ip.ip_address, ip.country, ip.city
ORDER BY failed_login_count DESC;

-- ----------------------------------------------------------------------------
-- QUERY 10: Generate an executive daily security summary
-- Concepts: DATE() truncation, Conditional aggregates, COUNT(), nested aggregations
-- ----------------------------------------------------------------------------
SELECT 
    DATE(al.timestamp) AS log_date,
    COUNT(al.log_id) AS total_events,
    COUNT(DISTINCT al.user_id) AS active_users,
    COUNT(DISTINCT al.ip_id) AS unique_ips,
    SUM(CASE WHEN al.status = 'SUCCESS' THEN 1 ELSE 0 END) AS total_successes,
    SUM(CASE WHEN al.status = 'FAILED' THEN 1 ELSE 0 END) AS total_failures,
    ROUND(SUM(CASE WHEN al.status = 'FAILED' THEN 1.0 ELSE 0.0 END) / COUNT(al.log_id) * 100, 2) AS failure_rate_pct,
    (SELECT COUNT(*) FROM alerts a WHERE DATE(a.created_at) = DATE(al.timestamp)) AS alerts_generated
FROM access_logs al
GROUP BY DATE(al.timestamp)
ORDER BY log_date DESC;
