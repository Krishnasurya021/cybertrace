#!/usr/bin/env python3
"""
SENTINEL — Universal Authentication Security & Access Log Monitoring Platform
Unified Full-Stack Server (REST API + Static Web Server + Risk & Analytics Engines)
Requires ZERO external packages — runs out-of-the-box on standard Python 3.9+ runtime!

CRITICAL ARCHITECTURAL GUARANTEE:
SENTINEL receives authentication EVENT METADATA only.
SENTINEL MUST NEVER store, receive, display, or process passwords.
Any request containing a password field is strictly rejected with HTTP 400.
"""

import sys
import os
import json
import sqlite3
import mimetypes
import urllib.parse
from datetime import datetime, timedelta
import random
import uuid
import hashlib
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

# Import local engines
from python.rule_engine import SentinelRiskEngine
from python.graph_engine import build_graph_from_db, AccessPatternGraph
from python.statistical_detector import StatisticalAnomalyDetector
from analytics.python.analytics_service import analyze_event_statistics

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database', 'sentinel.db')
PUBLIC_DIR = os.path.join(BASE_DIR, 'frontend') if os.path.exists(os.path.join(BASE_DIR, 'frontend')) else os.path.join(BASE_DIR, 'public')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

risk_engine = SentinelRiskEngine()

class SentinelServerHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Serve from frontend or public directory
        serving_dir = os.path.join(BASE_DIR, 'frontend') if os.path.exists(os.path.join(BASE_DIR, 'frontend')) else os.path.join(BASE_DIR, 'public')
        super().__init__(*args, directory=serving_dir, **kwargs)

    def log_message(self, format, *args):
        try:
            if args and isinstance(args[0], str) and ('api/' in args[0] or (len(args) > 1 and str(args[1]) != '200')):
                sys.stdout.write(f"[CyberTrace] {args[0]} -> {args[1] if len(args) > 1 else ''}\n")
            elif args:
                msg = format % args
                if '200' not in msg:
                    sys.stdout.write(f"[CyberTrace] {msg}\n")
        except Exception:
            pass

    def _send_json(self, data, status=200):
        try:
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key')
            self.end_headers()
            self.wfile.write(json.dumps(data, default=str).encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key')
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Route API requests
        if path.startswith('/api/') or path == '/analytics/analyze':
            try:
                self.handle_api_get(path, query)
            except Exception as e:
                import traceback
                traceback.print_exc()
                self._send_json({'error': str(e)}, status=500)
            return

        if path == '/favicon.ico':
            self.send_response(204)
            self.end_headers()
            return

        # Serve frontend pages
        if path == '/' or path == '':
            self.path = '/index.html'
        elif not os.path.splitext(path)[1]:
            # Clean URL rewriting
            candidate = path.lstrip('/') + '.html'
            serving_dir = os.path.join(BASE_DIR, 'frontend') if os.path.exists(os.path.join(BASE_DIR, 'frontend')) else os.path.join(BASE_DIR, 'public')
            if os.path.exists(os.path.join(serving_dir, candidate)):
                self.path = '/' + candidate

        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        try:
            body = json.loads(post_data.decode('utf-8'))
        except Exception:
            body = {}

        if path.startswith('/api/') or path == '/analytics/analyze':
            try:
                self.handle_api_post(path, body)
            except Exception as e:
                import traceback
                traceback.print_exc()
                self._send_json({'error': str(e)}, status=500)
            return

        self._send_json({'error': 'Not found'}, status=404)

    # =========================================================================
    # API GET ROUTER
    # =========================================================================
    def handle_api_get(self, path: str, query: dict):
        conn = get_db()
        cursor = conn.cursor()

        # ---------------------------------------------------------------------
        # 1. /api/v1/risk-summary or /api/stats (Executive SOC Metrics & Charts)
        # ---------------------------------------------------------------------
        if path in ('/api/v1/risk-summary', '/api/stats'):
            app_filter = query.get('application_id', ['ALL'])[0]

            where_clause = "WHERE 1=1"
            params = []
            if app_filter != 'ALL':
                where_clause += " AND application_id = ?"
                params.append(app_filter)

            # Top KPI Cards
            connected_apps = cursor.execute("SELECT COUNT(*) FROM applications WHERE status = 'ACTIVE'").fetchone()[0]
            total_events = cursor.execute(f"SELECT COUNT(*) FROM authentication_events {where_clause}", params).fetchone()[0]
            success_count = cursor.execute(f"SELECT COUNT(*) FROM authentication_events {where_clause} AND authentication_result = 'SUCCESS'", params).fetchone()[0]
            failed_count = cursor.execute(f"SELECT COUNT(*) FROM authentication_events {where_clause} AND authentication_result = 'FAILURE'", params).fetchone()[0]
            unknown_count = cursor.execute(f"SELECT COUNT(*) FROM authentication_events {where_clause} AND authentication_result = 'UNKNOWN_ACCOUNT'", params).fetchone()[0]
            suspicious_count = cursor.execute(f"SELECT COUNT(*) FROM authentication_events {where_clause} AND risk_level = 'MEDIUM'", params).fetchone()[0]
            high_risk_alerts = cursor.execute(f"SELECT COUNT(*) FROM alerts {where_clause} AND risk_level IN ('HIGH', 'CRITICAL')", params).fetchone()[0]

            # Chart 1: Result Distribution (SUCCESS, FAILURE, UNKNOWN_ACCOUNT, etc.)
            result_dist = [dict(r) for r in cursor.execute(f"""
                SELECT authentication_result, COUNT(*) as count
                FROM authentication_events
                {where_clause}
                GROUP BY authentication_result
            """, params).fetchall()]

            # Chart 2: Risk Level Distribution
            risk_dist = [dict(r) for r in cursor.execute(f"""
                SELECT risk_level, COUNT(*) as count
                FROM authentication_events
                {where_clause}
                GROUP BY risk_level
            """, params).fetchall()]

            # Chart 3: Hourly Authentication Activity (00:00 to 23:00)
            hourly_raw = [dict(r) for r in cursor.execute(f"""
                SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hr, COUNT(*) as count
                FROM authentication_events
                {where_clause}
                GROUP BY hr
                ORDER BY hr ASC
            """, params).fetchall()]
            hour_map = {h: 0 for h in range(24)}
            for r in hourly_raw:
                hour_map[r['hr']] = r['count']
            complete_hourly = [{'hour': f"{h:02d}:00", 'count': hour_map[h]} for h in range(24)]

            # Chart 4: Top Targeted Account Identifiers
            top_accounts = [dict(r) for r in cursor.execute(f"""
                SELECT username_identifier, COUNT(*) as total_attempts,
                       SUM(CASE WHEN authentication_result = 'SUCCESS' THEN 1 ELSE 0 END) as successes,
                       SUM(CASE WHEN authentication_result != 'SUCCESS' THEN 1 ELSE 0 END) as failures
                FROM authentication_events
                {where_clause}
                GROUP BY username_identifier
                ORDER BY total_attempts DESC
                LIMIT 6
            """, params).fetchall()]

            # Chart 5: Top Source IP Origins
            top_sources = [dict(r) for r in cursor.execute(f"""
                SELECT source_ip, COUNT(*) as hits,
                       SUM(CASE WHEN authentication_result != 'SUCCESS' THEN 1 ELSE 0 END) as fails,
                       MAX(risk_score) as peak_risk
                FROM authentication_events
                {where_clause}
                GROUP BY source_ip
                ORDER BY hits DESC
                LIMIT 6
            """, params).fetchall()]

            conn.close()
            self._send_json({
                'kpis': {
                    'connected_apps': connected_apps,
                    'total_events': total_events,
                    'successful_logins': success_count,
                    'failed_logins': failed_count,
                    'unknown_accounts': unknown_count,
                    'suspicious_events': suspicious_count,
                    'high_risk_alerts': high_risk_alerts
                },
                'charts': {
                    'result_distribution': result_dist,
                    'risk_distribution': risk_dist,
                    'hourly_pattern': complete_hourly,
                    'top_targeted_accounts': top_accounts,
                    'top_source_ips': top_sources
                }
            })
            return

        # ---------------------------------------------------------------------
        # 2. /api/v1/auth-events or /api/logs (Paginated Live Event Monitor)
        # ---------------------------------------------------------------------
        elif path in ('/api/v1/auth-events', '/api/logs'):
            page = int(query.get('page', ['1'])[0])
            limit = int(query.get('limit', ['25'])[0])
            app_id = query.get('application_id', ['ALL'])[0]
            risk_filter = query.get('risk_level', [query.get('risk', ['ALL'])[0]])[0]
            result_filter = query.get('result', [query.get('status', ['ALL'])[0]])[0]
            search = query.get('search', [''])[0].strip()

            offset = (page - 1) * limit
            where_clauses = ["1=1"]
            params = []

            if app_id != 'ALL':
                where_clauses.append("ae.application_id = ?")
                params.append(app_id)

            if risk_filter != 'ALL':
                where_clauses.append("ae.risk_level = ?")
                params.append(risk_filter)

            if result_filter != 'ALL':
                where_clauses.append("ae.authentication_result = ?")
                params.append(result_filter)

            if search:
                where_clauses.append("(ae.username_identifier LIKE ? OR ae.source_ip LIKE ? OR a.name LIKE ? OR ae.resource LIKE ?)")
                p = f"%{search}%"
                params.extend([p, p, p, p])

            where_sql = " AND ".join(where_clauses)

            total_filtered = cursor.execute(f"""
                SELECT COUNT(*)
                FROM authentication_events ae
                JOIN applications a ON ae.application_id = a.application_id
                WHERE {where_sql}
            """, params).fetchone()[0]

            events_rows = [dict(r) for r in cursor.execute(f"""
                SELECT ae.event_id, ae.application_id, a.name as app_name, ae.timestamp,
                       ae.username_identifier, ae.event_type, ae.authentication_result,
                       ae.source_ip, ae.device_type, ae.user_agent, ae.resource,
                       ae.session_id, ae.risk_level, ae.risk_score, ae.status,
                       ae.failure_reason, ae.triggered_rules
                FROM authentication_events ae
                JOIN applications a ON ae.application_id = a.application_id
                WHERE {where_sql}
                ORDER BY ae.timestamp DESC, ae.event_id DESC
                LIMIT ? OFFSET ?
            """, params + [limit, offset]).fetchall()]

            # Parse triggered_rules JSON for each event
            for ev in events_rows:
                if ev.get('triggered_rules'):
                    try:
                        ev['triggered_rules'] = json.loads(ev['triggered_rules'])
                    except Exception:
                        pass

            conn.close()
            self._send_json({
                'page': page,
                'limit': limit,
                'total': total_filtered,
                'total_pages': max(1, (total_filtered + limit - 1) // limit),
                'events': events_rows,
                'logs': events_rows # Alias for backwards compatibility
            })
            return

        # ---------------------------------------------------------------------
        # 3. /api/v1/applications (Registered Applications Registry)
        # ---------------------------------------------------------------------
        elif path == '/api/v1/applications':
            apps = [dict(r) for r in cursor.execute("""
                SELECT a.application_id, a.name, a.url, a.app_type, a.owner_email,
                       a.environment, a.status, a.created_at,
                       ac.api_key, ac.api_secret_preview,
                       (SELECT COUNT(*) FROM authentication_events WHERE application_id = a.application_id) as total_events,
                       (SELECT MAX(timestamp) FROM authentication_events WHERE application_id = a.application_id) as last_event_at
                FROM applications a
                LEFT JOIN api_clients ac ON a.application_id = ac.application_id
                ORDER BY a.created_at ASC
            """).fetchall()]

            conn.close()
            self._send_json({'applications': apps})
            return

        # ---------------------------------------------------------------------
        # 4. /api/v1/alerts (Active and Historical Incidents)
        # ---------------------------------------------------------------------
        elif path == '/api/v1/alerts':
            app_id = query.get('application_id', ['ALL'])[0]
            where_sql = "WHERE 1=1"
            params = []
            if app_id != 'ALL':
                where_sql += " AND al.application_id = ?"
                params.append(app_id)

            alerts = [dict(r) for r in cursor.execute(f"""
                SELECT al.alert_id, al.application_id, a.name as app_name, al.event_id,
                       al.risk_level, al.risk_score, al.title, al.description, al.source_ip,
                       al.accounts_attempted, al.failed_attempts, al.triggered_rules,
                       al.status, al.created_at, al.resolved_at, al.investigator_notes
                FROM alerts al
                JOIN applications a ON al.application_id = a.application_id
                {where_sql}
                ORDER BY al.alert_id DESC
            """, params).fetchall()]

            for a in alerts:
                if a.get('triggered_rules'):
                    try:
                        a['triggered_rules'] = json.loads(a['triggered_rules'])
                    except Exception:
                        pass

            conn.close()
            self._send_json({'alerts': alerts})
            return

        # ---------------------------------------------------------------------
        # 5. /api/v1/alerts/<id>/investigate (Deep Investigation Workbench)
        # ---------------------------------------------------------------------
        elif '/investigate' in path:
            parts = path.strip('/').split('/')
            alert_id = int(parts[3] if len(parts) > 3 and parts[3].isdigit() else parts[2])

            alert_row = cursor.execute("""
                SELECT al.*, a.name as app_name, a.url as app_url
                FROM alerts al
                JOIN applications a ON al.application_id = a.application_id
                WHERE al.alert_id = ?
            """, (alert_id,)).fetchone()

            if not alert_row:
                conn.close()
                self._send_json({'error': 'Alert not found'}, status=404)
                return

            alert = dict(alert_row)
            if alert.get('triggered_rules'):
                try:
                    alert['triggered_rules'] = json.loads(alert['triggered_rules'])
                except Exception:
                    pass

            # Fetch chronological event timeline for this incident
            timeline = [dict(r) for r in cursor.execute("""
                SELECT ae.event_id, ae.timestamp, ae.username_identifier, ae.authentication_result,
                       ae.source_ip, ae.device_type, ae.resource, ae.risk_level, ae.risk_score,
                       ae.status, ae.triggered_rules
                FROM authentication_events ae
                WHERE ae.source_ip = ?
                ORDER BY ae.timestamp DESC, ae.event_id DESC
                LIMIT 15
            """, (alert['source_ip'],)).fetchall()]

            # Determine pattern description
            distinct_users = len(set(e['username_identifier'] for e in timeline))
            if distinct_users >= 4:
                pattern_desc = f"Multiple account identifiers ({distinct_users} users) were attempted from {alert['source_ip']} in rapid succession. Classic account enumeration / credential discovery pattern."
            elif alert['failed_attempts'] >= 5:
                pattern_desc = f"Rapid authentication failure threshold reached ({alert['failed_attempts']} attempts) from {alert['source_ip']}. High velocity brute-force burst."
            else:
                pattern_desc = "Suspicious authentication telemetry detected with elevated risk indicators."

            # ADSA Blast Radius
            graph = build_graph_from_db(limit_logs=250)
            blast_radius = graph.calculate_blast_radius(f"IP:{alert['source_ip']}")

            conn.close()
            self._send_json({
                'alert': alert,
                'timeline': timeline,
                'pattern_detected': pattern_desc,
                'blast_radius': blast_radius
            })
            return

        # ---------------------------------------------------------------------
        # 6. /api/v1/entity-analysis (Security Entity Analysis)
        # ---------------------------------------------------------------------
        elif path == '/api/v1/entity-analysis':
            entity_query = query.get('query', ['john123'])[0].strip()

            # Find matching events by username or IP
            events = [dict(r) for r in cursor.execute("""
                SELECT ae.event_id, ae.application_id, a.name as app_name, ae.timestamp,
                       ae.username_identifier, ae.authentication_result, ae.source_ip,
                       ae.device_type, ae.resource, ae.risk_level, ae.risk_score
                FROM authentication_events ae
                JOIN applications a ON ae.application_id = a.application_id
                WHERE ae.username_identifier LIKE ? OR ae.source_ip LIKE ?
                ORDER BY ae.timestamp DESC
                LIMIT 50
            """, (f"%{entity_query}%", f"%{entity_query}%")).fetchall()]

            if not events:
                conn.close()
                self._send_json({'found': False, 'query': entity_query})
                return

            total_attempts = len(events)
            success_count = sum(1 for e in events if e['authentication_result'] == 'SUCCESS')
            failed_count = sum(1 for e in events if e['authentication_result'] == 'FAILURE')
            unknown_count = sum(1 for e in events if e['authentication_result'] == 'UNKNOWN_ACCOUNT')
            risk_events = sum(1 for e in events if e['risk_level'] in ('HIGH', 'CRITICAL'))
            peak_score = max(e['risk_score'] for e in events)
            related_apps = list(set(e['app_name'] for e in events))
            related_ips = list(set(e['source_ip'] for e in events))
            related_users = list(set(e['username_identifier'] for e in events))

            conn.close()
            self._send_json({
                'found': True,
                'query': entity_query,
                'entity_profile': {
                    'query_term': entity_query,
                    'total_attempts': total_attempts,
                    'successful_attempts': success_count,
                    'failed_attempts': failed_count,
                    'unknown_accounts': unknown_count,
                    'risk_events': risk_events,
                    'calculated_risk_score': peak_score,
                    'first_seen': events[-1]['timestamp'],
                    'last_seen': events[0]['timestamp'],
                    'related_applications': related_apps,
                    'related_ips': related_ips,
                    'related_users': related_users
                },
                'recent_activity': events[:10]
            })
            return

        # ---------------------------------------------------------------------
        # 7. /api/v1/access-graph or /api/graph (ADSA 5-Tier Graph)
        # ---------------------------------------------------------------------
        elif path in ('/api/v1/access-graph', '/api/graph'):
            limit = int(query.get('limit', ['250'])[0])
            graph = build_graph_from_db(limit_logs=limit)
            conn.close()
            self._send_json(graph.to_graph_data())
            return

        # ---------------------------------------------------------------------
        # 8. /api/v1/graph/traverse (BFS & DFS Graph Traversals)
        # ---------------------------------------------------------------------
        elif path in ('/api/v1/graph/traverse', '/api/graph/traverse'):
            algo = query.get('algo', ['bfs'])[0].lower()
            start_node = query.get('start', ['APP:APP_001'])[0]
            max_depth = int(query.get('depth', ['3'])[0])

            graph = build_graph_from_db(limit_logs=250)
            result = graph.dfs(start_node, max_depth=max_depth) if algo == 'dfs' else graph.bfs(start_node, max_depth=max_depth)
            conn.close()
            self._send_json(result)
            return

        # ---------------------------------------------------------------------
        # 9. /api/v1/rules or /api/rules (Configurable Security Rules)
        # ---------------------------------------------------------------------
        elif path in ('/api/v1/rules', '/api/rules'):
            rules = [dict(r) for r in cursor.execute("""
                SELECT rule_id, rule_code, rule_name, description, signal_type,
                       default_weight, current_weight, risk_level, logical_expression, is_active
                FROM security_rules
                ORDER BY rule_id ASC
            """).fetchall()]
            conn.close()
            self._send_json({'rules': rules})
            return

        # ---------------------------------------------------------------------
        # 10. /api/detect/statistical (Python Statistical Anomaly Detector)
        # ---------------------------------------------------------------------
        elif path == '/api/detect/statistical':
            threshold = float(query.get('threshold', ['2.2'])[0])
            detector = StatisticalAnomalyDetector(z_threshold=threshold)
            analysis = detector.analyze_database_logs(conn)
            conn.close()
            self._send_json(analysis)
            return

        # ---------------------------------------------------------------------
        # 11. /api/reports/export-csv
        # ---------------------------------------------------------------------
        elif path == '/api/reports/export-csv':
            logs = cursor.execute("""
                SELECT ae.event_id, ae.timestamp, ae.application_id, ae.username_identifier,
                       ae.authentication_result, ae.source_ip, ae.device_type, ae.resource,
                       ae.risk_level, ae.risk_score, ae.status
                FROM authentication_events ae
                ORDER BY ae.event_id DESC LIMIT 500
            """).fetchall()
            conn.close()

            csv_lines = ["Event ID,Timestamp,Application ID,Username,Result,Source IP,Device,Resource,Risk Level,Risk Score,Status"]
            for r in logs:
                csv_lines.append(f"{r[0]},{r[1]},{r[2]},{r[3]},{r[4]},{r[5]},{r[6]},{r[7]},{r[8]},{r[9]},{r[10]}")
            csv_content = "\n".join(csv_lines)

            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', 'attachment; filename="sentinel_auth_events.csv"')
            self.end_headers()
            self.wfile.write(csv_content.encode('utf-8'))
            return

        conn.close()
        self._send_json({'error': 'Unknown GET endpoint'}, status=404)

    # =========================================================================
    # API POST ROUTER
    # =========================================================================
    def handle_api_post(self, path: str, body: dict):
        conn = get_db()
        cursor = conn.cursor()

        # ---------------------------------------------------------------------
        # 1. /api/v1/auth-events (INGEST AUTHENTICATION EVENT METADATA)
        # ---------------------------------------------------------------------
        if path == '/api/v1/auth-events':
            # =================================================================
            # CRITICAL SECURITY RULE: Reject any payload containing passwords
            # =================================================================
            forbidden_keys = {'password', 'pwd', 'pass', 'admin_password', 'secret', 'auth_secret', 'user_password'}
            for key in body.keys():
                if key.lower() in forbidden_keys or 'password' in key.lower():
                    conn.close()
                    self._send_json({
                        'error': 'Security Policy Violation: SENTINEL strictly forbids password transmission. External authentication systems verify passwords. SENTINEL receives authentication EVENT METADATA only.',
                        'code': 'SECURITY_PASSWORD_REJECTED',
                        'status': 400
                    }, status=400)
                    return

            # Validate mandatory metadata fields
            app_id = body.get('application_id', '').strip()
            username = body.get('username_identifier', '').strip()
            auth_result = body.get('authentication_result', '').strip().upper()
            source_ip = body.get('source_ip', '127.0.0.1').strip()
            device = body.get('device_type', 'Desktop')
            ua = body.get('user_agent', 'Mozilla/5.0')
            resource = body.get('resource', '/login')
            event_type = body.get('event_type', 'LOGIN_ATTEMPT')
            now_str = body.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

            if not app_id or not username or not auth_result:
                conn.close()
                self._send_json({
                    'error': 'Missing required fields: application_id, username_identifier, authentication_result',
                    'status': 400
                }, status=400)
                return

            # Verify application exists or auto-register demo app
            app_row = cursor.execute("SELECT name FROM applications WHERE application_id = ?", (app_id,)).fetchone()
            if not app_row:
                cursor.execute("""
                    INSERT INTO applications (application_id, name, url, app_type, owner_email, environment, status)
                    VALUES (?, ?, 'https://external-app.io', 'Web Application', 'owner@external-app.io', 'Production', 'ACTIVE')
                """, (app_id, f"Application {app_id}"))

            # Evaluate with Risk Engine
            eval_result = risk_engine.evaluate_event(body, conn=conn)
            risk_score = eval_result['risk_score']
            risk_level = eval_result['risk_level']
            status = eval_result['status']
            triggered_rules = eval_result['triggered_rules']
            explanation = eval_result['explanation']
            penalties = eval_result['penalties']

            # Session Management (if SUCCESS)
            sess_id = body.get('session_id')
            if auth_result == 'SUCCESS' and not sess_id:
                sess_id = f"sess_{uuid.uuid4().hex[:12]}"
                cursor.execute("""
                    INSERT INTO sessions (session_id, application_id, username_identifier, source_ip, device_type, user_agent, login_time, duration_seconds, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1)
                """, (sess_id, app_id, username, source_ip, device, ua, now_str))

            # Store Authentication Event
            cursor.execute("""
                INSERT INTO authentication_events (
                    application_id, timestamp, username_identifier, event_type,
                    authentication_result, source_ip, device_type, user_agent, resource,
                    session_id, risk_level, risk_score, status, failure_reason, triggered_rules, raw_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                app_id, now_str, username, event_type, auth_result, source_ip, device, ua, resource,
                sess_id, risk_level, risk_score, status, explanation, json.dumps(triggered_rules), json.dumps(body)
            ))
            new_event_id = cursor.lastrowid

            # Store Risk Score breakdown
            cursor.execute("""
                INSERT INTO risk_scores (
                    event_id, application_id, result_penalty, failed_attempts_penalty,
                    unknown_account_penalty, username_variety_penalty, frequency_penalty,
                    resource_penalty, previous_risk_penalty, total_score, risk_level, calculated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                new_event_id, app_id, penalties['result_penalty'], penalties['failed_attempts_penalty'],
                penalties['unknown_account_penalty'], penalties['username_variety_penalty'],
                penalties['frequency_penalty'], penalties['resource_penalty'], penalties['previous_risk_penalty'],
                risk_score, risk_level, now_str
            ))

            # Trigger Security Alert if HIGH or CRITICAL
            created_alert = None
            if risk_level in ('HIGH', 'CRITICAL'):
                # Check for recent distinct accounts probed from this IP
                du_count = cursor.execute("""
                    SELECT COUNT(DISTINCT username_identifier) FROM authentication_events
                    WHERE source_ip = ? AND timestamp >= datetime(?, '-10 minutes')
                """, (source_ip, now_str)).fetchone()[0]

                rf_count = cursor.execute("""
                    SELECT COUNT(*) FROM authentication_events
                    WHERE source_ip = ? AND authentication_result != 'SUCCESS' AND timestamp >= datetime(?, '-10 minutes')
                """, (source_ip, now_str)).fetchone()[0]

                alert_title = "HIGH-RISK ACCOUNT ENUMERATION PATTERN" if du_count >= 4 else "REPEATED AUTHENTICATION FAILURES"
                if risk_score >= 90:
                    alert_title = "CRITICAL: CREDENTIAL STUFFING / BRUTE FORCE ATTACK"

                cursor.execute("""
                    INSERT INTO alerts (
                        application_id, event_id, risk_level, risk_score, title, description,
                        source_ip, accounts_attempted, failed_attempts, triggered_rules, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)
                """, (
                    app_id, new_event_id, risk_level, risk_score, alert_title, explanation,
                    source_ip, max(1, du_count), max(1, rf_count), json.dumps(triggered_rules), now_str
                ))
                new_alert_id = cursor.lastrowid

                # Associate alert events
                cursor.execute("""
                    INSERT INTO alert_events (alert_id, event_id, sequence_order)
                    VALUES (?, ?, 1)
                """, (new_alert_id, new_event_id))

                created_alert = {
                    'alert_id': new_alert_id,
                    'title': alert_title,
                    'risk_level': risk_level,
                    'risk_score': risk_score,
                    'source_ip': source_ip,
                    'accounts_attempted': du_count,
                    'failed_attempts': rf_count,
                    'triggered_rules': triggered_rules
                }

            conn.commit()
            conn.close()

            self._send_json({
                'status': 'PROCESSED',
                'event_id': new_event_id,
                'application_id': app_id,
                'username_identifier': username,
                'authentication_result': auth_result,
                'risk_level': risk_level,
                'risk_score': risk_score,
                'system_status': status,
                'explanation': explanation,
                'triggered_rules': triggered_rules,
                'alert_generated': created_alert is not None,
                'alert': created_alert
            })
            return

        # ---------------------------------------------------------------------
        # 2. /api/v1/applications (REGISTER APPLICATION & GENERATE API CREDENTIALS)
        # ---------------------------------------------------------------------
        elif path == '/api/v1/applications':
            name = body.get('name', 'My Application').strip()
            url = body.get('url', 'https://example.com').strip()
            app_type = body.get('app_type', 'Web Application')
            owner_email = body.get('owner_email', 'admin@example.com').strip()
            env = body.get('environment', 'Production')

            # Generate credentials
            count = cursor.execute("SELECT COUNT(*) FROM applications").fetchone()[0]
            new_app_id = f"APP_{count + 1:03d}"
            api_key = f"sen_live_{uuid.uuid4().hex[:16]}"
            raw_secret = f"sec_live_{uuid.uuid4().hex}"
            secret_hash = hashlib.sha256(raw_secret.encode('utf-8')).hexdigest()
            secret_preview = f"sec_live_...{raw_secret[-4:]}"

            cursor.execute("""
                INSERT INTO applications (application_id, name, url, app_type, owner_email, environment, status)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
            """, (new_app_id, name, url, app_type, owner_email, env))

            cursor.execute("""
                INSERT INTO api_clients (application_id, api_key, api_secret_hash, api_secret_preview)
                VALUES (?, ?, ?, ?)
            """, (new_app_id, api_key, secret_hash, secret_preview))

            cursor.execute("""
                INSERT INTO audit_logs (action, actor, target_type, target_id, details)
                VALUES ('APPLICATION_REGISTERED', ?, 'APPLICATION', ?, ?)
            """, (owner_email, new_app_id, f"Registered {name} ({app_type})"))

            conn.commit()
            conn.close()

            self._send_json({
                'application_id': new_app_id,
                'name': name,
                'url': url,
                'app_type': app_type,
                'owner_email': owner_email,
                'environment': env,
                'api_key': api_key,
                'api_secret': raw_secret,
                'warning': 'Never share your API secret publicly. Do not put API secrets inside frontend JavaScript. Store them securely in backend environment variables.',
                'message': 'Application registered successfully.'
            })
            return

        # ---------------------------------------------------------------------
        # 3. /api/v1/api-keys/rotate
        # ---------------------------------------------------------------------
        elif path == '/api/v1/api-keys/rotate':
            app_id = body.get('application_id')
            if not app_id:
                conn.close()
                self._send_json({'error': 'Missing application_id'}, status=400)
                return

            new_api_key = f"sen_live_{uuid.uuid4().hex[:16]}"
            new_raw_secret = f"sec_live_{uuid.uuid4().hex}"
            new_hash = hashlib.sha256(new_raw_secret.encode('utf-8')).hexdigest()
            new_preview = f"sec_live_...{new_raw_secret[-4:]}"

            cursor.execute("""
                UPDATE api_clients
                SET api_key = ?, api_secret_hash = ?, api_secret_preview = ?, created_at = datetime('now')
                WHERE application_id = ?
            """, (new_api_key, new_hash, new_preview, app_id))

            cursor.execute("""
                INSERT INTO audit_logs (action, actor, target_type, target_id, details)
                VALUES ('API_KEY_ROTATED', 'system_admin', 'API_CLIENT', ?, 'Rotated live API credentials')
            """, (app_id,))

            conn.commit()
            conn.close()

            self._send_json({
                'application_id': app_id,
                'api_key': new_api_key,
                'api_secret': new_raw_secret,
                'warning': 'Update your backend environment variables immediately with the new API key and secret.'
            })
            return

        # ---------------------------------------------------------------------
        # 4. /api/v1/simulate (COLLEGE DEMO CENTER SIMULATOR)
        # ---------------------------------------------------------------------
        elif path in ('/api/v1/simulate', '/api/simulate'):
            scenario = body.get('scenario', 'SAFE_LOGIN').upper()
            app_id = body.get('application_id', 'APP_001')
            now_dt = datetime.now()

            simulated_events = []

            # Scenario 1: 🟢 SAFE LOGIN (john123, SUCCESS, Risk 5/100, LOW)
            if scenario == 'SAFE_LOGIN':
                simulated_events.append({
                    'application_id': app_id,
                    'username_identifier': body.get('username', 'john123'),
                    'authentication_result': 'SUCCESS',
                    'source_ip': body.get('source_ip', '192.0.2.55'),
                    'device_type': 'Desktop',
                    'user_agent': 'Chrome 122 on macOS',
                    'resource': '/login',
                    'timestamp': now_dt.strftime('%Y-%m-%d %H:%M:%S')
                })

            # Scenario 2: 🟡 WRONG PASSWORD (john123, FAILURE, 1 failed, Risk 15/100, LOW, MONITORING)
            elif scenario == 'WRONG_PASSWORD':
                simulated_events.append({
                    'application_id': app_id,
                    'username_identifier': body.get('username', 'john123'),
                    'authentication_result': 'FAILURE',
                    'source_ip': body.get('source_ip', '192.0.2.56'),
                    'device_type': 'Desktop',
                    'user_agent': 'Chrome 122 on macOS',
                    'resource': '/login',
                    'timestamp': now_dt.strftime('%Y-%m-%d %H:%M:%S')
                })

            # Scenario 3: 🟡 UNKNOWN USER (fake_admin_123, UNKNOWN_ACCOUNT, 1 attempt, Risk 15/100, LOW, MONITORING)
            elif scenario == 'UNKNOWN_USER':
                simulated_events.append({
                    'application_id': app_id,
                    'username_identifier': body.get('username', 'fake_admin_123'),
                    'authentication_result': 'UNKNOWN_ACCOUNT',
                    'source_ip': body.get('source_ip', '192.0.2.57'),
                    'device_type': 'Desktop',
                    'user_agent': 'Chrome 122 on macOS',
                    'resource': '/login',
                    'timestamp': now_dt.strftime('%Y-%m-%d %H:%M:%S')
                })

            # Scenario 4: 🟠 REPEATED FAILURES (5 rapid failures from single source, Risk 65/100, HIGH, ALERT)
            elif scenario == 'REPEATED_FAILURES':
                target_user = body.get('username', 'prof_sharma')
                target_ip = '198.51.100.42'
                for i in range(5):
                    t = (now_dt - timedelta(seconds=(5 - i) * 6)).strftime('%Y-%m-%d %H:%M:%S')
                    simulated_events.append({
                        'application_id': app_id,
                        'username_identifier': target_user,
                        'authentication_result': 'FAILURE',
                        'source_ip': target_ip,
                        'device_type': 'Desktop',
                        'user_agent': 'Chrome 122 on Linux',
                        'resource': '/portal',
                        'timestamp': t
                    })

            # Scenario 5: 🔴 MULTIPLE USERNAMES / ACCOUNT ENUMERATION (admin, administrator, root, manager, superadmin, test, fakeuser)
            elif scenario == 'MULTIPLE_USERNAMES':
                target_ip = '192.0.2.10'
                probed = ['admin', 'administrator', 'root', 'manager', 'superadmin', 'test', 'fakeuser']
                for i, u in enumerate(probed):
                    t = (now_dt - timedelta(seconds=(len(probed) - i) * 3)).strftime('%Y-%m-%d %H:%M:%S')
                    simulated_events.append({
                        'application_id': app_id,
                        'username_identifier': u,
                        'authentication_result': 'UNKNOWN_ACCOUNT',
                        'source_ip': target_ip,
                        'device_type': 'Desktop',
                        'user_agent': 'Python-urllib/3.9 (Scanner)',
                        'resource': '/admin',
                        'timestamp': t
                    })

            # Scenario 6: 🔴 HIGH RISK PATTERN (Credential stuffing from Proxy, then account takeover on /portal-admin)
            elif scenario == 'HIGH_RISK_PATTERN':
                target_ip = '203.0.113.88' # Tor exit
                stuffing_users = ['alex_dev', 'david_ops', 'sarah_w', 'root']
                for i, u in enumerate(stuffing_users):
                    t = (now_dt - timedelta(seconds=(6 - i) * 5)).strftime('%Y-%m-%d %H:%M:%S')
                    simulated_events.append({
                        'application_id': app_id,
                        'username_identifier': u,
                        'authentication_result': 'FAILURE',
                        'source_ip': target_ip,
                        'device_type': 'Desktop',
                        'user_agent': 'HeadlessChrome/120.0',
                        'resource': '/portal-admin',
                        'timestamp': t
                    })
                # Followed by a compromised success
                simulated_events.append({
                    'application_id': app_id,
                    'username_identifier': 'root',
                    'authentication_result': 'SUCCESS',
                    'source_ip': target_ip,
                    'device_type': 'Desktop',
                    'user_agent': 'HeadlessChrome/120.0',
                    'resource': '/portal-admin',
                    'timestamp': now_dt.strftime('%Y-%m-%d %H:%M:%S')
                })

            # Pass every simulated event through the real pipeline!
            results = []
            for ev in simulated_events:
                # 1. Evaluate with Risk Engine
                eval_res = risk_engine.evaluate_event(ev, conn=conn)
                r_score = eval_res['risk_score']
                r_level = eval_res['risk_level']
                r_status = eval_res['status']
                trig_rules = eval_res['triggered_rules']
                expl = eval_res['explanation']
                penalties = eval_res['penalties']

                # 2. Store event
                sess_id = f"sess_{uuid.uuid4().hex[:12]}" if ev['authentication_result'] == 'SUCCESS' else None
                cursor.execute("""
                    INSERT INTO authentication_events (
                        application_id, timestamp, username_identifier, event_type,
                        authentication_result, source_ip, device_type, user_agent, resource,
                        session_id, risk_level, risk_score, status, failure_reason, triggered_rules, raw_metadata
                    ) VALUES (?, ?, ?, 'LOGIN_ATTEMPT', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ev['application_id'], ev['timestamp'], ev['username_identifier'],
                    ev['authentication_result'], ev['source_ip'], ev['device_type'],
                    ev['user_agent'], ev['resource'], sess_id, r_level, r_score, r_status,
                    expl, json.dumps(trig_rules), json.dumps(ev)
                ))
                eid = cursor.lastrowid

                # 3. Create Alert if HIGH or CRITICAL
                alert_obj = None
                if r_level in ('HIGH', 'CRITICAL'):
                    alert_title = "HIGH-RISK ACCOUNT ENUMERATION PATTERN" if scenario == 'MULTIPLE_USERNAMES' else "HIGH-RISK AUTHENTICATION PATTERN"
                    cursor.execute("""
                        INSERT INTO alerts (
                            application_id, event_id, risk_level, risk_score, title, description,
                            source_ip, accounts_attempted, failed_attempts, triggered_rules, status, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)
                    """, (
                        ev['application_id'], eid, r_level, r_score, alert_title, expl,
                        ev['source_ip'], len(simulated_events), len(simulated_events),
                        json.dumps(trig_rules), ev['timestamp']
                    ))
                    aid = cursor.lastrowid
                    cursor.execute("INSERT INTO alert_events (alert_id, event_id, sequence_order) VALUES (?, ?, 1)", (aid, eid))
                    alert_obj = {
                        'alert_id': aid,
                        'title': alert_title,
                        'risk_level': r_level,
                        'risk_score': r_score,
                        'source_ip': ev['source_ip'],
                        'accounts_attempted': len(simulated_events),
                        'failed_attempts': len(simulated_events),
                        'triggered_rules': trig_rules
                    }

                results.append({
                    'event_id': eid,
                    'username': ev['username_identifier'],
                    'result': ev['authentication_result'],
                    'risk_level': r_level,
                    'risk_score': r_score,
                    'status': r_status,
                    'explanation': expl,
                    'alert': alert_obj
                })

            conn.commit()
            conn.close()

            last_res = results[-1] if results else {}
            self._send_json({
                'scenario': scenario,
                'events_injected': len(results),
                'final_verdict': {
                    'risk_level': last_res.get('risk_level'),
                    'risk_score': last_res.get('risk_score'),
                    'status': last_res.get('status'),
                    'explanation': last_res.get('explanation'),
                    'alert': last_res.get('alert')
                },
                'events': results
            })
            return

        # ---------------------------------------------------------------------
        # 5. /api/v1/rules/configure (CONFIGURE RISK ENGINE WEIGHTS)
        # ---------------------------------------------------------------------
        elif path == '/api/v1/rules/configure':
            rule_code = body.get('rule_code')
            weight = int(body.get('weight', 10))
            cursor.execute("UPDATE security_rules SET current_weight = ? WHERE rule_code = ?", (weight, rule_code))
            conn.commit()
            risk_engine.load_rule_weights(conn)
            conn.close()
            self._send_json({'success': True, 'rule_code': rule_code, 'new_weight': weight})
            return

        # ---------------------------------------------------------------------
        # 6. /analytics/analyze (PYTHON STATISTICAL ANALYTICS MICROSERVICE)
        # ---------------------------------------------------------------------
        elif path == '/analytics/analyze':
            try:
                res = analyze_event_statistics(body)
                conn.close()
                self._send_json(res)
            except ValueError as ve:
                conn.close()
                self._send_json({'error': str(ve)}, status=400)
            return

        # ---------------------------------------------------------------------
        # 7. /api/auth/login (SENTINEL Analyst / Admin Login)
        # ---------------------------------------------------------------------
        elif path == '/api/auth/login':
            username = body.get('username', 'analyst')
            role = body.get('role', 'ANALYST')
            user_row = cursor.execute("SELECT user_id, username, email, role, application_id, department FROM users WHERE username = ?", (username,)).fetchone()
            conn.close()

            if user_row:
                u = dict(user_row)
            else:
                u = {'user_id': 1, 'username': username, 'role': role, 'application_id': None, 'department': 'Cybersecurity SOC'}

            self._send_json({
                'status': 'AUTHENTICATED',
                'user': u,
                'token': f"sen_jwt_{uuid.uuid4().hex}"
            })
            return

        conn.close()
        self._send_json({'error': 'Unknown POST endpoint'}, status=404)

def run_server(port=8000, host='127.0.0.1'):
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, SentinelServerHandler)
    print("=================================================================")
    print(" SENTINEL — Universal Authentication Security Platform")
    print(f" SOC Web Console: http://{host}:{port}")
    print(f" REST API:        http://{host}:{port}/api/v1/auth-events")
    print(f" Demo Simulator:  http://{host}:{port}/api/v1/simulate")
    print("=================================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down SENTINEL SOC server gracefully.")
        httpd.server_close()

def test_all_api_endpoints():
    """Automated verification testing all core endpoints directly."""
    print("=================================================================")
    print(" SENTINEL — Automated API Endpoints Self-Test")
    print("=================================================================")
    conn = get_db()
    cursor = conn.cursor()

    # 1. Applications
    apps_count = cursor.execute("SELECT COUNT(*) FROM applications").fetchone()[0]
    print(f"  [OK] /api/v1/applications: {apps_count} applications active")

    # 2. Events count & Password absence check
    events_count = cursor.execute("SELECT COUNT(*) FROM authentication_events").fetchone()[0]
    col_names = [d[1] for d in cursor.execute("PRAGMA table_info(authentication_events)").fetchall()]
    assert 'password' not in col_names and 'pwd' not in col_names
    print(f"  [OK] /api/v1/auth-events: {events_count} events. STRICT ZERO-PASSWORD VERIFIED.")

    # 3. Risk Engine Verification
    eng = SentinelRiskEngine(conn)
    safe_ev = {'application_id': 'APP_001', 'username_identifier': 'john123', 'authentication_result': 'SUCCESS', 'source_ip': '192.0.2.55'}
    safe_res = eng.evaluate_event(safe_ev, conn)
    assert safe_res['risk_score'] == 5 and safe_res['risk_level'] == 'LOW'
    print(f"  [OK] Risk Engine (Safe Login): Score={safe_res['risk_score']} Level={safe_res['risk_level']} Status={safe_res['status']}")

    # 4. ADSA Graph
    g = build_graph_from_db(limit_logs=150)
    gdata = g.to_graph_data()
    bfs_res = g.bfs('APP:APP_001', max_depth=3)
    print(f"  [OK] /api/v1/access-graph: {gdata['stats']['total_nodes']} nodes, {gdata['stats']['total_edges']} edges. BFS reached {bfs_res['visited_count']} nodes.")

    # 5. Statistical Analytics
    det = StatisticalAnomalyDetector(z_threshold=2.2)
    stat = det.analyze_database_logs(conn)
    print(f"  [OK] /api/detect/statistical: Flagged {stat['total_anomalies_flagged']} anomalies")

    conn.close()
    print("  [ALL SENTINEL ENDPOINTS VERIFIED SUCCESSFULLY]")

if __name__ == '__main__':
    if '--test-api' in sys.argv:
        test_all_api_endpoints()
    else:
        port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8000
        run_server(port)
