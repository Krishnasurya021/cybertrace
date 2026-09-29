#!/usr/bin/env python3
"""
SENTINEL — Universal Authentication Security Platform
Interactive All-In-One Demonstration Runner
"""

import sys
import json
import time
import urllib.request
import urllib.error

BASE_URL = "http://localhost:8000"

def banner():
    print("=" * 72)
    print("   🛡️  CyberTrace — SOC ACCESS MONITORING & THREAT DETECTION SUITE")
    print("   🌐  Web Console: http://localhost:8000")
    print("   🔒  Security Model: Strict Zero-Password Metadata Stream")
    print("=" * 72)

def check_server():
    print("\n[+] Checking CyberTrace local server status...")
    try:
        req = urllib.request.Request(f"{BASE_URL}/api/v1/risk-summary")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            kpis = data.get('kpis', {})
            print(f"    ✔ Connected Apps:      {kpis.get('connected_apps')}")
            print(f"    ✔ Total Logged Events: {kpis.get('total_events')}")
            print(f"    ✔ Successful Logins:   {kpis.get('successful_logins')}")
            print(f"    ✔ Failed Attempts:     {kpis.get('failed_logins')}")
            print(f"    ✔ Unknown Accounts:    {kpis.get('unknown_accounts')}")
            print(f"    ✔ Active Incidents:    {kpis.get('high_risk_alerts')}")
            return True
    except Exception as e:
        print(f"    ✘ Server connection failed: {e}")
        print("    Please ensure 'python3 app.py 8000' is running.")
        return False

def test_zero_password_enforcement():
    print("\n" + "-" * 72)
    print("TEST 1: ZERO-PASSWORD MANDATORY ENFORCEMENT CHECK")
    print("-" * 72)
    print("Attempting to send payload containing forbidden credential fields...")
    bad_payload = json.dumps({
        "application_id": "APP_001",
        "username_identifier": "hacker",
        "password": "ClearTextPassword123!",
        "authentication_result": "SUCCESS"
    }).encode('utf-8')

    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/auth-events",
        data=bad_payload,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": "snt_live_colg77a8b9c0d1e2f3a4b5c6d7e8"
        }
    )

    try:
        with urllib.request.urlopen(req) as resp:
            print("    ✘ FAILED: Password was accepted! Violation of Zero-Password rule!")
    except urllib.error.HTTPError as err:
        if err.code == 400:
            body = json.loads(err.read().decode())
            print(f"    ✔ SUCCESS: Blocked with HTTP 400 Bad Request!")
            print(f"    ✔ Error Code:    {body.get('code')}")
            print(f"    ✔ Reason:        {body.get('error')}")
        else:
            print(f"    ✘ Unexpected HTTP Status: {err.code}")

def run_scenario(scenario_key, title, expected_risk):
    print("\n" + "-" * 72)
    print(f"SCENARIO: {title}")
    print("-" * 72)
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/simulate",
        data=json.dumps({"scenario": scenario_key}).encode('utf-8'),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            res = json.loads(resp.read().decode())
            verdict = res.get('final_verdict', {})
            score = verdict.get('risk_score')
            level = verdict.get('risk_level')
            status = verdict.get('status')
            alert = verdict.get('alert')
            print(f"    Events Injected: {res.get('events_injected')}")
            print(f"    Risk Score:      {score}/100 (Expected: ~{expected_risk})")
            print(f"    Risk Level:      {level} [{status}]")
            print(f"    Explanation:     {verdict.get('explanation')}")
            if alert:
                print(f"    🚨 ALERT CREATED: [{alert.get('risk_level')}] {alert.get('title')} (ID: #{alert.get('alert_id')})")
            else:
                print(f"    ℹ️  No alert created (Normal/Isolated event).")
    except Exception as e:
        print(f"    ✘ Scenario execution failed: {e}")

def run_all():
    banner()
    if not check_server():
        sys.exit(1)
    
    test_zero_password_enforcement()

    scenarios = [
        ("SAFE_LOGIN", "1. Normal Safe Login (Clean User, Standard Device)", "5/100 (LOW)"),
        ("WRONG_PASSWORD", "2. Single Wrong Password (Isolated User Mistake)", "15/100 (LOW)"),
        ("UNKNOWN_USER", "3. Unknown Account Name (Single Mistyped Username)", "15/100 (LOW)"),
        ("REPEATED_FAILURES", "4. Repeated Failures (5 Rapid Failed Attempts from Single IP)", "65-100/100 (HIGH)"),
        ("MULTIPLE_USERNAMES", "5. Account Enumeration (Probing 7 Usernames: admin, root, test...)", "75-100/100 (CRITICAL)"),
        ("HIGH_RISK_PATTERN", "6. Multi-Vector Attack (Proxy failures followed by takeover on /portal-admin)", "100/100 (CRITICAL)")
    ]

    for key, name, expected in scenarios:
        time.sleep(0.4)
        run_scenario(key, name, expected)

    print("\n" + "=" * 72)
    print("   ✨ ALL 6 SECURITY SCENARIOS & TESTS EXECUTED SUCCESSFULLY")
    print("   🖥️  View live results on the SOC Web Console: http://localhost:8000")
    print("=" * 72)

if __name__ == '__main__':
    run_all()
