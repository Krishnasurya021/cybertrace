# SENTINEL — Universal Authentication Security & Access Log Monitoring Platform

![SENTINEL SOC Banner](https://img.shields.io/badge/Security-Universal%20SOC%20Platform-00f2fe?style=for-the-badge)
![Zero Password](https://img.shields.io/badge/Privacy-Zero%20Password%20Architecture-10b981?style=for-the-badge)
![Python](https://img.shields.io/badge/Runtime-Python%203.9+-3b82f6?style=for-the-badge)
![Java](https://img.shields.io/badge/OOPJ-Java%20%2B%20Spring%20Boot-f59e0b?style=for-the-badge)
![DBMS](https://img.shields.io/badge/DBMS-MySQL%20%2F%20SQLite%203NF-ef4444?style=for-the-badge)

**SENTINEL** is a commercial-grade, real-world oriented Cybersecurity Security Operations Center (SOC) platform designed to allow **any external website, portal, or web application** to securely connect its authentication system without sharing administrative passwords. 

SENTINEL ingests authentication **event metadata only**, analyzes behavioral patterns, computes multi-signal risk scores, detects brute-force attacks and account enumeration, and provides visual telemetry, live incident alerts, an interactive investigation workbench, and an ADSA 5-tier access graph.

---

## 🛡️ Core Security Architecture & Privacy Guarantee

> [!IMPORTANT]
> **STRICT ZERO-PASSWORD ARCHITECTURE:**
> 1. **SENTINEL NEVER asks for, receives, stores, displays, or processes passwords.**
> 2. The external website remains 100% responsible for verifying user credentials.
> 3. SENTINEL receives **authentication event metadata only** (`username_identifier`, `source_ip`, `authentication_result`, `timestamp`, `device_type`, `resource`).
> 4. Any API request containing a password field is automatically rejected with `HTTP 400 Bad Request` (`SECURITY_PASSWORD_REJECTED`).

---

## 🚀 Quick Start Instructions

The system requires **zero external pip or npm packages** — it runs directly out-of-the-box using the built-in Python 3 standard runtime:

```bash
# 1. Initialize the 3NF Database & Seed 5 Applications (Pre-seeded sentinel.db included)
python3 database/db_init.py

# 2. Launch the High-Performance Full-Stack SOC Console & REST API
python3 app.py 8000
```

Open your browser and navigate to:
👉 **[http://localhost:8000](http://localhost:8000)**

---

## 🎬 Official 32-Step Evaluation & Demonstration Flow

Follow this exact demonstration script to showcase SENTINEL to evaluators:

1. **Open SENTINEL Web Console**: Navigate to `http://localhost:8000`.
2. **3D Security Login Experience**:
   - Observe the 3D rotating security shield, cyber rings, laser scanner, and background particles.
   - Click **INITIALIZE SECURITY CENTER ➔**.
   - Watch the multi-step authentication sequence:
     `AUTHENTICATING` $\to$ `VERIFYING SESSION` $\to$ `LOADING SECURITY CENTER` $\to$ `INITIALIZING MONITOR` $\to$ `SECURITY CENTER READY`.
3. **SENTINEL SOC Dashboard Overview**:
   - Verify the 7 top KPI cards:
     - **CONNECTED APPS**: 5
     - **TOTAL EVENTS**: 509+
     - **SUCCESS**: ~428
     - **FAILED**: ~48
     - **UNKNOWN**: ~21
     - **SUSPICIOUS**: ~12
     - **HIGH RISK ALERTS**: 3
4. **Multi-Application Selector**:
   - Filter dropdown at top: Select `College Portal (APP_001)`.
   - Observe charts and live event tables instantly adjust to College Portal.
5. **Role-Based Perspective Switcher (RBAC)**:
   - Switch from **SECURITY ADMIN (GLOBAL)** to **APPLICATION OWNER**.
   - Verify view scope restricts strictly to the owner's registered application.
6. **Demo Center — Step 1: SIMULATE SAFE LOGIN**:
   - Click the green button **🟢 SAFE LOGIN** on the floating controller.
   - User: `john123`, Result: `SUCCESS`, IP: `192.0.2.55`.
   - Result: `🟢 SAFE`, Risk Score: `5/100` (`LOW`).
   - Reason: *"Successful authentication with no significant suspicious indicators."*
7. **Demo Center — Step 2: SIMULATE WRONG PASSWORD**:
   - Click the yellow button **🟡 WRONG PASSWORD**.
   - User: `john123`, Result: `FAILURE`, IP: `192.0.2.56`.
   - Result: `🟡 FAILED`, Risk Score: `15/100` (`LOW`, `MONITORING`).
   - Reason: *"Authentication failed. No significant suspicious pattern detected."*
   - **Critical Principle Demonstrated:** One wrong password is NOT classified as a cyber attack.
8. **Demo Center — Step 3: SIMULATE UNKNOWN USER**:
   - Click **🟡 UNKNOWN USER**.
   - User: `fake_admin_123`, Result: `UNKNOWN_ACCOUNT`, IP: `192.0.2.57`.
   - Result: `🟡 UNKNOWN ACCOUNT`, Risk Score: `15-20/100` (`LOW`, `SUSPICIOUS`).
   - Reason: *"Account identifier was not recognized. Monitoring continues."*
9. **Demo Center — Step 4: SIMULATE REPEATED FAILURES**:
   - Click **🟠 REPEATED FAILURES**.
   - User: `prof_sharma`, Result: 5 rapid failures from `198.51.100.42`.
   - Result: `🟠 SUSPICIOUS / ALERT`, Risk Score: `65/100` (`HIGH`).
   - Triggered Rule: `RULE-001` (Repeated Authentication Failures).
10. **Demo Center — Step 5: SIMULATE MULTIPLE USERNAMES (Account Enumeration)**:
    - Click **🔴 MULTIPLE USERNAMES**.
    - Target: `192.0.2.10` rapidly attempts `admin`, `administrator`, `root`, `manager`, `superadmin`, `test`, `fakeuser`.
    - Result: `🔴 HIGH RISK`, Risk Score: `88/100` (`CRITICAL`).
    - **LIVE SECURITY ALERT POPS UP** with siren animation!
11. **Live Security Alert Modal**:
    - Observe the modal showing Application, Source IP `192.0.2.10`, 7 Accounts Attempted, 7 Failures, Triggered Rules (`RULE-001`, `RULE-002`, `RULE-003`).
    - Click **INVESTIGATE INCIDENT ➔**.
12. **Alert Investigation Workbench**:
    - Observe the **Chronological Authentication Timeline** showing the exact sequence of 7 probes.
    - Read the **Pattern Detected** box: *"Multiple account identifiers were attempted from the same source within a short period."*
    - Inspect **ADSA Blast Radius** and resolve the incident.
13. **ADSA Access Pattern Graph**:
    - Click **ADSA Access Graph** in the sidebar.
    - Observe the 5-tier topology: `APPLICATION ➔ SOURCE IP ➔ USERNAME ➔ SESSION ➔ RESOURCE`.
    - Click **Run BFS Traversal** to explore blast radius.
    - Click **Run DFS Traversal** to explore penetration trajectory.
14. **Security Entity Analysis**:
    - Click **Entity Analysis**, search for `192.0.2.10`.
    - View total attempts, failed count, calculated risk score (88/100), and history.
15. **Connect Your Application & API Tester**:
    - Click **Connect Your App**.
    - Fill in the form: "Apex Portal", "https://portal.apex.edu", "Production", "admin@apex.edu".
    - Click Register $\to$ View generated Application ID, API Key, and Secret.
    - In the **Live API Tester**, click **Inject Password (Test Security Rejection)**.
    - Verify SENTINEL strictly rejects the password with `HTTP 400 Bad Request`.

---

## ⚖️ Multi-Signal Mathematical Risk Engine

SENTINEL combines 8 distinct mathematical signals:

| Signal | Evaluation Condition | Risk Penalty | Triggered Rule |
| :--- | :--- | :--- | :--- |
| **Authentication Result** | `FAILURE` / `UNKNOWN_ACCOUNT` | `+10` | `RULE-010` / `RULE-009` |
| **MFA Rejection** | `MFA_FAILURE` | `+20` | `RULE-008` |
| **Failure Velocity** | $\ge 5$ failures in 10 mins | `+25` | `RULE-001` |
| **Severe Failure Burst** | $\ge 10$ failures in 10 mins | `+40` | `RULE-001` |
| **Account Enumeration** | $\ge 4$ distinct usernames from IP | `+35` | `RULE-002` |
| **Severe Enumeration** | $\ge 7$ distinct usernames from IP | `+50` | `RULE-002` |
| **Request Velocity Spike** | $> 10$ requests / minute | `+25` | `RULE-003` |
| **Privilege Target** | Endpoint contains `/admin`, `/root`, `/keys` | `+30` | `RULE-005` |
| **Threat Origin** | Prior alerts from IP in past 24h | `+30` | `RULE-006` |
| **Account Takeover** | `SUCCESS` immediately after $\ge 4$ failures | `+35` | `RULE-004` |
| **Temporal Anomaly** | Off-hours (23:00 - 05:00) with failures | `+20` | `RULE-007` |

### Classification Tiers
- **0–24**: `LOW` (Status: `SAFE` or `MONITORING`)
- **25–49**: `MEDIUM` (Status: `SUSPICIOUS`)
- **50–74**: `HIGH` (Status: `ALERT`)
- **75–100**: `CRITICAL` (Status: `CRITICAL ALERT`)

---

## 📁 Repository Structure

```
SENTINEL/
├── app.py                     # High-performance full-stack server & REST API
├── frontend/                  # Modern Cybersecurity SOC Web Console
│   ├── index.html             # Master unified SOC platform & 3D login
│   ├── login.html             # Dedicated 3D security login page
│   ├── dashboard.html         # Dedicated SOC dashboard view
│   ├── integration.html       # Application connection portal & API tester
│   ├── alerts.html            # Incident monitoring & live alert modal
│   ├── investigation.html     # Threat investigation workbench & timeline
│   ├── applications.html      # Connected applications registry
│   ├── access-graph.html      # ADSA access pattern graph visualizer
│   ├── css/
│   │   └── style.css          # Curated SOC dark glassmorphism design system
│   └── js/
│       ├── app.js             # State manager, router, role perspective switcher
│       ├── login.js           # 3D canvas particles & multi-stage login sequence
│       ├── dashboard.js       # KPI metrics & SVG telemetry charts
│       ├── simulator.js       # 6-scenario Demo Center controller
│       ├── integration.js     # App registration & password rejection tester
│       ├── alerts.js          # Real-time alert streamer & animated modal
│       ├── investigation.js   # Incident timeline & blast radius inspector
│       ├── entity-analysis.js # Username & IP threat profiling
│       ├── access-graph.js    # Canvas 5-tier network graph engine
│       ├── rules.js           # Configurable risk weights & sliders
│       └── statistical.js     # Z-score statistical analysis lab
├── backend/
│   └── spring-boot/           # Full Java Spring Boot enterprise application
│       ├── pom.xml
│       └── src/main/java/com/sentinel/
├── java/src/com/sentinel/     # OOPJ Core Classes (11 classes demonstrating OOP)
│   ├── models/                # Application, ApiClient, AuthenticationEvent, RiskScore...
│   ├── analyzer/              # RiskAnalyzer, AlertManager, LogAnalyzer...
│   ├── graph/                 # GraphManager, AccessGraph, GraphNode...
│   └── Main.java              # Java runner demonstrating OOP & ADSA
├── analytics/python/          # Python statistical anomaly microservice
│   └── analytics_service.py   # /analytics/analyze endpoint (Mean, Median, StdDev, Z-score)
├── database/
│   ├── schema.sql             # MySQL 3NF normalized DDL (10 tables, no passwords)
│   ├── sentinel_schema.sql    # Mirror schema
│   ├── sample_data.sql        # 500+ realistic SQL insert statements
│   ├── db_init.py             # Database seed & generator script
│   └── sentinel.db            # Pre-seeded local zero-config SQLite database
├── docs/
│   ├── INTEGRATION_GUIDE.md   # Developer guide for external website owners
│   └── VIVA_GUIDE.md          # 20-point comprehensive viva voce defense guide
└── README.md
```

---

## 🎓 Academic Discipline Mapping

| Discipline | Implementation in SENTINEL |
| :--- | :--- |
| **DBMS** | 3NF normalized 10-table schema (`applications`, `api_clients`, `authentication_events`, `sessions`, `security_rules`, `risk_scores`, `alerts`, `alert_events`, `audit_logs`, `users`). B-Tree indexes for high-throughput querying. **Strictly zero password columns.** |
| **DMGT** | Formal propositional logic propositions ($P_1 \dots P_{10}$) with compound conjunctions and disjunctions determining risk levels. |
| **ADSA** | 5-tier graph topology (`APPLICATION ➔ IP ➔ USER ➔ SESSION ➔ RESOURCE`). Adjacency list representation, Breadth-First Search (BFS) for blast radius, Depth-First Search (DFS) for attack trajectories, and degree counting. |
| **OOPJ** | Enterprise Java architecture: `Application`, `ApiClient`, `AuthenticationEvent`, `RiskAnalyzer`, `RiskScore`, `SecurityRule`, `Alert`, `AlertManager`, `Session`, `LogAnalyzer`, `GraphManager`. Demonstrates encapsulation, polymorphism, inheritance, and exception handling. |
| **Python** | Statistical anomaly detection calculating sample Mean ($\mu$), Median, Standard Deviation ($\sigma$), and Z-Scores ($z = (x - \mu)/\sigma$) to identify statistical outliers without inspecting credentials. |
| **Cybersecurity** | SOC operations center, credential stuffing detection, account enumeration pattern recognition, blast radius triage, and cryptographic API credential rotation. |

---

## 🛡️ License
Educational & Professional Cybersecurity Product — Built for defensive monitoring, academic viva defense, and enterprise access log auditing.
