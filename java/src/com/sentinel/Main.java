package com.sentinel;

import com.sentinel.analyzer.LogAnalyzer;
import com.sentinel.analyzer.ReportGenerator;
import com.sentinel.exceptions.SecurityRuleViolationException;
import com.sentinel.graph.AccessGraph;
import com.sentinel.graph.GraphNode;
import com.sentinel.models.*;
import com.sentinel.strategies.RuleBasedDetector;
import com.sentinel.strategies.StatisticalDetector;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * ============================================================================
 * SENTINEL - Intelligent Access Log Monitoring & Anomaly Detection System
 * Module: OOPJ (Object-Oriented Programming in Java)
 * Engineering Demonstration Runner & Viva Showcase
 * ============================================================================
 * 
 * Demonstrates the 6 Fundamental OOP Principles:
 * 1. ENCAPSULATION: Private fields, public accessors, state validation in models.
 * 2. INHERITANCE: User -> Admin, Analyst, NormalUser.
 * 3. POLYMORPHISM: Dynamic dispatch via User.canAccess() and AnomalyDetectionStrategy.detect().
 * 4. ABSTRACTION: Abstract class User, Interface AnomalyDetectionStrategy.
 * 5. EXCEPTION HANDLING: Custom checked SecurityRuleViolationException & unchecked exceptions.
 * 6. COLLECTIONS FRAMEWORK: List, Map, Set, Queue (BFS), Stack (DFS).
 */
public class Main {

    public static void main(String[] args) {
        System.out.println("=================================================================");
        System.out.println("SENTINEL - OOPJ Core Engine & Educational Demonstration");
        System.out.println("=================================================================\n");

        // --------------------------------------------------------------------
        // DEMONSTRATION 1: INHERITANCE & POLYMORPHISM (User Hierarchy)
        // --------------------------------------------------------------------
        System.out.println(">>> [OOP 1 & 2] Demonstrating Inheritance & Polymorphism:");
        User admin = new Admin(1, "sec_admin", "admin@sentinel.soc", "SOC Operations", 10);
        User analyst = new Analyst(2, "sarah_analyst", "sarah@sentinel.soc", "Threat Intel", "LEVEL_3");
        User regularUser = new NormalUser(3, "alice_dev", "alice@corp.internal", "Engineering");

        Resource publicPortal = new Resource(1, "Portal Home", "/index.html", "PUBLIC", false, "USER");
        Resource restrictedVault = new Resource(2, "Vault Master Key", "/vault/keys/export", "CONFIDENTIAL", true, "ADMIN");

        List<User> userList = new ArrayList<>();
        userList.add(admin);
        userList.add(analyst);
        userList.add(regularUser);

        for (User u : userList) {
            System.out.printf("  * Polymorphic Dispatch for User: %-15s (Role: %-7s)\n", u.getUsername(), u.getRole());
            System.out.printf("      Can access Public Portal:     %b\n", u.canAccess(publicPortal));
            System.out.printf("      Can access Restricted Vault:  %b\n", u.canAccess(restrictedVault));
            System.out.printf("      Granted Permissions:          %s\n", u.getPermissions());
        }

        // --------------------------------------------------------------------
        // DEMONSTRATION 2: INTERFACES & STRATEGY PATTERN (Anomaly Detection)
        // --------------------------------------------------------------------
        System.out.println("\n>>> [OOP 3 & 4] Demonstrating Abstraction & Strategy Pattern:");
        
        IPAddress cleanIp = new IPAddress(1, "192.168.1.10", "United States", "New York", false, false, 5);
        IPAddress attackerIp = new IPAddress(2, "185.220.101.5", "Russia", "Tor Exit", true, true, 95);

        Session session1 = new Session(101, regularUser, cleanIp, "tok_101", LocalDateTime.now().minusHours(1), 1800, true);
        Session sessionAttacker = new Session(102, regularUser, attackerIp, "tok_102", LocalDateTime.now().minusHours(2), 300, false);

        List<AccessLog> sampleLogs = new ArrayList<>();
        // Normal log
        sampleLogs.add(new AccessLog(1, session1, regularUser, cleanIp, publicPortal, 
            LocalDateTime.now().minusMinutes(40), "GET", "PAGE_VIEW", "SUCCESS", 0, 200, 35));
        
        // Brute force attacks
        for (int i = 1; i <= 7; i++) {
            sampleLogs.add(new AccessLog(i + 1, sessionAttacker, regularUser, attackerIp, publicPortal,
                LocalDateTime.now().minusMinutes(20 - i), "POST", "USER_LOGIN", "FAILED", i, 401, 120));
        }

        // Unauthorized restricted access attempt
        sampleLogs.add(new AccessLog(9, session1, regularUser, cleanIp, restrictedVault,
            LocalDateTime.now().minusMinutes(5), "GET", "KEY_EXPORT", "BLOCKED", 0, 403, 20));

        // Initialize Analyzer with Strategy 1: DMGT Rule-Based Detector
        LogAnalyzer analyzer = new LogAnalyzer(new RuleBasedDetector());
        analyzer.addLogs(sampleLogs);
        List<Alert> ruleAlerts = analyzer.runAnalysis();
        System.out.printf("  Rule-Based Strategy produced %d alerts.\n", ruleAlerts.size());
        for (Alert a : ruleAlerts) {
            System.out.printf("    - [%s] %s: %s\n", a.getRiskLevel(), a.getTitle(), a.getDescription());
        }

        // Switch to Strategy 2 dynamically: Statistical Detector (Polymorphic replacement)
        System.out.println("\n  Dynamically switching strategy to Statistical Z-Score Detector...");
        analyzer.setDetectionStrategy(new StatisticalDetector(2.0));
        List<Alert> statAlerts = analyzer.runAnalysis();
        System.out.printf("  Statistical Strategy produced %d alerts.\n", statAlerts.size());
        for (Alert a : statAlerts) {
            System.out.printf("    - [%s] %s: %s\n", a.getRiskLevel(), a.getTitle(), a.getDescription());
        }

        // --------------------------------------------------------------------
        // DEMONSTRATION 3: CUSTOM EXCEPTION HANDLING
        // --------------------------------------------------------------------
        System.out.println("\n>>> [OOP 5] Demonstrating Custom Exception Handling:");
        try {
            System.out.println("  Evaluating critical policy on Restricted Resource access by NormalUser...");
            if (!regularUser.canAccess(restrictedVault)) {
                throw new SecurityRuleViolationException(
                    "Hard Policy Violation: Non-admin user attempted to access cryptographic vault keys.",
                    "PRIVILEGE_VIOLATION_RULE", "CRITICAL"
                );
            }
        } catch (SecurityRuleViolationException ex) {
            System.out.printf("  [CAUGHT EXPECTED EXCEPTION] %s\n", ex.getClass().getSimpleName());
            System.out.printf("    Rule Code:   %s\n", ex.getRuleCode());
            System.out.printf("    Risk Level:  %s\n", ex.getRiskLevel());
            System.out.printf("    Message:     %s\n", ex.getMessage());
        }

        // --------------------------------------------------------------------
        // DEMONSTRATION 4: ADSA GRAPH DATA STRUCTURE IN JAVA (BFS & DFS)
        // --------------------------------------------------------------------
        System.out.println("\n>>> [ADSA & OOP 6] Demonstrating Graph (Adjacency List, BFS, DFS):");
        AccessGraph graph = new AccessGraph();

        // USER -> IP -> SESSION -> RESOURCE
        graph.addEdge("U:alice", "USER", "Alice Dev", "IP:192.168.1.10", "IP", "Office IP");
        graph.addEdge("IP:192.168.1.10", "IP", "Office IP", "S:101", "SESSION", "Session 101");
        graph.addEdge("S:101", "SESSION", "Session 101", "R:portal", "RESOURCE", "Portal Home");
        graph.addEdge("S:101", "SESSION", "Session 101", "R:vault", "RESOURCE", "Key Vault");

        // Attacker path
        graph.addEdge("U:attacker", "USER", "Attacker", "IP:185.220.101.5", "IP", "Tor Exit");
        graph.addEdge("IP:185.220.101.5", "IP", "Tor Exit", "S:102", "SESSION", "Session 102");
        graph.addEdge("S:102", "SESSION", "Session 102", "R:portal", "RESOURCE", "Portal Home");

        System.out.println("  Graph constructed with " + graph.getNodeCount() + " unique nodes.");

        // Execute BFS from User:attacker
        List<GraphNode> bfsOrder = graph.bfs("U:attacker");
        System.out.print("  BFS Traversal from U:attacker: ");
        for (int i = 0; i < bfsOrder.size(); i++) {
            System.out.print(bfsOrder.get(i).getLabel() + (i < bfsOrder.size() - 1 ? " -> " : ""));
        }
        System.out.println();

        // Execute DFS from User:alice
        List<GraphNode> dfsOrder = graph.dfs("U:alice");
        System.out.print("  DFS Traversal from U:alice:    ");
        for (int i = 0; i < dfsOrder.size(); i++) {
            System.out.print(dfsOrder.get(i).getLabel() + (i < dfsOrder.size() - 1 ? " -> " : ""));
        }
        System.out.println();

        // --------------------------------------------------------------------
        // DEMONSTRATION 5: REPORT GENERATION
        // --------------------------------------------------------------------
        System.out.println("\n>>> Generating Executive Security Intelligence Report:");
        String report = ReportGenerator.generateTextReport(analyzer);
        System.out.println(report);

        // --------------------------------------------------------------------
        // DEMONSTRATION 6: UNIVERSAL AUTHENTICATION PLATFORM & RISK ENGINE
        // --------------------------------------------------------------------
        System.out.println(">>> [SENTINEL CORE] Demonstrating Universal Authentication Integration:");
        Application collegeApp = new Application("APP_001", "College Portal", "https://portal.apex.edu", "Portal", "admin@apex.edu", "Production");
        ApiClient collegeKey = new ApiClient(1, "APP_001", "sen_live_9b4a8e109f2d431c", "hash_secret", "sec_live_...2b5e");
        collegeApp.addApiClient(collegeKey);
        System.out.printf("  * Registered Application: %s (Key: %s)\n", collegeApp.getName(), collegeKey.getApiKey());

        // Event Ingestion without Passwords
        AuthenticationEvent authEv = new AuthenticationEvent(101, "APP_001", LocalDateTime.now(), "john123", "LOGIN_ATTEMPT", "SUCCESS", "192.0.2.55", "Desktop", "Chrome", "/login", null);
        com.sentinel.analyzer.RiskAnalyzer riskAnalyzer = new com.sentinel.analyzer.RiskAnalyzer();
        RiskScore score = riskAnalyzer.analyze(authEv, 0, 1, 1, false);
        System.out.printf("  * Evaluated Safe Login: Risk Score = %d/100, Level = %s, Status = %s\n", authEv.getRiskScore(), authEv.getRiskLevel(), authEv.getStatus());

        // Suspicious enumeration attack test
        AuthenticationEvent attackEv = new AuthenticationEvent(102, "APP_001", LocalDateTime.now(), "root", "LOGIN_ATTEMPT", "UNKNOWN_ACCOUNT", "192.0.2.10", "Desktop", "Scanner", "/admin", null);
        RiskScore attackScore = riskAnalyzer.analyze(attackEv, 6, 7, 18, true);
        System.out.printf("  * Evaluated Enumeration Attack: Risk Score = %d/100, Level = %s, Status = %s\n", attackEv.getRiskScore(), attackEv.getRiskLevel(), attackEv.getStatus());
        System.out.println("  [STRICT ZERO-PASSWORD VERIFIED: All events processed using metadata only.]\n");
    }
}
