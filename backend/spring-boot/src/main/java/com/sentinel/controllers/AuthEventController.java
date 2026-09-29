package com.sentinel.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;

/**
 * REST API Endpoint: /api/v1/auth-events
 * Ingests external authentication event metadata.
 * 
 * STRICT POLICY:
 * Rejects any request payload containing "password", "pwd", or "pass".
 */
@RestController
@RequestMapping("/api/v1/auth-events")
@CrossOrigin(origins = "*")
public class AuthEventController {

    private final List<Map<String, Object>> eventStore = Collections.synchronizedList(new ArrayList<>());

    @PostMapping
    public ResponseEntity<?> ingestAuthEvent(@RequestBody Map<String, Object> payload) {
        // 1. CRITICAL SECURITY VALIDATION: Never accept passwords
        for (String key : payload.keySet()) {
            String lowerKey = key.toLowerCase();
            if (lowerKey.contains("password") || lowerKey.equals("pwd") || lowerKey.equals("pass") || lowerKey.contains("secret")) {
                Map<String, Object> err = new HashMap<>();
                err.put("error", "Security Policy Violation: SENTINEL strictly forbids password transmission. Never send passwords to SENTINEL.");
                err.put("status", 400);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(err);
            }
        }

        // 2. Validate mandatory metadata fields
        if (!payload.containsKey("application_id") || !payload.containsKey("username_identifier") || !payload.containsKey("authentication_result")) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "Missing required event metadata: application_id, username_identifier, authentication_result");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(err);
        }

        String appId = String.valueOf(payload.get("application_id"));
        String username = String.valueOf(payload.get("username_identifier"));
        String result = String.valueOf(payload.get("authentication_result")).toUpperCase();
        String sourceIp = String.valueOf(payload.getOrDefault("source_ip", "127.0.0.1"));
        String resource = String.valueOf(payload.getOrDefault("resource", "/login"));

        // 3. Risk Engine Evaluation
        int riskScore = 5;
        String riskLevel = "LOW";
        String status = "SAFE";
        List<String> triggeredRules = new ArrayList<>();

        if ("FAILURE".equals(result)) {
            riskScore = 15;
            status = "MONITORING";
            triggeredRules.add("RULE-010");
        } else if ("UNKNOWN_ACCOUNT".equals(result)) {
            riskScore = 15;
            status = "MONITORING";
            triggeredRules.add("RULE-009");
        } else if ("MFA_FAILURE".equals(result)) {
            riskScore = 25;
            riskLevel = "MEDIUM";
            status = "SUSPICIOUS";
            triggeredRules.add("RULE-008");
        }

        Map<String, Object> stored = new HashMap<>(payload);
        stored.put("event_id", eventStore.size() + 1);
        stored.put("timestamp", payload.getOrDefault("timestamp", LocalDateTime.now().toString()));
        stored.put("risk_score", riskScore);
        stored.put("risk_level", riskLevel);
        stored.put("status", status);
        stored.put("triggered_rules", triggeredRules);
        eventStore.add(stored);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "RECEIVED");
        response.put("event_id", stored.get("event_id"));
        response.put("risk_level", riskLevel);
        response.put("risk_score", riskScore);
        response.put("status_code", status);
        response.put("explanation", "Authentication metadata successfully analyzed by SENTINEL Risk Engine.");

        return ResponseEntity.ok(response);
    }

    @GetMapping
    public ResponseEntity<?> getAuthEvents(
            @RequestParam(required = false) String application_id,
            @RequestParam(required = false) String risk_level,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "25") int limit) {

        List<Map<String, Object>> filtered = new ArrayList<>(eventStore);
        if (application_id != null && !application_id.equalsIgnoreCase("ALL")) {
            filtered.removeIf(e -> !application_id.equals(e.get("application_id")));
        }
        if (risk_level != null && !risk_level.equalsIgnoreCase("ALL")) {
            filtered.removeIf(e -> !risk_level.equalsIgnoreCase(String.valueOf(e.get("risk_level"))));
        }

        Map<String, Object> res = new HashMap<>();
        res.put("total", filtered.size());
        res.put("page", page);
        res.put("events", filtered);
        return ResponseEntity.ok(res);
    }
}
