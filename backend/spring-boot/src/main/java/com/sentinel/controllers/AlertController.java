package com.sentinel.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * REST API Endpoint: /api/v1/alerts
 * Security alerts management and investigation endpoint.
 */
@RestController
@RequestMapping("/api/v1/alerts")
@CrossOrigin(origins = "*")
public class AlertController {

    private final List<Map<String, Object>> alerts = Collections.synchronizedList(new ArrayList<>());

    public AlertController() {
        Map<String, Object> a1 = new HashMap<>();
        a1.put("alert_id", 1);
        a1.put("application_id", "APP_001");
        a1.put("risk_level", "CRITICAL");
        a1.put("risk_score", 88);
        a1.put("title", "HIGH-RISK ACCOUNT ENUMERATION PATTERN");
        a1.put("description", "Multiple non-existent administrative account identifiers attempted from 192.0.2.10 within seconds.");
        a1.put("source_ip", "192.0.2.10");
        a1.put("accounts_attempted", 7);
        a1.put("failed_attempts", 7);
        a1.put("status", "OPEN");
        alerts.add(a1);
    }

    @GetMapping
    public ResponseEntity<?> getAlerts(@RequestParam(required = false) String application_id) {
        List<Map<String, Object>> list = new ArrayList<>(alerts);
        if (application_id != null && !application_id.equalsIgnoreCase("ALL")) {
            list.removeIf(a -> !application_id.equals(a.get("application_id")));
        }
        return ResponseEntity.ok(Collections.singletonMap("alerts", list));
    }

    @GetMapping("/{id}/investigate")
    public ResponseEntity<?> investigateAlert(@PathVariable int id) {
        Optional<Map<String, Object>> alertOpt = alerts.stream().filter(a -> id == ((Integer) a.get("alert_id"))).findFirst();
        if (alertOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        Map<String, Object> res = new HashMap<>();
        res.put("alert", alertOpt.get());
        
        List<Map<String, Object>> timeline = new ArrayList<>();
        String[] probedUsers = {"admin", "administrator", "root", "manager", "superadmin", "test", "fakeuser"};
        for (int i = 0; i < probedUsers.length; i++) {
            Map<String, Object> step = new HashMap<>();
            step.put("sequence", i + 1);
            step.put("timestamp", "10:40:0" + (i + 1));
            step.put("username", probedUsers[i]);
            step.put("result", "UNKNOWN_ACCOUNT");
            step.put("source_ip", "192.0.2.10");
            timeline.add(step);
        }
        res.put("timeline", timeline);
        res.put("pattern_detected", "Multiple account identifiers were attempted from the same source within a short period.");

        return ResponseEntity.ok(res);
    }
}
