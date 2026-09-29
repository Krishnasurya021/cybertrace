package com.sentinel.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * REST API Endpoint: /api/v1/applications
 * Registers external customer applications and generates API credentials.
 * NEVER ASKS FOR ADMIN PASSWORDS.
 */
@RestController
@RequestMapping("/api/v1/applications")
@CrossOrigin(origins = "*")
public class ApplicationController {

    private final List<Map<String, Object>> applications = Collections.synchronizedList(new ArrayList<>());

    public ApplicationController() {
        // Pre-seed sample applications
        applications.add(createAppMap("APP_001", "College Portal", "https://portal.apexuniversity.edu", "Portal", "admin@apex.edu", "Production"));
        applications.add(createAppMap("APP_002", "E-Commerce Website", "https://shop.aurorastore.com", "Web Application", "secops@aurora.com", "Production"));
        applications.add(createAppMap("APP_003", "Company Portal", "https://intranet.novacorp.internal", "Portal", "it@novacorp.com", "Production"));
        applications.add(createAppMap("APP_004", "Mobile Application", "https://api.novafinance.app/mobile", "Mobile Application", "dev@novafinance.app", "Production"));
        applications.add(createAppMap("APP_005", "Customer Website", "https://portal.skylinecloud.io", "Website", "cloud-ops@skylinecloud.io", "Production"));
    }

    private Map<String, Object> createAppMap(String id, String name, String url, String type, String email, String env) {
        Map<String, Object> app = new HashMap<>();
        app.put("application_id", id);
        app.put("name", name);
        app.put("url", url);
        app.put("app_type", type);
        app.put("owner_email", email);
        app.put("environment", env);
        app.put("status", "ACTIVE");
        app.put("api_key", "sen_live_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16));
        app.put("api_secret_preview", "sec_live_..." + UUID.randomUUID().toString().substring(0, 4));
        return app;
    }

    @GetMapping
    public ResponseEntity<?> listApplications() {
        return ResponseEntity.ok(Collections.singletonMap("applications", applications));
    }

    @PostMapping
    public ResponseEntity<?> registerApplication(@RequestBody Map<String, Object> payload) {
        String name = String.valueOf(payload.getOrDefault("name", "New Application"));
        String url = String.valueOf(payload.getOrDefault("url", "https://example.com"));
        String type = String.valueOf(payload.getOrDefault("app_type", "Web Application"));
        String email = String.valueOf(payload.getOrDefault("owner_email", "developer@example.com"));
        String env = String.valueOf(payload.getOrDefault("environment", "Production"));

        String newId = "APP_" + String.format("%03d", applications.size() + 1);
        String apiKey = "sen_live_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        String apiSecretRaw = "sec_live_" + UUID.randomUUID().toString().replace("-", "");

        Map<String, Object> app = createAppMap(newId, name, url, type, email, env);
        app.put("api_key", apiKey);
        app.put("api_secret_preview", "sec_live_..." + apiSecretRaw.substring(apiSecretRaw.length() - 4));
        applications.add(app);

        Map<String, Object> response = new HashMap<>();
        response.put("application_id", newId);
        response.put("name", name);
        response.put("api_key", apiKey);
        response.put("api_secret", apiSecretRaw);
        response.put("warning", "Never share your API secret publicly. Do not put API secrets inside frontend JavaScript. Store them securely in backend environment variables.");
        response.put("message", "Application registered successfully.");

        return ResponseEntity.ok(response);
    }
}
