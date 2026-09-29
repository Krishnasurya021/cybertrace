package com.sentinel.models;

import java.util.Arrays;
import java.util.List;

/**
 * OOP Principle: INHERITANCE & POLYMORPHISM
 * Security Analyst subclass extending User.
 * Has monitoring and investigation privileges, but cannot reconfigure production systems.
 */
public class Analyst extends User {
    private String securityClearance;

    public Analyst(int userId, String username, String email, String department, String clearance) {
        super(userId, username, email, "ANALYST", department);
        this.securityClearance = clearance;
    }

    @Override
    public boolean canAccess(Resource resource) {
        // Analysts can access public, internal, and SOC monitoring resources
        String path = resource.getPath();
        if (path.startsWith("/soc/") || path.startsWith("/admin/audit-logs")) {
            return true;
        }
        return !resource.isRestricted();
    }

    @Override
    public List<String> getPermissions() {
        return Arrays.asList("VIEW_LOGS", "INVESTIGATE_ALERTS", "VIEW_GRAPH", "GENERATE_REPORTS");
    }

    public String getSecurityClearance() {
        return securityClearance;
    }
}
