package com.sentinel.models;

import java.util.Arrays;
import java.util.List;

/**
 * OOP Principle: INHERITANCE & POLYMORPHISM
 * Admin subclass extending User.
 * Has full access to all system resources including restricted vaults and configs.
 */
public class Admin extends User {
    private int adminPrivilegeLevel;

    public Admin(int userId, String username, String email, String department, int privilegeLevel) {
        super(userId, username, email, "ADMIN", department);
        this.adminPrivilegeLevel = privilegeLevel;
    }

    @Override
    public boolean canAccess(Resource resource) {
        // Admin can access all resources regardless of classification
        return true;
    }

    @Override
    public List<String> getPermissions() {
        return Arrays.asList("SYSTEM_CONFIG", "MANAGE_USERS", "MANAGE_RULES", "VIEW_ALL_LOGS", "EXPORT_VAULT");
    }

    public int getAdminPrivilegeLevel() {
        return adminPrivilegeLevel;
    }
}
