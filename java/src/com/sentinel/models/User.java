package com.sentinel.models;

import java.util.List;

/**
 * OOP Principle: ABSTRACTION & ENCAPSULATION
 * Abstract base class representing a system user entity.
 * Demonstrates:
 *  - Private fields with public getters/setters (Encapsulation)
 *  - Abstract methods enforced on derived classes (Abstraction)
 */
public abstract class User {
    private int userId;
    private String username;
    private String email;
    private String role;
    private String department;
    private boolean active;

    // Parameterized Constructor
    public User(int userId, String username, String email, String role, String department) {
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.role = role;
        this.department = department;
        this.active = true;
    }

    // Abstract method: Enforces polymorphic authorization check in subclasses
    public abstract boolean canAccess(Resource resource);

    // Abstract method: Subclasses return their specific permission scopes
    public abstract List<String> getPermissions();

    // Encapsulated Getters & Setters
    public int getUserId() { return userId; }
    public void setUserId(int userId) { this.userId = userId; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }

    @Override
    public String toString() {
        return String.format("User[ID=%d, Name=%s, Role=%s, Dept=%s]", userId, username, role, department);
    }
}
