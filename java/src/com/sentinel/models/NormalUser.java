package com.sentinel.models;

import java.util.Arrays;
import java.util.List;

/**
 * OOP Principle: INHERITANCE & POLYMORPHISM
 * Regular corporate user extending User.
 * Strictly limited to public and standard internal business resources.
 */
public class NormalUser extends User {

    public NormalUser(int userId, String username, String email, String department) {
        super(userId, username, email, "USER", department);
    }

    @Override
    public boolean canAccess(Resource resource) {
        // Regular users cannot access restricted or confidential assets
        return !resource.isRestricted();
    }

    @Override
    public List<String> getPermissions() {
        return Arrays.asList("VIEW_SELF_PROFILE", "ACCESS_STANDARD_APPS");
    }
}
