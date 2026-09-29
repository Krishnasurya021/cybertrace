package com.sentinel.models;

/**
 * OOP Principle: ENCAPSULATION
 * Represents protected digital resources, web paths, and endpoints.
 */
public class Resource {
    private int resourceId;
    private String name;
    private String path;
    private String classification; // PUBLIC, INTERNAL, RESTRICTED, CONFIDENTIAL
    private boolean restricted;
    private String requiredRole;

    public Resource(int resourceId, String name, String path, String classification, boolean restricted, String requiredRole) {
        this.resourceId = resourceId;
        this.name = name;
        this.path = path;
        this.classification = classification;
        this.restricted = restricted;
        this.requiredRole = requiredRole;
    }

    public int getResourceId() { return resourceId; }
    public String getName() { return name; }
    public String getPath() { return path; }
    public String getClassification() { return classification; }
    public boolean isRestricted() { return restricted; }
    public String getRequiredRole() { return requiredRole; }

    @Override
    public String toString() {
        return String.format("Resource[%d: %s (%s)]", resourceId, name, path);
    }
}
