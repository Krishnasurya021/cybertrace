package com.sentinel.models;

import java.time.LocalDateTime;

/**
 * OOP Principle: ENCAPSULATION
 * Represents an authenticated user session in the system.
 */
public class Session {
    private int sessionId;
    private User user;
    private IPAddress ipAddress;
    private String sessionToken;
    private LocalDateTime loginTime;
    private LocalDateTime logoutTime;
    private int durationSeconds;
    private boolean active;

    public Session(int sessionId, User user, IPAddress ipAddress, String sessionToken, LocalDateTime loginTime, int durationSeconds, boolean active) {
        this.sessionId = sessionId;
        this.user = user;
        this.ipAddress = ipAddress;
        this.sessionToken = sessionToken;
        this.loginTime = loginTime;
        this.durationSeconds = durationSeconds;
        this.active = active;
    }

    public int getSessionId() { return sessionId; }
    public User getUser() { return user; }
    public IPAddress getIpAddress() { return ipAddress; }
    public String getSessionToken() { return sessionToken; }
    public LocalDateTime getLoginTime() { return loginTime; }
    public LocalDateTime getLogoutTime() { return logoutTime; }
    public void setLogoutTime(LocalDateTime logoutTime) { this.logoutTime = logoutTime; }
    public int getDurationSeconds() { return durationSeconds; }
    public void setDurationSeconds(int durationSeconds) { this.durationSeconds = durationSeconds; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }

    @Override
    public String toString() {
        return String.format("Session[%d: User=%s, IP=%s, Dur=%ds, Active=%b]", 
            sessionId, user.getUsername(), ipAddress.getIpAddress(), durationSeconds, active);
    }
}
