package com.sentinel.models;

/**
 * OOP Principle: ENCAPSULATION
 * Represents an IP network origin and its threat intelligence score.
 */
public class IPAddress {
    private int ipId;
    private String ipAddress;
    private String country;
    private String city;
    private boolean knownProxy;
    private boolean vpn;
    private int riskScore; // 0 to 100

    public IPAddress(int ipId, String ipAddress, String country, String city, boolean knownProxy, boolean vpn, int riskScore) {
        this.ipId = ipId;
        this.ipAddress = ipAddress;
        this.country = country;
        this.city = city;
        this.knownProxy = knownProxy;
        this.vpn = vpn;
        this.riskScore = riskScore;
    }

    public int getIpId() { return ipId; }
    public String getIpAddress() { return ipAddress; }
    public String getCountry() { return country; }
    public String getCity() { return city; }
    public boolean isKnownProxy() { return knownProxy; }
    public boolean isVpn() { return vpn; }
    public int getRiskScore() { return riskScore; }

    public boolean isHighRisk() {
        return riskScore >= 70 || knownProxy;
    }

    @Override
    public String toString() {
        return String.format("IP[%s, %s, Risk=%d]", ipAddress, country, riskScore);
    }
}
