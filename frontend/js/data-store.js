/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: Unified Reactive Central Data Store (Single Source of Truth)
 * Manages: sentinel_auth_events, sentinel_alerts, sentinel_applications, sentinel_settings, sentinel_session
 * Provides transparent fallback between Live Backend API and LocalStorage Demo Mode.
 * Strictly enforces ZERO-PASSWORD compliance.
 */

const SentinelDataStore = (() => {
  const STORAGE_KEYS = {
    EVENTS: 'sentinel_auth_events',
    ALERTS: 'sentinel_alerts',
    APPS: 'sentinel_applications',
    SETTINGS: 'sentinel_settings',
    SESSION: 'sentinel_session'
  };

  // State
  let events = [];
  let alerts = [];
  let applications = [];
  let settings = {
    simulationSpeed: 3500,
    isLiveSimulation: false,
    backendOnline: false,
    mode: 'DEMO_MODE' // 'BACKEND_CONNECTED' or 'DEMO_MODE'
  };
  const listeners = {};

  // Standard Seed Applications
  const DEFAULT_APPLICATIONS = [
    {
      applicationId: 'APP_001',
      name: 'College Portal',
      url: 'https://portal.apex.edu',
      appType: 'Portal',
      environment: 'Production',
      ownerEmail: 'security@apex.edu',
      apiKey: 'snt_live_colg77a8b9c0d1e2f3a4b5c6d7e8',
      apiSecret: 'sec_live_9f8e7d6c5b4a3210fedcba9876543210',
      totalEvents: 0,
      createdAt: '2026-09-18 08:00:00'
    },
    {
      applicationId: 'APP_002',
      name: 'E-Commerce Website',
      url: 'https://store.apex.shop',
      appType: 'Website',
      environment: 'Production',
      ownerEmail: 'infosec@apex.shop',
      apiKey: 'snt_live_ecom112233445566778899aabbcc',
      apiSecret: 'sec_live_1234567890abcdef1234567890abcdef',
      totalEvents: 0,
      createdAt: '2026-09-18 09:30:00'
    },
    {
      applicationId: 'APP_003',
      name: 'Company Portal',
      url: 'https://internal.apexcorp.io',
      appType: 'Web Application',
      environment: 'Production',
      ownerEmail: 'ops@apexcorp.io',
      apiKey: 'snt_live_corp99887766554433221100fedc',
      apiSecret: 'sec_live_fedcba0987654321fedcba0987654321',
      totalEvents: 0,
      createdAt: '2026-09-18 10:15:00'
    },
    {
      applicationId: 'APP_004',
      name: 'Mobile Application',
      url: 'https://api.mobile.apex.io',
      appType: 'Mobile Application',
      environment: 'Production',
      ownerEmail: 'mobile-dev@apex.io',
      apiKey: 'snt_live_mobl33445566778899aabbccddeeff',
      apiSecret: 'sec_live_abcd1234ef009988aabbccddeeff0011',
      totalEvents: 0,
      createdAt: '2026-09-18 11:00:00'
    },
    {
      applicationId: 'APP_005',
      name: 'Customer Website',
      url: 'https://customer.apex.com',
      appType: 'Website',
      environment: 'Production',
      ownerEmail: 'admin@customer.apex.com',
      apiKey: 'snt_live_cust5566778899aabbccddeeff0011',
      apiSecret: 'sec_live_00112233445566778899aabbccddeeff',
      totalEvents: 0,
      createdAt: '2026-09-18 12:00:00'
    }
  ];

  // Helper to format ISO/Date strings
  function formatDate(d = new Date()) {
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  // Generate realistic seed events if store is empty
  function generateSeedEvents() {
    const seed = [];
    const seedAlerts = [];
    const now = Date.now();
    const ips = ['192.0.2.55', '192.0.2.56', '198.51.100.12', '198.51.100.25', '203.0.113.40', '192.0.2.10', '198.51.100.42'];
    const users = ['john123', 'emily_chem', 'rahul_eng', 'prof_sharma', 'dean_wilson', 'david_ops', 'sarah_w', 'alex_dev'];
    const apps = DEFAULT_APPLICATIONS;

    let idCounter = 1;

    // Normal safe logins
    for (let i = 0; i < 40; i++) {
      const u = users[i % users.length];
      const ip = ips[i % 5];
      const app = apps[i % apps.length];
      const time = new Date(now - (40 - i) * 180000);
      seed.push({
        id: idCounter++,
        timestamp: formatDate(time),
        applicationId: app.applicationId,
        applicationName: app.name,
        usernameIdentifier: u,
        authenticationResult: 'SUCCESS',
        sourceIp: ip,
        deviceType: i % 3 === 0 ? 'Mobile' : 'Desktop',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        resource: '/login',
        riskScore: 5,
        riskLevel: 'LOW',
        status: 'SAFE',
        explanation: 'Successful authentication with no significant suspicious indicators.',
        triggeredRules: [],
        alertId: null
      });
    }

    // Occasional wrong password (single failure)
    for (let i = 0; i < 6; i++) {
      const u = users[i % 4];
      const ip = ips[i % 4];
      const app = apps[0];
      const time = new Date(now - (25 - i) * 240000);
      seed.push({
        id: idCounter++,
        timestamp: formatDate(time),
        applicationId: app.applicationId,
        applicationName: app.name,
        usernameIdentifier: u,
        authenticationResult: 'FAILURE',
        sourceIp: ip,
        deviceType: 'Desktop',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        resource: '/login',
        riskScore: 15,
        riskLevel: 'LOW',
        status: 'MONITORING',
        explanation: 'Authentication failed. No significant suspicious pattern detected.',
        triggeredRules: [{ rule_code: 'RULE-010', name: 'Single Transient Failure', weight: 10 }],
        alertId: null
      });
    }

    // Anomaly Cluster 1: Repeated Failures on 198.51.100.42
    const burstIp = '198.51.100.42';
    for (let i = 0; i < 5; i++) {
      const time = new Date(now - (10 - i) * 60000);
      const isFifth = i === 4;
      const rScore = isFifth ? 65 : 15;
      const rLevel = isFifth ? 'HIGH' : 'LOW';
      const rStatus = isFifth ? 'ALERT' : 'MONITORING';
      const trigRules = isFifth
        ? [
            { rule_code: 'RULE-010', name: 'Single Transient Failure', weight: 10 },
            { rule_code: 'RULE-001', name: 'Repeated Authentication Failures (>=5)', weight: 50 }
          ]
        : [{ rule_code: 'RULE-010', name: 'Single Transient Failure', weight: 10 }];

      const ev = {
        id: idCounter++,
        timestamp: formatDate(time),
        applicationId: 'APP_001',
        applicationName: 'College Portal',
        usernameIdentifier: 'prof_sharma',
        authenticationResult: 'FAILURE',
        sourceIp: burstIp,
        deviceType: 'Desktop',
        userAgent: 'Chrome 122 on Linux',
        resource: '/portal',
        riskScore: rScore,
        riskLevel: rLevel,
        status: rStatus,
        explanation: isFifth
          ? 'Repeated authentication failures (5 attempts) detected from origin.'
          : 'Authentication failed. No significant suspicious pattern detected.',
        triggeredRules: trigRules,
        alertId: isFifth ? 1 : null
      };
      seed.push(ev);

      if (isFifth) {
        seedAlerts.push({
          id: 1,
          alertId: 1,
          timestamp: ev.timestamp,
          created_at: ev.timestamp,
          applicationId: 'APP_001',
          applicationName: 'College Portal',
          sourceIp: burstIp,
          usernameIdentifier: 'prof_sharma',
          riskLevel: 'HIGH',
          riskScore: 65,
          title: 'HIGH-RISK AUTHENTICATION PATTERN',
          reason: 'Repeated authentication failures (5 attempts) detected from origin.',
          status: 'OPEN',
          triggeredRules: trigRules,
          eventCount: 5,
          failedCount: 5
        });
      }
    }

    // Anomaly Cluster 2: Multiple Usernames probed from 192.0.2.10
    const scanIp = '192.0.2.10';
    const probed = ['admin', 'administrator', 'root', 'manager', 'superadmin', 'test', 'fakeuser'];
    probed.forEach((u, i) => {
      const time = new Date(now - (5 - i * 0.5) * 60000);
      const isSev = i === probed.length - 1;
      const rScore = isSev ? 88 : (i >= 3 ? 55 : 20);
      const rLevel = isSev ? 'CRITICAL' : (i >= 3 ? 'HIGH' : 'LOW');
      const rStatus = isSev ? 'CRITICAL_ALERT' : (i >= 3 ? 'ALERT' : 'MONITORING');
      const trigRules = isSev
        ? [
            { rule_code: 'RULE-009', name: 'Unknown Account Identifier', weight: 10 },
            { rule_code: 'RULE-002', name: 'High-Risk Account Enumeration Pattern', weight: 60 },
            { rule_code: 'RULE-005', name: 'Restricted Resource Probing', weight: 30 }
          ]
        : [{ rule_code: 'RULE-009', name: 'Unknown Account Identifier', weight: 10 }];

      const ev = {
        id: idCounter++,
        timestamp: formatDate(time),
        applicationId: 'APP_001',
        applicationName: 'College Portal',
        usernameIdentifier: u,
        authenticationResult: 'UNKNOWN_ACCOUNT',
        sourceIp: scanIp,
        deviceType: 'Desktop',
        userAgent: 'Python-urllib/3.9 (Scanner)',
        resource: '/admin',
        riskScore: rScore,
        riskLevel: rLevel,
        status: rStatus,
        explanation: isSev
          ? `High-risk account enumeration: ${probed.length} distinct usernames probed from same origin.`
          : 'Account identifier was not recognized. Monitoring continues.',
        triggeredRules: trigRules,
        alertId: isSev ? 2 : null
      };
      seed.push(ev);

      if (isSev) {
        seedAlerts.push({
          id: 2,
          alertId: 2,
          timestamp: ev.timestamp,
          created_at: ev.timestamp,
          applicationId: 'APP_001',
          applicationName: 'College Portal',
          sourceIp: scanIp,
          usernameIdentifier: 'Multiple Accounts (7)',
          riskLevel: 'CRITICAL',
          riskScore: 88,
          title: 'HIGH-RISK ACCOUNT ENUMERATION PATTERN',
          reason: 'Multiple unknown accounts targeted from same IP within short time window.',
          status: 'OPEN',
          triggeredRules: trigRules,
          eventCount: 7,
          failedCount: 7
        });
      }
    });

    return { events: seed, alerts: seedAlerts };
  }

  // Save current state to LocalStorage
  function persistToStorage() {
    try {
      localStorage.setItem(STORAGE_KEYS.EVENTS, JSON.stringify(events));
      localStorage.setItem(STORAGE_KEYS.ALERTS, JSON.stringify(alerts));
      localStorage.setItem(STORAGE_KEYS.APPS, JSON.stringify(applications));
      localStorage.setItem(STORAGE_KEYS.SETTINGS, JSON.stringify(settings));
    } catch (e) {
      console.warn('LocalStorage quota or access restriction:', e);
    }
  }

  // Load from LocalStorage
  function loadFromStorage() {
    try {
      const storedEvents = localStorage.getItem(STORAGE_KEYS.EVENTS);
      const storedAlerts = localStorage.getItem(STORAGE_KEYS.ALERTS);
      const storedApps = localStorage.getItem(STORAGE_KEYS.APPS);
      const storedSettings = localStorage.getItem(STORAGE_KEYS.SETTINGS);

      if (storedApps) {
        applications = JSON.parse(storedApps);
      } else {
        applications = [...DEFAULT_APPLICATIONS];
      }

      if (storedEvents && storedAlerts) {
        events = JSON.parse(storedEvents);
        alerts = JSON.parse(storedAlerts);
      } else {
        const seed = generateSeedEvents();
        events = seed.events;
        alerts = seed.alerts;
        persistToStorage();
      }

      if (storedSettings) {
        settings = { ...settings, ...JSON.parse(storedSettings) };
      }
    } catch (err) {
      console.error('Error loading from storage:', err);
      const seed = generateSeedEvents();
      events = seed.events;
      alerts = seed.alerts;
      applications = [...DEFAULT_APPLICATIONS];
    }
  }

  // Check if live backend server is reachable
  async function checkBackendConnectivity() {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      const res = await fetch('/api/v1/applications', { signal: controller.signal });
      clearTimeout(timeoutId);

      if (res.ok) {
        settings.backendOnline = true;
        settings.mode = 'BACKEND_CONNECTED';
        return true;
      }
    } catch (_) {
      // Backend not reached
    }
    settings.backendOnline = false;
    settings.mode = 'DEMO_MODE';
    return false;
  }

  // Sync state from backend if available
  async function syncFromBackend() {
    if (!settings.backendOnline) return false;
    try {
      // 1. Apps
      const appsRes = await fetch('/api/v1/applications');
      if (appsRes.ok) {
        const appsData = await appsRes.json();
        if (appsData.applications && appsData.applications.length > 0) {
          applications = appsData.applications.map(a => ({
            applicationId: a.application_id,
            name: a.name,
            url: a.url,
            appType: a.app_type,
            environment: a.environment,
            ownerEmail: a.owner_email || 'admin@apex.edu',
            apiKey: a.api_key,
            totalEvents: a.total_events || 0,
            createdAt: a.created_at
          }));
        }
      }

      // 2. Events
      const evsRes = await fetch('/api/v1/auth-events?limit=150');
      if (evsRes.ok) {
        const evsData = await evsRes.json();
        if (evsData.events && evsData.events.length > 0) {
          events = evsData.events.map(e => ({
            id: e.event_id,
            timestamp: e.timestamp,
            applicationId: e.application_id,
            applicationName: e.app_name || e.application_id,
            usernameIdentifier: e.username_identifier,
            authenticationResult: e.authentication_result,
            sourceIp: e.source_ip,
            deviceType: e.device_type,
            userAgent: e.user_agent,
            resource: e.resource,
            riskScore: e.risk_score,
            riskLevel: e.risk_level,
            status: e.status,
            explanation: e.failure_reason,
            triggeredRules: typeof e.triggered_rules === 'string' ? JSON.parse(e.triggered_rules || '[]') : (e.triggered_rules || []),
            alertId: null
          }));
        }
      }

      // 3. Alerts
      const alRes = await fetch('/api/v1/alerts');
      if (alRes.ok) {
        const alData = await alRes.json();
        if (alData.alerts && alData.alerts.length > 0) {
          alerts = alData.alerts.map(a => ({
            id: a.alert_id,
            alertId: a.alert_id,
            timestamp: a.created_at,
            created_at: a.created_at,
            applicationId: a.application_id,
            applicationName: a.app_name || a.application_id,
            sourceIp: a.source_ip,
            usernameIdentifier: a.username || a.source_ip,
            riskLevel: a.risk_level,
            riskScore: a.risk_score,
            title: a.title,
            reason: a.description || a.title,
            status: a.status,
            triggeredRules: typeof a.triggered_rules === 'string' ? JSON.parse(a.triggered_rules || '[]') : (a.triggered_rules || []),
            eventCount: a.accounts_attempted || 1,
            failedCount: a.failed_attempts || 1
          }));
        }
      }

      persistToStorage();
      notify('dataChanged');
      return true;
    } catch (e) {
      console.warn('Backend sync failed, maintaining local state:', e);
      return false;
    }
  }

  // Reactive Event Notification
  function on(eventName, callback) {
    if (!listeners[eventName]) listeners[eventName] = [];
    listeners[eventName].push(callback);
  }

  function notify(eventName, data) {
    if (listeners[eventName]) {
      listeners[eventName].forEach(cb => {
        try { cb(data); } catch (e) { console.error('Listener callback error:', e); }
      });
    }
  }

  /**
   * Records a new authentication event into the single source of truth.
   * Strictly enforces ZERO-PASSWORD policy.
   * Evaluates with centralized risk engine.
   * Auto-creates alerts if risk is HIGH/CRITICAL.
   */
  function addEvent(eventData) {
    // SECURITY AUDIT: Reject password parameters unconditionally
    const forbiddenKeys = ['password', 'raw_password', 'pass', 'admin_password', 'credential', 'secret'];
    for (let key in eventData) {
      if (forbiddenKeys.includes(key.toLowerCase())) {
        const errMsg = 'Security Policy Violation: SENTINEL strictly forbids password transmission. External authentication systems verify passwords. SENTINEL receives authentication EVENT METADATA only.';
        console.error(errMsg);
        throw new Error(errMsg);
      }
    }

    // Standardize event structure
    const rawResult = (eventData.authenticationResult || eventData.authentication_result || 'SUCCESS').toUpperCase();
    const validResults = ['SUCCESS', 'FAILURE', 'UNKNOWN_ACCOUNT', 'LOCKED_ACCOUNT', 'MFA_FAILURE', 'MFA_SUCCESS', 'SESSION_STARTED', 'SESSION_ENDED'];
    const result = validResults.includes(rawResult) ? rawResult : 'FAILURE';

    const appId = eventData.applicationId || eventData.application_id || 'APP_001';
    const appObj = applications.find(a => a.applicationId === appId) || { name: 'College Portal', applicationId: appId };

    const cleanEvent = {
      applicationId: appId,
      applicationName: appObj.name,
      usernameIdentifier: (eventData.usernameIdentifier || eventData.username_identifier || 'anonymous').trim(),
      authenticationResult: result,
      sourceIp: (eventData.sourceIp || eventData.source_ip || '127.0.0.1').trim(),
      deviceType: eventData.deviceType || eventData.device_type || 'Desktop',
      userAgent: eventData.userAgent || eventData.user_agent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      resource: eventData.resource || '/login',
      timestamp: eventData.timestamp || formatDate()
    };

    // Calculate Risk with Centralized Risk Engine
    const evalRes = window.SentinelRiskEngine
      ? window.SentinelRiskEngine.calculateRisk(cleanEvent, events)
      : { riskScore: 5, riskLevel: 'LOW', status: 'SAFE', explanation: 'Evaluated', triggeredRules: [] };

    const nextId = events.length > 0 ? Math.max(...events.map(e => e.id || 0)) + 1 : 1;

    const fullEvent = {
      id: nextId,
      ...cleanEvent,
      riskScore: evalRes.riskScore,
      riskLevel: evalRes.riskLevel,
      status: evalRes.status,
      explanation: evalRes.explanation,
      triggeredRules: evalRes.triggeredRules,
      alertId: null
    };

    // Create alert if HIGH or CRITICAL
    let alertCreated = null;
    if (fullEvent.riskLevel === 'HIGH' || fullEvent.riskLevel === 'CRITICAL') {
      const nextAlertId = alerts.length > 0 ? Math.max(...alerts.map(a => a.id || 0)) + 1 : 1;
      const alertTitle = fullEvent.triggeredRules.some(r => r.rule_code === 'RULE-002')
        ? 'HIGH-RISK ACCOUNT ENUMERATION PATTERN'
        : 'HIGH-RISK AUTHENTICATION PATTERN';

      alertCreated = {
        id: nextAlertId,
        alertId: nextAlertId,
        timestamp: fullEvent.timestamp,
        created_at: fullEvent.timestamp,
        applicationId: fullEvent.applicationId,
        applicationName: fullEvent.applicationName,
        sourceIp: fullEvent.sourceIp,
        usernameIdentifier: fullEvent.usernameIdentifier,
        riskLevel: fullEvent.riskLevel,
        riskScore: fullEvent.riskScore,
        title: alertTitle,
        reason: fullEvent.explanation,
        status: 'OPEN',
        triggeredRules: fullEvent.triggeredRules,
        eventCount: 1,
        failedCount: 1
      };

      alerts.unshift(alertCreated);
      fullEvent.alertId = nextAlertId;
    }

    // Add event at top of canonical stream
    events.unshift(fullEvent);

    // Update app total events
    const targetApp = applications.find(a => a.applicationId === appId);
    if (targetApp) {
      targetApp.totalEvents = (targetApp.totalEvents || 0) + 1;
    }

    // Persist to storage
    persistToStorage();

    // Transmit to backend if online (async, non-blocking)
    if (settings.backendOnline) {
      try {
        fetch('/api/v1/auth-events', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            application_id: fullEvent.applicationId,
            username_identifier: fullEvent.usernameIdentifier,
            authentication_result: fullEvent.authenticationResult,
            source_ip: fullEvent.sourceIp,
            device_type: fullEvent.deviceType,
            user_agent: fullEvent.userAgent,
            resource: fullEvent.resource,
            timestamp: fullEvent.timestamp
          })
        }).catch(() => {});
      } catch (_) {}
    }

    // Notify all UI components
    notify('dataChanged', { event: fullEvent, alert: alertCreated });
    return { event: fullEvent, alert: alertCreated };
  }

  // Get filtered events
  function getEvents(filter = {}) {
    let list = [...events];

    if (filter.applicationId && filter.applicationId !== 'ALL') {
      list = list.filter(e => e.applicationId === filter.applicationId);
    }
    if (filter.riskLevel && filter.riskLevel !== 'ALL') {
      list = list.filter(e => e.riskLevel === filter.riskLevel);
    }
    if (filter.result && filter.result !== 'ALL') {
      list = list.filter(e => e.authenticationResult === filter.result);
    }
    if (filter.search && filter.search.trim()) {
      const q = filter.search.toLowerCase().trim();
      list = list.filter(e =>
        String(e.id).includes(q) ||
        (e.usernameIdentifier && e.usernameIdentifier.toLowerCase().includes(q)) ||
        (e.sourceIp && e.sourceIp.toLowerCase().includes(q)) ||
        (e.applicationName && e.applicationName.toLowerCase().includes(q)) ||
        (e.resource && e.resource.toLowerCase().includes(q))
      );
    }

    // Default: newest first
    list.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    if (filter.limit) {
      list = list.slice(0, filter.limit);
    }
    return list;
  }

  // Get alerts
  function getAlerts(filter = {}) {
    let list = [...alerts];
    if (filter.applicationId && filter.applicationId !== 'ALL') {
      list = list.filter(a => a.applicationId === filter.applicationId);
    }
    if (filter.status && filter.status !== 'ALL') {
      list = list.filter(a => a.status === filter.status);
    }
    list.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return list;
  }

  // Update Alert Status (OPEN, INVESTIGATING, RESOLVED)
  function updateAlertStatus(alertId, newStatus) {
    const alert = alerts.find(a => a.id === alertId || a.alertId === alertId);
    if (alert) {
      alert.status = newStatus;
      persistToStorage();

      if (settings.backendOnline) {
        fetch(`/api/v1/alerts/${alertId}/update-status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus })
        }).catch(() => {});
      }

      notify('dataChanged', { alertUpdated: alert });
      return true;
    }
    return false;
  }

  // Get applications
  function getApplications() {
    return [...applications];
  }

  // Register new application
  function registerApplication(appData) {
    const nextNum = applications.length + 1;
    const appId = `APP_${String(nextNum).padStart(3, '0')}`;
    const randHex = (len = 24) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

    const newApp = {
      applicationId: appId,
      name: appData.name || `Application ${nextNum}`,
      url: appData.url || 'https://app.example.com',
      appType: appData.appType || appData.app_type || 'Web Application',
      environment: appData.environment || 'Production',
      ownerEmail: appData.ownerEmail || appData.owner_email || 'admin@example.com',
      apiKey: `snt_live_${randHex(24)}`,
      apiSecret: `sec_live_${randHex(32)}`,
      totalEvents: 0,
      createdAt: formatDate()
    };

    applications.push(newApp);
    persistToStorage();

    if (settings.backendOnline) {
      fetch('/api/v1/applications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newApp.name,
          url: newApp.url,
          app_type: newApp.appType,
          environment: newApp.environment,
          owner_email: newApp.ownerEmail
        })
      }).catch(() => {});
    }

    notify('dataChanged');
    return newApp;
  }

  // Calculate live statistics from actual events array
  function getStatistics(appFilter = 'ALL') {
    const targetEvents = appFilter === 'ALL'
      ? events
      : events.filter(e => e.applicationId === appFilter);

    const totalEvents = targetEvents.length;
    const successfulLogins = targetEvents.filter(e => e.authenticationResult === 'SUCCESS').length;
    const failedLogins = targetEvents.filter(e => e.authenticationResult === 'FAILURE').length;
    const unknownAccounts = targetEvents.filter(e => e.authenticationResult === 'UNKNOWN_ACCOUNT').length;
    const suspiciousEvents = targetEvents.filter(e => e.riskLevel === 'MEDIUM').length;
    const highRiskAlerts = targetEvents.filter(e => e.riskLevel === 'HIGH' || e.riskLevel === 'CRITICAL').length;
    const connectedApps = applications.length;

    // Hourly distribution (past 24h)
    const hourlyMap = {};
    for (let h = 0; h < 24; h++) {
      const hStr = `${String(h).padStart(2, '0')}:00`;
      hourlyMap[hStr] = 0;
    }
    targetEvents.forEach(e => {
      try {
        const d = new Date(e.timestamp.replace(' ', 'T'));
        const h = `${String(d.getHours()).padStart(2, '0')}:00`;
        if (h in hourlyMap) hourlyMap[h]++;
      } catch (_) {}
    });
    const hourlyPattern = Object.keys(hourlyMap).map(h => ({ hour: h, count: hourlyMap[h] }));

    // Result distribution
    const resultCounts = {};
    targetEvents.forEach(e => {
      const res = e.authenticationResult || 'SUCCESS';
      resultCounts[res] = (resultCounts[res] || 0) + 1;
    });
    const resultDistribution = Object.keys(resultCounts).map(r => ({ authentication_result: r, count: resultCounts[r] }));

    // Risk distribution
    const riskCounts = { 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0 };
    targetEvents.forEach(e => {
      const lvl = e.riskLevel || 'LOW';
      if (lvl in riskCounts) riskCounts[lvl]++;
    });
    const riskDistribution = Object.keys(riskCounts).map(lvl => ({ risk_level: lvl, count: riskCounts[lvl] }));

    // Top targeted accounts
    const accountCounts = {};
    targetEvents.forEach(e => {
      const u = e.usernameIdentifier || 'unknown';
      if (!accountCounts[u]) accountCounts[u] = { username_identifier: u, successes: 0, failures: 0, total_attempts: 0 };
      accountCounts[u].total_attempts++;
      if (e.authenticationResult === 'SUCCESS') accountCounts[u].successes++;
      else accountCounts[u].failures++;
    });
    const topTargetedAccounts = Object.values(accountCounts)
      .sort((a, b) => b.total_attempts - a.total_attempts)
      .slice(0, 6);

    return {
      kpis: {
        connected_apps: connectedApps,
        total_events: totalEvents,
        successful_logins: successfulLogins,
        failed_logins: failedLogins,
        unknown_accounts: unknownAccounts,
        suspicious_events: suspiciousEvents,
        high_risk_alerts: highRiskAlerts
      },
      charts: {
        hourly_pattern: hourlyPattern,
        result_distribution: resultDistribution,
        risk_distribution: riskDistribution,
        top_targeted_accounts: topTargetedAccounts
      }
    };
  }

  // Aggregate Source IP Analysis
  function getSourceIpAnalysis() {
    const ipMap = {};

    events.forEach(e => {
      const ip = e.sourceIp || '127.0.0.1';
      if (!ipMap[ip]) {
        ipMap[ip] = {
          sourceIp: ip,
          totalAttempts: 0,
          successful: 0,
          failed: 0,
          unknownAccounts: 0,
          uniqueUsernames: new Set(),
          applicationsTargeted: new Set(),
          highestRiskScore: 0,
          highestRiskLevel: 'LOW',
          latestActivity: e.timestamp
        };
      }
      const entry = ipMap[ip];
      entry.totalAttempts++;
      if (e.authenticationResult === 'SUCCESS') entry.successful++;
      else if (e.authenticationResult === 'FAILURE') entry.failed++;
      else if (e.authenticationResult === 'UNKNOWN_ACCOUNT') entry.unknownAccounts++;

      if (e.usernameIdentifier) entry.uniqueUsernames.add(e.usernameIdentifier);
      if (e.applicationName) entry.applicationsTargeted.add(e.applicationName);

      if (e.riskScore > entry.highestRiskScore) {
        entry.highestRiskScore = e.riskScore;
        entry.highestRiskLevel = e.riskLevel;
      }
      if (new Date(e.timestamp).getTime() > new Date(entry.latestActivity).getTime()) {
        entry.latestActivity = e.timestamp;
      }
    });

    return Object.values(ipMap).map(item => ({
      ...item,
      uniqueUsersCount: item.uniqueUsernames.size,
      uniqueUsersList: Array.from(item.uniqueUsernames),
      applicationsList: Array.from(item.applicationsTargeted)
    })).sort((a, b) => b.totalAttempts - a.totalAttempts);
  }

  // Aggregate Username Analysis
  function getUsernameAnalysis() {
    const userMap = {};

    events.forEach(e => {
      const u = e.usernameIdentifier || 'unknown';
      if (!userMap[u]) {
        userMap[u] = {
          username: u,
          applicationsTargeted: new Set(),
          totalAttempts: 0,
          successful: 0,
          failed: 0,
          unknown: 0,
          firstSeen: e.timestamp,
          lastSeen: e.timestamp,
          highestRiskScore: 0,
          highestRiskLevel: 'LOW'
        };
      }
      const entry = userMap[u];
      entry.totalAttempts++;
      if (e.authenticationResult === 'SUCCESS') entry.successful++;
      else if (e.authenticationResult === 'FAILURE') entry.failed++;
      else if (e.authenticationResult === 'UNKNOWN_ACCOUNT') entry.unknown++;

      if (e.applicationName) entry.applicationsTargeted.add(e.applicationName);

      if (e.riskScore > entry.highestRiskScore) {
        entry.highestRiskScore = e.riskScore;
        entry.highestRiskLevel = e.riskLevel;
      }
      if (new Date(e.timestamp).getTime() < new Date(entry.firstSeen).getTime()) entry.firstSeen = e.timestamp;
      if (new Date(e.timestamp).getTime() > new Date(entry.lastSeen).getTime()) entry.lastSeen = e.timestamp;
    });

    return Object.values(userMap).map(item => ({
      ...item,
      applicationsList: Array.from(item.applicationsTargeted)
    })).sort((a, b) => b.totalAttempts - a.totalAttempts);
  }

  // Clear demo data
  function clearDemoData() {
    events = [];
    alerts = [];
    applications.forEach(a => a.totalEvents = 0);
    persistToStorage();
    notify('dataChanged');
  }

  // Reset to default seeded state
  function resetToDefaults() {
    const seed = generateSeedEvents();
    events = seed.events;
    alerts = seed.alerts;
    applications = [...DEFAULT_APPLICATIONS];
    persistToStorage();
    notify('dataChanged');
  }

  // Initialize store on load
  async function init() {
    loadFromStorage();
    const online = await checkBackendConnectivity();
    if (online) {
      await syncFromBackend();
    }
    notify('dataChanged');
    return { online, mode: settings.mode };
  }

  return {
    init,
    addEvent,
    getEvents,
    getAlerts,
    updateAlertStatus,
    getApplications,
    registerApplication,
    getStatistics,
    getSourceIpAnalysis,
    getUsernameAnalysis,
    clearDemoData,
    resetToDefaults,
    syncFromBackend,
    getMode: () => settings.mode,
    isBackendOnline: () => settings.backendOnline,
    on
  };
})();

if (typeof window !== 'undefined') {
  window.SentinelDataStore = SentinelDataStore;
}
