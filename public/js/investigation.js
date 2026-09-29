/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: Threat Investigation Workbench & Forensic Dossier
 * Renders actual security incident data and event timelines from SentinelDataStore.
 */

const InvestigationModule = (() => {
  let currentAlertId = 1;

  function loadAlert(alertId) {
    if (!window.SentinelDataStore) return;
    const alerts = SentinelDataStore.getAlerts();
    const id = alertId || (window.SentinelState && SentinelState.activeAlertId) || (alerts[0] ? alerts[0].id : 1);
    currentAlertId = id;

    const alert = alerts.find(a => a.id === id || a.alertId === id) || alerts[0];
    if (!alert) {
      showEmptyState();
      return;
    }

    renderInvestigation(alert);
  }

  function loadEvent(eventId) {
    if (!window.SentinelDataStore) return;
    const events = SentinelDataStore.getEvents();
    const ev = events.find(e => e.id === eventId);
    if (!ev) return;

    // Build synthetic alert/dossier package for this event
    const dossier = {
      id: ev.id,
      alertId: ev.id,
      applicationName: ev.applicationName,
      applicationId: ev.applicationId,
      sourceIp: ev.sourceIp,
      usernameIdentifier: ev.usernameIdentifier,
      riskLevel: ev.riskLevel,
      riskScore: ev.riskScore,
      timestamp: ev.timestamp,
      title: `${ev.riskLevel} RISK AUTHENTICATION EVENT #${ev.id}`,
      reason: ev.explanation,
      status: ev.status,
      triggeredRules: ev.triggeredRules,
      eventCount: 1,
      failedCount: ev.authenticationResult === 'SUCCESS' ? 0 : 1
    };

    renderInvestigation(dossier);
  }

  function renderInvestigation(alert) {
    const setText = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    setText('invAlertId', `#ALT-${String(alert.id || alert.alertId || 1).padStart(4, '0')}`);
    setText('invApp', `${alert.applicationName || 'College Portal'} (${alert.applicationId || 'APP_001'})`);
    setText('invSourceIp', alert.sourceIp || '192.0.2.10');
    setText('invRiskLevel', `${alert.riskLevel || 'HIGH'} (${alert.riskScore || 75}/100)`);
    setText('invCreatedAt', alert.timestamp || alert.created_at || '--');
    setText('invPatternDetected', alert.reason || 'Anomalous multi-signal authentication activity detected.');

    // Fetch related events from this Source IP from SentinelDataStore
    const allEvents = window.SentinelDataStore ? SentinelDataStore.getEvents() : [];
    const sourceIp = alert.sourceIp;
    const relatedEvents = allEvents.filter(e => e.sourceIp === sourceIp);

    // Timeline Rendering
    const timelineContainer = document.getElementById('invTimelineContainer');
    if (timelineContainer) {
      if (relatedEvents.length === 0) {
        timelineContainer.innerHTML = '<div style="color:#64748b; padding:16px;">No chronological timeline events recorded for this origin.</div>';
      } else {
        timelineContainer.innerHTML = relatedEvents.map((ev, i) => {
          const isFailure = ev.authenticationResult !== 'SUCCESS';
          return `
            <div style="display:flex; align-items:flex-start; gap:12px; margin-bottom:12px; position:relative;">
              <div style="width:24px; height:24px; border-radius:50%; background:${isFailure ? '#ef4444' : '#10b981'}; display:flex; align-items:center; justify-content:center; font-size:11px; font-weight:700; color:#fff; flex-shrink:0;">
                ${relatedEvents.length - i}
              </div>
              <div style="flex:1; background:rgba(15, 23, 42, 0.7); border:1px solid var(--border-glass); border-radius:8px; padding:8px 12px;">
                <div style="display:flex; justify-content:space-between; font-size:11px; color:#94a3b8; margin-bottom:2px;">
                  <span style="font-family:'JetBrains Mono';">${ev.timestamp}</span>
                  <span class="badge ${isFailure ? 'badge-critical' : 'badge-safe'}">${ev.authenticationResult}</span>
                </div>
                <div style="display:flex; justify-content:space-between; align-items:center;">
                  <span style="font-family:'JetBrains Mono'; font-weight:700; color:#38bdf8;">${ev.usernameIdentifier}</span>
                  <span style="font-size:11px; color:#64748b;">Target: <code style="color:#fff;">${ev.resource || '/login'}</code></span>
                </div>
                ${ev.explanation ? `<div style="font-size:11px; color:#cbd5e1; margin-top:4px;">${ev.explanation}</div>` : ''}
              </div>
            </div>
          `;
        }).join('');
      }
    }

    // Triggered Heuristic Rules
    const rulesContainer = document.getElementById('invTriggeredRulesContainer');
    if (rulesContainer) {
      const rules = Array.isArray(alert.triggeredRules || alert.triggered_rules)
        ? (alert.triggeredRules || alert.triggered_rules)
        : [];

      if (rules.length === 0) {
        rulesContainer.innerHTML = '<div style="color:#64748b; font-size:12px;">No automated heuristic rules attached.</div>';
      } else {
        rulesContainer.innerHTML = rules.map(r => `
          <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 12px; background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.2); border-radius:6px; margin-bottom:6px;">
            <div>
              <b style="color:#f87171; font-family:'JetBrains Mono'; font-size:12px;">${r.rule_code || r}</b>
              <div style="font-size:11px; color:#cbd5e1;">${r.name || 'Security Heuristic Pattern'}</div>
            </div>
            <span style="font-family:'JetBrains Mono'; font-weight:700; color:#ef4444;">+${r.weight || 25} Risk</span>
          </div>
        `).join('');
      }
    }

    // ADSA Blast Radius Assessment
    const targetedUsers = new Set();
    const targetedEndpoints = new Set();
    relatedEvents.forEach(e => {
      if (e.usernameIdentifier) targetedUsers.add(e.usernameIdentifier);
      if (e.resource) targetedEndpoints.add(e.resource);
    });

    setText('invBlastNodes', targetedUsers.size + targetedEndpoints.size + 2);
    setText('invBlastUsers', Array.from(targetedUsers).slice(0, 7).join(', ') || 'None');
    setText('invBlastResources', Array.from(targetedEndpoints).slice(0, 5).join(', ') || '/login');
  }

  function showEmptyState() {
    const setText = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };
    setText('invAlertId', '#ALT-0000');
    setText('invApp', 'No Active Incidents');
    setText('invSourceIp', '--');
    setText('invRiskLevel', 'SAFE (0/100)');
    setText('invCreatedAt', '--');
    setText('invPatternDetected', 'No active security incidents flagged in the system.');
  }

  function resolveCurrentIncident() {
    if (!window.SentinelDataStore) return;
    SentinelDataStore.updateAlertStatus(currentAlertId, 'RESOLVED');
    showToast(`Incident #ALT-${String(currentAlertId).padStart(4, '0')} marked as RESOLVED ✓`, 'success');
    loadAlert(currentAlertId);
  }

  return {
    loadAlert,
    loadEvent,
    resolveCurrentIncident,
    init: () => {
      const btnResolve = document.getElementById('btnResolveIncident');
      if (btnResolve) {
        btnResolve.addEventListener('click', resolveCurrentIncident);
      }

      if (window.SentinelDataStore) {
        SentinelDataStore.on('dataChanged', () => {
          if (SentinelState.currentView === 'investigation') {
            loadAlert(currentAlertId);
          }
        });
      }
    }
  };
})();

if (typeof window !== 'undefined') {
  window.InvestigationModule = InvestigationModule;
  document.addEventListener('DOMContentLoaded', InvestigationModule.init);
}
