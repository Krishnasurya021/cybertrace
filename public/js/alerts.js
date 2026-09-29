/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: Alerts Management & Live Emergency Alert Modal
 * Reads & updates directly from SentinelDataStore (Single Source of Truth).
 */

const AlertsModule = (() => {

  function loadAlerts() {
    if (!window.SentinelDataStore) return;

    const appId = (window.SentinelState && SentinelState.currentAppFilter) || 'ALL';
    const statusFilter = (document.getElementById('alertsStatusFilter') || {}).value || 'ALL';

    const alerts = SentinelDataStore.getAlerts({
      applicationId: appId,
      status: statusFilter
    });

    const tbody = document.getElementById('alertsTableBody');
    if (!tbody) return;

    if (!alerts || alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:28px; color:#64748b;">No active security alerts matching criteria.</td></tr>';
      return;
    }

    tbody.innerHTML = alerts.map(a => {
      const isCritical = a.riskLevel === 'CRITICAL' || a.risk_level === 'CRITICAL';
      const riskLevel = a.riskLevel || a.risk_level || 'HIGH';
      const riskScore = a.riskScore || a.risk_score || 75;
      const status = a.status || 'OPEN';
      const alertId = a.id || a.alertId || 1;
      const sourceIp = a.sourceIp || a.source_ip || '--';

      let statusBadgeClass = 'badge-critical';
      if (status === 'INVESTIGATING') statusBadgeClass = 'badge-monitoring';
      if (status === 'RESOLVED') statusBadgeClass = 'badge-safe';

      return `
        <tr class="${isCritical ? 'row-critical' : 'row-high'}">
          <td style="font-family:'JetBrains Mono'; font-weight:700; color:#fff;">#ALT-${String(alertId).padStart(4, '0')}</td>
          <td style="font-weight:600; color:#fff;">${a.applicationName || a.applicationId || 'College Portal'}</td>
          <td style="color:#f87171; font-weight:700;">${a.title || 'High-Risk Incident'}</td>
          <td style="font-family:'JetBrains Mono'; color:#cbd5e1;">${sourceIp}</td>
          <td><span class="badge ${isCritical ? 'badge-critical' : 'badge-alert'}">${riskLevel} (${riskScore}/100)</span></td>
          <td><span class="badge ${statusBadgeClass}">${status}</span></td>
          <td style="font-size:11.5px; color:#94a3b8; font-family:'JetBrains Mono';">${a.timestamp || a.created_at || '--'}</td>
          <td>
            <div style="display:flex; gap:6px; flex-wrap:wrap;">
              <button onclick="AlertsModule.openInvestigation(${alertId})" class="demo-btn demo-btn-critical" style="padding:3px 8px; font-size:10.5px;" title="View Deep Forensic Investigation">
                🔍 Investigate
              </button>
              ${status !== 'INVESTIGATING' && status !== 'RESOLVED' ? `
                <button onclick="AlertsModule.markInvestigating(${alertId})" class="demo-btn demo-btn-unknown" style="padding:3px 8px; font-size:10.5px;" title="Set Status to Investigating">
                  🟡 Investigate
                </button>
              ` : ''}
              ${status !== 'RESOLVED' ? `
                <button onclick="AlertsModule.resolveAlert(${alertId})" class="demo-btn demo-btn-safe" style="padding:3px 8px; font-size:10.5px;" title="Mark Alert as Resolved">
                  ✓ Resolve
                </button>
              ` : `
                <span style="font-size:11px; color:#10b981; font-weight:600; padding:2px 4px;">Resolved</span>
              `}
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Update sidebar alert badge
    const openCount = SentinelDataStore.getAlerts().filter(a => a.status === 'OPEN').length;
    const navBadge = document.getElementById('navAlertBadge');
    if (navBadge) navBadge.textContent = openCount;
  }

  function markInvestigating(alertId) {
    if (!window.SentinelDataStore) return;
    SentinelDataStore.updateAlertStatus(alertId, 'INVESTIGATING');
    showToast(`Alert #ALT-${String(alertId).padStart(4, '0')} marked as INVESTIGATING`, 'info');
    loadAlerts();
  }

  function resolveAlert(alertId) {
    if (!window.SentinelDataStore) return;
    SentinelDataStore.updateAlertStatus(alertId, 'RESOLVED');
    showToast(`Alert #ALT-${String(alertId).padStart(4, '0')} marked as RESOLVED ✓`, 'success');
    loadAlerts();
  }

  function showLiveAlertModal(alert) {
    const existing = document.getElementById('liveAlertModalContainer');
    if (existing) existing.remove();

    const container = document.createElement('div');
    container.id = 'liveAlertModalContainer';
    container.className = 'alert-modal-backdrop active';

    const rules = Array.isArray(alert.triggeredRules || alert.triggered_rules)
      ? (alert.triggeredRules || alert.triggered_rules)
      : [];
    const alertId = alert.id || alert.alertId || 1;

    container.innerHTML = `
      <div class="alert-modal-card">
        <div class="alert-modal-header">
          <div class="alert-siren-icon">🚨</div>
          <div class="alert-title-wrap">
            <h2>SECURITY ALERT: ${alert.title || 'HIGH-RISK AUTHENTICATION PATTERN'}</h2>
            <div class="alert-subtitle">Automated SIEM Risk Engine Detection Active</div>
          </div>
        </div>

        <div class="alert-details-grid">
          <div class="alert-field">
            <label>APPLICATION</label>
            <span>${alert.applicationName || alert.applicationId || 'College Portal'}</span>
          </div>
          <div class="alert-field">
            <label>SOURCE ORIGIN</label>
            <span style="color:#38bdf8;">${alert.sourceIp || alert.source_ip}</span>
          </div>
          <div class="alert-field">
            <label>TARGET IDENTIFIER</label>
            <span style="color:#f87171;">${alert.usernameIdentifier || alert.username || 'Multiple'}</span>
          </div>
          <div class="alert-field">
            <label>RISK SEVERITY</label>
            <span style="color:#ef4444; font-size:15px; font-weight:700;">${alert.riskScore || alert.risk_score}/100 [${alert.riskLevel || alert.risk_level}]</span>
          </div>
          <div class="alert-field">
            <label>PATTERN REASON</label>
            <span style="color:#cbd5e1; font-size:12px;">${alert.reason || 'Anomalous authentication behavior'}</span>
          </div>
          <div class="alert-field">
            <label>INCIDENT STATUS</label>
            <span style="color:#f59e0b; font-weight:700;">OPEN (ACTION REQUIRED)</span>
          </div>
        </div>

        <div class="triggered-rules-box">
          <div class="rules-heading">TRIGGERED SECURITY RULES &amp; HEURISTICS:</div>
          <div class="rules-pills">
            ${rules.map(r => `
              <div class="rule-tag">
                <b>${typeof r === 'string' ? r : r.rule_code}</b>: ${r.name || 'Pattern Heuristic'} (+${r.weight || 25})
              </div>
            `).join('') || '<div class="rule-tag">RULE-001: Repeated Failures</div><div class="rule-tag">RULE-002: Multiple Accounts</div>'}
          </div>
        </div>

        <div class="alert-actions">
          <button onclick="document.getElementById('liveAlertModalContainer').remove()" class="btn-dismiss">DISMISS</button>
          <button onclick="AlertsModule.openInvestigation(${alertId})" class="btn-investigate">INVESTIGATE INCIDENT ➔</button>
        </div>
      </div>
    `;

    document.body.appendChild(container);
  }

  function openInvestigation(alertId) {
    const existing = document.getElementById('liveAlertModalContainer');
    if (existing) existing.remove();

    if (window.SentinelState) {
      SentinelState.activeAlertId = alertId;
    }
    if (window.switchView) {
      switchView('investigation');
    }
    if (window.InvestigationModule) {
      InvestigationModule.loadAlert(alertId);
    }
  }

  return {
    loadAlerts,
    markInvestigating,
    resolveAlert,
    showLiveAlertModal,
    openInvestigation,
    init: () => {
      loadAlerts();

      if (window.SentinelDataStore) {
        SentinelDataStore.on('dataChanged', () => {
          if (SentinelState.currentView === 'alerts' || SentinelState.currentView === 'dashboard') {
            loadAlerts();
          }
        });
      }

      const statusFilt = document.getElementById('alertsStatusFilter');
      if (statusFilt) {
        statusFilt.addEventListener('change', loadAlerts);
      }
    }
  };
})();

if (typeof window !== 'undefined') {
  window.AlertsModule = AlertsModule;
  document.addEventListener('DOMContentLoaded', AlertsModule.init);
}
