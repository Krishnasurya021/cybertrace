/**
 * SENTINEL - Alert Investigation Module
 * Handles alert triage table, slide-out investigation workbench,
 * DMGT truth evaluation breakdown, and ADSA blast radius calculation.
 */

const AlertInvestigationModule = {
  currentAlertId: null,

  async loadAlerts() {
    try {
      const res = await fetch('/api/alerts');
      if (!res.ok) return;
      const data = await res.json();
      this.renderTable(data.alerts);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    }
  },

  renderTable(alerts) {
    const tbody = document.getElementById('alertsTableBody');
    if (!alerts || alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 40px; color: var(--text-muted);">No open security alerts. All systems secure.</td></tr>`;
      return;
    }

    tbody.innerHTML = alerts.map(a => {
      let riskBadge = `<span class="badge badge-low">LOW</span>`;
      if (a.risk_level === 'CRITICAL') riskBadge = `<span class="badge badge-critical">CRITICAL</span>`;
      else if (a.risk_level === 'HIGH') riskBadge = `<span class="badge badge-high">HIGH</span>`;
      else if (a.risk_level === 'MEDIUM') riskBadge = `<span class="badge badge-medium">MEDIUM</span>`;

      return `
        <tr>
          <td class="font-mono">#A${a.alert_id}</td>
          <td>${riskBadge}</td>
          <td>
            <strong>${a.title}</strong>
            <div style="font-size: 0.73rem; color: var(--text-muted);">${a.description.slice(0, 60)}...</div>
          </td>
          <td>
            <strong>${a.username}</strong>
            <div style="font-size: 0.7rem; color: var(--text-muted);">${a.department || ''}</div>
          </td>
          <td class="font-mono">
            ${a.ip_address}
            <div style="font-size: 0.7rem; color: var(--text-muted);">${a.country || ''}</div>
          </td>
          <td>
            <span class="font-mono" style="font-size: 0.74rem; color: var(--accent-cyan);">${a.rule_code || 'CUSTOM'}</span>
          </td>
          <td class="font-mono" style="font-size: 0.74rem;">${a.created_at}</td>
          <td>
            <span class="badge ${a.status === 'OPEN' ? 'badge-failed' : 'badge-success'}">${a.status}</span>
          </td>
          <td>
            <button class="btn btn-primary" style="padding: 4px 10px; font-size: 0.75rem;" onclick="AlertInvestigationModule.openAlert(${a.alert_id})">
              Investigate 🔍
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  async openAlert(alertId) {
    this.currentAlertId = alertId;
    try {
      const res = await fetch(`/api/alerts/${alertId}/investigate`);
      if (!res.ok) {
        showToast('Could not load investigation data for alert #' + alertId, 'danger');
        return;
      }
      const data = await res.json();
      const a = data.alert;

      // Header
      document.getElementById('drawerAlertTitle').textContent = `Investigation: Alert #A${a.alert_id}`;
      document.getElementById('drawerAlertTime').textContent = `Logged At: ${a.created_at}`;

      // Incident overview
      const rBadge = document.getElementById('drawerRiskBadge');
      rBadge.textContent = a.risk_level;
      rBadge.className = `badge badge-${a.risk_level.toLowerCase()}`;
      document.getElementById('drawerRuleCode').textContent = `Rule: ${a.rule_code || 'STATISTICAL_OUTLIER'}`;
      document.getElementById('drawerAlertDescription').textContent = a.description;

      // Affected entities
      document.getElementById('drawerPropUser').textContent = `${a.username} (${a.email || 'N/A'})`;
      document.getElementById('drawerPropRole').textContent = a.role;
      document.getElementById('drawerPropIP').textContent = `${a.ip_address} (Risk Score: ${a.ip_risk}/100)`;
      document.getElementById('drawerPropLocation').textContent = `${a.city}, ${a.country} ${a.is_known_proxy ? '⚠️ [KNOWN PROXY/TOR]' : ''}`;
      document.getElementById('drawerPropResource').textContent = `${a.resource_name} (${a.path})`;
      document.getElementById('drawerPropFailedAttempts').textContent = a.failed_attempts;

      // DMGT Propositional Logic Breakdown
      document.getElementById('drawerDmgtFormula').textContent = `Rule Formula: ${a.logical_expression || 'Statistical Z-Score |z| >= 2.5'}`;
      const truthMapEl = document.getElementById('drawerTruthMap');
      if (data.dmgt_evaluation && data.dmgt_evaluation.facts_evaluated) {
        const f = data.dmgt_evaluation.facts_evaluated;
        truthMapEl.innerHTML = `
          <div style="color: ${f.failed_attempts > 5 ? '#f87171' : '#34d399'};">P1 (FailedAttempts > 5): ${f.failed_attempts > 5} (Observed: ${f.failed_attempts})</div>
          <div style="color: ${f.hour >= 23 || f.hour < 5 ? '#fbbf24' : '#34d399'};">P3 (OffHours 23:00-05:00): ${f.hour >= 23 || f.hour < 5} (Observed hour: ${f.hour}:00)</div>
          <div style="color: ${f.is_restricted && f.user_role !== 'ADMIN' ? '#f87171' : '#34d399'};">P4 (Unauthorized Restricted): ${Boolean(f.is_restricted && f.user_role !== 'ADMIN')} (Role: ${f.user_role})</div>
          <div style="color: ${f.is_known_proxy ? '#f87171' : '#34d399'};">P5 (Proxy / Tor Node): ${Boolean(f.is_known_proxy)}</div>
        `;
      } else {
        truthMapEl.innerHTML = `<div style="color: var(--text-muted);">Standard DMGT evaluation applied.</div>`;
      }

      // ADSA Blast Radius
      const b = data.blast_radius;
      document.getElementById('drawerBlastTotal').textContent = `${b.total_compromised_nodes} connected entities`;
      const exposedNames = b.resources_exposed.map(r => r.label).slice(0, 4);
      document.getElementById('drawerBlastDetails').innerHTML = `
        <div>• Impacted Users: ${b.users_impacted.map(u => u.label).join(', ') || 'None'}</div>
        <div>• Involved IPs: ${b.ips_involved.map(ip => ip.label).join(', ') || 'None'}</div>
        <div>• Exposed Resources: ${exposedNames.join(', ') || 'None'}</div>
      `;

      // Timeline
      const timelineEl = document.getElementById('drawerTimeline');
      timelineEl.innerHTML = data.timeline.map(t => `
        <div class="timeline-item">
          <div class="timeline-dot ${t.status === 'FAILED' ? 'failed' : ''}"></div>
          <div class="timeline-content">
            <div style="color: var(--text-muted); font-size: 0.7rem;">${t.timestamp}</div>
            <div><strong>${t.action}</strong> on <code>${t.path}</code> (${t.status})</div>
          </div>
        </div>
      `).join('');

      // Open Drawer
      document.getElementById('drawerOverlay').classList.add('open');
      document.getElementById('investigationDrawer').classList.add('open');
    } catch (err) {
      console.error('Failed to open alert drawer:', err);
    }
  },

  closeDrawer() {
    document.getElementById('drawerOverlay').classList.remove('open');
    document.getElementById('investigationDrawer').classList.remove('open');
  },

  async updateStatus(newStatus) {
    if (!this.currentAlertId) return;
    try {
      const res = await fetch(`/api/alerts/${this.currentAlertId}/update-status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus, notes: `Investigated by analyst via SOC drawer.` })
      });
      if (res.ok) {
        showToast(`Alert #${this.currentAlertId} marked as ${newStatus}`, 'success');
        this.closeDrawer();
        this.loadAlerts();
      }
    } catch (err) {
      showToast('Failed to update alert status: ' + err.message, 'danger');
    }
  }
};

// Listeners
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btnCloseDrawer').addEventListener('click', () => AlertInvestigationModule.closeDrawer());
  document.getElementById('drawerOverlay').addEventListener('click', () => AlertInvestigationModule.closeDrawer());
  document.getElementById('btnMarkInvestigating').addEventListener('click', () => AlertInvestigationModule.updateStatus('INVESTIGATING'));
  document.getElementById('btnMarkResolved').addEventListener('click', () => AlertInvestigationModule.updateStatus('RESOLVED'));
});
