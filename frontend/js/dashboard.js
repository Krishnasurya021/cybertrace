/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: SOC Dashboard, Dynamic KPI Telemetry & Live Monitor Stream
 * Reads directly from SentinelDataStore (Single Source of Truth).
 */

const DashboardModule = (() => {

  function loadData() {
    if (!window.SentinelDataStore) return;

    const appId = (window.SentinelState && SentinelState.currentAppFilter) || 'ALL';
    const stats = SentinelDataStore.getStatistics(appId);

    updateKPIs(stats.kpis);
    renderHourlyChart(stats.charts.hourly_pattern);
    renderResultDistribution(stats.charts.result_distribution);
    renderRiskDistribution(stats.charts.risk_distribution);
    renderTopAccounts(stats.charts.top_targeted_accounts);

    loadLiveLogs();
  }

  function updateKPIs(kpis) {
    if (!kpis) return;
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = Number(val || 0).toLocaleString();
    };

    setVal('kpiConnectedApps', kpis.connected_apps);
    setVal('kpiTotalEvents', kpis.total_events);
    setVal('kpiSuccessLogins', kpis.successful_logins);
    setVal('kpiFailedLogins', kpis.failed_logins);
    setVal('kpiUnknownAccounts', kpis.unknown_accounts);
    setVal('kpiSuspiciousEvents', kpis.suspicious_events);
    setVal('kpiHighRiskAlerts', kpis.high_risk_alerts);

    const navBadge = document.getElementById('navAlertBadge');
    if (navBadge) navBadge.textContent = kpis.high_risk_alerts;
  }

  function renderHourlyChart(hourlyData) {
    const container = document.getElementById('hourlyChartContainer');
    if (!container || !hourlyData || !hourlyData.length) return;

    const maxCount = Math.max(...hourlyData.map(d => d.count), 5);
    const width = container.clientWidth || 500;
    const height = 180;
    const padding = 28;

    const points = hourlyData.map((d, i) => {
      const x = padding + (i / Math.max(1, hourlyData.length - 1)) * (width - padding * 2);
      const y = height - padding - (d.count / maxCount) * (height - padding * 2);
      return { x, y, hour: d.hour, count: d.count };
    });

    const pathD = points.reduce((acc, p, i) => `${acc} ${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`, '');
    const areaD = `${pathD} L ${points[points.length - 1].x} ${height - padding} L ${points[0].x} ${height - padding} Z`;

    container.innerHTML = `
      <svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}">
        <defs>
          <linearGradient id="areaGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stop-color="#00f2fe" stop-opacity="0.35"/>
            <stop offset="100%" stop-color="#00f2fe" stop-opacity="0.0"/>
          </linearGradient>
        </defs>
        <!-- Horizontal grid lines -->
        <line x1="${padding}" y1="${height - padding}" x2="${width - padding}" y2="${height - padding}" stroke="rgba(255,255,255,0.1)" stroke-width="1"/>
        <line x1="${padding}" y1="${(height - padding) / 2}" x2="${width - padding}" y2="${(height - padding) / 2}" stroke="rgba(255,255,255,0.05)" stroke-dasharray="4 2"/>
        <!-- Area & Line -->
        <path d="${areaD}" fill="url(#areaGrad)"/>
        <path d="${pathD}" fill="none" stroke="#00f2fe" stroke-width="2.5" stroke-linecap="round"/>
        <!-- Data dots -->
        ${points.filter((_, i) => i % 3 === 0).map(p => `
          <circle cx="${p.x}" cy="${p.y}" r="3.5" fill="#00f2fe" stroke="#070b13" stroke-width="1.5"/>
          <text x="${p.x}" y="${height - 8}" fill="#64748b" font-size="9" text-anchor="middle" font-family="'JetBrains Mono'">${p.hour.substring(0,2)}h</text>
        `).join('')}
      </svg>
    `;
  }

  function renderResultDistribution(results) {
    const container = document.getElementById('resultsDistContainer');
    if (!container || !results) return;

    const total = results.reduce((acc, r) => acc + r.count, 0) || 1;
    const colorMap = {
      'SUCCESS': '#10b981',
      'FAILURE': '#f59e0b',
      'UNKNOWN_ACCOUNT': '#38bdf8',
      'MFA_FAILURE': '#f97316',
      'LOCKED_ACCOUNT': '#ef4444'
    };

    if (results.length === 0) {
      container.innerHTML = '<div style="color:#64748b; font-size:12px; padding:12px;">No telemetry logged yet.</div>';
      return;
    }

    container.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:8px;">
        ${results.map(r => {
          const pct = Math.round((r.count / total) * 100);
          const color = colorMap[r.authentication_result] || '#94a3b8';
          return `
            <div>
              <div style="display:flex; justify-content:space-between; font-size:11.5px; margin-bottom:3px;">
                <span style="font-weight:600; color:#fff;">${r.authentication_result}</span>
                <span style="font-family:'JetBrains Mono'; color:${color}; font-weight:700;">${r.count} (${pct}%)</span>
              </div>
              <div style="height:6px; background:rgba(255,255,255,0.06); border-radius:3px; overflow:hidden;">
                <div style="width:${pct}%; height:100%; background:${color}; border-radius:3px;"></div>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }

  function renderRiskDistribution(risks) {
    const container = document.getElementById('riskDistContainer');
    if (!container || !risks) return;

    const riskColors = {
      'LOW': '#10b981',
      'MEDIUM': '#f59e0b',
      'HIGH': '#f97316',
      'CRITICAL': '#ef4444'
    };

    const total = risks.reduce((acc, r) => acc + r.count, 0) || 1;

    container.innerHTML = `
      <div style="display:flex; gap:6px; height:12px; border-radius:6px; overflow:hidden; margin-bottom:12px; background:rgba(255,255,255,0.04);">
        ${risks.map(r => {
          const pct = Math.max(r.count > 0 ? 3 : 0, Math.round((r.count / total) * 100));
          return `<div style="width:${pct}%; background:${riskColors[r.risk_level] || '#fff'};" title="${r.risk_level}: ${r.count}"></div>`;
        }).join('')}
      </div>
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
        ${risks.map(r => `
          <div style="display:flex; align-items:center; gap:6px; font-size:11px;">
            <span style="width:8px; height:8px; border-radius:50%; background:${riskColors[r.risk_level]};"></span>
            <span style="color:var(--text-secondary);">${r.risk_level}:</span>
            <span style="font-family:'JetBrains Mono'; font-weight:700; color:#fff;">${r.count}</span>
          </div>
        `).join('')}
      </div>
    `;
  }

  function renderTopAccounts(accounts) {
    const container = document.getElementById('topAccountsContainer');
    if (!container || !accounts) return;

    if (accounts.length === 0) {
      container.innerHTML = '<div style="color:#64748b; font-size:12px; padding:12px;">No activity logged yet.</div>';
      return;
    }

    container.innerHTML = accounts.map(a => `
      <div style="display:flex; align-items:center; justify-content:space-between; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.04); font-size:12px;">
        <span style="font-family:'JetBrains Mono'; color:#fff; font-weight:600;">${a.username_identifier}</span>
        <div style="display:flex; gap:10px; font-family:'JetBrains Mono'; font-size:11px;">
          <span style="color:#10b981;">✓ ${a.successes}</span>
          <span style="color:#f87171;">✗ ${a.failures}</span>
          <span style="color:var(--cyan-primary); font-weight:700;">Tot: ${a.total_attempts}</span>
        </div>
      </div>
    `).join('');
  }

  function loadLiveLogs() {
    if (!window.SentinelDataStore) return;

    const appId = (window.SentinelState && SentinelState.currentAppFilter) || 'ALL';
    const search = (document.getElementById('liveLogSearchInput') || {}).value || '';
    const risk = (document.getElementById('liveLogRiskFilter') || {}).value || 'ALL';
    const result = (document.getElementById('liveLogResultFilter') || {}).value || 'ALL';

    const events = SentinelDataStore.getEvents({
      applicationId: appId,
      riskLevel: risk,
      result: result,
      search: search,
      limit: 25
    });

    const tbodyList = [
      document.getElementById('liveLogsTableBody'),
      document.getElementById('fullLiveLogsTableBody')
    ];

    tbodyList.forEach(tbody => {
      if (!tbody) return;

      if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding:24px; color:#64748b;">No authentication events matching current filter criteria.</td></tr>';
        return;
      }

      tbody.innerHTML = events.map(ev => {
        const timeStr = ev.timestamp ? ev.timestamp.split(' ')[1] || ev.timestamp : '--:--:--';
        const isCritical = ev.riskLevel === 'CRITICAL';
        const isHigh = ev.riskLevel === 'HIGH';
        const rowClass = isCritical ? 'row-critical' : (isHigh ? 'row-high' : '');

        let statusBadgeClass = 'badge-safe';
        if (ev.status === 'MONITORING') statusBadgeClass = 'badge-monitoring';
        if (ev.status === 'SUSPICIOUS') statusBadgeClass = 'badge-suspicious';
        if (ev.status === 'ALERT') statusBadgeClass = 'badge-alert';
        if (ev.status === 'CRITICAL_ALERT') statusBadgeClass = 'badge-critical';

        let scoreColor = '#10b981';
        if (ev.riskScore >= 75) scoreColor = '#ef4444';
        else if (ev.riskScore >= 50) scoreColor = '#f97316';
        else if (ev.riskScore >= 25) scoreColor = '#f59e0b';

        return `
          <tr class="${rowClass}" onclick="DashboardModule.inspectEvent(${ev.id})" style="cursor:pointer;">
            <td style="font-family:'JetBrains Mono'; font-size:11.5px; color:#94a3b8;">${timeStr}</td>
            <td style="font-weight:600; color:#fff;">${ev.applicationName || ev.applicationId}</td>
            <td style="font-family:'JetBrains Mono'; font-weight:600; color:${isCritical ? '#f87171' : '#38bdf8'};">${ev.usernameIdentifier}</td>
            <td><span class="badge ${ev.authenticationResult === 'SUCCESS' ? 'badge-safe' : 'badge-suspicious'}">${ev.authenticationResult}</span></td>
            <td style="font-family:'JetBrains Mono'; color:#cbd5e1;">${ev.sourceIp}</td>
            <td>${ev.deviceType || 'Desktop'}</td>
            <td><span class="badge ${statusBadgeClass}">${ev.riskLevel}</span></td>
            <td><span class="score-badge" style="background:${scoreColor}22; color:${scoreColor}; border:1px solid ${scoreColor}44;">${ev.riskScore}/100</span></td>
            <td><span class="badge ${statusBadgeClass}">${ev.status}</span></td>
          </tr>
        `;
      }).join('');
    });
  }

  function clearFilters() {
    const s = document.getElementById('liveLogSearchInput');
    const r = document.getElementById('liveLogRiskFilter');
    const res = document.getElementById('liveLogResultFilter');
    if (s) s.value = '';
    if (r) r.value = 'ALL';
    if (res) res.value = 'ALL';
    loadLiveLogs();
  }

  function inspectEvent(eventId) {
    if (!window.SentinelDataStore) return;
    const events = SentinelDataStore.getEvents();
    const ev = events.find(e => e.id === eventId);
    if (!ev) return;

    const existing = document.getElementById('eventInspectorModal');
    if (existing) existing.remove();

    const rules = Array.isArray(ev.triggeredRules) ? ev.triggeredRules : [];

    const modal = document.createElement('div');
    modal.id = 'eventInspectorModal';
    modal.className = 'alert-modal-backdrop active';
    modal.innerHTML = `
      <div class="alert-modal-card" style="border-color:var(--cyan-primary); max-width:640px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
          <h3 style="font-family:var(--font-display); font-size:16px; color:#fff;">Authentication Event Inspector #${ev.id}</h3>
          <button onclick="document.getElementById('eventInspectorModal').remove()" style="background:transparent; border:none; color:#94a3b8; font-size:18px; cursor:pointer;">✕</button>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; font-size:12px; margin-bottom:14px; background:#070b13; padding:12px; border-radius:8px;">
          <div><span style="color:#64748b;">Timestamp:</span> <b style="color:#fff;">${ev.timestamp}</b></div>
          <div><span style="color:#64748b;">Application:</span> <b style="color:#fff;">${ev.applicationName} (${ev.applicationId})</b></div>
          <div><span style="color:#64748b;">Identity:</span> <b style="color:#38bdf8;">${ev.usernameIdentifier}</b></div>
          <div><span style="color:#64748b;">Result:</span> <b style="color:#fff;">${ev.authenticationResult}</b></div>
          <div><span style="color:#64748b;">Source IP:</span> <b style="color:#cbd5e1;">${ev.sourceIp}</b></div>
          <div><span style="color:#64748b;">Device &amp; Endpoint:</span> <b style="color:#fff;">${ev.deviceType} (${ev.resource || '/login'})</b></div>
          <div><span style="color:#64748b;">Risk Score:</span> <b style="color:var(--cyan-primary);">${ev.riskScore}/100 [${ev.riskLevel}]</b></div>
          <div><span style="color:#64748b;">Telemetry Status:</span> <b style="color:#10b981;">${ev.status}</b></div>
        </div>
        <div style="background:rgba(16, 185, 129, 0.08); border:1px solid rgba(16, 185, 129, 0.3); border-radius:6px; padding:10px; margin-bottom:12px; font-size:11.5px; color:#34d399;">
          🛡️ <b>STRICT ZERO-PASSWORD VERIFIED:</b> SENTINEL verified this authentication event metadata without receiving, storing, or processing any raw passwords.
        </div>
        <div style="margin-bottom:12px;">
          <div style="font-size:11px; font-weight:700; color:#94a3b8; margin-bottom:4px;">RISK ENGINE EXPLANATION:</div>
          <p style="font-size:12px; color:#e2e8f0; background:rgba(255,255,255,0.03); padding:8px 12px; border-radius:6px;">${ev.explanation || 'Standard authentication event.'}</p>
        </div>
        ${rules.length > 0 ? `
          <div style="margin-bottom:14px;">
            <div style="font-size:11px; font-weight:700; color:#94a3b8; margin-bottom:6px;">TRIGGERED HEURISTIC RULES:</div>
            <div style="display:flex; flex-wrap:wrap; gap:6px;">
              ${rules.map(r => `<span class="rule-tag"><b>${r.rule_code}</b>: ${r.name} (+${r.weight})</span>`).join('')}
            </div>
          </div>
        ` : ''}
        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:16px;">
          <button onclick="DashboardModule.investigateEvent(${ev.id})" class="btn-investigate" style="padding:6px 14px; font-size:11.5px;">
            Open in Investigation Dossier ➔
          </button>
          <button onclick="document.getElementById('eventInspectorModal').remove()" class="btn-dismiss">Close Inspector</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  function investigateEvent(eventId) {
    const existing = document.getElementById('eventInspectorModal');
    if (existing) existing.remove();

    if (window.switchView) switchView('investigation');
    if (window.InvestigationModule) {
      InvestigationModule.loadEvent(eventId);
    }
  }

  return {
    loadData,
    loadLiveLogs,
    inspectEvent,
    investigateEvent,
    clearFilters,
    init: () => {
      loadData();

      // Reactive binding
      if (window.SentinelDataStore) {
        SentinelDataStore.on('dataChanged', () => {
          loadData();
        });
      }

      const searchInp = document.getElementById('liveLogSearchInput');
      if (searchInp) searchInp.addEventListener('input', () => loadLiveLogs());

      const riskFilt = document.getElementById('liveLogRiskFilter');
      if (riskFilt) riskFilt.addEventListener('change', () => loadLiveLogs());

      const resFilt = document.getElementById('liveLogResultFilter');
      if (resFilt) resFilt.addEventListener('change', () => loadLiveLogs());

      const btnClear = document.getElementById('btnClearLiveLogFilters');
      if (btnClear) btnClear.addEventListener('click', clearFilters);
    }
  };
})();

if (typeof window !== 'undefined') {
  window.DashboardModule = DashboardModule;
  document.addEventListener('DOMContentLoaded', DashboardModule.init);
}
