/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: Source IP & Username Analysis Intelligence Views
 * Renders aggregated telemetry directly from SentinelDataStore.
 */

const SourceAnalysisModule = (() => {
  let activeTab = 'ip'; // 'ip' or 'user'
  let filterQuery = '';

  function init() {
    render();
    if (window.SentinelDataStore) {
      SentinelDataStore.on('dataChanged', () => {
        if (SentinelState.currentView === 'source-analysis' || SentinelState.currentView === 'entity-analysis') {
          render();
        }
      });
    }

    const searchInput = document.getElementById('sourceAnalysisSearch');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        filterQuery = e.target.value.toLowerCase().trim();
        render();
      });
    }

    const tabIpBtn = document.getElementById('tabSourceIp');
    if (tabIpBtn) {
      tabIpBtn.addEventListener('click', () => {
        activeTab = 'ip';
        tabIpBtn.classList.add('active');
        const tabUserBtn = document.getElementById('tabUsername');
        if (tabUserBtn) tabUserBtn.classList.remove('active');
        render();
      });
    }

    const tabUserBtn = document.getElementById('tabUsername');
    if (tabUserBtn) {
      tabUserBtn.addEventListener('click', () => {
        activeTab = 'user';
        tabUserBtn.classList.add('active');
        const tabIpBtn = document.getElementById('tabSourceIp');
        if (tabIpBtn) tabIpBtn.classList.remove('active');
        render();
      });
    }
  }

  function render() {
    if (activeTab === 'ip') {
      renderIpTable();
    } else {
      renderUsernameTable();
    }
  }

  function renderIpTable() {
    const tbody = document.getElementById('sourceAnalysisTableBody');
    const thead = document.getElementById('sourceAnalysisTableHead');
    if (!tbody || !thead) return;

    thead.innerHTML = `
      <tr>
        <th>IP ADDRESS</th>
        <th>TOTAL ATTEMPTS</th>
        <th>SUCCESS</th>
        <th>FAILED</th>
        <th>UNKNOWN ACCOUNTS</th>
        <th>UNIQUE USERS</th>
        <th>APPLICATIONS</th>
        <th>HIGHEST RISK</th>
        <th>LATEST ACTIVITY</th>
        <th>ACTION</th>
      </tr>
    `;

    const ipData = window.SentinelDataStore ? SentinelDataStore.getSourceIpAnalysis() : [];
    const filtered = ipData.filter(item =>
      !filterQuery ||
      item.sourceIp.toLowerCase().includes(filterQuery) ||
      item.applicationsList.some(a => a.toLowerCase().includes(filterQuery)) ||
      item.uniqueUsersList.some(u => u.toLowerCase().includes(filterQuery))
    );

    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" style="text-align:center; padding:24px; color:#64748b;">No matching source IP records found.</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.map(item => {
      let riskBadgeClass = 'badge-safe';
      if (item.highestRiskLevel === 'CRITICAL') riskBadgeClass = 'badge-critical';
      else if (item.highestRiskLevel === 'HIGH') riskBadgeClass = 'badge-alert';
      else if (item.highestRiskLevel === 'MEDIUM') riskBadgeClass = 'badge-suspicious';

      return `
        <tr onclick="SourceAnalysisModule.showIpEvents('${item.sourceIp}')" style="cursor:pointer;">
          <td style="font-family:'JetBrains Mono'; font-weight:700; color:#38bdf8;">${item.sourceIp}</td>
          <td style="font-family:'JetBrains Mono'; font-weight:700; color:#fff;">${item.totalAttempts}</td>
          <td style="color:#10b981; font-weight:600;">${item.successful}</td>
          <td style="color:#f87171; font-weight:600;">${item.failed}</td>
          <td style="color:#38bdf8;">${item.unknownAccounts}</td>
          <td><span class="badge badge-monitoring">${item.uniqueUsersCount} users</span></td>
          <td style="font-size:11.5px; color:#cbd5e1;">${item.applicationsList.slice(0, 2).join(', ') || 'None'}</td>
          <td><span class="badge ${riskBadgeClass}">${item.highestRiskLevel} (${item.highestRiskScore}/100)</span></td>
          <td style="font-family:'JetBrains Mono'; font-size:11px; color:#94a3b8;">${item.latestActivity}</td>
          <td>
            <button onclick="event.stopPropagation(); SourceAnalysisModule.filterInLiveMonitor('${item.sourceIp}')" class="demo-btn demo-btn-unknown" style="padding:2px 8px; font-size:10.5px;">
              Filter Logs ➔
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function renderUsernameTable() {
    const tbody = document.getElementById('sourceAnalysisTableBody');
    const thead = document.getElementById('sourceAnalysisTableHead');
    if (!tbody || !thead) return;

    thead.innerHTML = `
      <tr>
        <th>USERNAME IDENTIFIER</th>
        <th>APPLICATIONS TARGETED</th>
        <th>TOTAL ATTEMPTS</th>
        <th>SUCCESS</th>
        <th>FAILED</th>
        <th>UNKNOWN</th>
        <th>FIRST SEEN</th>
        <th>LAST SEEN</th>
        <th>HIGHEST RISK</th>
        <th>ACTION</th>
      </tr>
    `;

    const userData = window.SentinelDataStore ? SentinelDataStore.getUsernameAnalysis() : [];
    const filtered = userData.filter(item =>
      !filterQuery ||
      item.username.toLowerCase().includes(filterQuery) ||
      item.applicationsList.some(a => a.toLowerCase().includes(filterQuery))
    );

    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" style="text-align:center; padding:24px; color:#64748b;">No matching username records found.</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.map(item => {
      let riskBadgeClass = 'badge-safe';
      if (item.highestRiskLevel === 'CRITICAL') riskBadgeClass = 'badge-critical';
      else if (item.highestRiskLevel === 'HIGH') riskBadgeClass = 'badge-alert';
      else if (item.highestRiskLevel === 'MEDIUM') riskBadgeClass = 'badge-suspicious';

      return `
        <tr onclick="SourceAnalysisModule.showUserEvents('${item.username}')" style="cursor:pointer;">
          <td style="font-family:'JetBrains Mono'; font-weight:700; color:#38bdf8;">${item.username}</td>
          <td style="font-size:11.5px; color:#cbd5e1;">${item.applicationsList.slice(0, 2).join(', ') || 'All'}</td>
          <td style="font-family:'JetBrains Mono'; font-weight:700; color:#fff;">${item.totalAttempts}</td>
          <td style="color:#10b981; font-weight:600;">${item.successful}</td>
          <td style="color:#f87171; font-weight:600;">${item.failed}</td>
          <td style="color:#38bdf8;">${item.unknown}</td>
          <td style="font-family:'JetBrains Mono'; font-size:11px; color:#94a3b8;">${item.firstSeen}</td>
          <td style="font-family:'JetBrains Mono'; font-size:11px; color:#94a3b8;">${item.lastSeen}</td>
          <td><span class="badge ${riskBadgeClass}">${item.highestRiskLevel} (${item.highestRiskScore}/100)</span></td>
          <td>
            <button onclick="event.stopPropagation(); SourceAnalysisModule.filterInLiveMonitor('${item.username}')" class="demo-btn demo-btn-unknown" style="padding:2px 8px; font-size:10.5px;">
              Filter Logs ➔
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function filterInLiveMonitor(term) {
    if (window.switchView) switchView('dashboard');
    const input = document.getElementById('liveLogSearchInput');
    if (input) {
      input.value = term;
      if (window.DashboardModule) DashboardModule.loadLiveLogs();
    }
  }

  function showIpEvents(ip) {
    const events = window.SentinelDataStore ? SentinelDataStore.getEvents({ search: ip, limit: 20 }) : [];
    showDetailModal(`Origin IP Telemetry: ${ip}`, events);
  }

  function showUserEvents(user) {
    const events = window.SentinelDataStore ? SentinelDataStore.getEvents({ search: user, limit: 20 }) : [];
    showDetailModal(`Targeted Account Telemetry: ${user}`, events);
  }

  function showDetailModal(title, eventsList) {
    const existing = document.getElementById('sourceAnalysisDetailModal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'sourceAnalysisDetailModal';
    modal.className = 'alert-modal-backdrop active';
    modal.innerHTML = `
      <div class="alert-modal-card" style="max-width:750px; border-color:var(--cyan-primary);">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
          <h3 style="font-family:var(--font-display); font-size:17px; color:#fff;">${title}</h3>
          <button onclick="document.getElementById('sourceAnalysisDetailModal').remove()" style="background:transparent; border:none; color:#94a3b8; font-size:18px; cursor:pointer;">✕</button>
        </div>
        <p style="font-size:12px; color:#94a3b8; margin-bottom:12px;">Showing latest authentication records matching this entity from single source of truth:</p>
        <div class="table-responsive" style="max-height:380px; overflow-y:auto;">
          <table class="soc-table">
            <thead>
              <tr>
                <th>TIME</th>
                <th>APP</th>
                <th>USERNAME</th>
                <th>RESULT</th>
                <th>ORIGIN IP</th>
                <th>RISK</th>
              </tr>
            </thead>
            <tbody>
              ${eventsList.map(ev => `
                <tr>
                  <td style="font-family:'JetBrains Mono'; font-size:11px; color:#94a3b8;">${ev.timestamp}</td>
                  <td>${ev.applicationName || ev.applicationId}</td>
                  <td style="font-family:'JetBrains Mono'; color:#38bdf8;">${ev.usernameIdentifier}</td>
                  <td><span class="badge ${ev.authenticationResult === 'SUCCESS' ? 'badge-safe' : 'badge-suspicious'}">${ev.authenticationResult}</span></td>
                  <td style="font-family:'JetBrains Mono';">${ev.sourceIp}</td>
                  <td><span class="score-badge" style="background:rgba(0,242,254,0.1); color:var(--cyan-primary);">${ev.riskScore}/100</span></td>
                </tr>
              `).join('') || '<tr><td colspan="6" style="text-align:center; padding:16px;">No records.</td></tr>'}
            </tbody>
          </table>
        </div>
        <div style="display:flex; justify-content:flex-end; margin-top:16px;">
          <button onclick="document.getElementById('sourceAnalysisDetailModal').remove()" class="btn-dismiss">Close</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  return {
    init,
    render,
    showIpEvents,
    showUserEvents,
    filterInLiveMonitor
  };
})();

if (typeof window !== 'undefined') {
  window.SourceAnalysisModule = SourceAnalysisModule;
  document.addEventListener('DOMContentLoaded', SourceAnalysisModule.init);
}
