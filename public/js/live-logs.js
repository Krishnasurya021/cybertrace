/**
 * SENTINEL - Live Access Logs Monitor Module
 * Handles tabular log rendering, search, filters, pagination, and anomaly highlights.
 */

const LiveLogsModule = {
  currentPage: 1,
  limit: 25,
  totalPages: 1,

  isFirstPage() {
    return this.currentPage === 1;
  },

  async loadLogs(isBackground = false) {
    const search = document.getElementById('logSearchInput').value;
    const status = document.getElementById('filterStatus').value;
    const risk = document.getElementById('filterRisk').value;

    const query = new URLSearchParams({
      page: this.currentPage,
      limit: this.limit,
      search: search,
      status: status,
      risk: risk
    });

    try {
      const res = await fetch(`/api/logs?${query.toString()}`);
      if (!res.ok) return;
      const data = await res.json();

      this.totalPages = data.total_pages;
      this.renderTable(data.logs);
      document.getElementById('logPaginationInfo').textContent = 
        `Showing page ${data.page} of ${data.total_pages} (${data.total.toLocaleString()} total events)`;

      // Prev/Next buttons
      document.getElementById('btnLogPrevPage').disabled = (data.page <= 1);
      document.getElementById('btnLogNextPage').disabled = (data.page >= data.total_pages);
    } catch (err) {
      console.error('Failed to fetch logs:', err);
    }
  },

  renderTable(logs) {
    const tbody = document.getElementById('liveLogsTableBody');
    if (!logs || logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 40px; color: var(--text-muted);">No access logs matched the specified filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(l => {
      const isFailed = l.status === 'FAILED' || l.status === 'BLOCKED';
      const isSuspicious = Boolean(l.alert_id || l.is_anomaly || isFailed);
      const rowClass = isSuspicious ? 'suspicious-row' : '';

      // Status badge
      let statusBadge = `<span class="badge badge-success">${l.status}</span>`;
      if (l.status === 'FAILED') statusBadge = `<span class="badge badge-failed">FAILED</span>`;
      if (l.status === 'BLOCKED') statusBadge = `<span class="badge badge-blocked">BLOCKED</span>`;

      // Risk badge
      let riskBadge = `<span style="color: var(--text-muted); font-size: 0.72rem;">--</span>`;
      if (l.risk_level === 'CRITICAL') riskBadge = `<span class="badge badge-critical">CRITICAL</span>`;
      else if (l.risk_level === 'HIGH') riskBadge = `<span class="badge badge-high">HIGH</span>`;
      else if (l.risk_level === 'MEDIUM') riskBadge = `<span class="badge badge-medium">MEDIUM</span>`;
      else if (l.risk_level === 'LOW') riskBadge = `<span class="badge badge-low">LOW</span>`;

      // Anomaly indicator
      let anomalyText = `<span style="color: var(--text-muted); font-size: 0.75rem;">Normal</span>`;
      if (l.alert_id) {
        anomalyText = `<a href="javascript:void(0)" onclick="AlertInvestigationModule.openAlert(${l.alert_id})" style="color: #fbbf24; text-decoration: underline; font-weight: 600;">Alert #${l.alert_id} 🔍</a>`;
      } else if (l.failed_attempts > 0) {
        anomalyText = `<span style="color: #f87171; font-size: 0.75rem;">${l.failed_attempts} fails</span>`;
      }

      return `
        <tr class="${rowClass}">
          <td class="font-mono">#${l.log_id}</td>
          <td class="font-mono" style="font-size: 0.75rem;">${l.timestamp}</td>
          <td>
            <strong>${l.username}</strong>
            <div style="font-size: 0.7rem; color: var(--text-muted);">${l.role}</div>
          </td>
          <td class="font-mono">
            ${l.ip_address}
            <div style="font-size: 0.7rem; color: var(--text-muted);">${l.country || ''}</div>
          </td>
          <td>
            <div style="font-size: 0.78rem;">${l.resource_name}</div>
            <div class="font-mono" style="font-size: 0.7rem; color: var(--text-muted);">${l.path}</div>
          </td>
          <td><span class="font-mono" style="font-size: 0.75rem;">${l.http_method} ${l.action}</span></td>
          <td>${statusBadge}</td>
          <td>${riskBadge}</td>
          <td>${anomalyText}</td>
        </tr>
      `;
    }).join('');
  }
};

// Initialize Listeners
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btnApplyLogFilters').addEventListener('click', () => {
    LiveLogsModule.currentPage = 1;
    LiveLogsModule.loadLogs();
  });

  document.getElementById('btnResetLogFilters').addEventListener('click', () => {
    document.getElementById('logSearchInput').value = '';
    document.getElementById('filterStatus').value = 'ALL';
    document.getElementById('filterRisk').value = 'ALL';
    LiveLogsModule.currentPage = 1;
    LiveLogsModule.loadLogs();
  });

  document.getElementById('btnLogPrevPage').addEventListener('click', () => {
    if (LiveLogsModule.currentPage > 1) {
      LiveLogsModule.currentPage--;
      LiveLogsModule.loadLogs();
    }
  });

  document.getElementById('btnLogNextPage').addEventListener('click', () => {
    if (LiveLogsModule.currentPage < LiveLogsModule.totalPages) {
      LiveLogsModule.currentPage++;
      LiveLogsModule.loadLogs();
    }
  });
});
