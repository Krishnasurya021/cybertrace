/**
 * SENTINEL - Security Reports Module
 * Handles executive reporting, rule violation statistics, and CSV data export.
 */

const ReportsModule = {
  async loadSummary() {
    try {
      const res = await fetch('/api/reports/summary');
      if (!res.ok) return;
      const data = await res.json();

      document.getElementById('reportGeneratedAt').textContent = `Generated: ${data.generated_at}`;
      document.getElementById('repTotalLogs').textContent = data.total_logs_analyzed.toLocaleString();
      document.getElementById('repTotalAnomalies').textContent = data.total_anomalies_detected;
      document.getElementById('repHighRisk').textContent = data.high_risk_events;
      document.getElementById('repSuspiciousIPs').textContent = data.suspicious_ips_tracked;

      // Violations table
      const tbody = document.getElementById('reportViolationsTableBody');
      if (data.rule_violations && data.rule_violations.length > 0) {
        tbody.innerHTML = data.rule_violations.map(v => {
          let riskBadge = `<span class="badge badge-medium">MEDIUM</span>`;
          if (v.risk_level === 'CRITICAL') riskBadge = `<span class="badge badge-critical">CRITICAL</span>`;
          else if (v.risk_level === 'HIGH') riskBadge = `<span class="badge badge-high">HIGH</span>`;

          return `
            <tr>
              <td><strong>${v.rule_name}</strong></td>
              <td>${riskBadge}</td>
              <td class="font-mono" style="font-weight: 700; color: var(--accent-cyan);">${v.count} violations</td>
            </tr>
          `;
        }).join('');
      } else {
        tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; padding: 20px; color: var(--text-muted);">No rule violations on record.</td></tr>`;
      }
    } catch (err) {
      console.error('Failed to load reports summary:', err);
    }
  }
};
