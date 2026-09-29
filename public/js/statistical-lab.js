/**
 * SENTINEL - Python Statistical Anomaly Lab Module
 * Handles dynamic Z-Score calculation, threshold slider,
 * baseline distributions, and detected outlier table.
 */

const StatisticalLabModule = {
  async loadAnalysis() {
    const threshold = document.getElementById('zThresholdSlider').value;
    document.getElementById('zThresholdVal').textContent = `|z| ≥ ${threshold}`;

    try {
      const res = await fetch(`/api/detect/statistical?threshold=${threshold}`);
      if (!res.ok) return;
      const data = await res.json();

      this.renderBaselines(data.baselines);
      this.renderAnomalies(data.anomalies);
    } catch (err) {
      console.error('Failed to load statistical analysis:', err);
    }
  },

  renderBaselines(baselines) {
    const grid = document.getElementById('statBaselinesGrid');
    if (!baselines || !grid) return;

    const cards = [
      {
        title: 'Failed Logins per IP',
        icon: '⚠️',
        data: baselines.failed_logins_per_ip
      },
      {
        title: 'Session Duration (sec)',
        icon: '⏱️',
        data: baselines.session_duration_seconds
      },
      {
        title: 'User Request Velocity',
        icon: '🚀',
        data: baselines.user_request_volume
      }
    ];

    grid.innerHTML = cards.map(c => `
      <div class="kpi-card" style="padding: 14px;">
        <div class="kpi-label">${c.icon} ${c.title}</div>
        <div style="font-size: 0.82rem; margin-top: 6px; line-height: 1.5; color: var(--text-secondary);">
          <div>• Mean (μ): <strong style="color: #fff;">${c.data.mean}</strong></div>
          <div>• Median: <strong style="color: #fff;">${c.data.median}</strong></div>
          <div>• Std Dev (σ): <strong style="color: var(--accent-cyan);">${c.data.std_dev}</strong></div>
        </div>
      </div>
    `).join('');
  },

  renderAnomalies(anomalies) {
    const tbody = document.getElementById('statAnomaliesTableBody');
    if (!anomalies || anomalies.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 30px; color: var(--text-muted);">No statistical anomalies detected at current threshold. Try lowering the threshold slider.</td></tr>`;
      return;
    }

    tbody.innerHTML = anomalies.map(a => {
      let riskBadge = `<span class="badge badge-medium">MEDIUM</span>`;
      if (a.risk_level === 'CRITICAL') riskBadge = `<span class="badge badge-critical">CRITICAL</span>`;
      else if (a.risk_level === 'HIGH') riskBadge = `<span class="badge badge-high">HIGH</span>`;

      return `
        <tr>
          <td><strong style="color: var(--accent-cyan);">${a.dimension}</strong></td>
          <td><strong>${a.entity_name}</strong> <span style="font-size: 0.7rem; color: var(--text-muted);">(${a.entity_type})</span></td>
          <td class="font-mono">${a.observed_value}</td>
          <td class="font-mono">${a.mean}</td>
          <td class="font-mono">${a.std_dev}</td>
          <td class="font-mono" style="font-weight: 700; color: #f87171;">${a.z_score >= 0 ? '+' : ''}${a.z_score}</td>
          <td>${riskBadge}</td>
          <td style="font-size: 0.78rem;">${a.reason}</td>
        </tr>
      `;
    }).join('');
  }
};

// Listeners
document.addEventListener('DOMContentLoaded', () => {
  const slider = document.getElementById('zThresholdSlider');
  if (slider) {
    slider.addEventListener('input', () => {
      document.getElementById('zThresholdVal').textContent = `|z| ≥ ${slider.value}`;
    });
    slider.addEventListener('change', () => StatisticalLabModule.loadAnalysis());
  }

  const btnRecompute = document.getElementById('btnRunStatisticalAnalysis');
  if (btnRecompute) {
    btnRecompute.addEventListener('click', () => {
      showToast('Recomputing statistical baselines and Z-scores...');
      StatisticalLabModule.loadAnalysis();
    });
  }
});
