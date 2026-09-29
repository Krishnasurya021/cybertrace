/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: Python Statistical Anomaly Detection Lab
 * Fetches Z-score anomaly detections from backend or calculates on local store as fallback.
 */

const StatisticalModule = (() => {

  function calculateLocalStatistics(events, threshold) {
    // 1. Failed logins per IP
    const failsByIp = {};
    const reqsByUser = {};

    events.forEach(e => {
      const ip = e.sourceIp || '127.0.0.1';
      const u = e.usernameIdentifier || 'user';
      if (!failsByIp[ip]) failsByIp[ip] = 0;
      if (['FAILURE', 'UNKNOWN_ACCOUNT', 'MFA_FAILURE'].includes(e.authenticationResult)) {
        failsByIp[ip]++;
      }
      reqsByUser[u] = (reqsByUser[u] || 0) + 1;
    });

    const ipVals = Object.values(failsByIp);
    const userVals = Object.values(reqsByUser);

    function getStats(arr) {
      if (arr.length === 0) return { mean: 0, median: 0, std_dev: 1 };
      const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
      const sorted = [...arr].sort((a, b) => a - b);
      const median = sorted[Math.floor(sorted.length / 2)] || 0;
      const variance = arr.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / Math.max(1, arr.length);
      const stdDev = Math.sqrt(variance) || 1;
      return {
        mean: parseFloat(mean.toFixed(2)),
        median: parseFloat(median.toFixed(2)),
        std_dev: parseFloat(stdDev.toFixed(2))
      };
    }

    const ipStats = getStats(ipVals);
    const userStats = getStats(userVals);

    const anomalies = [];
    const t = parseFloat(threshold) || 2.2;

    // Check IP failures
    for (let ip in failsByIp) {
      const val = failsByIp[ip];
      const z = (val - ipStats.mean) / ipStats.std_dev;
      if (z >= t && val >= 3) {
        anomalies.push({
          dimension: 'FAILED_LOGIN_BURST',
          entity_name: ip,
          observed_value: val,
          mean: ipStats.mean,
          std_dev: ipStats.std_dev,
          z_score: parseFloat(z.toFixed(2)),
          risk_level: z >= 3.0 ? 'CRITICAL' : 'HIGH',
          explanation: `Origin IP ${ip} generated ${val} failures (${z.toFixed(2)}σ above mean baseline of ${ipStats.mean}).`
        });
      }
    }

    // Check User requests
    for (let u in reqsByUser) {
      const val = reqsByUser[u];
      const z = (val - userStats.mean) / userStats.std_dev;
      if (z >= t && val >= 5) {
        anomalies.push({
          dimension: 'REQUEST_VELOCITY_ANOMALY',
          entity_name: u,
          observed_value: val,
          mean: userStats.mean,
          std_dev: userStats.std_dev,
          z_score: parseFloat(z.toFixed(2)),
          risk_level: z >= 3.0 ? 'CRITICAL' : 'HIGH',
          explanation: `Account identifier ${u} generated ${val} requests (${z.toFixed(2)}σ above baseline of ${userStats.mean}).`
        });
      }
    }

    return {
      baselines: {
        failed_logins_per_ip: ipStats,
        requests_per_user: userStats
      },
      anomalies
    };
  }

  async function loadAnalysis() {
    const thresholdEl = document.getElementById('statThresholdSlider');
    const threshold = thresholdEl ? thresholdEl.value : 2.2;
    const threshValEl = document.getElementById('statThresholdValue');
    if (threshValEl) threshValEl.textContent = threshold;

    let data = null;

    try {
      const res = await fetch(`/api/detect/statistical?threshold=${threshold}`);
      if (res.ok) {
        data = await res.json();
      }
    } catch (_) {}

    // Offline fallback
    if (!data || !data.baselines) {
      const events = window.SentinelDataStore ? SentinelDataStore.getEvents() : [];
      data = calculateLocalStatistics(events, threshold);
    }

    // Baselines
    const b = data.baselines || {};
    const setText = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    if (b.failed_logins_per_ip) {
      setText('baseFailsMean', b.failed_logins_per_ip.mean);
      setText('baseFailsMedian', b.failed_logins_per_ip.median);
      setText('baseFailsStd', b.failed_logins_per_ip.std_dev);
    }
    if (b.requests_per_user) {
      setText('baseReqsMean', b.requests_per_user.mean);
      setText('baseReqsMedian', b.requests_per_user.median);
      setText('baseReqsStd', b.requests_per_user.std_dev);
    }

    // Anomaly Table
    const tbody = document.getElementById('statisticalAnomaliesTableBody');
    if (tbody) {
      const anomalies = data.anomalies || [];
      if (!anomalies.length) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px; color:#64748b;">No observations exceed the selected Z-score threshold (|z| &ge; ' + threshold + ').</td></tr>';
        return;
      }

      tbody.innerHTML = anomalies.map(a => `
        <tr>
          <td style="font-weight:700; color:#fff;">${a.dimension}</td>
          <td style="font-family:'JetBrains Mono'; color:#38bdf8;">${a.entity_name}</td>
          <td style="font-family:'JetBrains Mono'; font-weight:700; color:#fff;">${a.observed_value}</td>
          <td style="font-family:'JetBrains Mono'; color:#94a3b8;">μ=${a.mean}, σ=${a.std_dev}</td>
          <td style="font-family:'JetBrains Mono'; font-weight:700; color:${Math.abs(a.z_score) >= 3.0 ? '#ef4444' : '#f97316'};">z=${a.z_score}</td>
          <td><span class="badge ${a.risk_level === 'CRITICAL' ? 'badge-critical' : 'badge-alert'}">${a.risk_level}</span></td>
          <td style="font-size:11.5px; color:#cbd5e1;">${a.explanation}</td>
        </tr>
      `).join('');
    }
  }

  return {
    loadAnalysis,
    init: () => {
      const slider = document.getElementById('statThresholdSlider');
      if (slider) slider.addEventListener('input', loadAnalysis);
    }
  };
})();

if (typeof window !== 'undefined') {
  window.StatisticalModule = StatisticalModule;
  document.addEventListener('DOMContentLoaded', StatisticalModule.init);
}
