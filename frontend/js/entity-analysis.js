/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: Security Entity Threat Analysis Deep Dive
 * Analyzes target entity across historical telemetry from SentinelDataStore.
 */

const EntityAnalysisModule = (() => {

  function analyzeFromStore(q) {
    if (!window.SentinelDataStore) return null;
    const allEvents = SentinelDataStore.getEvents();
    const query = (q || '').toLowerCase().trim();

    const matching = allEvents.filter(e =>
      (e.usernameIdentifier && e.usernameIdentifier.toLowerCase().includes(query)) ||
      (e.sourceIp && e.sourceIp.toLowerCase().includes(query))
    );

    if (matching.length === 0) return null;

    let success = 0, failed = 0, unknown = 0, riskEvents = 0, maxScore = 0;
    const apps = new Set();
    const ips = new Set();

    matching.forEach(e => {
      if (e.authenticationResult === 'SUCCESS') success++;
      else if (e.authenticationResult === 'FAILURE') failed++;
      else if (e.authenticationResult === 'UNKNOWN_ACCOUNT') unknown++;

      if (e.riskLevel === 'HIGH' || e.riskLevel === 'CRITICAL') riskEvents++;
      if (e.riskScore > maxScore) maxScore = e.riskScore;

      if (e.applicationName) apps.add(e.applicationName);
      if (e.sourceIp) ips.add(e.sourceIp);
    });

    const sortedByTime = [...matching].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    return {
      found: true,
      entity_profile: {
        query_term: q,
        total_attempts: matching.length,
        successful_attempts: success,
        failed_attempts: failed,
        unknown_accounts: unknown,
        risk_events: riskEvents,
        calculated_risk_score: maxScore,
        first_seen: sortedByTime[0] ? sortedByTime[0].timestamp : '--',
        last_seen: sortedByTime[sortedByTime.length - 1] ? sortedByTime[sortedByTime.length - 1].timestamp : '--',
        related_applications: Array.from(apps),
        related_ips: Array.from(ips)
      },
      recent_activity: matching.slice(0, 10).map(e => ({
        timestamp: e.timestamp,
        app_name: e.applicationName || e.applicationId,
        username_identifier: e.usernameIdentifier,
        authentication_result: e.authenticationResult,
        source_ip: e.sourceIp,
        risk_level: e.riskLevel,
        risk_score: e.riskScore
      }))
    };
  }

  async function searchEntity(queryTerm) {
    const q = queryTerm || (document.getElementById('entitySearchInput') || {}).value || '192.0.2.10';
    let data = null;

    try {
      const res = await fetch(`/api/v1/entity-analysis?query=${encodeURIComponent(q)}`);
      if (res.ok) {
        data = await res.json();
      }
    } catch (_) {}

    // Fallback to local store
    if (!data || !data.found) {
      data = analyzeFromStore(q);
    }

    if (!data || !data.found) {
      showToast(`No authentication telemetry found for '${q}'`, 'info');
      return;
    }

    const p = data.entity_profile;
    const setText = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    setText('entTargetName', p.query_term);
    setText('entTotalAttempts', p.total_attempts);
    setText('entSuccessCount', p.successful_attempts);
    setText('entFailedCount', p.failed_attempts);
    setText('entUnknownCount', p.unknown_accounts);
    setText('entRiskEvents', p.risk_events);
    setText('entFirstSeen', p.first_seen);
    setText('entLastSeen', p.last_seen);
    setText('entRelatedApps', (p.related_applications || []).join(', ') || 'None');
    setText('entRelatedIps', (p.related_ips || []).join(', ') || 'None');

    // Risk score meter
    const meterVal = document.getElementById('entScoreVal');
    if (meterVal) {
      meterVal.textContent = `${p.calculated_risk_score}/100`;
      meterVal.style.color = p.calculated_risk_score >= 75 ? '#ef4444' : p.calculated_risk_score >= 50 ? '#f97316' : '#10b981';
    }

    // Recent activity table
    const tbody = document.getElementById('entityHistoryTableBody');
    if (tbody && data.recent_activity) {
      tbody.innerHTML = data.recent_activity.map(ev => `
        <tr>
          <td style="font-family:'JetBrains Mono'; font-size:11.5px; color:#94a3b8;">${ev.timestamp}</td>
          <td style="font-weight:600; color:#fff;">${ev.app_name}</td>
          <td style="font-family:'JetBrains Mono'; color:#38bdf8;">${ev.username_identifier}</td>
          <td><span class="badge ${ev.authentication_result === 'SUCCESS' ? 'badge-safe' : 'badge-suspicious'}">${ev.authentication_result}</span></td>
          <td style="font-family:'JetBrains Mono';">${ev.source_ip}</td>
          <td><span class="badge badge-monitoring">${ev.risk_level} (${ev.risk_score}/100)</span></td>
        </tr>
      `).join('');
    }

    showToast(`Analyzed entity profile for '${p.query_term}'`, 'success');
  }

  return {
    search: searchEntity,
    init: () => {
      const btn = document.getElementById('btnSearchEntity');
      if (btn) btn.addEventListener('click', () => searchEntity());
      const inp = document.getElementById('entitySearchInput');
      if (inp) {
        inp.addEventListener('keypress', (e) => {
          if (e.key === 'Enter') searchEntity();
        });
      }
    }
  };
})();

if (typeof window !== 'undefined') {
  window.EntityAnalysisModule = EntityAnalysisModule;
  document.addEventListener('DOMContentLoaded', EntityAnalysisModule.init);
}
