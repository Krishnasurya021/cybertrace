/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: Configurable Risk Engine & Detection Rules
 * Syncs rule weights with backend and SentinelRiskEngine.
 */

const RulesModule = (() => {

  const DEFAULT_RULES = [
    { rule_code: 'RULE-001', rule_name: 'Repeated Authentication Failures', description: 'Triggers when repeated login failures occur within temporal window.', risk_level: 'HIGH', logical_expression: 'failed_attempts >= 5', current_weight: 50 },
    { rule_code: 'RULE-002', rule_name: 'Multiple Account Identifiers', description: 'Detects horizontal brute-force spraying across multiple usernames.', risk_level: 'CRITICAL', logical_expression: 'distinct_users >= 4', current_weight: 60 },
    { rule_code: 'RULE-003', rule_name: 'Abnormal Request Frequency', description: 'Detects extreme request velocity spikes indicative of automated attacks.', risk_level: 'HIGH', logical_expression: 'req_per_min >= 10', current_weight: 25 },
    { rule_code: 'RULE-004', rule_name: 'Brute Force Success (Takeover)', description: 'Flags successful authentication directly preceded by repeated failures.', risk_level: 'CRITICAL', logical_expression: 'success == true && prior_fails >= 4', current_weight: 50 },
    { rule_code: 'RULE-005', rule_name: 'Restricted Resource Probing', description: 'Probing targeted at administrative, privileged, or internal endpoints.', risk_level: 'HIGH', logical_expression: 'resource in [/admin, /root, /portal-admin]', current_weight: 30 },
    { rule_code: 'RULE-006', rule_name: 'High-Risk Source IP Reputation', description: 'Origin IP has generated security alerts within the preceding 24 hours.', risk_level: 'HIGH', logical_expression: 'ip_alerts_24h > 0', current_weight: 30 },
    { rule_code: 'RULE-007', rule_name: 'Off-Hours Authentication Failures', description: 'Multiple failures occurring outside standard operating hours (23:00 - 05:00).', risk_level: 'MEDIUM', logical_expression: 'hour in [23..05] && failures >= 3', current_weight: 20 },
    { rule_code: 'RULE-008', rule_name: 'MFA Challenge Failure Burst', description: 'Repeated failures specifically on multi-factor authentication challenges.', risk_level: 'HIGH', logical_expression: 'mfa_failures >= 2', current_weight: 25 },
    { rule_code: 'RULE-009', rule_name: 'Unknown Account Identifier', description: 'Authentication attempted against non-existent user account.', risk_level: 'LOW', logical_expression: 'user_exists == false', current_weight: 10 },
    { rule_code: 'RULE-010', rule_name: 'Single Transient Failure', description: 'Isolated single authentication failure with no prior threat history.', risk_level: 'LOW', logical_expression: 'failures == 1 && clean_history == true', current_weight: 10 }
  ];

  async function loadRules() {
    let rulesList = DEFAULT_RULES;

    try {
      const res = await fetch('/api/v1/rules');
      if (res.ok) {
        const data = await res.json();
        if (data.rules && data.rules.length > 0) {
          rulesList = data.rules;
        }
      }
    } catch (_) {
      // Offline fallback
    }

    const container = document.getElementById('rulesListContainer');
    if (!container) return;

    container.innerHTML = rulesList.map(r => `
      <div class="glass-panel" style="padding:16px 20px; margin-bottom:12px; display:flex; align-items:center; justify-content:space-between; gap:16px;">
        <div style="flex:1;">
          <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
            <span style="font-family:'JetBrains Mono'; font-weight:700; color:#38bdf8;">${r.rule_code}</span>
            <b style="color:#fff; font-size:13.5px;">${r.rule_name}</b>
            <span class="badge ${r.risk_level === 'CRITICAL' ? 'badge-critical' : 'badge-monitoring'}">${r.risk_level}</span>
          </div>
          <p style="font-size:12px; color:#94a3b8; margin-bottom:4px;">${r.description}</p>
          <code style="font-size:11px; color:#64748b;">${r.logical_expression}</code>
        </div>

        <div style="display:flex; align-items:center; gap:12px; min-width:180px;">
          <input type="range" min="0" max="75" value="${r.current_weight}" 
            onchange="RulesModule.updateWeight('${r.rule_code}', this.value)" 
            style="accent-color:var(--cyan-primary); cursor:pointer; flex:1;"/>
          <span id="weightVal_${r.rule_code}" style="font-family:'JetBrains Mono'; font-weight:700; color:var(--cyan-primary); width:32px; text-align:right;">
            +${r.current_weight}
          </span>
        </div>
      </div>
    `).join('');
  }

  async function updateWeight(ruleCode, newWeight) {
    const val = parseInt(newWeight, 10) || 0;
    const valSpan = document.getElementById(`weightVal_${ruleCode}`);
    if (valSpan) valSpan.textContent = `+${val}`;

    // Update local client engine
    if (window.SentinelRiskEngine) {
      if (ruleCode === 'RULE-001') SentinelRiskEngine.setWeight('failed_attempts_5', val);
      else if (ruleCode === 'RULE-002') SentinelRiskEngine.setWeight('multiple_usernames_7', val);
      else if (ruleCode === 'RULE-003') SentinelRiskEngine.setWeight('high_frequency_10', val);
      else if (ruleCode === 'RULE-004') SentinelRiskEngine.setWeight('brute_force_success', val);
      else if (ruleCode === 'RULE-005') SentinelRiskEngine.setWeight('restricted_resource', val);
      else if (ruleCode === 'RULE-006') SentinelRiskEngine.setWeight('previous_high_risk', val);
      else if (ruleCode === 'RULE-007') SentinelRiskEngine.setWeight('off_hours_failures', val);
      else if (ruleCode === 'RULE-008') SentinelRiskEngine.setWeight('mfa_failure', val);
      else if (ruleCode === 'RULE-009') SentinelRiskEngine.setWeight('unknown_account', val);
      else if (ruleCode === 'RULE-010') SentinelRiskEngine.setWeight('single_failure', val);
    }

    try {
      fetch('/api/v1/rules/configure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule_code: ruleCode, weight: val })
      }).catch(() => {});
    } catch (_) {}

    showToast(`Updated weight for ${ruleCode} to +${val}`, 'success');
  }

  return {
    loadRules,
    updateWeight,
    init: () => {
      loadRules();
    }
  };
})();

if (typeof window !== 'undefined') {
  window.RulesModule = RulesModule;
  document.addEventListener('DOMContentLoaded', RulesModule.init);
}
