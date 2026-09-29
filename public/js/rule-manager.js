/**
 * SENTINEL - DMGT Rule Manager Module
 * Renders security rule propositions, logical formulas, and risk level mappings.
 */

const RuleManagerModule = {
  async loadRules() {
    try {
      const res = await fetch('/api/rules');
      if (!res.ok) return;
      const data = await res.json();
      this.renderTable(data.rules);
    } catch (err) {
      console.error('Failed to load DMGT rules:', err);
    }
  },

  renderTable(rules) {
    const tbody = document.getElementById('rulesTableBody');
    if (!rules || rules.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; padding: 30px; color: var(--text-muted);">No rules defined.</td></tr>`;
      return;
    }

    tbody.innerHTML = rules.map(r => {
      let riskBadge = `<span class="badge badge-low">LOW</span>`;
      if (r.risk_level === 'CRITICAL') riskBadge = `<span class="badge badge-critical">CRITICAL</span>`;
      else if (r.risk_level === 'HIGH') riskBadge = `<span class="badge badge-high">HIGH</span>`;
      else if (r.risk_level === 'MEDIUM') riskBadge = `<span class="badge badge-medium">MEDIUM</span>`;

      return `
        <tr>
          <td><strong class="font-mono" style="color: var(--accent-cyan);">${r.rule_code}</strong></td>
          <td>
            <strong>${r.rule_name}</strong>
            <div style="font-size: 0.73rem; color: var(--text-muted);">${r.description || ''}</div>
          </td>
          <td>
            <code class="font-mono" style="background: rgba(0,242,254,0.08); padding: 4px 8px; border-radius: 4px; color: #38bdf8;">
              ${r.logical_expression}
            </code>
          </td>
          <td>${riskBadge}</td>
          <td>
            <span class="badge badge-success">ACTIVE</span>
          </td>
        </tr>
      `;
    }).join('');
  }
};
