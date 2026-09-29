/**
 * SENTINEL - DBMS SQL Studio Module
 * Executes and presents the 10 academic curriculum SQL anomaly queries.
 */

const DBMSStudioModule = {
  queriesData: [],
  activeQueryIndex: 0,

  async loadQueries() {
    try {
      const res = await fetch('/api/dbms/queries');
      if (!res.ok) return;
      const data = await res.json();
      this.queriesData = data.queries || [];

      this.renderTabs();
      this.displayQuery(0);
    } catch (err) {
      console.error('Failed to load DBMS queries:', err);
    }
  },

  renderTabs() {
    const container = document.getElementById('queryTabsContainer');
    if (!container || !this.queriesData) return;

    container.innerHTML = this.queriesData.map((q, idx) => `
      <button class="query-tab-btn ${idx === this.activeQueryIndex ? 'active' : ''}" onclick="DBMSStudioModule.displayQuery(${idx})">
        Q${q.id}: ${q.title.split('(')[0].slice(0, 20)}..
      </button>
    `).join('');
  },

  displayQuery(index) {
    this.activeQueryIndex = index;
    const q = this.queriesData[index];
    if (!q) return;

    // Update tab active state
    document.querySelectorAll('.query-tab-btn').forEach((btn, idx) => {
      btn.classList.toggle('active', idx === index);
    });

    document.getElementById('queryTitleDisplay').textContent = `Query #${q.id}: ${q.title}`;
    document.getElementById('queryConceptsDisplay').textContent = `DBMS Academic Concepts: ${q.concepts}`;
    document.getElementById('queryTimingDisplay').textContent = `Execution Time: ${q.execution_time_ms} ms (${q.row_count} rows returned)`;
    document.getElementById('sqlCodeDisplay').textContent = q.sql;

    // Render result table
    const thead = document.getElementById('queryResultHead');
    const tbody = document.getElementById('queryResultBody');

    if (!q.rows || q.rows.length === 0) {
      thead.innerHTML = '';
      tbody.innerHTML = `<tr><td style="text-align: center; padding: 25px; color: var(--text-muted);">Query executed successfully. 0 rows returned for condition.</td></tr>`;
      return;
    }

    thead.innerHTML = `<tr>${q.columns.map(c => `<th>${c.replace(/_/g, ' ')}</th>`).join('')}</tr>`;
    tbody.innerHTML = q.rows.map(r => `
      <tr>
        ${q.columns.map(c => `<td class="${c.includes('ip') || c.includes('time') || c.includes('id') ? 'font-mono' : ''}">${r[c] !== null ? r[c] : 'NULL'}</td>`).join('')}
      </tr>
    `).join('');
  }
};
