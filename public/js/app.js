/**
 * SENTINEL — Universal Authentication Security & Access Monitoring Platform
 * Module: Application Core Router, State Manager & Event Hub
 * Coordinates all modules around SentinelDataStore (Single Source of Truth).
 */

const SentinelState = {
  currentView: 'dashboard',
  currentAppFilter: 'ALL',
  currentRole: 'ADMIN', // 'ADMIN' (Security Admin) or 'APP_OWNER' (Application Owner)
  applications: [],
  activeAlertId: null,
  isLiveStreaming: true
};

// Centralized Toast Notifications
function showToast(message, type = 'info') {
  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.style.cssText = 'position:fixed;top:20px;right:20px;z-index:999999;display:flex;flex-direction:column;gap:8px;pointer-events:none;';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  const borderColor = type === 'danger'
    ? 'var(--risk-critical)'
    : type === 'success'
    ? 'var(--risk-safe)'
    : 'var(--cyan-primary)';

  toast.style.cssText = `
    background: #0f172a;
    border: 1px solid ${borderColor};
    border-left: 4px solid ${borderColor};
    color: #fff;
    padding: 12px 16px;
    border-radius: 8px;
    font-size: 12.5px;
    box-shadow: 0 10px 25px rgba(0,0,0,0.6);
    display: flex;
    align-items: center;
    gap: 8px;
    pointer-events: all;
    transition: all 0.3s ease;
  `;
  const icon = type === 'danger' ? '🚨' : type === 'success' ? '🛡️' : 'ℹ️';
  toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-10px)';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// Global View Switcher
function switchView(viewName) {
  SentinelState.currentView = viewName;

  // Update nav links
  document.querySelectorAll('.nav-link').forEach(link => {
    link.classList.toggle('active', link.getAttribute('data-view') === viewName);
  });

  // Update view panels
  document.querySelectorAll('.view-section').forEach(sec => {
    sec.classList.toggle('active', sec.id === `view-${viewName}`);
  });

  // Update Page Title
  const titles = {
    'dashboard': 'Security Operations Center (SOC) Overview',
    'live-logs': 'Live Authentication Event Telemetry Stream',
    'alerts': 'Security Incidents & Live Alert Monitoring',
    'investigation': 'Incident Triage & Threat Investigation Workbench',
    'applications': 'Connected Applications & Credential Registry',
    'integration': 'Connect Your Application — Integration Guide & API Tester',
    'source-analysis': 'Source IP & Targeted Username Intelligence Analysis',
    'access-graph': 'ADSA 5-Tier Access Pattern Graph Visualizer',
    'entity-analysis': 'Security Entity Threat Analysis',
    'rules': 'Configurable Risk Engine & Detection Rules',
    'statistical': 'Python Statistical Anomaly Detection Lab',
    'demo-center': 'Demo Center, Live Simulation & System Settings'
  };
  const titleEl = document.getElementById('currentPageTitle');
  if (titleEl) titleEl.textContent = titles[viewName] || 'SENTINEL SOC';

  // Trigger view data refresh
  if (viewName === 'dashboard' && window.DashboardModule) DashboardModule.loadData();
  if (viewName === 'live-logs' && window.DashboardModule) DashboardModule.loadLiveLogs();
  if (viewName === 'alerts' && window.AlertsModule) AlertsModule.loadAlerts();
  if (viewName === 'investigation' && window.InvestigationModule) InvestigationModule.loadAlert();
  if (viewName === 'applications' && window.IntegrationModule) IntegrationModule.loadApplications();
  if (viewName === 'source-analysis' && window.SourceAnalysisModule) SourceAnalysisModule.render();
  if (viewName === 'access-graph' && window.AccessGraphModule) AccessGraphModule.initGraph();
  if (viewName === 'entity-analysis' && window.EntityAnalysisModule) EntityAnalysisModule.search();
  if (viewName === 'rules' && window.RulesModule) RulesModule.loadRules();
  if (viewName === 'statistical' && window.StatisticalModule) StatisticalModule.loadAnalysis();
}

// Populate Applications Dropdown in Top Bar
function loadApplicationsDropdown() {
  if (!window.SentinelDataStore) return;
  const apps = SentinelDataStore.getApplications();
  SentinelState.applications = apps;

  const appSelect = document.getElementById('appFilterSelect');
  if (appSelect) {
    const prevVal = appSelect.value;
    appSelect.innerHTML = '<option value="ALL">ALL APPLICATIONS (Global SOC)</option>';
    apps.forEach(app => {
      const opt = document.createElement('option');
      opt.value = app.applicationId;
      opt.textContent = `${app.applicationId} — ${app.name} (${app.appType})`;
      appSelect.appendChild(opt);
    });
    if (prevVal) appSelect.value = prevVal;
  }
}

// Update Connection Badge (Backend Connected vs Demo Mode)
function updateConnectionBadge() {
  const modeBadge = document.getElementById('backendModeBadge');
  if (!modeBadge) return;

  const isOnline = window.SentinelDataStore && SentinelDataStore.isBackendOnline();
  if (isOnline) {
    modeBadge.innerHTML = '<span style="color:#10b981;">●</span> LIVE BACKEND CONNECTED';
    modeBadge.style.color = '#34d399';
    modeBadge.style.borderColor = 'rgba(16,185,129,0.3)';
    modeBadge.title = 'Connected to SENTINEL Local Server on port 8000';
  } else {
    modeBadge.innerHTML = '<span style="color:#f59e0b;">●</span> DEMO MODE (LOCAL STORAGE)';
    modeBadge.style.color = '#fbbf24';
    modeBadge.style.borderColor = 'rgba(245,158,11,0.3)';
    modeBadge.title = 'Running in resilient offline Demo Mode with LocalStorage persistence';
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  // Initialize unified data store first!
  if (window.SentinelDataStore) {
    await SentinelDataStore.init();
  }

  loadApplicationsDropdown();
  updateConnectionBadge();

  // Navigation Links
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const view = link.getAttribute('data-view');
      switchView(view);
    });
  });

  // Application Filter Change
  const appSelect = document.getElementById('appFilterSelect');
  if (appSelect) {
    appSelect.addEventListener('change', (e) => {
      SentinelState.currentAppFilter = e.target.value;
      showToast(`Filtered SOC telemetry to: ${e.target.options[e.target.selectedIndex].text}`);
      if (window.DashboardModule) DashboardModule.loadData();
    });
  }

  // Role Perspective Switcher (RBAC)
  const roleSelect = document.getElementById('rolePerspectiveSelect');
  if (roleSelect) {
    roleSelect.addEventListener('change', (e) => {
      SentinelState.currentRole = e.target.value;
      const roleBadge = document.getElementById('currentRoleBadge');
      if (SentinelState.currentRole === 'APP_OWNER') {
        if (roleBadge) roleBadge.textContent = 'ROLE: APPLICATION OWNER';
        if (appSelect) {
          appSelect.value = 'APP_001';
          SentinelState.currentAppFilter = 'APP_001';
        }
        showToast('Switched perspective to APPLICATION OWNER (Scoped to College Portal)', 'info');
      } else {
        if (roleBadge) roleBadge.textContent = 'ROLE: SECURITY ADMIN (GLOBAL)';
        showToast('Switched perspective to SECURITY ADMIN (Global Access across all apps)', 'info');
      }
      if (window.DashboardModule) DashboardModule.loadData();
    });
  }

  // Quick Connect Button in header
  const btnQuickConnect = document.getElementById('btnQuickConnect');
  if (btnQuickConnect) {
    btnQuickConnect.addEventListener('click', () => {
      switchView('integration');
    });
  }

  // Handle URL hash navigation (e.g. index.html#alerts, index.html#dashboard)
  const hash = window.location.hash.replace('#', '');
  if (hash) {
    const overlay = document.getElementById('loginScreenOverlay');
    if (overlay) overlay.classList.add('hidden');
    switchView(hash);
  }
});

if (typeof window !== 'undefined') {
  window.switchView = switchView;
  window.showToast = showToast;
  window.loadApplicationsDropdown = loadApplicationsDropdown;
}
