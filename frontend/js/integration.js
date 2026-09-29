/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: Application Connection & Integration Workbench
 * Manages tenant registration and verifies strict zero-password compliance.
 */

const IntegrationModule = (() => {

  function loadApplications() {
    if (!window.SentinelDataStore) return;
    const apps = SentinelDataStore.getApplications();

    const tbody = document.getElementById('connectedAppsTableBody');
    if (!tbody) return;

    if (!apps || apps.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:20px; color:#64748b;">No applications registered.</td></tr>';
      return;
    }

    tbody.innerHTML = apps.map(a => `
      <tr>
        <td style="font-family:'JetBrains Mono'; font-weight:700; color:#fff;">${a.applicationId}</td>
        <td><b style="color:#38bdf8;">${a.name}</b></td>
        <td style="font-family:'JetBrains Mono'; font-size:11.5px; color:#cbd5e1;">${a.url}</td>
        <td><span class="badge badge-monitoring">${a.appType}</span></td>
        <td><span class="badge badge-safe">${a.environment}</span></td>
        <td style="font-family:'JetBrains Mono'; color:var(--cyan-primary);">${a.apiKey ? a.apiKey.substring(0, 18) + '...' : '—'}</td>
        <td style="font-family:'JetBrains Mono'; font-weight:700; color:#fff;">${a.totalEvents || 0}</td>
        <td>
          <button onclick="IntegrationModule.rotateKey('${a.applicationId}')" class="demo-btn demo-btn-unknown" style="padding:3px 9px; font-size:10.5px;" title="Rotate Cryptographic API Key">
            🔄 Rotate
          </button>
        </td>
      </tr>
    `).join('');
  }

  function handleRegisterApplication(e) {
    e.preventDefault();
    const name = document.getElementById('regAppName').value.trim();
    const url = document.getElementById('regAppUrl').value.trim();
    const type = document.getElementById('regAppType').value;
    const email = document.getElementById('regAppEmail').value.trim();
    const env = document.getElementById('regAppEnv').value;

    if (!name || !url || !email) {
      showToast('Please fill in all required fields.', 'danger');
      return;
    }

    const newApp = SentinelDataStore.registerApplication({
      name,
      url,
      appType: type,
      environment: env,
      ownerEmail: email
    });

    showToast(`Application '${newApp.name}' registered successfully!`, 'success');
    showCredentialsModal(newApp);
    loadApplications();

    // Reset form
    document.getElementById('registerAppForm').reset();

    // Refresh dropdowns in header
    if (window.loadApplicationsDropdown) {
      window.loadApplicationsDropdown();
    }
  }

  function showCredentialsModal(creds) {
    const existing = document.getElementById('credsModalContainer');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'credsModalContainer';
    modal.className = 'alert-modal-backdrop active';
    modal.innerHTML = `
      <div class="alert-modal-card" style="border-color:var(--cyan-primary); max-width:620px;">
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:14px;">
          <span style="font-size:26px;">🔑</span>
          <div>
            <h3 style="font-family:var(--font-display); font-size:18px; color:#fff;">API Credentials Generated</h3>
            <div style="font-size:11.5px; color:var(--cyan-primary);">Application: ${creds.name} (${creds.applicationId})</div>
          </div>
        </div>

        <div style="background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); border-radius:8px; padding:12px; margin-bottom:16px; font-size:11.5px; color:#fca5a5; line-height:1.4;">
          ⚠️ <b>IMPORTANT ZERO-PASSWORD SECURITY RULE:</b><br/>
          Your website authenticates its own users. When integrating, transmit authentication <b>EVENT METADATA ONLY</b> to <code>POST /api/v1/auth-events</code>. Never transmit, log, or forward raw user passwords.
        </div>

        <div style="display:flex; flex-direction:column; gap:10px; margin-bottom:20px;">
          <div>
            <label style="font-size:10.5px; color:#94a3b8; font-weight:700; text-transform:uppercase;">APPLICATION ID</label>
            <div style="display:flex; gap:8px; margin-top:3px;">
              <input type="text" readonly value="${creds.applicationId}" style="flex:1; background:#070b13; border:1px solid var(--border-glass); color:#fff; padding:8px 12px; border-radius:6px; font-family:'JetBrains Mono'; font-size:12px;"/>
              <button onclick="navigator.clipboard.writeText('${creds.applicationId}'); showToast('Application ID copied!', 'success');" class="btn-header">Copy</button>
            </div>
          </div>

          <div>
            <label style="font-size:10.5px; color:#94a3b8; font-weight:700; text-transform:uppercase;">API KEY (Public Identifier)</label>
            <div style="display:flex; gap:8px; margin-top:3px;">
              <input type="text" readonly value="${creds.apiKey}" style="flex:1; background:#070b13; border:1px solid var(--border-glass); color:var(--cyan-primary); padding:8px 12px; border-radius:6px; font-family:'JetBrains Mono'; font-size:12px;"/>
              <button onclick="navigator.clipboard.writeText('${creds.apiKey}'); showToast('API Key copied!', 'success');" class="btn-header">Copy</button>
            </div>
          </div>

          <div>
            <label style="font-size:10.5px; color:#94a3b8; font-weight:700; text-transform:uppercase;">API SECRET (Backend Only — Never Expose to Frontend)</label>
            <div style="display:flex; gap:8px; margin-top:3px;">
              <input type="text" readonly value="${creds.apiSecret}" style="flex:1; background:#070b13; border:1px solid var(--border-glass); color:#fbbf24; padding:8px 12px; border-radius:6px; font-family:'JetBrains Mono'; font-size:12px;"/>
              <button onclick="navigator.clipboard.writeText('${creds.apiSecret}'); showToast('API Secret copied!', 'success');" class="btn-header">Copy</button>
            </div>
          </div>
        </div>

        <div style="display:flex; justify-content:flex-end;">
          <button onclick="document.getElementById('credsModalContainer').remove()" class="btn-login-submit" style="width:auto; padding:8px 18px;">
            Done &amp; Saved Credentials ✓
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  function rotateKey(appId) {
    const apps = SentinelDataStore.getApplications();
    const app = apps.find(a => a.applicationId === appId);
    if (!app) return;

    if (confirm(`Rotate API credentials for application '${app.name}' (${appId})? Any older keys will be revoked.`)) {
      const randHex = (len = 24) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');
      app.apiKey = `snt_live_${randHex(24)}`;
      app.apiSecret = `sec_live_${randHex(32)}`;
      showToast(`Rotated API Key for ${app.name}`, 'success');
      loadApplications();
      showCredentialsModal(app);
    }
  }

  function testAuthEvent(injectForbiddenPassword = false) {
    const outputEl = document.getElementById('apiTesterOutput');
    if (!outputEl) return;

    outputEl.textContent = 'Transmitting telemetry to SENTINEL ingest engine...\n';

    const appId = (window.SentinelState && SentinelState.currentAppFilter !== 'ALL')
      ? SentinelState.currentAppFilter
      : 'APP_001';

    if (injectForbiddenPassword) {
      // Intentionally violate the Zero-Password Policy
      const forbiddenPayload = {
        application_id: appId,
        username_identifier: 'malicious_hacker',
        password: 'PlainTextPassword123!', // FORBIDDEN!
        authentication_result: 'SUCCESS'
      };

      try {
        SentinelDataStore.addEvent(forbiddenPayload);
        outputEl.textContent = 'CRITICAL FAILURE: Password was accepted! Zero-Password rule violated.';
        outputEl.style.color = '#ef4444';
      } catch (err) {
        outputEl.style.color = '#f87171';
        outputEl.textContent = `[HTTP 400 BAD REQUEST] SECURITY POLICY ENFORCEMENT:\n${JSON.stringify({
          error: err.message,
          code: "SECURITY_PASSWORD_REJECTED",
          status: 400,
          policy: "ZERO-PASSWORD STRICT COMPLIANCE"
        }, null, 2)}`;
        showToast('Zero-Password Rule Enforced: Password transmission rejected!', 'danger');
      }
    } else {
      // Clean, legitimate authentication metadata
      const cleanPayload = {
        applicationId: appId,
        usernameIdentifier: 'test_user_77',
        authenticationResult: 'SUCCESS',
        sourceIp: '192.0.2.55',
        deviceType: 'Desktop',
        userAgent: 'Chrome 122 on macOS',
        resource: '/login'
      };

      try {
        const res = SentinelDataStore.addEvent(cleanPayload);
        outputEl.style.color = '#34d399';
        outputEl.textContent = `[HTTP 200 OK] AUTHENTICATION EVENT INGESTED:\n${JSON.stringify({
          event_id: res.event.id,
          application_id: res.event.applicationId,
          username: res.event.usernameIdentifier,
          result: res.event.authenticationResult,
          risk_score: `${res.event.riskScore}/100 (${res.event.riskLevel})`,
          status: res.event.status,
          zero_password_verified: true
        }, null, 2)}`;
        showToast('Safe Login Metadata ingested successfully (Risk Score: 5/100, SAFE)', 'success');
      } catch (err) {
        outputEl.textContent = 'Error: ' + err.message;
      }
    }
  }

  function setLanguageTab(lang) {
    document.querySelectorAll('.tab-btn').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-lang') === lang);
    });

    const snippetBox = document.getElementById('integrationSnippetCode');
    if (!snippetBox) return;

    const snippets = {
      'nodejs': `// Node.js (Express / Fetch) Integration
const sendAuthEvent = async (user, result, req) => {
  await fetch('http://localhost:8000/api/v1/auth-events', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': process.env.SENTINEL_API_KEY
    },
    body: JSON.stringify({
      application_id: process.env.SENTINEL_APP_ID,
      event_type: 'LOGIN_ATTEMPT',
      username_identifier: user.username,
      authentication_result: result, // SUCCESS | FAILURE | UNKNOWN_ACCOUNT
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      source_ip: req.ip,
      device_type: 'Desktop',
      user_agent: req.headers['user-agent'],
      resource: '/login'
      // CRITICAL: NEVER SEND PASSWORDS!
    })
  });
};`,
      'python': `# Python (Flask / FastAPI) Integration
import requests
from datetime import datetime

def notify_sentinel_auth(username, result, client_ip, user_agent):
    payload = {
        "application_id": "APP_001",
        "event_type": "LOGIN_ATTEMPT",
        "username_identifier": username,
        "authentication_result": result, # "SUCCESS" or "FAILURE"
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": client_ip,
        "device_type": "Desktop",
        "user_agent": user_agent,
        "resource": "/login"
        # STRICT RULE: NEVER SEND PASSWORDS TO SENTINEL!
    }
    requests.post("http://localhost:8000/api/v1/auth-events", json=payload)`,
      'java': `// Java (Spring Boot) RestTemplate Integration
AuthenticationEventDTO event = AuthenticationEventDTO.builder()
    .applicationId("APP_001")
    .usernameIdentifier(username)
    .authenticationResult(authSuccess ? "SUCCESS" : "FAILURE")
    .sourceIp(request.getRemoteAddr())
    .userAgent(request.getHeader("User-Agent"))
    .resource("/login")
    // NOTE: NEVER SEND PASSWORDS TO SENTINEL!
    .build();

restTemplate.postForEntity("http://localhost:8000/api/v1/auth-events", event, String.class);`,
      'curl': `# cURL Integration Example
curl -X POST http://localhost:8000/api/v1/auth-events \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: snt_live_colg77a8b9c0d1e2f3a4b5c6d7e8" \\
  -d '{
    "application_id": "APP_001",
    "event_type": "LOGIN_ATTEMPT",
    "username_identifier": "user_123",
    "authentication_result": "SUCCESS",
    "timestamp": "2026-09-20 10:42:21",
    "source_ip": "192.0.2.10",
    "user_agent": "Chrome",
    "device_type": "Desktop",
    "resource": "/login"
  }'`
    };

    snippetBox.textContent = snippets[lang] || snippets['nodejs'];
  }

  return {
    loadApplications,
    rotateKey,
    testAuthEvent,
    setLanguageTab,
    init: () => {
      loadApplications();
      setLanguageTab('nodejs');

      const form = document.getElementById('registerAppForm');
      if (form) form.addEventListener('submit', handleRegisterApplication);

      const btnTestSafe = document.getElementById('btnTestEventSafe');
      if (btnTestSafe) btnTestSafe.addEventListener('click', () => testAuthEvent(false));

      const btnTestReject = document.getElementById('btnTestEventReject');
      if (btnTestReject) btnTestReject.addEventListener('click', () => testAuthEvent(true));

      document.querySelectorAll('.tab-btn').forEach(b => {
        b.addEventListener('click', () => setLanguageTab(b.getAttribute('data-lang')));
      });

      if (window.SentinelDataStore) {
        SentinelDataStore.on('dataChanged', () => {
          if (SentinelState.currentView === 'applications') {
            loadApplications();
          }
        });
      }
    }
  };
})();

if (typeof window !== 'undefined') {
  window.IntegrationModule = IntegrationModule;
  document.addEventListener('DOMContentLoaded', IntegrationModule.init);
}
