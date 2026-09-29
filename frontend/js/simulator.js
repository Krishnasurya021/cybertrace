/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: Demo Center & Live Real-Time Attack Simulator
 * Injects realistic authentication telemetry into SentinelDataStore.
 */

const SimulatorModule = (() => {
  let liveSimTimer = null;
  let isSimulating = false;

  const POOL_USERS = ['john123', 'emily_chem', 'rahul_eng', 'prof_sharma', 'dean_wilson', 'david_ops', 'sarah_w', 'alex_dev', 'priya_cs', 'student_94'];
  const POOL_IPS = ['198.51.100.12', '198.51.100.25', '203.0.113.40', '192.0.2.10', '198.51.100.42'];
  const POOL_APPS = ['APP_001', 'APP_002', 'APP_003', 'APP_004', 'APP_005'];

  function runScenario(scenarioKey) {
    if (!window.SentinelDataStore) return;

    const appId = (window.SentinelState && SentinelState.currentAppFilter !== 'ALL')
      ? SentinelState.currentAppFilter
      : 'APP_001';

    let lastResult = null;

    switch (scenarioKey) {
      // 1. Safe Login
      case 'SAFE_LOGIN': {
        lastResult = SentinelDataStore.addEvent({
          applicationId: appId,
          usernameIdentifier: 'john123',
          authenticationResult: 'SUCCESS',
          sourceIp: '192.0.2.55',
          deviceType: 'Desktop',
          userAgent: 'Chrome 122 on macOS',
          resource: '/login'
        });
        showToast('Authentication event recorded: Safe Login (Score 5/100, LOW)', 'success');
        break;
      }

      // 2. Wrong Password (1 isolated failure)
      case 'WRONG_PASSWORD': {
        lastResult = SentinelDataStore.addEvent({
          applicationId: appId,
          usernameIdentifier: 'john123',
          authenticationResult: 'FAILURE',
          sourceIp: '192.0.2.56',
          deviceType: 'Desktop',
          userAgent: 'Chrome 122 on macOS',
          resource: '/login'
        });
        showToast('Authentication event recorded: Wrong Password (Score 15/100, LOW, MONITORING)', 'info');
        break;
      }

      // 3. Unknown Username (1 isolated attempt)
      case 'UNKNOWN_USER': {
        lastResult = SentinelDataStore.addEvent({
          applicationId: appId,
          usernameIdentifier: 'fake_admin_123',
          authenticationResult: 'UNKNOWN_ACCOUNT',
          sourceIp: '198.51.100.25',
          deviceType: 'Mobile',
          userAgent: 'Safari Mobile 17 on iOS',
          resource: '/login'
        });
        showToast('Authentication event recorded: Unknown Username (Score 15/100, LOW, MONITORING)', 'info');
        break;
      }

      // 4. Repeated Failures (5 rapid failures from single IP)
      case 'REPEATED_FAILURES': {
        const ip = '198.51.100.42';
        for (let i = 0; i < 5; i++) {
          lastResult = SentinelDataStore.addEvent({
            applicationId: appId,
            usernameIdentifier: 'prof_sharma',
            authenticationResult: 'FAILURE',
            sourceIp: ip,
            deviceType: 'Desktop',
            userAgent: 'Chrome 122 on Linux',
            resource: '/portal'
          });
        }
        showToast('Repeated Failures detected! 5 attempts logged. High-Risk Alert generated.', 'danger');
        break;
      }

      // 5. Multiple Usernames (Account Enumeration: 7 probed usernames from 192.0.2.10)
      case 'MULTIPLE_USERNAMES': {
        const ip = '192.0.2.10';
        const probed = ['admin', 'administrator', 'root', 'manager', 'superadmin', 'test', 'fakeuser'];
        probed.forEach(u => {
          lastResult = SentinelDataStore.addEvent({
            applicationId: appId,
            usernameIdentifier: u,
            authenticationResult: 'UNKNOWN_ACCOUNT',
            sourceIp: ip,
            deviceType: 'Desktop',
            userAgent: 'Python-urllib/3.9 (Scanner)',
            resource: '/admin'
          });
        });
        showToast(`Account Enumeration detected! ${probed.length} accounts probed. Critical Alert generated.`, 'danger');
        break;
      }

      // 6. High Frequency Attack Pattern (25 rapid velocity requests)
      case 'HIGH_FREQUENCY': {
        const ip = '203.0.113.88';
        for (let i = 0; i < 20; i++) {
          lastResult = SentinelDataStore.addEvent({
            applicationId: appId,
            usernameIdentifier: i % 2 === 0 ? 'root' : 'alex_dev',
            authenticationResult: 'FAILURE',
            sourceIp: ip,
            deviceType: 'Server / Bot',
            userAgent: 'Hydra/9.5 (Automated Credential Tester)',
            resource: '/portal-admin'
          });
        }
        showToast('High Request Velocity Spike detected (>20 req/min). Critical Alert generated.', 'danger');
        break;
      }

      // 7. Successful Login After Failures (Brute Force Takeover)
      case 'TAKEOVER_AFTER_FAILS': {
        const ip = '203.0.113.99';
        // 4 failed attempts
        for (let i = 0; i < 4; i++) {
          SentinelDataStore.addEvent({
            applicationId: appId,
            usernameIdentifier: 'dean_wilson',
            authenticationResult: 'FAILURE',
            sourceIp: ip,
            deviceType: 'Desktop',
            userAgent: 'Firefox 123 on Windows',
            resource: '/finance'
          });
        }
        // Followed by compromised SUCCESS
        lastResult = SentinelDataStore.addEvent({
          applicationId: appId,
          usernameIdentifier: 'dean_wilson',
          authenticationResult: 'SUCCESS',
          sourceIp: ip,
          deviceType: 'Desktop',
          userAgent: 'Firefox 123 on Windows',
          resource: '/finance'
        });
        showToast('CRITICAL: Successful login after 4 consecutive failures! Account Takeover Alert triggered.', 'danger');
        break;
      }

      default:
        console.warn('Unknown scenario:', scenarioKey);
    }

    // If an alert was generated, display the siren modal
    if (lastResult && lastResult.alert && window.AlertsModule) {
      setTimeout(() => {
        AlertsModule.showLiveAlertModal(lastResult.alert);
      }, 250);
    }
  }

  // Real-Time Background Simulation
  function startLiveSimulation() {
    if (liveSimTimer) clearInterval(liveSimTimer);
    isSimulating = true;
    updateSimulationUI();
    showToast('Live Simulation Started: Generating real-time authentication telemetry...', 'info');

    liveSimTimer = setInterval(() => {
      if (!isSimulating || !window.SentinelDataStore) return;

      const rand = Math.random();
      const u = POOL_USERS[Math.floor(Math.random() * POOL_USERS.length)];
      const ip = POOL_IPS[Math.floor(Math.random() * POOL_IPS.length)];
      const app = POOL_APPS[Math.floor(Math.random() * POOL_APPS.length)];

      let res = 'SUCCESS';
      if (rand > 0.85) res = 'UNKNOWN_ACCOUNT';
      else if (rand > 0.65) res = 'FAILURE';

      SentinelDataStore.addEvent({
        applicationId: app,
        usernameIdentifier: u,
        authenticationResult: res,
        sourceIp: ip,
        deviceType: Math.random() > 0.4 ? 'Desktop' : 'Mobile',
        userAgent: 'Mozilla/5.0 (Standard Client)',
        resource: res === 'UNKNOWN_ACCOUNT' ? '/admin' : '/login'
      });
    }, 3500);
  }

  function pauseLiveSimulation() {
    if (liveSimTimer) {
      clearInterval(liveSimTimer);
      liveSimTimer = null;
    }
    isSimulating = false;
    updateSimulationUI();
    showToast('Live Simulation Paused.', 'info');
  }

  function toggleLiveSimulation() {
    if (isSimulating) {
      pauseLiveSimulation();
    } else {
      startLiveSimulation();
    }
  }

  function updateSimulationUI() {
    const dot = document.getElementById('liveSimIndicatorDot');
    const label = document.getElementById('liveSimStatusText');
    const toggleBtn = document.getElementById('btnToggleLiveSim');

    if (dot) {
      dot.style.background = isSimulating ? '#10b981' : '#64748b';
      dot.className = isSimulating ? 'pulse-dot' : '';
    }
    if (label) {
      label.textContent = isSimulating ? 'LIVE SIMULATION: ACTIVE' : 'LIVE SIMULATION: PAUSED';
      label.style.color = isSimulating ? '#34d399' : '#94a3b8';
    }
    if (toggleBtn) {
      toggleBtn.textContent = isSimulating ? '⏸ Pause Simulation' : '▶ Start Live Simulation';
      toggleBtn.style.background = isSimulating ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)';
    }
  }

  function clearDemoData() {
    if (confirm('Are you sure you want to clear all authentication events and alerts from the demo store?')) {
      if (window.SentinelDataStore) {
        SentinelDataStore.clearDemoData();
      }
      showToast('Demo data cleared. All counters reset to zero.', 'info');
    }
  }

  function resetDemoData() {
    if (window.SentinelDataStore) {
      SentinelDataStore.resetToDefaults();
    }
    showToast('Demo data reset to realistic default baseline.', 'success');
  }

  return {
    run: runScenario,
    startLiveSimulation,
    pauseLiveSimulation,
    toggleLiveSimulation,
    clearDemoData,
    resetDemoData,
    init: () => {
      // Button bindings
      const btnSafe = document.getElementById('btnSimSafe');
      if (btnSafe) btnSafe.addEventListener('click', () => runScenario('SAFE_LOGIN'));

      const btnWrong = document.getElementById('btnSimWrong');
      if (btnWrong) btnWrong.addEventListener('click', () => runScenario('WRONG_PASSWORD'));

      const btnUnknown = document.getElementById('btnSimUnknown');
      if (btnUnknown) btnUnknown.addEventListener('click', () => runScenario('UNKNOWN_USER'));

      const btnBurst = document.getElementById('btnSimBurst');
      if (btnBurst) btnBurst.addEventListener('click', () => runScenario('REPEATED_FAILURES'));

      const btnMulti = document.getElementById('btnSimMulti');
      if (btnMulti) btnMulti.addEventListener('click', () => runScenario('MULTIPLE_USERNAMES'));

      const btnHighFreq = document.getElementById('btnSimHighFreq');
      if (btnHighFreq) btnHighFreq.addEventListener('click', () => runScenario('HIGH_FREQUENCY'));

      const btnTakeover = document.getElementById('btnSimTakeover');
      if (btnTakeover) btnTakeover.addEventListener('click', () => runScenario('TAKEOVER_AFTER_FAILS'));

      const btnClear = document.getElementById('btnClearDemoData');
      if (btnClear) btnClear.addEventListener('click', clearDemoData);

      const btnReset = document.getElementById('btnResetDemoData');
      if (btnReset) btnReset.addEventListener('click', resetDemoData);

      const btnToggle = document.getElementById('btnToggleLiveSim');
      if (btnToggle) btnToggle.addEventListener('click', toggleLiveSimulation);
    }
  };
})();

if (typeof window !== 'undefined') {
  window.SimulatorModule = SimulatorModule;
  document.addEventListener('DOMContentLoaded', SimulatorModule.init);
}
