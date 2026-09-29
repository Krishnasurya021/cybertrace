/**
 * ============================================================================
 * SENTINEL — Intelligent Access Log Monitoring & Anomaly Detection
 * Standalone Frontend Demonstration Engine (Vanilla JavaScript)
 * ============================================================================
 * 
 * Demonstrates:
 *  - 3D Canvas cyber particles & visual scan pipeline
 *  - Rule-based access anomaly detection & risk scoring
 *  - Real-time simulated SOC telemetry log ingestion
 *  - Interactive investigation workbench with circular risk meter
 *  - Dynamic ADSA access pattern network graph (User -> IP -> Session -> Resource)
 */

// Global Application State
const SentinelApp = {
  activeScreen: 'login', // 'login' or 'dashboard'
  currentTab: 'dashboard',
  isStreamPaused: false,
  streamInterval: null,
  alertCount: 1,
  counters: {
    totalLogins: 1248,
    activeSessions: 42,
    failedLogins: 87,
    safeLogins: 1137,
    riskEvents: 24,
    highRisk: 8
  },
  lastAnalysis: null
};

// ============================================================================
// 1. RISK CALCULATION & RULE ENGINE (DMGT LOGIC)
// ============================================================================

/**
 * Checks if failed attempts exceed standard security threshold.
 * Proposition P1: failedAttempts >= 5
 */
function checkFailedAttempts(attempts) {
  return attempts >= 5;
}

/**
 * Checks if login timestamp is outside regular business hours (06:00 to 22:00).
 * Proposition P3: offHours
 */
function checkLoginTime(timeStr) {
  if (!timeStr) return false;
  // Detect off-hours e.g. "02:47 AM", "01:15 AM", "23:40"
  if (timeStr.includes('02:') || timeStr.includes('01:') || timeStr.includes('03:') || timeStr.includes('04:') || timeStr.includes('23:')) {
    return true;
  }
  return false;
}

/**
 * Checks if hardware fingerprint signature is unknown or unverified.
 */
function checkDevice(deviceStr) {
  if (!deviceStr) return true;
  return deviceStr.toLowerCase().includes('unknown');
}

/**
 * Checks if targeted endpoint is a restricted or confidential system resource.
 * Proposition P4: restrictedResource
 */
function checkResource(resourceStr) {
  if (!resourceStr) return false;
  const restrictedList = ['admin', 'vault', 'root', 'ssh', 'keys', 'config'];
  return restrictedList.some(keyword => resourceStr.toLowerCase().includes(keyword));
}

/**
 * Checks if access request frequency deviates from human operational baseline.
 * Proposition P2: abnormalFrequency
 */
function checkFrequency(frequencyStr) {
  if (!frequencyStr) return false;
  return frequencyStr.toLowerCase().includes('high');
}

/**
 * Core Risk Calculation Engine:
 * Implements weighted scoring based on triggered propositions.
 */
function calculateRiskScore(facts) {
  let riskScore = 0;
  const triggeredRules = [];

  // RULE 01: Failed Attempts >= 5 (+30 pts)
  if (checkFailedAttempts(facts.failedAttempts)) {
    riskScore += 30;
    triggeredRules.push({
      code: 'RULE-01',
      title: 'Multiple Failed Login Attempts',
      detail: `${facts.failedAttempts} consecutive authentication failures detected.`,
      points: 30
    });
  }

  // RULE 02: Unusual Login Time (+20 pts)
  if (checkLoginTime(facts.loginTime)) {
    riskScore += 20;
    triggeredRules.push({
      code: 'RULE-02',
      title: 'Unusual Login Time',
      detail: `Access attempt recorded at ${facts.loginTime} outside normal operational window.`,
      points: 20
    });
  }

  // RULE 03: Unknown Device (+15 pts)
  if (checkDevice(facts.device)) {
    riskScore += 15;
    triggeredRules.push({
      code: 'RULE-03',
      title: 'Unknown Device Fingerprint',
      detail: `Hardware signature "${facts.device}" not recognized in user profile.`,
      points: 15
    });
  }

  // RULE 04: Restricted Resource (+25 pts)
  if (checkResource(facts.resource)) {
    riskScore += 25;
    triggeredRules.push({
      code: 'RULE-04',
      title: 'Restricted Resource Requested',
      detail: `Attempted access to protected endpoint "${facts.resource}".`,
      points: 25
    });
  }

  // RULE 05: Abnormal Access Frequency (+20 pts)
  if (checkFrequency(facts.frequency)) {
    riskScore += 20;
    triggeredRules.push({
      code: 'RULE-05',
      title: 'Abnormal Access Frequency',
      detail: `Request rate (${facts.frequency}) deviates significantly from user baseline.`,
      points: 20
    });
  }

  // Cap score at 100
  if (riskScore > 100) riskScore = 100;

  // Determine categorical Risk Level
  let riskLevel = 'LOW';
  if (riskScore >= 80) riskLevel = 'CRITICAL';
  else if (riskScore >= 60) riskLevel = 'HIGH';
  else if (riskScore >= 30) riskLevel = 'MEDIUM';

  return {
    score: riskScore,
    riskLevel: riskLevel,
    triggeredRules: triggeredRules,
    isSafe: riskScore < 30
  };
}

/**
 * High-Level Analyzer: Evaluates incoming credentials & simulated telemetry
 */
function analyzeLogin(userData) {
  const username = userData.username.trim().toLowerCase();

  let facts = {};

  if (username === 'suspicious') {
    facts = {
      user: 'suspicious',
      ip: '185.XX.XX.45',
      loginTime: '02:47 AM',
      failedAttempts: 7,
      resource: 'Admin Panel',
      device: 'Unknown Device',
      location: 'Unknown (External Proxy)',
      frequency: 'Very High',
      sessionStatus: 'BLOCKED'
    };
  } else {
    // Normal analyst baseline
    facts = {
      user: userData.username || 'analyst',
      ip: '192.168.1.24',
      loginTime: '10:32 AM',
      failedAttempts: 0,
      resource: 'Dashboard',
      device: 'MacBook Pro',
      location: 'Hyderabad, IN',
      frequency: 'Normal',
      sessionStatus: 'ACTIVE'
    };
  }

  const evaluation = calculateRiskScore(facts);
  return {
    facts: facts,
    evaluation: evaluation
  };
}

// ============================================================================
// 2. SECURITY SCANNING & VERIFICATION MODAL FLOW (2-3 SECONDS)
// ============================================================================

function showSecurityScan(analysis, onComplete) {
  const modal = document.getElementById('scanModal');
  const stageTitle = document.getElementById('scanStageTitle');
  const stepMsg = document.getElementById('scanStepMsg');
  const progressBar = document.getElementById('scanProgressBar');
  const verdictBox = document.getElementById('scanVerdictBox');

  // Reset modal UI
  modal.classList.add('open');
  verdictBox.style.display = 'none';
  verdictBox.innerHTML = '';
  progressBar.style.width = '0%';
  stageTitle.textContent = 'SECURITY SYSTEM SCANNING...';
  stepMsg.textContent = 'AUTHENTICATING ACCESS CREDENTIALS...';

  const checkItems = [
    document.getElementById('chkUser'),
    document.getElementById('chkPattern'),
    document.getElementById('chkIP'),
    document.getElementById('chkTime'),
    document.getElementById('chkSession')
  ];

  checkItems.forEach(item => {
    item.className = 'check-item';
    item.textContent = item.textContent.replace('✓', '○').replace('⚠', '○');
  });

  const steps = [
    { pct: 20, item: 0, text: 'VERIFYING USER IDENTITY...', label: '✓ USER IDENTITY VERIFIED' },
    { pct: 40, item: 1, text: 'ANALYZING ACCESS PATTERNS...', label: analysis.evaluation.isSafe ? '✓ ACCESS PATTERN NORMAL' : '⚠ SUSPICIOUS PATTERN OBSERVED' },
    { pct: 60, item: 2, text: 'CHECKING ORIGIN IP & REPUTATION...', label: analysis.evaluation.isSafe ? '✓ CORPORATE LAN IP: 192.168.1.24' : '⚠ SUSPICIOUS PROXY: 185.XX.XX.45' },
    { pct: 80, item: 3, text: 'CHECKING LOGIN TIME WINDOW...', label: analysis.evaluation.isSafe ? '✓ NORMAL BUSINESS HOURS: 10:32 AM' : '⚠ OFF-HOURS ACCESS DETECTED: 02:47 AM' },
    { pct: 100, item: 4, text: 'SECURITY ANALYSIS COMPLETE', label: analysis.evaluation.isSafe ? '✓ SESSION BEHAVIOR APPROVED' : '⚠ ABNORMAL REPEATED FAILURES' }
  ];

  let currentStep = 0;

  const interval = setInterval(() => {
    if (currentStep < steps.length) {
      const s = steps[currentStep];
      progressBar.style.width = s.pct + '%';
      stepMsg.textContent = s.text;

      const el = checkItems[s.item];
      el.classList.add('done');
      if (!analysis.evaluation.isSafe && (s.item === 1 || s.item === 2 || s.item === 3 || s.item === 4)) {
        el.classList.add('alert-step');
        el.textContent = s.label;
      } else {
        el.textContent = s.label;
      }

      currentStep++;
    } else {
      clearInterval(interval);
      // Scan complete: Show verdict box
      stageTitle.textContent = analysis.evaluation.isSafe ? 'ACCESS GRANTED' : 'SECURITY ALERT DETECTED';
      stepMsg.textContent = 'ANALYSIS COMPLETE — RISK SCORE EVALUATED';

      if (analysis.evaluation.isSafe) {
        showSafeResult(analysis);
      } else {
        showRiskResult(analysis);
      }

      if (onComplete) onComplete();
    }
  }, 480); // Total duration ~2.4 seconds
}

function showSafeResult(analysis) {
  const verdictBox = document.getElementById('scanVerdictBox');
  verdictBox.style.display = 'block';

  verdictBox.innerHTML = `
    <div class="verdict-banner-safe">
      <div class="verdict-title">
        <span>🛡️</span>
        <span>ACCESS SAFE • ZERO-TRUST PASSED</span>
      </div>
      <div class="verdict-desc">
        "Login pattern matches trusted user behavior profile. No anomaly propositions triggered."
      </div>
      <div style="font-size: 0.8rem; margin-bottom: 12px; font-family: var(--font-mono);">
        Risk Level: <strong style="color: #10b981;">LOW (${analysis.evaluation.score}/100)</strong> • User: <strong>${analysis.facts.user}</strong>
      </div>
      <button class="btn-primary-action" id="btnProceedToDash" style="width: 100%; padding: 12px;">
        PROCEED TO SOC DASHBOARD →
      </button>
    </div>
  `;

  document.getElementById('btnProceedToDash').addEventListener('click', () => {
    closeScanModal();
    openDashboard('analyst', false);
  });
}

function showRiskResult(analysis) {
  const verdictBox = document.getElementById('scanVerdictBox');
  verdictBox.style.display = 'block';

  const rulesList = analysis.evaluation.triggeredRules.map(r => `<li>⚠ ${r.title} (+${r.points} pts)</li>`).join('');

  verdictBox.innerHTML = `
    <div class="verdict-banner-risk">
      <div class="verdict-title">
        <span>⚠</span>
        <span>SECURITY ALERT • SUSPICIOUS LOGIN DETECTED</span>
      </div>
      <div class="verdict-desc">
        "Critical anomalies detected! 5 security rules violated including multiple failed attempts and off-hours proxy routing."
      </div>
      <div style="font-size: 0.82rem; margin-bottom: 8px; font-family: var(--font-mono);">
        Risk Score: <strong style="color: #ef4444; font-size: 1.1rem;">${analysis.evaluation.score}/100</strong> • Level: <strong style="color: #ef4444;">${analysis.evaluation.riskLevel}</strong>
      </div>
      <ul style="font-size: 0.76rem; text-align: left; padding-left: 24px; margin-bottom: 14px; line-height: 1.6;">
        ${rulesList}
      </ul>
      <div style="display: flex; gap: 10px;">
        <button class="demo-btn demo-btn-risk" id="btnInvestigateFromScan" style="flex: 1; padding: 10px; justify-content: center;">
          INVESTIGATE ALERT 🔍
        </button>
        <button class="demo-btn demo-btn-reset" id="btnProceedRiskDash" style="flex: 1; padding: 10px; justify-content: center;">
          VIEW DASHBOARD
        </button>
      </div>
    </div>
  `;

  document.getElementById('btnInvestigateFromScan').addEventListener('click', () => {
    closeScanModal();
    openDashboard('suspicious', true);
    switchSocTab('alerts');
  });

  document.getElementById('btnProceedRiskDash').addEventListener('click', () => {
    closeScanModal();
    openDashboard('suspicious', true);
  });
}

function closeScanModal() {
  document.getElementById('scanModal').classList.remove('open');
}

// ============================================================================
// 3. LIVE ALERT POPUP BANNER
// ============================================================================

function createAlert(analysis) {
  const popup = document.getElementById('liveAlertPopup');
  const userEl = document.getElementById('popupUser');
  const ipEl = document.getElementById('popupIP');
  const riskEl = document.getElementById('popupRiskBadge');
  const rulesList = document.getElementById('popupRulesList');

  userEl.textContent = analysis.facts.user;
  ipEl.textContent = analysis.facts.ip;
  riskEl.textContent = `${analysis.evaluation.riskLevel} (${analysis.evaluation.score}/100)`;

  rulesList.innerHTML = analysis.evaluation.triggeredRules.map(r => `<li>• ${r.title} (${r.detail})</li>`).join('');

  popup.classList.add('show');

  // Auto increment nav alert badge
  SentinelApp.alertCount++;
  document.getElementById('navAlertBadge').textContent = SentinelApp.alertCount;

  // Auto increment counters
  SentinelApp.counters.riskEvents++;
  SentinelApp.counters.highRisk++;
  updateDashboardCounters();
}

function dismissAlertPopup() {
  document.getElementById('liveAlertPopup').classList.remove('show');
}

// ============================================================================
// 4. DASHBOARD & TAB MANAGEMENT
// ============================================================================

function openDashboard(userRole, isSuspicious = false) {
  document.getElementById('loginScreen').classList.remove('active');
  document.getElementById('dashboardScreen').classList.add('active');
  SentinelApp.activeScreen = 'dashboard';

  // Update top profile
  if (isSuspicious) {
    document.getElementById('topUserName').textContent = 'Analyst (Viewing Threat)';
    document.getElementById('topDefconBadge').className = 'status-pill status-pill-threat critical';
    document.getElementById('topDefconBadge').innerHTML = '<span>THREAT LEVEL: CRITICAL / RED</span>';
    setGaugeScore(90, 'CRITICAL', '#ef4444');
    createAlert(SentinelApp.lastAnalysis);
  } else {
    document.getElementById('topUserName').textContent = 'Sarah Analyst';
    document.getElementById('topDefconBadge').className = 'status-pill status-pill-threat';
    document.getElementById('topDefconBadge').innerHTML = '<span>THREAT LEVEL: LOW / NORMAL</span>';
    setGaugeScore(8, 'LOW', '#10b981');
  }

  // Animate counters
  updateDashboardCounters(true);

  // Initialize Access Pattern Graph
  renderAccessGraph(isSuspicious);

  // Add event to live logs
  const now = new Date().toLocaleTimeString();
  if (isSuspicious) {
    addLiveLog({
      time: '02:47:11',
      user: 'suspicious',
      ip: '185.XX.XX.45',
      device: 'Unknown Device',
      resource: 'Admin Panel',
      status: 'FAILED',
      risk: 'CRITICAL',
      score: 90
    });
  } else {
    addLiveLog({
      time: now,
      user: userRole,
      ip: '192.168.1.24',
      device: 'MacBook Pro',
      resource: 'Dashboard',
      status: 'SUCCESS',
      risk: 'SAFE',
      score: 5
    });
  }

  // Switch to default overview tab
  switchSocTab('dashboard');
}

function switchSocTab(tabName) {
  SentinelApp.currentTab = tabName;

  // Update sidebar active link
  document.querySelectorAll('.sidebar-nav .nav-link').forEach(link => {
    link.classList.toggle('active', link.getAttribute('data-tab') === tabName);
  });

  // Update visible panel
  document.querySelectorAll('.soc-view-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === `tab-${tabName}`);
  });
}

function showInvestigationDetail() {
  switchSocTab('alerts');
  const circle = document.getElementById('invMeterCircle');
  if (circle) {
    // Circumference = 2 * PI * 65 ≈ 408.4
    const offset = 408.4 - (408.4 * 90) / 100;
    circle.style.strokeDashoffset = offset;
  }
}

// Circular Meter Helper
function setGaugeScore(score, levelText, color) {
  const circle = document.getElementById('mainDashboardMeterCircle');
  const scoreText = document.getElementById('mainDashboardRiskScore');
  const levelBadge = document.getElementById('mainDashboardRiskLevel');
  const gaugeTag = document.getElementById('gaugeStatusText');

  if (circle) {
    const offset = 408.4 - (408.4 * score) / 100;
    circle.style.strokeDashoffset = offset;
    circle.style.stroke = color;
  }
  if (scoreText) scoreText.textContent = score;
  if (levelBadge) {
    levelBadge.textContent = levelText;
    levelBadge.style.color = color;
  }
  if (gaugeTag) {
    gaugeTag.textContent = levelText;
    gaugeTag.style.color = color;
  }
}

// Animate Counters
function updateDashboardCounters(animate = false) {
  const fields = [
    { id: 'counterTotalLogins', val: SentinelApp.counters.totalLogins },
    { id: 'counterActiveSessions', val: SentinelApp.counters.activeSessions },
    { id: 'counterFailedLogins', val: SentinelApp.counters.failedLogins },
    { id: 'counterSafeLogins', val: SentinelApp.counters.safeLogins },
    { id: 'counterRiskEvents', val: SentinelApp.counters.riskEvents },
    { id: 'counterHighRisk', val: SentinelApp.counters.highRisk }
  ];

  fields.forEach(f => {
    const el = document.getElementById(f.id);
    if (!el) return;
    if (animate) {
      animateCounter(el, f.val);
    } else {
      el.textContent = f.val.toLocaleString();
    }
  });
}

function animateCounter(element, target) {
  let start = 0;
  const duration = 1000;
  const stepTime = 25;
  const steps = duration / stepTime;
  const increment = target / steps;

  const timer = setInterval(() => {
    start += increment;
    if (start >= target) {
      element.textContent = target.toLocaleString();
      clearInterval(timer);
    } else {
      element.textContent = Math.floor(start).toLocaleString();
    }
  }, stepTime);
}

// ============================================================================
// 5. LIVE ACCESS LOG STREAM & CONTINUOUS SIMULATOR
// ============================================================================

function addLiveLog(log) {
  const quickTbody = document.getElementById('quickLogsTableBody');
  const fullTbody = document.getElementById('fullLiveLogsTableBody');

  const isRisk = log.risk === 'CRITICAL' || log.risk === 'HIGH';
  const rowClass = isRisk ? 'row-suspicious' : '';

  let riskBadge = `<span class="badge-safe">SAFE</span>`;
  if (log.risk === 'CRITICAL') riskBadge = `<span class="badge-critical">CRITICAL</span>`;
  else if (log.risk === 'HIGH') riskBadge = `<span class="badge-high">HIGH</span>`;
  else if (log.risk === 'MEDIUM') riskBadge = `<span class="badge-medium">MEDIUM</span>`;

  let statusBadge = log.status === 'SUCCESS' 
    ? `<span style="color: #34d399; font-weight: 700;">SUCCESS</span>`
    : `<span style="color: #f87171; font-weight: 700;">FAILED</span>`;

  const rowHtml = `
    <tr class="${rowClass}">
      <td class="font-mono">${log.time}</td>
      <td><strong>${log.user}</strong></td>
      <td class="font-mono">${log.ip}</td>
      <td>${log.device}</td>
      <td><code>${log.resource}</code></td>
      <td>${statusBadge}</td>
      <td>${riskBadge}</td>
      <td class="font-mono" style="font-weight: 700; color: ${isRisk ? '#f87171' : 'var(--accent-cyan)'};">${log.score}</td>
    </tr>
  `;

  if (quickTbody) quickTbody.insertAdjacentHTML('afterbegin', rowHtml);
  if (fullTbody) fullTbody.insertAdjacentHTML('afterbegin', rowHtml);

  // Keep quick table to 6 rows
  if (quickTbody && quickTbody.children.length > 6) {
    quickTbody.lastElementChild.remove();
  }
}

// Continuous background simulator
function startLiveLogSimulator() {
  const sampleUsers = ['analyst', 'user102', 'bob_dev', 'alice_qa', 'finance_user', 'carol_hr'];
  const sampleIPs = ['192.168.1.24', '192.168.1.40', '192.168.1.55', '10.0.4.18', '172.16.10.88'];
  const sampleDevices = ['MacBook Pro', 'Windows 11', 'Linux Workstation', 'iPhone 15', 'iPad Pro'];
  const sampleResources = ['/dashboard', '/git/repos', '/intranet/docs', '/profile', '/api/v1/data'];

  SentinelApp.streamInterval = setInterval(() => {
    if (SentinelApp.isStreamPaused) return;

    const randUser = sampleUsers[Math.floor(Math.random() * sampleUsers.length)];
    const randIP = sampleIPs[Math.floor(Math.random() * sampleIPs.length)];
    const randDev = sampleDevices[Math.floor(Math.random() * sampleDevices.length)];
    const randRes = sampleResources[Math.floor(Math.random() * sampleResources.length)];
    const now = new Date().toLocaleTimeString();

    SentinelApp.counters.totalLogins++;
    SentinelApp.counters.safeLogins++;
    updateDashboardCounters();

    addLiveLog({
      time: now,
      user: randUser,
      ip: randIP,
      device: randDev,
      resource: randRes,
      status: 'SUCCESS',
      risk: 'SAFE',
      score: Math.floor(Math.random() * 12) + 2
    });
  }, 4500);
}

// ============================================================================
// 6. ADSA ACCESS PATTERN NETWORK GRAPH (SVG RENDERER)
// ============================================================================

function renderAccessGraph(isSuspicious = false) {
  const svg = document.getElementById('accessGraphSvg');
  const label = document.getElementById('graphModeLabel');
  if (!svg) return;

  if (isSuspicious) {
    label.innerHTML = `Status: <strong style="color:#f87171;">CRITICAL ATTACK TRAJECTORY</strong> (suspicious → 185.XX.XX.45 → Session Blocked → Admin Panel)`;

    svg.innerHTML = `
      <defs>
        <filter id="nodeGlowRed" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="6" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <linearGradient id="linkRedGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="#ef4444" stop-opacity="0.8"/>
          <stop offset="100%" stop-color="#ef4444" stop-opacity="0.8"/>
        </linearGradient>
      </defs>

      <!-- Connection Lines with pulse animation -->
      <line x1="120" y1="180" x2="300" y2="180" stroke="url(#linkRedGrad)" stroke-width="4" stroke-dasharray="6 4"/>
      <line x1="300" y1="180" x2="480" y2="180" stroke="url(#linkRedGrad)" stroke-width="4" stroke-dasharray="6 4"/>
      <line x1="480" y1="180" x2="640" y2="180" stroke="url(#linkRedGrad)" stroke-width="4" stroke-dasharray="6 4"/>

      <!-- Pulsing Data Packet on attack path -->
      <circle cx="300" cy="180" r="7" fill="#f87171">
        <animate attributeName="cx" values="120;640" dur="2.2s" repeatCount="indefinite"/>
      </circle>

      <!-- Node 1: User -->
      <g transform="translate(120, 180)">
        <circle r="36" fill="#1e1b4b" stroke="#ef4444" stroke-width="3" filter="url(#nodeGlowRed)"/>
        <text y="-5" text-anchor="middle" fill="#fff" font-weight="700" font-size="12">suspicious</text>
        <text y="14" text-anchor="middle" fill="#fca5a5" font-size="10">USER NODE</text>
      </g>

      <!-- Node 2: IP Address -->
      <g transform="translate(300, 180)">
        <circle r="36" fill="#1c1917" stroke="#ef4444" stroke-width="3" filter="url(#nodeGlowRed)"/>
        <text y="-5" text-anchor="middle" fill="#fff" font-weight="700" font-size="12">185.XX.XX.45</text>
        <text y="14" text-anchor="middle" fill="#fca5a5" font-size="10">TOR PROXY</text>
      </g>

      <!-- Node 3: Session -->
      <g transform="translate(480, 180)">
        <circle r="36" fill="#064e3b" stroke="#ef4444" stroke-width="3" filter="url(#nodeGlowRed)"/>
        <text y="-5" text-anchor="middle" fill="#fff" font-weight="700" font-size="12">Blocked Auth</text>
        <text y="14" text-anchor="middle" fill="#fca5a5" font-size="10">SESSION (7 Fails)</text>
      </g>

      <!-- Node 4: Resource -->
      <g transform="translate(640, 180)">
        <circle r="36" fill="#450a0a" stroke="#ef4444" stroke-width="3" filter="url(#nodeGlowRed)"/>
        <text y="-5" text-anchor="middle" fill="#fff" font-weight="700" font-size="12">Admin Panel</text>
        <text y="14" text-anchor="middle" fill="#fca5a5" font-size="10">RESTRICTED</text>
      </g>
    `;
  } else {
    label.innerHTML = `Status: <strong>Normal Baseline Connection</strong> (analyst → 192.168.1.24 → Session 101 → Dashboard)`;

    svg.innerHTML = `
      <defs>
        <filter id="nodeGlowCyan" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="5" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <linearGradient id="linkCyanGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.7"/>
          <stop offset="100%" stop-color="#00f2fe" stop-opacity="0.9"/>
        </linearGradient>
      </defs>

      <!-- Connection Lines -->
      <line x1="120" y1="180" x2="300" y2="180" stroke="url(#linkCyanGrad)" stroke-width="3"/>
      <line x1="300" y1="180" x2="480" y2="180" stroke="url(#linkCyanGrad)" stroke-width="3"/>
      <line x1="480" y1="180" x2="640" y2="180" stroke="url(#linkCyanGrad)" stroke-width="3"/>

      <!-- Animated Data Packet -->
      <circle cx="300" cy="180" r="6" fill="#00f2fe">
        <animate attributeName="cx" values="120;640" dur="3s" repeatCount="indefinite"/>
      </circle>

      <!-- Node 1: User -->
      <g transform="translate(120, 180)">
        <circle r="36" fill="#0f172a" stroke="#3b82f6" stroke-width="2.5" filter="url(#nodeGlowCyan)"/>
        <text y="-5" text-anchor="middle" fill="#fff" font-weight="700" font-size="12">analyst</text>
        <text y="14" text-anchor="middle" fill="#38bdf8" font-size="10">USER NODE</text>
      </g>

      <!-- Node 2: IP Address -->
      <g transform="translate(300, 180)">
        <circle r="36" fill="#0f172a" stroke="#f59e0b" stroke-width="2.5" filter="url(#nodeGlowCyan)"/>
        <text y="-5" text-anchor="middle" fill="#fff" font-weight="700" font-size="12">192.168.1.24</text>
        <text y="14" text-anchor="middle" fill="#fbbf24" font-size="10">LAN IP NODE</text>
      </g>

      <!-- Node 3: Session -->
      <g transform="translate(480, 180)">
        <circle r="36" fill="#0f172a" stroke="#10b981" stroke-width="2.5" filter="url(#nodeGlowCyan)"/>
        <text y="-5" text-anchor="middle" fill="#fff" font-weight="700" font-size="12">Session 101</text>
        <text y="14" text-anchor="middle" fill="#34d399" font-size="10">ACTIVE TOKEN</text>
      </g>

      <!-- Node 4: Resource -->
      <g transform="translate(640, 180)">
        <circle r="36" fill="#0f172a" stroke="#00f2fe" stroke-width="2.5" filter="url(#nodeGlowCyan)"/>
        <text y="-5" text-anchor="middle" fill="#fff" font-weight="700" font-size="12">Dashboard</text>
        <text y="14" text-anchor="middle" fill="#38bdf8" font-size="10">INTERNAL APP</text>
      </g>
    `;
  }
}

// ============================================================================
// 7. DEMO SIMULATION SHORTCUTS (FOR EASY PRESENTATION)
// ============================================================================

function simulateSafeLogin() {
  document.getElementById('usernameInput').value = 'analyst';
  document.getElementById('passwordInput').value = '1234';

  if (SentinelApp.activeScreen === 'dashboard') {
    // Return to login screen first to show full animation
    document.getElementById('dashboardScreen').classList.remove('active');
    document.getElementById('loginScreen').classList.add('active');
    SentinelApp.activeScreen = 'login';
  }

  const analysis = analyzeLogin({ username: 'analyst', password: '1234' });
  SentinelApp.lastAnalysis = analysis;
  showSecurityScan(analysis);
}

function simulateRiskLogin() {
  document.getElementById('usernameInput').value = 'suspicious';
  document.getElementById('passwordInput').value = '9999';

  if (SentinelApp.activeScreen === 'dashboard') {
    document.getElementById('dashboardScreen').classList.remove('active');
    document.getElementById('loginScreen').classList.add('active');
    SentinelApp.activeScreen = 'login';
  }

  const analysis = analyzeLogin({ username: 'suspicious', password: '9999' });
  SentinelApp.lastAnalysis = analysis;
  showSecurityScan(analysis);
}

function resetDemo() {
  dismissAlertPopup();
  closeScanModal();

  // Reset counters
  SentinelApp.counters = {
    totalLogins: 1248,
    activeSessions: 42,
    failedLogins: 87,
    safeLogins: 1137,
    riskEvents: 24,
    highRisk: 8
  };
  SentinelApp.alertCount = 1;
  document.getElementById('navAlertBadge').textContent = '1';
  updateDashboardCounters();

  // Clear live tables back to default samples
  const quickTbody = document.getElementById('quickLogsTableBody');
  const fullTbody = document.getElementById('fullLiveLogsTableBody');
  if (quickTbody) quickTbody.innerHTML = '';
  if (fullTbody) fullTbody.innerHTML = '';

  // Return to Login screen
  document.getElementById('dashboardScreen').classList.remove('active');
  document.getElementById('loginScreen').classList.add('active');
  SentinelApp.activeScreen = 'login';
  document.getElementById('usernameInput').value = 'analyst';
  document.getElementById('passwordInput').value = '1234';
}

// ============================================================================
// 8. 3D BACKGROUND PARTICLES ON CANVAS
// ============================================================================

function initCyberBackgroundCanvas() {
  const canvas = document.getElementById('cyberBackgroundCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let width = canvas.width = window.innerWidth;
  let height = canvas.height = window.innerHeight;

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const particles = [];
  const count = Math.min(50, Math.floor(width / 25));

  for (let i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.7,
      vy: (Math.random() - 0.5) * 0.7,
      radius: Math.random() * 2 + 1,
      alpha: Math.random() * 0.6 + 0.2
    });
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);

    // Draw connecting lines between close particles
    for (let i = 0; i < particles.length; i++) {
      const p1 = particles[i];
      p1.x += p1.vx;
      p1.y += p1.vy;

      if (p1.x < 0 || p1.x > width) p1.vx *= -1;
      if (p1.y < 0 || p1.y > height) p1.vy *= -1;

      // Draw particle dot
      ctx.beginPath();
      ctx.arc(p1.x, p1.y, p1.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0, 242, 254, ${p1.alpha})`;
      ctx.fill();

      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
        if (dist < 110) {
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `rgba(0, 242, 254, ${(1 - dist / 110) * 0.2})`;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(draw);
  }

  draw();
}

// ============================================================================
// 9. INITIALIZATION & EVENT LISTENERS
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  initCyberBackgroundCanvas();
  startLiveLogSimulator();

  // Initial dummy logs
  addLiveLog({
    time: '10:32:14',
    user: 'analyst',
    ip: '192.168.1.24',
    device: 'MacBook Pro',
    resource: 'Dashboard',
    status: 'SUCCESS',
    risk: 'SAFE',
    score: 5
  });

  addLiveLog({
    time: '10:35:42',
    user: 'user102',
    ip: '192.168.1.40',
    device: 'Windows 11',
    resource: 'Profile',
    status: 'SUCCESS',
    risk: 'SAFE',
    score: 8
  });

  // Login Form Submission
  const form = document.getElementById('loginForm');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const uname = document.getElementById('usernameInput').value;
    const pword = document.getElementById('passwordInput').value;

    const analysis = analyzeLogin({ username: uname, password: pword });
    SentinelApp.lastAnalysis = analysis;
    showSecurityScan(analysis);
  });

  // Autofill chips
  document.getElementById('btnAutofillSafe').addEventListener('click', () => {
    document.getElementById('usernameInput').value = 'analyst';
    document.getElementById('passwordInput').value = '1234';
  });

  document.getElementById('btnAutofillRisk').addEventListener('click', () => {
    document.getElementById('usernameInput').value = 'suspicious';
    document.getElementById('passwordInput').value = '9999';
  });

  // Floating Demo Center Buttons
  document.getElementById('btnSimSafe').addEventListener('click', simulateSafeLogin);
  document.getElementById('btnSimRisk').addEventListener('click', simulateRiskLogin);
  document.getElementById('btnResetDemo').addEventListener('click', resetDemo);

  document.getElementById('btnToggleToLogin').addEventListener('click', () => {
    document.getElementById('dashboardScreen').classList.remove('active');
    document.getElementById('loginScreen').classList.add('active');
    SentinelApp.activeScreen = 'login';
  });

  document.getElementById('btnToggleToDash').addEventListener('click', () => {
    openDashboard('analyst', false);
  });

  // Top Logout Button
  document.getElementById('btnLogout').addEventListener('click', () => {
    resetDemo();
  });

  // Sidebar Tab Clicks
  document.querySelectorAll('.sidebar-nav .nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const tab = link.getAttribute('data-tab');
      switchSocTab(tab);
    });
  });

  // Alert Popup Buttons
  document.getElementById('btnDismissAlert').addEventListener('click', dismissAlertPopup);
  document.getElementById('btnDismissAlertAlt').addEventListener('click', dismissAlertPopup);
  document.getElementById('btnViewAlertDetail').addEventListener('click', () => {
    dismissAlertPopup();
    showInvestigationDetail();
  });

  // Pause / Resume Stream Button
  const btnStream = document.getElementById('btnPauseResumeStream');
  if (btnStream) {
    btnStream.addEventListener('click', () => {
      SentinelApp.isStreamPaused = !SentinelApp.isStreamPaused;
      btnStream.textContent = SentinelApp.isStreamPaused ? 'Resume Feed' : 'Pause Feed';
      btnStream.className = SentinelApp.isStreamPaused ? 'demo-btn demo-btn-risk' : 'demo-btn demo-btn-safe';
    });
  }

  // Live log search box
  const searchBox = document.getElementById('logSearchBox');
  if (searchBox) {
    searchBox.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('#fullLiveLogsTableBody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }

  // Access Graph Mode Toggle Button
  const btnToggleGraph = document.getElementById('btnToggleGraphAttackView');
  let graphIsAttack = false;
  if (btnToggleGraph) {
    btnToggleGraph.addEventListener('click', () => {
      graphIsAttack = !graphIsAttack;
      renderAccessGraph(graphIsAttack);
      btnToggleGraph.textContent = graphIsAttack 
        ? 'Show Normal Baseline Trajectory' 
        : 'Highlight Suspicious Attack Trajectory';
      btnToggleGraph.className = graphIsAttack ? 'demo-btn demo-btn-safe' : 'demo-btn demo-btn-risk';
    });
  }
});
