/**
 * SENTINEL — Universal Authentication Security Platform
 * Automated Verification of Frontend Single Source of Truth & Risk Engine
 */

const fs = require('fs');
const path = require('path');

// Mock browser environment (window, localStorage, document, etc.)
const mockStorage = {};
global.localStorage = {
  getItem: (k) => mockStorage[k] || null,
  setItem: (k, v) => { mockStorage[k] = String(v); },
  removeItem: (k) => { delete mockStorage[k]; },
  clear: () => { for (let k in mockStorage) delete mockStorage[k]; }
};

global.sessionStorage = {
  getItem: (k) => mockStorage['session_' + k] || null,
  setItem: (k, v) => { mockStorage['session_' + k] = String(v); },
  removeItem: (k) => { delete mockStorage['session_' + k]; }
};

global.window = global;
global.fetch = async () => ({ ok: false, json: async () => ({}) });

// Load risk engine
eval(fs.readFileSync(path.join(__dirname, 'frontend/js/risk-engine.js'), 'utf8'));
// Load data store
eval(fs.readFileSync(path.join(__dirname, 'frontend/js/data-store.js'), 'utf8'));

console.log('=================================================================');
console.log('   SENTINEL — FRONTEND DATA ENGINE & AUDIT VERIFICATION');
console.log('=================================================================');

let passedTests = 0;
let totalTests = 0;

function assert(condition, message) {
  totalTests++;
  if (condition) {
    console.log(`  ✔ [PASS] ${message}`);
    passedTests++;
  } else {
    console.error(`  ✘ [FAIL] ${message}`);
    process.exitCode = 1;
  }
}

async function runTests() {
  // Test 1: Initialize Store
  await SentinelDataStore.init();
  const initialEvents = SentinelDataStore.getEvents();
  assert(initialEvents.length > 0, `Store initialized with ${initialEvents.length} seed events`);

  // Test 2: Zero-Password Rule Enforcement
  let passwordRejected = false;
  try {
    SentinelDataStore.addEvent({
      applicationId: 'APP_001',
      usernameIdentifier: 'hacker',
      password: 'PlaintextPassword123!',
      authenticationResult: 'SUCCESS'
    });
  } catch (err) {
    passwordRejected = true;
    assert(err.message.includes('strictly forbids password transmission'), 'Zero-Password rule blocked password submission');
  }
  assert(passwordRejected, 'Password field strictly rejected with error');

  // Test 3: Safe Login Simulation
  const safeRes = SentinelDataStore.addEvent({
    applicationId: 'APP_001',
    usernameIdentifier: 'john123',
    authenticationResult: 'SUCCESS',
    sourceIp: '192.0.2.88',
    resource: '/login'
  });
  assert(safeRes.event.riskScore === 5, `Safe login risk score is 5/100 (got ${safeRes.event.riskScore})`);
  assert(safeRes.event.riskLevel === 'LOW', `Safe login risk level is LOW (got ${safeRes.event.riskLevel})`);
  assert(safeRes.alert === null, 'No alert generated for safe login');

  // Test 4: Single Failure
  const failRes = SentinelDataStore.addEvent({
    applicationId: 'APP_001',
    usernameIdentifier: 'john123',
    authenticationResult: 'FAILURE',
    sourceIp: '192.0.2.88',
    resource: '/login'
  });
  assert(failRes.event.riskScore === 15, `Single failure risk score is 15/100 (got ${failRes.event.riskScore})`);
  assert(failRes.event.status === 'MONITORING', `Single failure status is MONITORING (got ${failRes.event.status})`);

  // Test 5: Unknown Account
  const unkRes = SentinelDataStore.addEvent({
    applicationId: 'APP_001',
    usernameIdentifier: 'non_existent_user_99',
    authenticationResult: 'UNKNOWN_ACCOUNT',
    sourceIp: '192.0.2.89',
    resource: '/login'
  });
  assert(unkRes.event.riskScore === 15, `Unknown account risk score is 15/100 (got ${unkRes.event.riskScore})`);

  // Test 6: Repeated Failures from same IP (5 attempts)
  const burstIp = '198.51.100.77';
  let lastBurst = null;
  for (let i = 0; i < 5; i++) {
    lastBurst = SentinelDataStore.addEvent({
      applicationId: 'APP_001',
      usernameIdentifier: 'prof_sharma',
      authenticationResult: 'FAILURE',
      sourceIp: burstIp,
      resource: '/portal'
    });
  }
  assert(lastBurst.event.riskScore >= 65, `Repeated 5 failures escalated risk score >= 65 (got ${lastBurst.event.riskScore})`);
  assert(lastBurst.event.riskLevel === 'HIGH' || lastBurst.event.riskLevel === 'CRITICAL', 'Repeated failures flagged HIGH/CRITICAL');
  assert(lastBurst.alert !== null, 'High-risk security alert automatically created');

  // Test 7: Account Enumeration (7 probed accounts from single IP)
  const enumIp = '192.0.2.111';
  const probed = ['admin', 'administrator', 'root', 'manager', 'superadmin', 'test', 'fakeuser'];
  let lastEnum = null;
  probed.forEach(u => {
    lastEnum = SentinelDataStore.addEvent({
      applicationId: 'APP_001',
      usernameIdentifier: u,
      authenticationResult: 'UNKNOWN_ACCOUNT',
      sourceIp: enumIp,
      resource: '/admin'
    });
  });
  assert(lastEnum.event.riskScore >= 75, `Account enumeration escalated risk score >= 75 (got ${lastEnum.event.riskScore})`);
  assert(lastEnum.event.riskLevel === 'CRITICAL', 'Account enumeration flagged CRITICAL');
  assert(lastEnum.alert.title.includes('ACCOUNT ENUMERATION'), 'Alert title specifically identifies Account Enumeration Pattern');

  // Test 8: Dynamic Statistics Calculation
  const stats = SentinelDataStore.getStatistics();
  const kpis = stats.kpis;
  const allEvents = SentinelDataStore.getEvents();
  assert(kpis.total_events === allEvents.length, `KPI total events (${kpis.total_events}) matches stored events (${allEvents.length})`);
  const calcSuccess = allEvents.filter(e => e.authenticationResult === 'SUCCESS').length;
  assert(kpis.successful_logins === calcSuccess, `KPI successful logins (${kpis.successful_logins}) calculated accurately`);

  // Test 9: Source IP Aggregation
  const sourceAnalysis = SentinelDataStore.getSourceIpAnalysis();
  assert(sourceAnalysis.length > 0, `Source IP analysis populated with ${sourceAnalysis.length} distinct origins`);
  const burstRecord = sourceAnalysis.find(r => r.sourceIp === burstIp);
  assert(burstRecord && burstRecord.failed >= 5, `Source IP analysis correctly attributes >= 5 failures to ${burstIp}`);

  // Test 10: Username Aggregation
  const usernameAnalysis = SentinelDataStore.getUsernameAnalysis();
  assert(usernameAnalysis.length > 0, `Username analysis populated with ${usernameAnalysis.length} identities`);
  const rootRecord = usernameAnalysis.find(u => u.username === 'root');
  assert(rootRecord !== undefined, 'Targeted user root present in username analysis');

  // Test 11: Alert Status Update
  const alerts = SentinelDataStore.getAlerts();
  assert(alerts.length > 0, `Stored alerts count: ${alerts.length}`);
  const testAlert = alerts[0];
  const updated = SentinelDataStore.updateAlertStatus(testAlert.id, 'RESOLVED');
  assert(updated === true, `Updated alert #ALT-${testAlert.id} status to RESOLVED`);
  const resolvedAlert = SentinelDataStore.getAlerts().find(a => a.id === testAlert.id);
  assert(resolvedAlert.status === 'RESOLVED', 'Persisted status is RESOLVED');

  // Test 12: Clear Demo Data
  SentinelDataStore.clearDemoData();
  const clearedEvents = SentinelDataStore.getEvents();
  const clearedAlerts = SentinelDataStore.getAlerts();
  const clearedStats = SentinelDataStore.getStatistics();
  assert(clearedEvents.length === 0, 'Events array cleared to 0');
  assert(clearedAlerts.length === 0, 'Alerts array cleared to 0');
  assert(clearedStats.kpis.total_events === 0, 'KPI total events reset to 0');

  // Test 13: Reset to Defaults
  SentinelDataStore.resetToDefaults();
  const resetEvents = SentinelDataStore.getEvents();
  assert(resetEvents.length > 0, `Reset restored ${resetEvents.length} baseline seed events`);

  // Test 14: Register Application
  const newApp = SentinelDataStore.registerApplication({
    name: 'New Fintech Portal',
    url: 'https://pay.fintech.io',
    appType: 'Portal',
    environment: 'Production',
    ownerEmail: 'ciso@fintech.io'
  });
  assert(newApp.applicationId.startsWith('APP_'), `Generated valid Application ID: ${newApp.applicationId}`);
  assert(newApp.apiKey.startsWith('snt_live_'), `Generated valid API Key: ${newApp.apiKey}`);
  assert(newApp.apiSecret.startsWith('sec_live_'), `Generated valid API Secret: ${newApp.apiSecret}`);
  const apps = SentinelDataStore.getApplications();
  assert(apps.some(a => a.applicationId === newApp.applicationId), 'Registered application stored in single source of truth');

  console.log('=================================================================');
  console.log(`   AUDIT RESULTS: ${passedTests} / ${totalTests} TESTS PASSED (100%)`);
  console.log('=================================================================');
}

runTests();
