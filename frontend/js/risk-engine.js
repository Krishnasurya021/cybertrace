/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: Centralized Client-Side Risk Engine
 * Evaluates multi-dimensional signals across temporal windows.
 * Strictly adheres to ZERO-PASSWORD principle.
 */

const SentinelRiskEngine = (() => {
  const DEFAULT_WEIGHTS = {
    single_failure: 10,
    unknown_account: 10,
    mfa_failure: 20,
    locked_account: 15,
    failed_attempts_5: 50,
    failed_attempts_10: 70,
    multiple_usernames_2: 15,
    multiple_usernames_4: 35,
    multiple_usernames_7: 60,
    high_frequency_10: 25,
    high_frequency_25: 40,
    restricted_resource: 30,
    previous_high_risk: 30,
    brute_force_success: 50,
    off_hours_failures: 20
  };

  let currentWeights = { ...DEFAULT_WEIGHTS };

  function loadWeights(customWeights) {
    if (customWeights && typeof customWeights === 'object') {
      currentWeights = { ...DEFAULT_WEIGHTS, ...customWeights };
    }
  }

  function getWeights() {
    return { ...currentWeights };
  }

  function setWeight(key, val) {
    if (key in currentWeights) {
      currentWeights[key] = Math.max(0, Math.min(100, parseInt(val, 10) || 0));
    }
  }

  /**
   * Evaluates an authentication event against historical context.
   * @param {Object} event - The authentication event being evaluated
   * @param {Array} previousEvents - Array of previously recorded events
   * @returns {Object} { riskScore, riskLevel, status, triggeredRules, explanation, penalties }
   */
  function calculateRisk(event, previousEvents = []) {
    const baseScore = 5;
    const result = (event.authenticationResult || event.authentication_result || 'SUCCESS').toUpperCase();
    const sourceIp = (event.sourceIp || event.source_ip || '127.0.0.1').trim();
    const username = (event.usernameIdentifier || event.username_identifier || '').trim();
    const resource = (event.resource || '/login').toLowerCase();
    const eventTime = event.timestamp ? new Date(event.timestamp.replace(' ', 'T')).getTime() : Date.now();

    const penalties = {
      result_penalty: 0,
      failed_attempts_penalty: 0,
      username_variety_penalty: 0,
      frequency_penalty: 0,
      resource_penalty: 0,
      previous_risk_penalty: 0,
      off_hours_penalty: 0
    };

    const triggeredRules = [];
    const explanationClauses = [];

    // 1. Result Classification
    if (result === 'SUCCESS') {
      // Clean base
    } else if (result === 'FAILURE') {
      penalties.result_penalty = currentWeights.single_failure;
      triggeredRules.push({
        rule_code: 'RULE-010',
        name: 'Single Transient Failure',
        weight: currentWeights.single_failure
      });
      explanationClauses.push('Authentication failed. No significant suspicious pattern detected.');
    } else if (result === 'UNKNOWN_ACCOUNT') {
      penalties.result_penalty = currentWeights.unknown_account;
      triggeredRules.push({
        rule_code: 'RULE-009',
        name: 'Unknown Account Identifier',
        weight: currentWeights.unknown_account
      });
      explanationClauses.push('Account identifier was not recognized. Monitoring continues.');
    } else if (result === 'MFA_FAILURE') {
      penalties.result_penalty = currentWeights.mfa_failure;
      triggeredRules.push({
        rule_code: 'RULE-008',
        name: 'MFA Challenge Failure',
        weight: currentWeights.mfa_failure
      });
      explanationClauses.push('Multi-factor authentication challenge rejected.');
    } else if (result === 'LOCKED_ACCOUNT') {
      penalties.result_penalty = currentWeights.locked_account;
      explanationClauses.push('Authentication attempt against locked account.');
    }

    // Temporal Window Calculations (past 10 mins = 600,000 ms)
    const window10m = 10 * 60 * 1000;
    const window5m = 5 * 60 * 1000;
    const window1m = 1 * 60 * 1000;
    const window24h = 24 * 60 * 60 * 1000;

    const eventsFromIp = previousEvents.filter(e => {
      const ip = e.sourceIp || e.source_ip || '';
      return ip === sourceIp;
    });

    const recentFails = eventsFromIp.filter(e => {
      const res = (e.authenticationResult || e.authentication_result || '').toUpperCase();
      const t = e.timestamp ? new Date(e.timestamp.replace(' ', 'T')).getTime() : 0;
      return ['FAILURE', 'UNKNOWN_ACCOUNT', 'MFA_FAILURE'].includes(res) && (eventTime - t <= window10m);
    }).length;

    const isCurrentFail = ['FAILURE', 'UNKNOWN_ACCOUNT', 'MFA_FAILURE'].includes(result);
    const effectiveFails = recentFails + (isCurrentFail ? 1 : 0);

    // 2. Failed Attempts Frequency Signal
    if (effectiveFails >= 10) {
      penalties.failed_attempts_penalty = currentWeights.failed_attempts_10;
      triggeredRules.push({
        rule_code: 'RULE-001',
        name: 'Repeated Authentication Failures (>=10)',
        weight: currentWeights.failed_attempts_10
      });
      explanationClauses.push(`Severe failure volume: ${effectiveFails} failed attempts observed from origin.`);
    } else if (effectiveFails >= 5) {
      penalties.failed_attempts_penalty = currentWeights.failed_attempts_5;
      triggeredRules.push({
        rule_code: 'RULE-001',
        name: 'Repeated Authentication Failures (>=5)',
        weight: currentWeights.failed_attempts_5
      });
      explanationClauses.push(`Repeated authentication failures (${effectiveFails} attempts) detected.`);
    }

    // 3. Account Enumeration / Multiple Usernames Signal (past 5 mins)
    const probedUsers = new Set();
    eventsFromIp.forEach(e => {
      const t = e.timestamp ? new Date(e.timestamp.replace(' ', 'T')).getTime() : 0;
      if (eventTime - t <= window5m) {
        const u = e.usernameIdentifier || e.username_identifier;
        if (u) probedUsers.add(u);
      }
    });
    if (username) probedUsers.add(username);
    const distinctUsers = probedUsers.size;

    if (distinctUsers >= 7) {
      penalties.username_variety_penalty = currentWeights.multiple_usernames_7;
      triggeredRules.push({
        rule_code: 'RULE-002',
        name: 'High-Risk Account Enumeration Pattern',
        weight: currentWeights.multiple_usernames_7
      });
      explanationClauses.push(`High-risk account enumeration: ${distinctUsers} distinct usernames probed from same origin.`);
    } else if (distinctUsers >= 4) {
      penalties.username_variety_penalty = currentWeights.multiple_usernames_4;
      triggeredRules.push({
        rule_code: 'RULE-002',
        name: 'Multiple Account Identifiers',
        weight: currentWeights.multiple_usernames_4
      });
      explanationClauses.push(`Multiple account identifiers (${distinctUsers} users) attempted from single source.`);
    } else if (distinctUsers >= 2 && result !== 'SUCCESS') {
      penalties.username_variety_penalty = currentWeights.multiple_usernames_2;
    }

    // 4. Request Velocity Frequency Signal (past 1 min)
    const recentReqCount = eventsFromIp.filter(e => {
      const t = e.timestamp ? new Date(e.timestamp.replace(' ', 'T')).getTime() : 0;
      return eventTime - t <= window1m;
    }).length + 1;

    if (recentReqCount >= 25) {
      penalties.frequency_penalty = currentWeights.high_frequency_25;
      triggeredRules.push({
        rule_code: 'RULE-003',
        name: 'Extreme Request Velocity Spike',
        weight: currentWeights.high_frequency_25
      });
      explanationClauses.push(`Extreme request velocity: ${recentReqCount} requests/min.`);
    } else if (recentReqCount >= 10) {
      penalties.frequency_penalty = currentWeights.high_frequency_10;
      triggeredRules.push({
        rule_code: 'RULE-003',
        name: 'Abnormal Request Frequency',
        weight: currentWeights.high_frequency_10
      });
      explanationClauses.push(`Abnormal request frequency: ${recentReqCount} req/min.`);
    }

    // 5. Restricted Resource Probing
    const restrictedTargets = ['/admin', '/root', '/portal-admin', '/api/v1/keys', '/finance', '/sysadmin'];
    if (restrictedTargets.some(target => resource.includes(target))) {
      penalties.resource_penalty = currentWeights.restricted_resource;
      triggeredRules.push({
        rule_code: 'RULE-005',
        name: 'Restricted Resource Probing',
        weight: currentWeights.restricted_resource
      });
      explanationClauses.push(`Direct authentication attempt targeting restricted endpoint: ${resource}.`);
    }

    // 6. Previous High-Risk IP Activity (past 24h)
    const hadPriorAlert = eventsFromIp.some(e => {
      const t = e.timestamp ? new Date(e.timestamp.replace(' ', 'T')).getTime() : 0;
      const r = (e.riskLevel || e.risk_level || '').toUpperCase();
      return (r === 'HIGH' || r === 'CRITICAL') && (eventTime - t <= window24h);
    });

    if (hadPriorAlert) {
      penalties.previous_risk_penalty = currentWeights.previous_high_risk;
      triggeredRules.push({
        rule_code: 'RULE-006',
        name: 'High-Risk Source IP Reputation',
        weight: currentWeights.previous_high_risk
      });
      explanationClauses.push('Source IP has triggered security alerts in the past 24 hours.');
    }

    // 7. Brute Force Success / Account Takeover (SUCCESS preceded by >= 4 consecutive failures)
    if (result === 'SUCCESS') {
      const userIpEvents = eventsFromIp.filter(e => {
        const u = e.usernameIdentifier || e.username_identifier || '';
        return u === username;
      }).slice(-5);

      const recentFailsSeq = userIpEvents.filter(e => {
        const res = (e.authenticationResult || e.authentication_result || '').toUpperCase();
        return ['FAILURE', 'UNKNOWN_ACCOUNT'].includes(res);
      }).length;

      if (recentFailsSeq >= 4) {
        penalties.previous_risk_penalty += currentWeights.brute_force_success;
        triggeredRules.push({
          rule_code: 'RULE-004',
          name: 'Brute Force Success (Account Takeover)',
          weight: currentWeights.brute_force_success
        });
        explanationClauses.push(`CRITICAL: Successful login after ${recentFailsSeq} consecutive failed attempts.`);
      }
    }

    // 8. Off-Hours Temporal Anomaly (23:00 - 05:00) with failures
    try {
      const dateObj = new Date(eventTime);
      const hour = dateObj.getHours();
      if ((hour >= 23 || hour < 5) && (effectiveFails >= 3 || result !== 'SUCCESS')) {
        penalties.off_hours_penalty = currentWeights.off_hours_failures;
        triggeredRules.push({
          rule_code: 'RULE-007',
          name: 'Off-Hours Authentication Failures',
          weight: currentWeights.off_hours_failures
        });
        explanationClauses.push(`Anomalous off-hours access activity observed at ${String(hour).padStart(2, '0')}:00.`);
      }
    } catch (_) {}

    // Calculate Final Risk Score (Clamped 0 - 100)
    const totalPenalties = Object.values(penalties).reduce((a, b) => a + b, 0);
    const rawScore = baseScore + totalPenalties;
    const riskScore = Math.min(100, Math.max(0, rawScore));

    // Classification
    let riskLevel = 'LOW';
    let status = 'SAFE';

    if (riskScore >= 75) {
      riskLevel = 'CRITICAL';
      status = 'CRITICAL_ALERT';
    } else if (riskScore >= 50) {
      riskLevel = 'HIGH';
      status = 'ALERT';
    } else if (riskScore >= 25) {
      riskLevel = 'MEDIUM';
      status = ['UNKNOWN_ACCOUNT', 'FAILURE'].includes(result) ? 'SUSPICIOUS' : 'MONITORING';
    } else {
      riskLevel = 'LOW';
      status = result === 'SUCCESS' ? 'SAFE' : 'MONITORING';
    }

    const explanation = explanationClauses.length > 0
      ? explanationClauses.join(' ')
      : 'Successful authentication with no significant suspicious indicators.';

    return {
      riskScore,
      riskLevel,
      status,
      triggeredRules,
      explanation,
      penalties
    };
  }

  return {
    calculateRisk,
    getWeights,
    setWeight,
    loadWeights,
    DEFAULT_WEIGHTS
  };
})();

if (typeof window !== 'undefined') {
  window.SentinelRiskEngine = SentinelRiskEngine;
  window.calculateRisk = (ev, prev) => SentinelRiskEngine.calculateRisk(ev, prev);
}
