import db from '../database/db.js';

/**
 * Log security event to audit log
 * 
 * 🔹 STEP E: Session events logged for visibility
 */
export function logAuditEvent({
  userId,
  email,
  event,
  details,
  riskScore = null,
  severity = 'INFO', // Session events can have severity
  ipAddress,
  userAgent,
  location,
  success = true
}) {
  const stmt = db.prepare(`
    INSERT INTO audit_logs (user_id, email, event, details, risk_score, ip_address, user_agent, location, success)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    userId || null,
    email,
    event,
    details,
    riskScore,
    ipAddress,
    userAgent,
    location ? JSON.stringify(location) : null,
    success ? 1 : 0
  );

  // Console log for session security events
  if (event.includes('Session')) {
    const icon = success ? '✅' : '⚠️';
    console.log(`${icon} [SESSION] ${event}: ${details}`);
  }
}

/**
 * Get audit logs for user
 */
export function getAuditLogs(userId, limit = 50) {
  const stmt = db.prepare(`
    SELECT * FROM audit_logs
    WHERE user_id = ?
    ORDER BY timestamp DESC
    LIMIT ?
  `);

  return stmt.all(userId, limit).map(log => ({
    ...log,
    type: log.success ? 'success' : 'danger',
    location: log.location ? JSON.parse(log.location) : null
  }));
}

/**
 * Get all recent audit logs
 */
export function getAllAuditLogs(limit = 100) {
  const stmt = db.prepare(`
    SELECT * FROM audit_logs
    ORDER BY timestamp DESC
    LIMIT ?
  `);

  return stmt.all(limit).map(log => ({
    ...log,
    type: getLogType(log.event, log.success),
    location: log.location ? JSON.parse(log.location) : null
  }));
}

function getLogType(event, success) {
  if (!success) return 'danger';
  if (event.includes('risk') || event.includes('fallback')) return 'warning';
  return 'success';
}

/**
 * Track fallback usage
 */
export function trackFallbackUsage(userId, email, reason = 'User initiated OTP login') {
  const stmt = db.prepare(`
    INSERT INTO fallback_usage (user_id, email, reason)
    VALUES (?, ?, ?)
  `);

  stmt.run(userId, email, reason);
}

/**
 * Get fallback usage count
 */
export function getFallbackUsageCount(userId, days = 7) {
  const stmt = db.prepare(`
    SELECT COUNT(*) as count
    FROM fallback_usage
    WHERE user_id = ?
    AND timestamp > datetime('now', '-' || ? || ' days')
  `);

  const result = stmt.get(userId, days);
  return result ? result.count : 0;
}

/**
 * Check for abuse patterns
 */
export function checkFallbackAbuse(userId) {
  const count = getFallbackUsageCount(userId, 7);
  
  if (count > 10) {
    return {
      isAbuse: true,
      severity: 'high',
      message: `Excessive fallback usage detected: ${count} times in 7 days`,
      action: 'Account security review required'
    };
  }
  
  if (count > 5) {
    return {
      isAbuse: true,
      severity: 'medium',
      message: `High fallback usage: ${count} times in 7 days`,
      action: 'Consider re-registering passkey'
    };
  }
  
  return {
    isAbuse: false,
    count
  };
}

/**
 * Log risk event
 */
export function logRiskEvent(userId, eventType, riskScore, factors) {
  const stmt = db.prepare(`
    INSERT INTO risk_events (user_id, event_type, risk_score, factors)
    VALUES (?, ?, ?, ?)
  `);

  stmt.run(userId, eventType, riskScore, JSON.stringify(factors));
}

/**
 * Get recent failed attempts
 */
export function getRecentFailedAttempts(email, minutes = 30) {
  const stmt = db.prepare(`
    SELECT COUNT(*) as count
    FROM audit_logs
    WHERE email = ?
    AND success = 0
    AND event LIKE '%login%'
    AND timestamp > datetime('now', '-' || ? || ' minutes')
  `);

  const result = stmt.get(email, minutes);
  return result ? result.count : 0;
}
