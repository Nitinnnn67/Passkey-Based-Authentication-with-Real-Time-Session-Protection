import crypto from 'crypto';
import db from '../database/db.js';
import { getDeviceFingerprint, getDeviceName } from './riskAssessment.js';

/**
 * SESSION PROTECTION MANAGER
 * 
 * 🔒 Real security starts AFTER login
 * - Binds session to device/browser context
 * - Validates every request against original context
 * - Detects token theft and hijacking attempts
 */

// In-memory session store (production mein Redis use karo)
const activeSessions = new Map();

/**
 * 🔹 STEP A: Create Session (After Successful Login)
 * 
 * Session token generate + device/browser context bind
 */
export function createSession(userId, email, req, riskScore) {
  // Generate secure session token
  const sessionToken = crypto.randomBytes(32).toString('hex');
  
  // Capture device & browser context
  const deviceFingerprint = getDeviceFingerprint(req);
  const deviceName = getDeviceName(req.headers['user-agent']);
  const browserInfo = extractBrowserInfo(req.headers['user-agent']);
  
  // Session context
  const sessionContext = {
    sessionId: sessionToken,
    userId,
    email,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    
    // Device binding
    deviceFingerprint,
    deviceName,
    browserInfo,
    
    // Security context
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    initialRiskScore: riskScore,
    currentRiskLevel: getRiskLevel(riskScore),
    
    // Session state
    isActive: true,
    rotationCount: 0
  };
  
  // Store session
  activeSessions.set(sessionToken, sessionContext);
  
  // Persist to database for audit trail
  try {
    db.prepare(`
      INSERT INTO sessions 
      (session_id, user_id, email, device_fingerprint, device_name, browser_info, ip_address, created_at, risk_level)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      sessionToken,
      userId,
      email,
      deviceFingerprint,
      deviceName,
      JSON.stringify(browserInfo),
      req.ip,
      new Date().toISOString(),
      sessionContext.currentRiskLevel
    );
  } catch (error) {
    console.error('Session DB persist error:', error);
    // Continue - session still works from memory
  }
  
  console.log(`✅ Session created for ${email} on ${deviceName} (Risk: ${sessionContext.currentRiskLevel})`);
  
  return {
    sessionToken,
    expiresIn: '24h',
    deviceBound: true,
    riskLevel: sessionContext.currentRiskLevel
  };
}

/**
 * 🔹 STEP B: Validate Session (Every Request)
 * 
 * Check token validity + context matching
 */
export function validateSession(sessionToken, req) {
  const session = activeSessions.get(sessionToken);
  
  if (!session) {
    return {
      valid: false,
      reason: 'SESSION_NOT_FOUND',
      requiresAuth: true
    };
  }
  
  // Check if session expired (24 hours)
  const sessionAge = Date.now() - session.createdAt;
  if (sessionAge > 24 * 60 * 60 * 1000) {
    invalidateSession(sessionToken);
    return {
      valid: false,
      reason: 'SESSION_EXPIRED',
      requiresAuth: true
    };
  }
  
  // 🔒 CRITICAL: Context matching (anti-hijacking)
  const currentFingerprint = getDeviceFingerprint(req);
  const currentUserAgent = req.headers['user-agent'];
  
  // Device mismatch = potential token theft
  if (session.deviceFingerprint !== currentFingerprint) {
    console.warn(`⚠️ SECURITY: Device mismatch for session ${sessionToken.substring(0, 8)}`);
    invalidateSession(sessionToken);
    return {
      valid: false,
      reason: 'DEVICE_MISMATCH',
      requiresAuth: true,
      securityEvent: true
    };
  }
  
  // Browser mismatch = suspicious
  if (session.userAgent !== currentUserAgent) {
    console.warn(`⚠️ SECURITY: Browser change detected for session ${sessionToken.substring(0, 8)}`);
    // Downgrade session instead of immediate rejection
    session.currentRiskLevel = 'HIGH';
    return {
      valid: true,
      downgraded: true,
      reason: 'BROWSER_CHANGE',
      riskLevel: 'HIGH',
      limitedAccess: true
    };
  }
  
  // IP change = monitor (common with mobile)
  if (session.ipAddress !== req.ip) {
    console.log(`ℹ️ IP change for session ${sessionToken.substring(0, 8)}: ${session.ipAddress} → ${req.ip}`);
    // Update but don't reject
    session.ipAddress = req.ip;
  }
  
  // Update last activity
  session.lastActivity = Date.now();
  
  return {
    valid: true,
    session,
    userId: session.userId,
    email: session.email,
    riskLevel: session.currentRiskLevel,
    deviceName: session.deviceName
  };
}

/**
 * 🔹 STEP C: Adjust Session Based on Risk
 * 
 * Dynamic privilege adjustment
 */
export function adjustSessionRisk(sessionToken, newRiskScore, reason) {
  const session = activeSessions.get(sessionToken);
  
  if (!session) return false;
  
  const oldRiskLevel = session.currentRiskLevel;
  const newRiskLevel = getRiskLevel(newRiskScore);
  
  session.currentRiskLevel = newRiskLevel;
  session.lastRiskUpdate = Date.now();
  session.lastRiskReason = reason;
  
  console.log(`🔄 Session risk adjusted: ${oldRiskLevel} → ${newRiskLevel} (${reason})`);
  
  // HIGH risk = limited actions
  if (newRiskLevel === 'HIGH') {
    session.limitedAccess = true;
    session.sensitiveActionsBlocked = true;
  }
  
  return {
    adjusted: true,
    oldRiskLevel,
    newRiskLevel,
    limitedAccess: session.limitedAccess
  };
}

/**
 * 🔹 STEP D: Rotate Session (Anti-Hijack)
 * 
 * Generate new token after sensitive actions
 */
export function rotateSession(oldToken, req) {
  const session = activeSessions.get(oldToken);
  
  if (!session) return null;
  
  // Generate new token
  const newToken = crypto.randomBytes(32).toString('hex');
  
  // Copy session data with new token
  const rotatedSession = {
    ...session,
    sessionId: newToken,
    rotatedAt: Date.now(),
    rotationCount: session.rotationCount + 1,
    previousToken: oldToken
  };
  
  // Replace old session
  activeSessions.delete(oldToken);
  activeSessions.set(newToken, rotatedSession);
  
  console.log(`🔄 Session rotated (count: ${rotatedSession.rotationCount})`);
  
  return newToken;
}

/**
 * Invalidate session (logout or security event)
 */
export function invalidateSession(sessionToken, reason = 'USER_LOGOUT') {
  const session = activeSessions.get(sessionToken);
  
  if (session) {
    session.isActive = false;
    session.invalidatedAt = Date.now();
    session.invalidationReason = reason;
    
    // Remove from active sessions
    activeSessions.delete(sessionToken);
    
    // Mark as invalidated in DB
    try {
      db.prepare(`
        UPDATE sessions 
        SET is_active = 0, invalidated_at = ?, invalidation_reason = ?
        WHERE session_id = ?
      `).run(new Date().toISOString(), reason, sessionToken);
    } catch (error) {
      console.error('Session invalidation DB error:', error);
    }
    
    console.log(`🔒 Session invalidated: ${reason}`);
  }
  
  return true;
}

/**
 * Get all active sessions for user (for dashboard)
 */
export function getUserSessions(userId) {
  const sessions = [];
  
  for (const [token, session] of activeSessions) {
    if (session.userId === userId && session.isActive) {
      sessions.push({
        sessionId: token.substring(0, 8) + '...',
        deviceName: session.deviceName,
        browserInfo: session.browserInfo,
        createdAt: new Date(session.createdAt).toLocaleString(),
        lastActivity: new Date(session.lastActivity).toLocaleString(),
        riskLevel: session.currentRiskLevel,
        ipAddress: session.ipAddress
      });
    }
  }
  
  return sessions;
}

/**
 * Extract browser info from user agent
 */
function extractBrowserInfo(userAgent) {
  if (!userAgent) return { browser: 'Unknown', os: 'Unknown' };
  
  let browser = 'Unknown';
  let os = 'Unknown';
  
  // Browser detection
  if (userAgent.includes('Chrome')) browser = 'Chrome';
  else if (userAgent.includes('Firefox')) browser = 'Firefox';
  else if (userAgent.includes('Safari')) browser = 'Safari';
  else if (userAgent.includes('Edge')) browser = 'Edge';
  
  // OS detection
  if (userAgent.includes('Windows')) os = 'Windows';
  else if (userAgent.includes('Mac')) os = 'macOS';
  else if (userAgent.includes('Linux')) os = 'Linux';
  else if (userAgent.includes('Android')) os = 'Android';
  else if (userAgent.includes('iOS')) os = 'iOS';
  
  return { browser, os };
}

/**
 * Convert risk score to level
 */
function getRiskLevel(riskScore) {
  if (riskScore < 30) return 'LOW';
  if (riskScore < 60) return 'MEDIUM';
  return 'HIGH';
}

/**
 * Cleanup expired sessions (run periodically)
 */
export function cleanupExpiredSessions() {
  const now = Date.now();
  let cleaned = 0;
  
  for (const [token, session] of activeSessions) {
    const age = now - session.createdAt;
    if (age > 24 * 60 * 60 * 1000) {
      invalidateSession(token, 'EXPIRED');
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    console.log(`🧹 Cleaned ${cleaned} expired sessions`);
  }
}

// Run cleanup every hour
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);
