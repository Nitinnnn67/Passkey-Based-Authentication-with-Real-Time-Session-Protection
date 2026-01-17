import { validateSession, adjustSessionRisk, invalidateSession } from '../utils/sessionManager.js';
import { logAuditEvent } from '../utils/auditLogger.js';

/**
 * SESSION VALIDATION MIDDLEWARE
 * 
 * 🔒 Validates EVERY request against session context
 * 
 * Usage:
 * router.get('/protected', requireSession, (req, res) => {...})
 */
export function requireSession(req, res, next) {
  // Extract session token from Authorization header
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      error: 'No session token',
      requiresAuth: true 
    });
  }
  
  const sessionToken = authHeader.substring(7); // Remove "Bearer "
  
  // 🔹 STEP B: Validate session + context
  const validation = validateSession(sessionToken, req);
  
  if (!validation.valid) {
    // Log security event
    if (validation.securityEvent) {
      logAuditEvent({
        email: 'UNKNOWN',
        event: 'Session Rejected',
        details: `Reason: ${validation.reason}`,
        severity: 'HIGH',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
    }
    
    return res.status(401).json({ 
      error: 'Invalid session',
      reason: validation.reason,
      requiresAuth: true 
    });
  }
  
  // Session downgraded due to risk
  if (validation.downgraded) {
    console.warn(`⚠️ Session downgraded: ${validation.reason}`);
    
    logAuditEvent({
      email: validation.email,
      event: 'Session Downgraded',
      details: `Reason: ${validation.reason}, Risk: ${validation.riskLevel}`,
      severity: 'MEDIUM',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
  }
  
  // Attach session info to request
  req.session.user = {
    userId: validation.userId,
    email: validation.email,
    deviceName: validation.deviceName,
    riskLevel: validation.riskLevel,
    limitedAccess: validation.limitedAccess || false
  };
  
  req.sessionToken = sessionToken;
  
  next();
}

/**
 * SENSITIVE ACTION PROTECTION
 * 
 * Extra validation for high-risk operations
 * Usage:
 * router.post('/transfer', requireSession, requireLowRisk, (req, res) => {...})
 */
export function requireLowRisk(req, res, next) {
  const user = req.session.user;
  
  if (!user) {
    return res.status(401).json({ error: 'Session required' });
  }
  
  // Block if high risk or limited access
  if (user.riskLevel === 'HIGH' || user.limitedAccess) {
    logAuditEvent({
      email: user.email,
      event: 'Sensitive Action Blocked',
      details: `Risk level: ${user.riskLevel}, Limited access: ${user.limitedAccess}`,
      severity: 'HIGH',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    return res.status(403).json({ 
      error: 'Action not allowed',
      reason: 'High risk session or limited access',
      riskLevel: user.riskLevel,
      suggestReAuth: true
    });
  }
  
  next();
}

/**
 * OPTIONAL: Session exists but not required
 * 
 * For public endpoints that benefit from session context
 */
export function optionalSession(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const sessionToken = authHeader.substring(7);
    const validation = validateSession(sessionToken, req);
    
    if (validation.valid) {
      req.session.user = {
        userId: validation.userId,
        email: validation.email,
        riskLevel: validation.riskLevel
      };
      req.sessionToken = sessionToken;
    }
  }
  
  next();
}

/**
 * RATE LIMITING per session
 * 
 * Prevent abuse from single session
 */
const sessionRateLimits = new Map();

export function rateLimitBySession(maxRequests = 100, windowMs = 60000) {
  return (req, res, next) => {
    const sessionToken = req.sessionToken;
    
    if (!sessionToken) {
      return next(); // No session = no rate limit
    }
    
    const now = Date.now();
    const key = sessionToken;
    
    if (!sessionRateLimits.has(key)) {
      sessionRateLimits.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    
    const limit = sessionRateLimits.get(key);
    
    if (now > limit.resetAt) {
      // Reset window
      limit.count = 1;
      limit.resetAt = now + windowMs;
      return next();
    }
    
    if (limit.count >= maxRequests) {
      return res.status(429).json({ 
        error: 'Too many requests',
        retryAfter: Math.ceil((limit.resetAt - now) / 1000) 
      });
    }
    
    limit.count++;
    next();
  };
}
