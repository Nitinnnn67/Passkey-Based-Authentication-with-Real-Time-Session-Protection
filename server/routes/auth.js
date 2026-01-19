import express from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import db from '../database/db.js';
import { 
  calculateRiskScore, 
  getDeviceFingerprint, 
  getLocation, 
  isUnusualTime,
  getDeviceName,
  formatRiskAssessment,
  isPasskeyCapable
} from '../utils/riskAssessment.js';
import {
  logAuditEvent,
  trackFallbackUsage,
  getFallbackUsageCount,
  checkFallbackAbuse,
  logRiskEvent,
  getRecentFailedAttempts
} from '../utils/auditLogger.js';
import {
  generateOTP,
  storeOTP,
  verifyOTP,
  sendOTPEmail
} from '../utils/otpService.js';
import {
  createSession,
  rotateSession,
  invalidateSession
} from '../utils/sessionManager.js';

const router = express.Router();

// WebAuthn configuration
const rpName = process.env.RP_NAME || 'Passkey Auth System';
const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.RP_ORIGIN || 'http://localhost:5173';

// Temporary storage for challenges (in production, use Redis or session store)
const challenges = new Map();

/**
 * Registration: Generate Options
 */
router.post('/register/options', async (req, res) => {
  try {
    const { email, username } = req.body;

    if (!email || !username) {
      return res.status(400).json({ error: 'Email and username required' });
    }

    // Check if user already exists
    const existingUser = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Generate registration options
    // Convert email to Uint8Array for userID (required in v10+)
    const userIDBuffer = Buffer.from(email);
    
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: new Uint8Array(userIDBuffer),
      userName: username,
      userDisplayName: username,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        // Allow both platform (device) and cross-platform (portable) authenticators
        // This enables passkey sync across devices via iCloud, Google, etc.
        authenticatorAttachment: undefined // Don't restrict - allow any authenticator
      }
    });

    // Store challenge
    challenges.set(email, options.challenge);

    // Log event
    logAuditEvent({
      email,
      event: 'Registration Started',
      details: `User ${username} initiated registration`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      location: getLocation(req.ip)
    });

    res.json(options);
  } catch (error) {
    console.error('Registration options error:', error);
    res.status(500).json({ 
      error: 'Failed to generate registration options',
      details: error.message 
    });
  }
});

/**
 * Registration: Verify Response
 */
router.post('/register/verify', async (req, res) => {
  try {
    const { email, credential } = req.body;

    const expectedChallenge = challenges.get(email);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Challenge not found' });
    }

    // Verify registration response
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID
    });

    if (!verification.verified) {
      logAuditEvent({
        email,
        event: 'Registration Failed',
        details: 'Credential verification failed',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false
      });
      return res.status(400).json({ error: 'Verification failed' });
    }

    // Get user from temp registration or create new
    const existingUser = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    let userId;

    if (!existingUser) {
      const username = credential.response.userHandle || email.split('@')[0];
      const insertUser = db.prepare('INSERT INTO users (email, username) VALUES (?, ?)');
      const result = insertUser.run(email, username);
      userId = result.lastInsertRowid;
    } else {
      userId = existingUser.id;
    }

    // Store credential
    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
    
    // Use credential.rawId (base64url format from browser) for consistency with login
    const credIdToStore = credential.rawId;
    console.log('💾 Storing credential ID:', credIdToStore);
    
    const insertCred = db.prepare(`
      INSERT INTO credentials (id, user_id, public_key, counter, transports)
      VALUES (?, ?, ?, ?, ?)
    `);

    insertCred.run(
      credIdToStore,
      userId,
      Buffer.from(credentialPublicKey).toString('base64'),
      counter,
      JSON.stringify(credential.response.transports || [])
    );

    // Register device
    const deviceFingerprint = getDeviceFingerprint(req);
    const deviceName = getDeviceName(req.headers['user-agent']);
    
    db.prepare(`
      INSERT OR REPLACE INTO known_devices (user_id, device_fingerprint, device_name, trust_level)
      VALUES (?, ?, ?, 100)
    `).run(userId, deviceFingerprint, deviceName);

    // Clean up challenge
    challenges.delete(email);

    // Log success
    logAuditEvent({
      userId,
      email,
      event: 'Registration Complete',
      details: `User registered with passkey on ${deviceName}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      location: getLocation(req.ip)
    });

    res.json({ 
      verified: true, 
      message: 'Registration successful' 
    });
  } catch (error) {
    console.error('Registration verification error:', error);
    res.status(500).json({ error: 'Registration verification failed' });
  }
});

/**
 * Login: Generate Authentication Options
 */
router.post('/login/options', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }
    
    // Check if user exists
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(404).json({ error: 'User not found. Please register first.' });
    }
    
    // Get all credentials for this user (supports multiple devices)
    const userCredentials = db.prepare('SELECT * FROM credentials WHERE user_id = ?').all(user.id);
    
    if (userCredentials.length === 0) {
      return res.status(404).json({ 
        error: 'No passkey found for this account',
        message: 'Please register a passkey first or use OTP login'
      });
    }
    
    // Convert stored credentials to allowCredentials format
    const allowCredentials = userCredentials.map(cred => {
      try {
        // Parse transports safely
        let transports = ['internal', 'hybrid'];
        if (cred.transports) {
          try {
            transports = typeof cred.transports === 'string' ? JSON.parse(cred.transports) : cred.transports;
          } catch (e) {
            console.warn('Failed to parse transports:', e);
          }
        }
        
        // Keep credential ID as base64url string (don't convert to Buffer)
        return {
          id: cred.id, // Already in base64url format
          type: 'public-key',
          transports
        };
      } catch (error) {
        console.error('Error processing credential:', error);
        return null;
      }
    }).filter(cred => cred !== null);
    
    if (allowCredentials.length === 0) {
      return res.status(500).json({ error: 'Failed to process stored credentials' });
    }
    
    // Generate authentication options with user's credentials
    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: 'preferred',
      allowCredentials // Only allow this user's passkeys
    });

    // Store challenge with email
    challenges.set(`login-${email}`, options.challenge);

    res.json(options);
  } catch (error) {
    console.error('Login options error:', error);
    res.status(500).json({ error: 'Failed to generate login options', details: error.message });
  }
});

/**
 * Login: Verify Authentication Response
 */
router.post('/login/verify', async (req, res) => {
  try {
    const { credential, email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    const expectedChallenge = challenges.get(`login-${email}`);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Challenge not found or expired' });
    }

    // Get credential from database
    const credId = credential.rawId;
    console.log('🔍 Looking for credential ID:', credId);
    
    const storedCred = db.prepare('SELECT * FROM credentials WHERE id = ?').get(credId);
    
    if (!storedCred) {
      console.log('❌ Credential not found:', credId);
      logAuditEvent({
        email,
        event: 'Login Failed',
        details: 'Credential not found or doesn\'t belong to this user',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false
      });
      return res.status(400).json({ error: 'Credential not found' });
    }

    // Get user
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(storedCred.user_id);

    // Convert base64url credential ID to Buffer for verification
    // base64url uses - and _ instead of + and /, and no padding
    const base64 = storedCred.id.replace(/-/g, '+').replace(/_/g, '/');
    const credentialIDBuffer = Buffer.from(base64, 'base64');
    
    // Verify authentication
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: credentialIDBuffer,
        credentialPublicKey: Buffer.from(storedCred.public_key, 'base64'),
        counter: storedCred.counter
      }
    });

    if (!verification.verified) {
      logAuditEvent({
        userId: user.id,
        email: user.email,
        event: 'Login Failed',
        details: 'Authentication verification failed',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false
      });
      return res.status(400).json({ error: 'Verification failed' });
    }

    // Update counter
    db.prepare('UPDATE credentials SET counter = ? WHERE id = ?')
      .run(verification.authenticationInfo.newCounter, credId);

    // Risk assessment
    const deviceFingerprint = getDeviceFingerprint(req);
    const knownDevice = db.prepare(`
      SELECT * FROM known_devices 
      WHERE user_id = ? AND device_fingerprint = ?
    `).get(user.id, deviceFingerprint);

    const fallbackCount = getFallbackUsageCount(user.id, 7);
    const recentFailures = getRecentFailedAttempts(user.email, 30);

    const deviceCountResult = db.prepare('SELECT COUNT(*) as count FROM known_devices WHERE user_id = ?').get(user.id);
    const deviceCount = deviceCountResult ? deviceCountResult.count : 0;

    const riskFactors = {
      deviceKnown: !!knownDevice,
      deviceTrustLevel: knownDevice?.trust_level || 0,
      unusualLocation: false, // Simplified
      unusualTime: isUnusualTime(),
      recentFailures,
      fallbackUsageCount: fallbackCount,
      multipleDevices: deviceCount
    };

    const riskAnalysis = calculateRiskScore(riskFactors);

    // Update or create device record
    if (knownDevice) {
      db.prepare(`
        UPDATE known_devices 
        SET last_seen = CURRENT_TIMESTAMP, trust_level = MIN(100, trust_level + 5)
        WHERE id = ?
      `).run(knownDevice.id);
    } else {
      const deviceName = getDeviceName(req.headers['user-agent']);
      db.prepare(`
        INSERT INTO known_devices (user_id, device_fingerprint, device_name, trust_level)
        VALUES (?, ?, ?, 30)
      `).run(user.id, deviceFingerprint, deviceName);
    }

    // Log risk event
    logRiskEvent(user.id, 'passkey_login', riskAnalysis.score, riskFactors);

    // Log successful login
    logAuditEvent({
      userId: user.id,
      email: user.email,
      event: 'Passkey Login Success',
      details: formatRiskAssessment(riskAnalysis),
      riskScore: riskAnalysis.score,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      location: getLocation(req.ip)
    });

    // Set session
    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.username = user.username;

    // 🔹 STEP A: Create Session (After Successful Login)
    // Bind session to device/browser context
    // 🔐 This will automatically invalidate any previous sessions
    const sessionData = createSession(user.id, user.email, req, riskAnalysis.score);

    // Clean up challenge
    challenges.delete(`login-${email}`);

    console.log(`✅ Login successful: ${user.email} on ${sessionData.riskLevel} risk session`);

    res.json({
      verified: true,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        accessLevel: riskAnalysis.accessLevel,
        riskScore: riskAnalysis.score,
        deviceKnown: riskFactors.deviceKnown
      },
      // 🔒 Session token for future requests
      session: {
        token: sessionData.sessionToken,
        expiresIn: sessionData.expiresIn,
        deviceBound: sessionData.deviceBound,
        riskLevel: sessionData.riskLevel
      },
      // Notify user if previous sessions were logged out
      message: sessionData.previousSessionsInvalidated > 0 
        ? `Login successful. ${sessionData.previousSessionsInvalidated} previous session(s) from other device(s) have been logged out.`
        : 'Login successful'
    });
  } catch (error) {
    console.error('Login verification error:', error);
    res.status(500).json({ error: 'Login verification failed' });
  }
});

/**
 * OTP Login: Request OTP
 */
router.post('/otp/request', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    // Check if user exists
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(404).json({ error: 'User not found. Please register first.' });
    }

    // 🔒 PASSKEY-FIRST POLICY: Block OTP if device supports passkeys
    const deviceSupportsPasskey = isPasskeyCapable(req.headers['user-agent']);
    
    if (deviceSupportsPasskey) {
      logAuditEvent({
        userId: user.id,
        email,
        event: 'OTP Blocked - Passkey Available',
        details: 'Device supports passkeys, OTP fallback disabled',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false
      });

      return res.status(403).json({ 
        error: 'Passkey authentication required',
        message: 'Your device supports passkeys. Please use passkey authentication.',
        deviceSupportsPasskey: true,
        fallbackDisabled: true
      });
    }

    // Check fallback abuse
    const abuseCheck = checkFallbackAbuse(user.id);
    if (abuseCheck.isAbuse) {
      logAuditEvent({
        userId: user.id,
        email,
        event: 'Fallback Abuse Detected',
        details: abuseCheck.message,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false
      });

      return res.status(429).json({ 
        error: 'Too many OTP requests',
        message: abuseCheck.message,
        action: abuseCheck.action
      });
    }

    // Generate and send OTP
    const otp = generateOTP();
    storeOTP(email, otp, 'login', 10);
    await sendOTPEmail(email, otp, 'login');

    // Track fallback usage
    trackFallbackUsage(user.id, email, 'User requested OTP login');

    // Log event
    logAuditEvent({
      userId: user.id,
      email,
      event: 'OTP Requested',
      details: 'Fallback authentication initiated',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      success: true, 
      message: 'OTP sent to your email',
      fallbackCount: abuseCheck.count + 1
    });
  } catch (error) {
    console.error('OTP request error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

/**
 * OTP Login: Verify OTP
 */
router.post('/otp/verify', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP required' });
    }

    // Verify OTP
    const otpCheck = verifyOTP(email, otp, 'login');
    if (!otpCheck.valid) {
      logAuditEvent({
        email,
        event: 'OTP Verification Failed',
        details: otpCheck.reason,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false
      });

      return res.status(400).json({ error: otpCheck.reason });
    }

    // Get user
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Risk assessment for OTP login (higher risk)
    const deviceFingerprint = getDeviceFingerprint(req);
    const knownDevice = db.prepare(`
      SELECT * FROM known_devices 
      WHERE user_id = ? AND device_fingerprint = ?
    `).get(user.id, deviceFingerprint);

    const fallbackCount = getFallbackUsageCount(user.id, 7);

    const riskFactors = {
      deviceKnown: !!knownDevice,
      deviceTrustLevel: knownDevice?.trust_level || 0,
      unusualLocation: false,
      unusualTime: isUnusualTime(),
      recentFailures: getRecentFailedAttempts(email, 30),
      fallbackUsageCount: fallbackCount,
      multipleDevices: db.prepare('SELECT COUNT(*) as count FROM known_devices WHERE user_id = ?').get(user.id).count
    };

    const riskAnalysis = calculateRiskScore(riskFactors);

    // Log risk event
    logRiskEvent(user.id, 'otp_login', riskAnalysis.score, riskFactors);

    // Log successful OTP login
    logAuditEvent({
      userId: user.id,
      email,
      event: 'OTP Login Success',
      details: `Fallback authentication completed. ${formatRiskAssessment(riskAnalysis)}`,
      riskScore: riskAnalysis.score,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      location: getLocation(req.ip)
    });

    // Set session
    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.username = user.username;

    // 🔹 STEP A: Create Session (OTP Login - Higher Risk)
    // Mark as fallback authentication
    // 🔐 This will automatically invalidate any previous sessions
    const sessionData = createSession(user.id, user.email, req, riskAnalysis.score);

    console.log(`✅ OTP Login successful: ${user.email} on ${sessionData.riskLevel} risk session`);

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        accessLevel: riskAnalysis.accessLevel,
        riskScore: riskAnalysis.score,
        deviceKnown: riskFactors.deviceKnown
      },
      // 🔒 Session token
      session: {
        token: sessionData.sessionToken,
        expiresIn: sessionData.expiresIn,
        riskLevel: sessionData.riskLevel,
        limitedAccess: sessionData.riskLevel === 'HIGH'
      },
      // Notify user if previous sessions were logged out
      message: sessionData.previousSessionsInvalidated > 0 
        ? `Login successful. ${sessionData.previousSessionsInvalidated} previous session(s) from other device(s) have been logged out.`
        : 'Login successful'
    });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

/**
 * Step-Up Authentication: Request
 */
router.post('/stepup/request', async (req, res) => {
  try {
    const { action } = req.body;

    if (!req.session.userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    // Generate and send OTP
    const otp = generateOTP();
    storeOTP(user.email, otp, 'stepup', 10);
    await sendOTPEmail(user.email, otp, 'stepup');

    // Log event
    logAuditEvent({
      userId: user.id,
      email: user.email,
      event: 'Step-Up Authentication Requested',
      details: `Additional verification required for action: ${action}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      success: true, 
      message: 'Verification code sent' 
    });
  } catch (error) {
    console.error('Step-up request error:', error);
    res.status(500).json({ error: 'Failed to request verification' });
  }
});

/**
 * Step-Up Authentication: Verify
 */
router.post('/stepup/verify', async (req, res) => {
  try {
    const { otp, action } = req.body;

    if (!req.session.userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    // Verify OTP
    const otpCheck = verifyOTP(user.email, otp, 'stepup');
    if (!otpCheck.valid) {
      logAuditEvent({
        userId: user.id,
        email: user.email,
        event: 'Step-Up Verification Failed',
        details: `Failed to verify for action: ${action}`,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false
      });

      return res.status(400).json({ error: otpCheck.reason });
    }

    // Log success
    logAuditEvent({
      userId: user.id,
      email: user.email,
      event: 'Step-Up Verification Success',
      details: `Action "${action}" authorized after additional verification`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      success: true, 
      message: 'Verification successful',
      action 
    });
  } catch (error) {
    console.error('Step-up verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

/**
 * Get session info
 */
router.get('/session', (req, res) => {
  if (req.session.userId) {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
    res.json({ 
      user: {
        id: user.id,
        email: user.email,
        username: user.username
      } 
    });
  } else {
    res.json({ user: null });
  }
});

/**
 * Logout
 */
router.post('/logout', (req, res) => {
  const userId = req.session.userId;
  const email = req.session.email;
  const sessionToken = req.headers.authorization?.substring(7); // Get token from header

  if (userId) {
    logAuditEvent({
      userId,
      email,
      event: 'User Logout',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
  }

  // 🔒 Invalidate session token
  if (sessionToken) {
    invalidateSession(sessionToken, 'USER_LOGOUT');
  }

  req.session.destroy();
  res.json({ success: true });
});

// ========================================
// 🔒 PROTECTED ROUTES (Session Required)
// ========================================

/**
 * Get user profile (Protected)
 * 
 * 🔹 STEP B: Session validated on every request
 */
router.get('/profile', async (req, res) => {
  try {
    // Extract session token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Session token required' });
    }

    const sessionToken = authHeader.substring(7);
    
    // Import validation here (inline to avoid circular deps)
    const { validateSession } = await import('../utils/sessionManager.js');
    const validation = validateSession(sessionToken, req);

    if (!validation.valid) {
      return res.status(401).json({ 
        error: 'Invalid session',
        reason: validation.reason,
        requiresAuth: true 
      });
    }

    // Get user data
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(validation.userId);
    
    res.json({
      user: {
        id: user.id,
        email: user.email,
        username: user.username
      },
      session: {
        deviceName: validation.deviceName,
        riskLevel: validation.riskLevel,
        limitedAccess: validation.limitedAccess || false
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

/**
 * Sensitive action example (Protected + Low Risk Required)
 * 
 * 🔹 STEP C: Risk-based access control
 */
router.post('/sensitive-action', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Session token required' });
    }

    const sessionToken = authHeader.substring(7);
    
    const { validateSession } = await import('../utils/sessionManager.js');
    const validation = validateSession(sessionToken, req);

    if (!validation.valid) {
      return res.status(401).json({ 
        error: 'Invalid session',
        requiresAuth: true 
      });
    }

    // 🔒 Block high-risk sessions
    if (validation.riskLevel === 'HIGH' || validation.limitedAccess) {
      logAuditEvent({
        userId: validation.userId,
        email: validation.email,
        event: 'Sensitive Action Blocked',
        details: `Risk level: ${validation.riskLevel}`,
        severity: 'HIGH',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      return res.status(403).json({
        error: 'Action not allowed on high-risk session',
        riskLevel: validation.riskLevel,
        suggestReAuth: true
      });
    }

    // 🔹 STEP D: Rotate session after sensitive action
    const { rotateSession } = await import('../utils/sessionManager.js');
    const newToken = rotateSession(sessionToken, req);

    logAuditEvent({
      userId: validation.userId,
      email: validation.email,
      event: 'Sensitive Action Performed',
      details: 'Action authorized, session rotated',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({
      success: true,
      message: 'Action completed',
      // Return new token for client to use
      newSessionToken: newToken
    });
  } catch (error) {
    console.error('Sensitive action error:', error);
    res.status(500).json({ error: 'Action failed' });
  }
});

/**
 * 🔒 SESSION STATUS CHECK
 * 
 * Shows session protection in action
 */
router.get('/session-status', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.json({ 
        sessionActive: false,
        message: 'No session token provided'
      });
    }

    const sessionToken = authHeader.substring(7);
    
    const { validateSession, getUserSessions } = await import('../utils/sessionManager.js');
    const validation = validateSession(sessionToken, req);

    if (!validation.valid) {
      return res.json({
        sessionActive: false,
        reason: validation.reason,
        requiresAuth: true
      });
    }

    // Get all user sessions
    const allSessions = getUserSessions(validation.userId);

    res.json({
      sessionActive: true,
      currentSession: {
        deviceName: validation.deviceName,
        riskLevel: validation.riskLevel,
        limitedAccess: validation.limitedAccess || false,
        downgraded: validation.downgraded || false
      },
      user: {
        email: validation.email,
        totalActiveSessions: allSessions.length
      },
      allSessions
    });
  } catch (error) {
    console.error('Session status error:', error);
    res.status(500).json({ error: 'Failed to check session' });
  }
});

/**
 * Logout
 */
router.post('/logout', (req, res) => {
  const userId = req.session.userId;
  const email = req.session.email;
  const sessionToken = req.headers.authorization?.substring(7); // Get token from header

  if (userId) {
    logAuditEvent({
      userId,
      email,
      event: 'User Logout',
      details: 'User logged out',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
  }

  // 🔒 Invalidate session token
  if (sessionToken) {
    invalidateSession(sessionToken, 'USER_LOGOUT');
  }

  req.session.destroy();
  res.json({ success: true });
});

/**
 * Add Passkey to Existing Account - Generate Options
 */
router.post('/passkey/add-options', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }
    
    // Check if user exists
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Generate registration options for additional passkey
    const userIDBuffer = Buffer.from(email);
    
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: new Uint8Array(userIDBuffer),
      userName: user.username,
      userDisplayName: user.username,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        authenticatorAttachment: undefined // Allow any authenticator
      },
      // Exclude already registered credentials
      excludeCredentials: db.prepare('SELECT id FROM credentials WHERE user_id = ?')
        .all(user.id)
        .map(cred => ({
          id: cred.id,
          type: 'public-key'
        }))
    });
    
    // Store challenge
    challenges.set(`add-passkey-${email}`, options.challenge);
    
    logAuditEvent({
      userId: user.id,
      email,
      event: 'Add Passkey Started',
      details: 'User initiated adding new passkey to account',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.json(options);
  } catch (error) {
    console.error('Add passkey options error:', error);
    res.status(500).json({ error: 'Failed to generate options', details: error.message });
  }
});

/**
 * Add Passkey to Existing Account - Verify
 */
router.post('/passkey/add-verify', async (req, res) => {
  try {
    const { email, credential, deviceName } = req.body;
    
    const expectedChallenge = challenges.get(`add-passkey-${email}`);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Challenge not found' });
    }
    
    // Verify registration response
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID
    });
    
    if (!verification.verified) {
      logAuditEvent({
        email,
        event: 'Add Passkey Failed',
        details: 'Credential verification failed',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false
      });
      return res.status(400).json({ error: 'Verification failed' });
    }
    
    // Get user
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Store new credential
    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
    const credId = Buffer.from(credentialID).toString('base64url');
    
    console.log('💾 Storing additional credential ID:', credId);
    
    const transports = credential.response.transports || ['hybrid', 'internal'];
    
    db.prepare(`
      INSERT INTO credentials (id, user_id, public_key, counter, transports)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      credId,
      user.id,
      Buffer.from(credentialPublicKey).toString('base64'),
      counter,
      JSON.stringify(transports)
    );
    
    // Clean up challenge
    challenges.delete(`add-passkey-${email}`);
    
    logAuditEvent({
      userId: user.id,
      email,
      event: 'Passkey Added',
      details: `New passkey registered for ${deviceName || 'device'}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.json({ 
      success: true,
      message: 'Passkey added successfully'
    });
  } catch (error) {
    console.error('Add passkey verify error:', error);
    res.status(500).json({ error: 'Failed to add passkey' });
  }
});

/**
 * List User's Passkeys
 */
router.get('/passkeys/list', async (req, res) => {
  try {
    const sessionToken = req.headers.authorization?.replace('Bearer ', '');
    
    if (!sessionToken) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const { validateSession } = await import('../utils/sessionManager.js');
    const validation = validateSession(sessionToken, req);
    
    if (!validation.valid) {
      return res.status(401).json({ error: validation.reason || 'Session invalid' });
    }
    
    const passkeys = db.prepare(`
      SELECT id, created_at, transports
      FROM credentials
      WHERE user_id = ?
      ORDER BY created_at DESC
    `).all(validation.session.userId);
    
    res.json(passkeys);
  } catch (error) {
    console.error('List passkeys error:', error);
    res.status(500).json({ error: 'Failed to fetch passkeys' });
  }
});

/**
 * Delete Passkey
 */
router.post('/passkeys/delete', async (req, res) => {
  try {
    const { credentialId } = req.body;
    const sessionToken = req.headers.authorization?.replace('Bearer ', '');
    
    if (!sessionToken) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const { validateSession } = await import('../utils/sessionManager.js');
    const validation = validateSession(sessionToken, req);
    
    if (!validation.valid) {
      return res.status(401).json({ error: validation.reason || 'Session invalid' });
    }
    
    const userId = validation.session.userId;
    const email = validation.session.email;
    
    // Check if user has more than one passkey
    const count = db.prepare('SELECT COUNT(*) as count FROM credentials WHERE user_id = ?')
      .get(userId).count;
    
    if (count <= 1) {
      return res.status(400).json({ error: 'Cannot delete last passkey' });
    }
    
    // Delete credential
    db.prepare('DELETE FROM credentials WHERE id = ? AND user_id = ?')
      .run(credentialId, userId);
    
    logAuditEvent({
      userId,
      email,
      event: 'Passkey Deleted',
      details: `Passkey ${credentialId.substring(0, 16)}... was removed`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Delete passkey error:', error);
    res.status(500).json({ error: 'Failed to delete passkey' });
  }
});

/**
 * Step-Up Authentication - Request
 */
router.post('/stepup/request', async (req, res) => {
  try {
    const sessionToken = req.headers.authorization?.replace('Bearer ', '');
    
    if (!sessionToken) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const { validateSession } = await import('../utils/sessionManager.js');
    const validation = validateSession(sessionToken, req);
    
    if (!validation.valid) {
      return res.status(401).json({ error: validation.reason || 'Session invalid' });
    }
    
    const { action } = req.body;
    const email = validation.session.email;
    const userId = validation.session.userId;
    
    // Generate OTP for step-up authentication
    const otp = generateOTP(email);
    
    logAuditEvent({
      userId,
      email,
      event: 'Step-Up Auth Requested',
      details: `User requested step-up authentication for: ${action}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    console.log(`🔒 Step-up OTP for ${email}: ${otp}`);
    
    res.json({ success: true, message: 'OTP sent' });
  } catch (error) {
    console.error('Step-up request error:', error);
    res.status(500).json({ error: 'Failed to request step-up authentication' });
  }
});

/**
 * Step-Up Authentication - Verify
 */
router.post('/stepup/verify', async (req, res) => {
  try {
    const sessionToken = req.headers.authorization?.replace('Bearer ', '');
    
    if (!sessionToken) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const { validateSession } = await import('../utils/sessionManager.js');
    const validation = validateSession(sessionToken, req);
    
    if (!validation.valid) {
      return res.status(401).json({ error: validation.reason || 'Session invalid' });
    }
    
    const { otp, action } = req.body;
    const email = validation.session.email;
    const userId = validation.session.userId;
    
    // Verify OTP
    if (!verifyOTP(email, otp)) {
      logAuditEvent({
        userId,
        email,
        event: 'Step-Up Auth Failed',
        details: `Invalid OTP for action: ${action}`,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false
      });
      return res.status(400).json({ error: 'Invalid OTP' });
    }
    
    logAuditEvent({
      userId,
      email,
      event: 'Step-Up Auth Success',
      details: `Step-up authentication completed for: ${action}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.json({ success: true, message: 'Verification successful' });
  } catch (error) {
    console.error('Step-up verify error:', error);
    res.status(500).json({ error: 'Failed to verify step-up authentication' });
  }
});

export default router;
