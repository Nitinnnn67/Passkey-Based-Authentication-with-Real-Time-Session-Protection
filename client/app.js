import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

// State management
let currentUser = null;
let pendingAction = null;
let sessionToken = null; // Store session token
let sessionMonitorInterval = null; // For periodic checks

// API base URL
const API_URL = '/api';

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
  initializeEventListeners();
  checkPasskeySupport(); // Check if device supports passkeys
  checkSession();
});

// 🔒 Check passkey support and hide OTP button if supported
function checkPasskeySupport() {
  const isSupported = window.PublicKeyCredential !== undefined && 
                      navigator.credentials !== undefined;
  
  const otpLoginBtn = document.getElementById('otpLoginBtn');
  
  if (isSupported) {
    // Device supports passkeys - hide OTP button
    otpLoginBtn.style.display = 'none';
    console.log('✅ Passkey supported - OTP fallback disabled');
  } else {
    // Device doesn't support passkeys - show OTP as fallback
    otpLoginBtn.style.display = 'block';
    console.log('⚠️ Passkey not supported - OTP fallback enabled');
    
    // Show warning message
    const loginScreen = document.getElementById('loginScreen');
    const warning = document.createElement('div');
    warning.className = 'alert alert-warning';
    warning.style.marginTop = '10px';
    warning.innerHTML = '<strong>⚠️ Note:</strong> Your device/browser doesn\'t support passkeys. Using OTP fallback.';
    loginScreen.querySelector('.card-body').appendChild(warning);
  }
}

// Event listeners
function initializeEventListeners() {
  // Login screen
  document.getElementById('passkeyLoginBtn').addEventListener('click', handlePasskeyLogin);
  document.getElementById('otpLoginBtn').addEventListener('click', showOtpScreen);
  document.getElementById('registerBtn').addEventListener('click', showRegisterScreen);
  
  // Register screen
  document.getElementById('registerForm').addEventListener('submit', handleRegistration);
  document.getElementById('backToLoginBtn').addEventListener('click', showLoginScreen);
  
  // OTP screen
  document.getElementById('otpRequestForm').addEventListener('submit', handleOtpRequest);
  document.getElementById('verifyOtpBtn').addEventListener('click', handleOtpVerify);
  document.getElementById('backToLoginFromOtp').addEventListener('click', showLoginScreen);
  
  // Dashboard
  document.getElementById('logoutBtn').addEventListener('click', handleLogout);
  document.getElementById('addPasskeyBtn').addEventListener('click', handleAddPasskey);
  document.getElementById('managePasskeysBtn').addEventListener('click', handleManagePasskeys);
  document.getElementById('viewDataBtn').addEventListener('click', () => showNotification('Data viewing access granted!', 'success'));
  document.getElementById('changeEmailBtn').addEventListener('click', () => handleSensitiveAction('change-email'));
  document.getElementById('exportDataBtn').addEventListener('click', () => handleSensitiveAction('export-data'));
  document.getElementById('viewLogsBtn').addEventListener('click', handleViewLogs);
  
  // Step-up modal
  document.getElementById('verifyStepUpBtn').addEventListener('click', handleStepUpVerify);
  document.getElementById('cancelStepUpBtn').addEventListener('click', hideStepUpModal);
  
  // Passkeys modal
  document.getElementById('closePasskeysBtn').addEventListener('click', hidePasskeysModal);
}

// Screen navigation
function showScreen(screenId) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(screenId).classList.add('active');
}

function showLoginScreen() {
  showScreen('loginScreen');
}

function showRegisterScreen() {
  showScreen('registerScreen');
}

function showOtpScreen() {
  // Pre-fill email from login screen
  const loginEmail = document.getElementById('loginEmail').value;
  if (loginEmail) {
    document.getElementById('otpEmail').value = loginEmail;
  }
  showScreen('otpScreen');
}

function showDashboard(userData, sessionData) {
  currentUser = userData;
  
  // Store session token and initialize session data with defaults if missing
  if (sessionData && sessionData.token) {
    sessionToken = sessionData.token;
  }
  
  // Ensure session data has required fields
  if (sessionData && !sessionData.riskLevel) {
    sessionData.riskLevel = 'LOW';
  }
  if (sessionData && !sessionData.expiresIn) {
    sessionData.expiresIn = '24h';
  }
  if (sessionData && !sessionData.deviceBound) {
    sessionData.deviceBound = true;
  }
  
  document.getElementById('username').textContent = userData.username || 'User';
  
  // Display access level
  const accessLevel = userData.accessLevel || 'full-access';
  const accessBadge = document.getElementById('accessLevel');
  if (accessBadge) {
    accessBadge.textContent = accessLevel.replace('-', ' ');
    accessBadge.className = `badge ${accessLevel}`;
  }
  
  // Display risk info
  const riskInfo = document.getElementById('riskInfo');
  if (riskInfo && userData.riskScore !== undefined) {
    riskInfo.textContent = `Risk Score: ${userData.riskScore}/100 | Device: ${userData.deviceKnown ? 'Known' : 'Unknown'}`;
  }
  
  // Always initialize session monitoring - use defaults if no session data
  const finalSessionData = sessionData || {
    token: 'temp-session',
    riskLevel: 'MEDIUM',
    expiresIn: '24h',
    deviceBound: false
  };
  
  initializeSessionMonitoring(finalSessionData);
  
  // Start periodic session checks only if we have a real token
  if (sessionData && sessionData.token) {
    startSessionMonitoring();
  }
  
  showScreen('dashboardScreen');
}

// Passkey Registration
async function handleRegistration(e) {
  e.preventDefault();
  
  const email = document.getElementById('regEmail').value;
  const username = document.getElementById('regUsername').value;
  
  try {
    showNotification('Initiating passkey registration...', 'success');
    
    // Get registration options from server
    const optionsRes = await fetch(`${API_URL}/auth/register/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, username })
    });
    
    if (!optionsRes.ok) {
      throw new Error('Failed to get registration options');
    }
    
    const options = await optionsRes.json();
    
    // Start WebAuthn registration
    const credential = await startRegistration(options);
    
    // Verify registration with server
    const verifyRes = await fetch(`${API_URL}/auth/register/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, credential })
    });
    
    if (!verifyRes.ok) {
      throw new Error('Registration verification failed');
    }
    
    const result = await verifyRes.json();
    
    showNotification('✨ Registration successful! You can now login.', 'success');
    setTimeout(showLoginScreen, 2000);
    
  } catch (error) {
    console.error('Registration error:', error);
    showNotification(`Registration failed: ${error.message}`, 'error');
  }
}

// Passkey Login
async function handlePasskeyLogin() {
  try {
    const email = document.getElementById('loginEmail').value;
    
    if (!email) {
      showNotification('Please enter your email first', 'error');
      return;
    }
    
    showNotification('Starting passkey authentication...', 'success');
    
    // Get authentication options for this specific user
    const optionsRes = await fetch(`${API_URL}/auth/login/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    
    if (!optionsRes.ok) {
      const error = await optionsRes.json();
      throw new Error(error.message || error.error || 'Failed to get login options');
    }
    
    const options = await optionsRes.json();
    
    // Start WebAuthn authentication
    const credential = await startAuthentication(options);
    
    // Verify authentication with server
    const verifyRes = await fetch(`${API_URL}/auth/login/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential, email })
    });
    
    if (!verifyRes.ok) {
      throw new Error('Authentication verification failed');
    }
    
    const result = await verifyRes.json();
    
    // Show notification with session info
    const message = result.message || '✅ Login successful!';
    showNotification(message, 'success');
    showDashboard(result.user, result.session);
    
  } catch (error) {
    console.error('Login error:', error);
    showNotification(`Login failed: ${error.message}`, 'error');
  }
}

// OTP Fallback
async function handleOtpRequest(e) {
  e.preventDefault();
  
  const email = document.getElementById('otpEmail').value;
  
  try {
    const res = await fetch(`${API_URL}/auth/otp/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    
    if (!res.ok) {
      // Check if it's passkey-required error
      if (res.status === 403) {
        const errorData = await res.json();
        if (errorData.fallbackDisabled) {
          showNotification('🔒 ' + errorData.message, 'error');
          return;
        }
      }
      throw new Error('Failed to send OTP');
    }
    
    showNotification('📱 OTP sent to your email!', 'success');
    document.getElementById('otpVerifySection').style.display = 'block';
    
  } catch (error) {
    showNotification(`OTP request failed: ${error.message}`, 'error');
  }
}

async function handleOtpVerify() {
  const email = document.getElementById('otpEmail').value;
  const otp = document.getElementById('otpCode').value;
  
  if (!otp || otp.length !== 6) {
    showNotification('Please enter a valid 6-digit OTP', 'error');
    return;
  }
  
  try {
    const res = await fetch(`${API_URL}/auth/otp/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, otp })
    });
    
    if (!res.ok) {
      throw new Error('Invalid OTP');
    }
    
    const result = await res.json();
    
    showNotification('✅ OTP verified! Login successful.', 'success');
    showDashboard(result.user, result.session);
    
  } catch (error) {
    showNotification(`Verification failed: ${error.message}`, 'error');
  }
}

// Step-up Authentication
async function handleSensitiveAction(action) {
  pendingAction = action;
  
  try {
    const res = await fetch(`${API_URL}/auth/stepup/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action })
    });
    
    if (!res.ok) {
      throw new Error('Step-up request failed');
    }
    
    showNotification('🔒 Verification OTP sent to your email', 'warning');
    showStepUpModal();
    
  } catch (error) {
    showNotification(`Action failed: ${error.message}`, 'error');
  }
}

function showStepUpModal() {
  document.getElementById('stepUpModal').classList.add('active');
}

function hideStepUpModal() {
  document.getElementById('stepUpModal').classList.remove('active');
  document.getElementById('stepUpOtp').value = '';
  pendingAction = null;
}

async function handleStepUpVerify() {
  const otp = document.getElementById('stepUpOtp').value;
  
  if (!otp || otp.length !== 6) {
    showNotification('Please enter a valid 6-digit OTP', 'error');
    return;
  }
  
  try {
    const res = await fetch(`${API_URL}/auth/stepup/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ otp, action: pendingAction })
    });
    
    if (!res.ok) {
      throw new Error('Verification failed');
    }
    
    showNotification(`✅ Action "${pendingAction}" completed successfully!`, 'success');
    hideStepUpModal();
    
  } catch (error) {
    showNotification(`Verification failed: ${error.message}`, 'error');
  }
}

// Audit Logs
async function handleViewLogs() {
  try {
    const res = await fetch(`${API_URL}/logs/audit`, {
      credentials: 'include' // Include session cookie
    });
    
    if (!res.ok) {
      throw new Error('Failed to fetch logs');
    }
    
    const logs = await res.json();
    
    const logsContainer = document.getElementById('logsContainer');
    
    if (!logs || logs.length === 0) {
      logsContainer.innerHTML = '<div class="log-empty">No audit logs available</div>';
    } else {
      logsContainer.innerHTML = logs.map(log => {
        const timestamp = log.timestamp || log.created_at;
        const success = log.success !== undefined ? log.success : 1;
        const statusClass = success ? 'success' : 'error';
        
        return `
          <div class="log-entry ${statusClass}">
            <div class="log-header">
              <span class="log-event">${log.event || 'Event'}</span>
              <span class="timestamp">${timestamp ? new Date(timestamp).toLocaleString() : 'Unknown time'}</span>
            </div>
            <div class="log-details">${log.details || 'No details'}</div>
            ${log.ip_address ? `<div class="log-meta">IP: ${log.ip_address}</div>` : ''}
            ${log.risk_score !== undefined ? `<div class="log-meta">Risk Score: ${log.risk_score}</div>` : ''}
          </div>
        `;
      }).join('');
    }
    
    document.getElementById('auditLogs').style.display = 'block';
    
    // Scroll to logs
    document.getElementById('auditLogs').scrollIntoView({ behavior: 'smooth' });
    
  } catch (error) {
    console.error('Logs error:', error);
    showNotification(`Failed to load logs: ${error.message}`, 'error');
  }
}

// Session management
async function checkSession() {
  try {
    const res = await fetch(`${API_URL}/auth/session`);
    
    if (res.ok) {
      const data = await res.json();
      if (data.user) {
        showDashboard(data.user);
      }
    }
  } catch (error) {
    // No active session
  }
}

async function handleLogout() {
  try {
    // Stop session monitoring
    stopSessionMonitoring();
    
    const headers = sessionToken ? {
      'Authorization': `Bearer ${sessionToken}`
    } : {};
    
    await fetch(`${API_URL}/auth/logout`, { 
      method: 'POST',
      headers 
    });
    
    addSessionEvent('🔒 Session Ended', 'User logged out', 'info');
    
    currentUser = null;
    sessionToken = null;
    showNotification('Logged out successfully', 'success');
    showLoginScreen();
  } catch (error) {
    showNotification('Logout failed', 'error');
  }
}

// Notifications
function showNotification(message, type = 'success') {
  const notification = document.getElementById('notification');
  notification.textContent = message;
  notification.className = `notification ${type} show`;
  
  setTimeout(() => {
    notification.classList.remove('show');
  }, 3000);
}

// =======================================
// 🔒 SESSION MONITORING FUNCTIONS
// =======================================

/**
 * Initialize session monitoring display
 */
function initializeSessionMonitoring(sessionData) {
  if (!sessionData) {
    console.warn('No session data provided');
    sessionData = { riskLevel: 'MEDIUM', expiresIn: '24h', deviceBound: false };
  }
  
  // Clear any existing content
  const eventsContainer = document.getElementById('sessionEventsContainer');
  if (eventsContainer) {
    eventsContainer.innerHTML = '';
  }
  
  const sessionsContainer = document.getElementById('activeSessionsContainer');
  if (sessionsContainer) {
    sessionsContainer.innerHTML = '';
  }
  
  // Update session status display
  updateSessionStatus({
    tokenStatus: sessionData.token ? 'Active' : 'Local',
    deviceBinding: sessionData.deviceBound ? 'Verified' : 'Local Device',
    riskLevel: sessionData.riskLevel || 'LOW',
    lastActivity: 'Just now'
  });
  
  // Initial session event
  addSessionEvent(
    '🔐 Session Initialized', 
    `Risk: ${sessionData.riskLevel || 'LOW'}, Expires: ${sessionData.expiresIn || '24h'}`,
    'success'
  );
  
  // Add welcome event
  addSessionEvent(
    '✅ Login Successful',
    `Session created and device bound`,
    'success'
  );
  
  // Show current session info
  displayActiveSessions([{
    deviceName: navigator.platform || 'Current Device',
    browserInfo: {
      browser: getBrowserName(),
      os: getOSName()
    },
    lastActivity: 'Just now',
    ipAddress: 'Current session',
    riskLevel: sessionData.riskLevel || 'LOW'
  }]);
}

// Helper functions to get browser and OS info
function getBrowserName() {
  const ua = navigator.userAgent;
  if (ua.includes('Chrome')) return 'Chrome';
  if (ua.includes('Firefox')) return 'Firefox';
  if (ua.includes('Safari')) return 'Safari';
  if (ua.includes('Edge')) return 'Edge';
  return 'Browser';
}

function getOSName() {
  const ua = navigator.userAgent;
  if (ua.includes('Windows')) return 'Windows';
  if (ua.includes('Mac')) return 'macOS';
  if (ua.includes('Linux')) return 'Linux';
  if (ua.includes('Android')) return 'Android';
  if (ua.includes('iOS')) return 'iOS';
  return 'OS';
}

/**
 * Update session status indicators
 */
function updateSessionStatus(status) {
  // Add safety checks for undefined values
  if (!status) {
    console.warn('Status object is undefined');
    return;
  }
  
  document.getElementById('sessionTokenStatus').textContent = status.tokenStatus || 'Unknown';
  document.getElementById('deviceBindingStatus').textContent = status.deviceBinding || 'Unknown';
  
  const riskElement = document.getElementById('riskLevelStatus');
  const riskLevel = status.riskLevel || 'UNKNOWN';
  riskElement.textContent = riskLevel;
  riskElement.className = `stat-value badge-${riskLevel.toLowerCase()}`;
  
  document.getElementById('lastActivityStatus').textContent = status.lastActivity || 'Unknown';
  document.getElementById('lastActivityStatus').classList.add('updating');
  setTimeout(() => {
    document.getElementById('lastActivityStatus').classList.remove('updating');
  }, 1000);
}

/**
 * Add session event to real-time log
 */
function addSessionEvent(title, message, type = 'info') {
  const container = document.getElementById('sessionEventsContainer');
  
  if (!container) {
    console.warn('Session events container not found');
    return;
  }
  
  // Check if empty message exists
  const emptyMsg = container.querySelector('.events-empty');
  if (emptyMsg) emptyMsg.remove();
  
  const eventItem = document.createElement('div');
  eventItem.className = `event-item ${type}`;
  
  const now = new Date();
  const timeStr = now.toLocaleTimeString();
  
  eventItem.innerHTML = `
    <div class="event-message">${title}</div>
    <div style="font-size: 12px; color: var(--text-light); margin-top: 4px;">${message}</div>
    <span class="event-time">${timeStr}</span>
  `;
  
  // Add to top
  container.insertBefore(eventItem, container.firstChild);
  
  // Keep only last 10 events
  while (container.children.length > 10) {
    container.removeChild(container.lastChild);
  }
  
  // Show notification for important events
  if (type === 'danger' || type === 'warning') {
    showNotification(title, type === 'danger' ? 'error' : 'warning');
  }
}

/**
 * Load and display all active sessions
 */
async function loadActiveSessions() {
  if (!sessionToken) return;
  
  try {
    const res = await fetch(`${API_URL}/auth/session-status`, {
      headers: {
        'Authorization': `Bearer ${sessionToken}`
      }
    });
    
    if (!res.ok) {
      if (res.status === 401) {
        handleSessionExpired();
      }
      return;
    }
    
    const data = await res.json();
    displayActiveSessions(data.allSessions || [], data.currentSession);
    
    // Update session status from response
    if (data.currentSession) {
      updateSessionStatus({
        tokenStatus: 'Active',
        deviceBinding: 'Verified',
        riskLevel: data.currentSession.riskLevel || 'LOW',
        lastActivity: 'Just now'
      });
    }
    
  } catch (error) {
    console.error('Failed to load sessions:', error);
  }
}

/**
 * Display active sessions list
 */
function displayActiveSessions(sessions, currentSession) {
  const container = document.getElementById('activeSessionsContainer');
  
  if (!container) {
    console.warn('Active sessions container not found');
    return;
  }
  
  container.innerHTML = '';
  
  if (!sessions || sessions.length === 0) {
    container.innerHTML = '<div class="sessions-empty">Currently 1 active session (this device)</div>';
    return;
  }
  
  sessions.forEach((session, index) => {
    const isCurrent = index === 0; // Assume first is current
    const riskLevel = session.riskLevel || 'MEDIUM';
    
    const sessionItem = document.createElement('div');
    sessionItem.className = `session-item ${isCurrent ? 'current' : ''} ${riskLevel === 'HIGH' ? 'high-risk' : ''}`;
    
    const browserInfo = session.browserInfo || {};
    const browser = typeof browserInfo === 'string' ? JSON.parse(browserInfo) : browserInfo;
    
    sessionItem.innerHTML = `
      <div class="session-info-left">
        <div class="session-device">
          ${session.deviceName || 'Unknown Device'} ${isCurrent ? '(Current)' : ''}
        </div>
        <div class="session-details">
          ${browser.browser || 'Unknown'} on ${browser.os || 'Unknown'} • 
          Last active: ${session.lastActivity || 'Unknown'} • IP: ${session.ipAddress || 'Unknown'}
        </div>
      </div>
      <span class="session-badge ${riskLevel.toLowerCase()}">${riskLevel}</span>
    `;
    
    container.appendChild(sessionItem);
  });
}

/**
 * Start periodic session monitoring (every 10 seconds)
 */
function startSessionMonitoring() {
  // Clear any existing interval
  stopSessionMonitoring();
  
  addSessionEvent('📡 Monitoring Started', 'Session validation every 10 seconds', 'info');
  
  // Check immediately
  performSessionCheck();
  
  // Then check every 10 seconds
  sessionMonitorInterval = setInterval(performSessionCheck, 10000);
}

/**
 * Stop session monitoring
 */
function stopSessionMonitoring() {
  if (sessionMonitorInterval) {
    clearInterval(sessionMonitorInterval);
    sessionMonitorInterval = null;
  }
}

/**
 * Perform session validation check
 */
async function performSessionCheck() {
  if (!sessionToken) return;
  
  try {
    const res = await fetch(`${API_URL}/auth/session-status`, {
      headers: {
        'Authorization': `Bearer ${sessionToken}`
      }
    });
    
    if (!res.ok) {
      if (res.status === 401) {
        const errorData = await res.json();
        handleSessionError(errorData);
      }
      return;
    }
    
    const data = await res.json();
    
    // Update last activity time
    updateSessionStatus({
      tokenStatus: 'Active',
      deviceBinding: 'Verified',
      riskLevel: data.currentSession.riskLevel,
      lastActivity: 'Just now'
    });
    
    // Check for risk level changes
    if (data.currentSession.downgraded) {
      addSessionEvent(
        '⚠️ Session Downgraded',
        'Risk level increased - limited access',
        'warning'
      );
    }
    
    // Reload sessions list
    displayActiveSessions(data.allSessions || [], data.currentSession);
    
  } catch (error) {
    console.error('Session check failed:', error);
    addSessionEvent('❌ Check Failed', 'Network error - retrying...', 'danger');
  }
}

/**
 * Handle session errors (expired, invalid, etc.)
 */
function handleSessionError(errorData) {
  const reason = errorData.reason || 'UNKNOWN';
  
  let message = 'Session validation failed';
  let eventType = 'danger';
  
  switch(reason) {
    case 'SESSION_EXPIRED':
      message = '⏰ Session Expired';
      addSessionEvent(message, 'Please login again (24h expiry)', eventType);
      break;
    
    case 'DEVICE_MISMATCH':
      message = '🚨 Device Mismatch Detected';
      addSessionEvent(message, 'Token used from different device - security breach!', eventType);
      break;
    
    case 'SESSION_NOT_FOUND':
      message = '❌ Session Not Found';
      addSessionEvent(message, 'Session invalidated or never created', eventType);
      break;
    
    default:
      addSessionEvent('❌ Session Invalid', reason, eventType);
  }
  
  updateSessionStatus({
    tokenStatus: 'Invalid',
    deviceBinding: 'Failed',
    riskLevel: 'HIGH',
    lastActivity: 'Session ended'
  });
  
  // Show prominent notification
  showNotification(message + ' - Please login again', 'error');
  
  // Redirect to login after 3 seconds
  setTimeout(() => {
    stopSessionMonitoring();
    sessionToken = null;
    currentUser = null;
    showLoginScreen();
  }, 3000);
}

/**
 * Handle session expired specifically
 */
function handleSessionExpired() {
  handleSessionError({ reason: 'SESSION_EXPIRED' });
}

// =======================================
// 🔑 PASSKEY MANAGEMENT FUNCTIONS
// =======================================

/**
 * Add new passkey to current device
 */
async function handleAddPasskey() {
  if (!currentUser) {
    showNotification('Please login first', 'error');
    return;
  }
  
  try {
    showNotification('Starting passkey registration for this device...', 'success');
    
    // Get registration options for additional passkey
    const optionsRes = await fetch(`${API_URL}/auth/passkey/add-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ 
        email: currentUser.email,
        deviceName: `${getOSName()} - ${getBrowserName()}`
      })
    });
    
    if (!optionsRes.ok) {
      const error = await optionsRes.json();
      throw new Error(error.error || 'Failed to get registration options');
    }
    
    const options = await optionsRes.json();
    
    // Start WebAuthn registration
    const credential = await startRegistration(options);
    
    // Verify and store new passkey
    const verifyRes = await fetch(`${API_URL}/auth/passkey/add-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ 
        email: currentUser.email,
        credential,
        deviceName: `${getOSName()} - ${getBrowserName()}`
      })
    });
    
    if (!verifyRes.ok) {
      throw new Error('Failed to verify passkey');
    }
    
    showNotification('✅ Passkey added to this device! You can now use it to login.', 'success');
    
    // Add session event
    addSessionEvent(
      '🔑 New Passkey Added',
      `Passkey registered for ${getOSName()} - ${getBrowserName()}`,
      'success'
    );
    
  } catch (error) {
    console.error('Add passkey error:', error);
    showNotification(`Failed to add passkey: ${error.message}`, 'error');
  }
}

/**
 * Manage passkeys - view and delete
 */
async function handleManagePasskeys() {
  if (!currentUser) {
    showNotification('Please login first', 'error');
    return;
  }
  
  try {
    // Fetch user's passkeys
    const res = await fetch(`${API_URL}/auth/passkeys/list`, {
      credentials: 'include'
    });
    
    if (!res.ok) {
      throw new Error('Failed to fetch passkeys');
    }
    
    const passkeys = await res.json();
    
    const container = document.getElementById('passkeysListContainer');
    
    if (passkeys.length === 0) {
      container.innerHTML = '<p style="text-align: center; color: #999;">No passkeys registered</p>';
    } else {
      container.innerHTML = passkeys.map((pk, index) => `
        <div style="padding: 15px; border: 1px solid #ddd; border-radius: 8px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <div style="font-weight: bold; margin-bottom: 5px;">
              🔑 Passkey ${index + 1}
            </div>
            <div style="font-size: 13px; color: #666;">
              Added: ${new Date(pk.created_at).toLocaleDateString()}
            </div>
            <div style="font-size: 12px; color: #999; margin-top: 3px;">
              ID: ${pk.id.substring(0, 16)}...
            </div>
          </div>
          <button 
            onclick="deletePasskey('${pk.id}')" 
            class="btn btn-secondary"
            style="padding: 8px 16px; font-size: 13px;"
            ${passkeys.length === 1 ? 'disabled title="Cannot delete last passkey"' : ''}>
            Delete
          </button>
        </div>
      `).join('');
    }
    
    showPasskeysModal();
    
  } catch (error) {
    console.error('Manage passkeys error:', error);
    showNotification(`Failed to load passkeys: ${error.message}`, 'error');
  }
}

/**
 * Delete a passkey
 */
window.deletePasskey = async function(credentialId) {
  if (!confirm('Are you sure you want to delete this passkey? You won\'t be able to use it to login anymore.')) {
    return;
  }
  
  try {
    const res = await fetch(`${API_URL}/auth/passkeys/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ credentialId })
    });
    
    if (!res.ok) {
      throw new Error('Failed to delete passkey');
    }
    
    showNotification('✅ Passkey deleted successfully', 'success');
    hidePasskeysModal();
    
    // Add session event
    addSessionEvent(
      '🗑️ Passkey Removed',
      'A passkey was deleted from your account',
      'warning'
    );
    
  } catch (error) {
    console.error('Delete passkey error:', error);
    showNotification(`Failed to delete passkey: ${error.message}`, 'error');
  }
}

function showPasskeysModal() {
  document.getElementById('passkeysModal').classList.add('active');
}

function hidePasskeysModal() {
  document.getElementById('passkeysModal').classList.remove('active');
}

