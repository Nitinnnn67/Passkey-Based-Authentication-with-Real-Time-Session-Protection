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
  document.getElementById('viewDataBtn').addEventListener('click', () => showNotification('Data viewing access granted!', 'success'));
  document.getElementById('changeEmailBtn').addEventListener('click', () => handleSensitiveAction('change-email'));
  document.getElementById('exportDataBtn').addEventListener('click', () => handleSensitiveAction('export-data'));
  document.getElementById('viewLogsBtn').addEventListener('click', handleViewLogs);
  
  // Step-up modal
  document.getElementById('verifyStepUpBtn').addEventListener('click', handleStepUpVerify);
  document.getElementById('cancelStepUpBtn').addEventListener('click', hideStepUpModal);
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
  showScreen('otpScreen');
}

function showDashboard(userData, sessionData) {
  currentUser = userData;
  
  // Store session token
  if (sessionData && sessionData.token) {
    sessionToken = sessionData.token;
    addSessionEvent('✅ Session Created', `Token bound to ${sessionData.deviceBound ? 'device' : 'browser'}`, 'success');
  }
  
  document.getElementById('username').textContent = userData.username;
  
  // Display access level
  const accessLevel = userData.accessLevel || 'full-access';
  const accessBadge = document.getElementById('accessLevel');
  accessBadge.textContent = accessLevel.replace('-', ' ');
  accessBadge.className = `badge ${accessLevel}`;
  
  // Display risk info
  const riskInfo = document.getElementById('riskInfo');
  if (userData.riskScore !== undefined) {
    riskInfo.textContent = `Risk Score: ${userData.riskScore}/100 | Device: ${userData.deviceKnown ? 'Known' : 'Unknown'}`;
  }
  
  // 🔒 Initialize session monitoring
  initializeSessionMonitoring(sessionData);
  
  // Start periodic session checks
  startSessionMonitoring();
  
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
    showNotification('Starting passkey authentication...', 'success');
    
    // Get authentication options
    const optionsRes = await fetch(`${API_URL}/auth/login/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (!optionsRes.ok) {
      throw new Error('Failed to get login options');
    }
    
    const options = await optionsRes.json();
    
    // Start WebAuthn authentication
    const credential = await startAuthentication(options);
    
    // Verify authentication with server
    const verifyRes = await fetch(`${API_URL}/auth/login/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential })
    });
    
    if (!verifyRes.ok) {
      throw new Error('Authentication verification failed');
    }
    
    const result = await verifyRes.json();
    
    showNotification('✅ Login successful!', 'success');
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
    const res = await fetch(`${API_URL}/logs/audit`);
    
    if (!res.ok) {
      throw new Error('Failed to fetch logs');
    }
    
    const logs = await res.json();
    
    const logsContainer = document.getElementById('logsContainer');
    logsContainer.innerHTML = logs.map(log => `
      <div class="log-entry ${log.type}">
        <div class="timestamp">${new Date(log.timestamp).toLocaleString()}</div>
        <div><strong>${log.event}</strong></div>
        <div>${log.details}</div>
      </div>
    `).join('');
    
    document.getElementById('auditLogs').style.display = 'block';
    
  } catch (error) {
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
  if (!sessionData) return;
  
  // Update session status display
  updateSessionStatus({
    tokenStatus: 'Active',
    deviceBinding: 'Verified',
    riskLevel: sessionData.riskLevel || 'LOW',
    lastActivity: 'Just now'
  });
  
  // Initial session event
  addSessionEvent(
    '🔐 Session Initialized', 
    `Risk: ${sessionData.riskLevel}, Expires: ${sessionData.expiresIn}`,
    'success'
  );
  
  // Load active sessions
  loadActiveSessions();
}

/**
 * Update session status indicators
 */
function updateSessionStatus(status) {
  document.getElementById('sessionTokenStatus').textContent = status.tokenStatus;
  document.getElementById('deviceBindingStatus').textContent = status.deviceBinding;
  
  const riskElement = document.getElementById('riskLevelStatus');
  riskElement.textContent = status.riskLevel;
  riskElement.className = `stat-value badge-${status.riskLevel.toLowerCase()}`;
  
  document.getElementById('lastActivityStatus').textContent = status.lastActivity;
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
        riskLevel: data.currentSession.riskLevel,
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
  container.innerHTML = '';
  
  if (sessions.length === 0) {
    container.innerHTML = '<div class="sessions-empty">No active sessions</div>';
    return;
  }
  
  sessions.forEach((session, index) => {
    const isCurrent = index === 0; // Assume first is current
    
    const sessionItem = document.createElement('div');
    sessionItem.className = `session-item ${isCurrent ? 'current' : ''} ${session.riskLevel === 'HIGH' ? 'high-risk' : ''}`;
    
    sessionItem.innerHTML = `
      <div class="session-info-left">
        <div class="session-device">
          ${session.deviceName} ${isCurrent ? '(Current)' : ''}
        </div>
        <div class="session-details">
          ${session.browserInfo?.browser || 'Unknown'} on ${session.browserInfo?.os || 'Unknown'} • 
          Last active: ${session.lastActivity} • IP: ${session.ipAddress}
        </div>
      </div>
      <span class="session-badge ${session.riskLevel.toLowerCase()}">${session.riskLevel}</span>
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

