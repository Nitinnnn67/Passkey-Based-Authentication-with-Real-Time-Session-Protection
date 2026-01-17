import geoip from 'geoip-lite';

/**
 * Calculate risk score based on multiple factors
 */
export function calculateRiskScore(factors) {
  let riskScore = 0;
  const reasons = [];

  // Device known check (40 points)
  if (!factors.deviceKnown) {
    riskScore += 40;
    reasons.push('Unknown device');
  } else if (factors.deviceTrustLevel < 50) {
    riskScore += 20;
    reasons.push('Low device trust level');
  }

  // Location check (30 points)
  if (factors.unusualLocation) {
    riskScore += 30;
    reasons.push('Unusual location');
  }

  // Time check (15 points)
  if (factors.unusualTime) {
    riskScore += 15;
    reasons.push('Unusual time of access');
  }

  // Recent failures (15 points)
  if (factors.recentFailures > 0) {
    riskScore += Math.min(15, factors.recentFailures * 5);
    reasons.push(`${factors.recentFailures} recent failed attempts`);
  }

  // Fallback usage check (20 points)
  if (factors.fallbackUsageCount > 3) {
    riskScore += 20;
    reasons.push('Excessive fallback usage');
  } else if (factors.fallbackUsageCount > 0) {
    riskScore += 10;
    reasons.push('Using fallback authentication');
  }

  // Multiple devices (10 points)
  if (factors.multipleDevices > 5) {
    riskScore += 10;
    reasons.push('Many devices registered');
  }

  return {
    score: Math.min(100, riskScore),
    level: getRiskLevel(riskScore),
    reasons,
    accessLevel: getAccessLevel(riskScore)
  };
}

function getRiskLevel(score) {
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function getAccessLevel(score) {
  if (score >= 70) return 'restricted';
  if (score >= 40) return 'limited-access';
  return 'full-access';
}

/**
 * Extract device fingerprint from request
 */
export function getDeviceFingerprint(req) {
  const userAgent = req.headers['user-agent'] || '';
  const acceptLanguage = req.headers['accept-language'] || '';
  const acceptEncoding = req.headers['accept-encoding'] || '';
  
  // Simple fingerprint (in production, use more sophisticated methods)
  return Buffer.from(`${userAgent}:${acceptLanguage}:${acceptEncoding}`).toString('base64');
}

/**
 * Get location from IP
 */
export function getLocation(ip) {
  // Remove IPv6 prefix if present
  const cleanIp = ip.replace('::ffff:', '');
  
  const geo = geoip.lookup(cleanIp);
  
  if (!geo) {
    return { country: 'Unknown', city: 'Unknown', coordinates: null };
  }
  
  return {
    country: geo.country,
    city: geo.city || 'Unknown',
    coordinates: geo.ll,
    timezone: geo.timezone
  };
}

/**
 * Check if current time is unusual for user
 */
export function isUnusualTime() {
  const hour = new Date().getHours();
  
  // Consider 2 AM - 6 AM as unusual (simplified)
  return hour >= 2 && hour < 6;
}

/**
 * Generate device name from user agent
 */
export function getDeviceName(userAgent) {
  if (userAgent.includes('iPhone')) return 'iPhone';
  if (userAgent.includes('iPad')) return 'iPad';
  if (userAgent.includes('Android')) return 'Android Device';
  if (userAgent.includes('Windows')) return 'Windows PC';
  if (userAgent.includes('Mac')) return 'Mac';
  if (userAgent.includes('Linux')) return 'Linux PC';
  return 'Unknown Device';
}

/**
 * Format risk assessment for audit log
 */
export function formatRiskAssessment(riskAnalysis) {
  return `Risk Level: ${riskAnalysis.level.toUpperCase()} (${riskAnalysis.score}/100) - ${riskAnalysis.reasons.join(', ') || 'No risk factors detected'}`;
}

/**
 * 🔒 Check if device supports passkeys (WebAuthn)
 * 
 * Passkey support detection based on browser/OS
 */
export function isPasskeyCapable(userAgent) {
  if (!userAgent) return false;
  
  const ua = userAgent.toLowerCase();
  
  // ✅ Modern browsers with passkey support
  
  // Chrome 108+ on any platform
  if (ua.includes('chrome/')) {
    const chromeVersion = parseInt(ua.match(/chrome\/(\d+)/)?.[1] || '0');
    if (chromeVersion >= 108) return true;
  }
  
  // Edge 108+ (Chromium-based)
  if (ua.includes('edg/')) {
    const edgeVersion = parseInt(ua.match(/edg\/(\d+)/)?.[1] || '0');
    if (edgeVersion >= 108) return true;
  }
  
  // Safari 16+ on macOS/iOS (has passkey support)
  if (ua.includes('safari/') && !ua.includes('chrome')) {
    if (ua.includes('version/')) {
      const safariVersion = parseInt(ua.match(/version\/(\d+)/)?.[1] || '0');
      if (safariVersion >= 16) return true;
    }
  }
  
  // Firefox 119+ (experimental, but supported)
  if (ua.includes('firefox/')) {
    const firefoxVersion = parseInt(ua.match(/firefox\/(\d+)/)?.[1] || '0');
    if (firefoxVersion >= 119) return true;
  }
  
  // ✅ Platform-based detection
  
  // iPhone/iPad on iOS 16+
  if (ua.includes('iphone') || ua.includes('ipad')) {
    // iOS 16+ has passkey support
    return true;
  }
  
  // macOS 13+ (Ventura) has passkey support
  if (ua.includes('macintosh') || ua.includes('mac os x')) {
    return true;
  }
  
  // Android 9+ with Chrome
  if (ua.includes('android') && ua.includes('chrome/')) {
    return true;
  }
  
  // Windows 10/11 with modern browser
  if (ua.includes('windows nt')) {
    const windowsVersion = parseFloat(ua.match(/windows nt ([\d.]+)/)?.[1] || '0');
    // Windows 10 (NT 10.0) and above
    if (windowsVersion >= 10.0) {
      // Check if modern browser is present
      if (ua.includes('chrome/') || ua.includes('edg/') || ua.includes('firefox/')) {
        return true;
      }
    }
  }
  
  // ❌ Old browsers / unsupported platforms
  return false;
}
