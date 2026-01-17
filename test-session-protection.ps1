# 🧪 Session Protection Test Script

# ========================================
# Setup
# ========================================
$BASE_URL = "http://localhost:3000/api/auth"
$Headers = @{
    "Content-Type" = "application/json"
}

Write-Host "`n🔒 SESSION PROTECTION TESTING`n" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

# ========================================
# Test 1: Login & Session Creation
# ========================================
Write-Host "`n📋 Test 1: Login & Session Creation" -ForegroundColor Yellow
Write-Host "-" * 50 -ForegroundColor Gray

$loginBody = @{
    credential = @{
        rawId = "your_credential_id"
        # Add proper credential structure
    }
} | ConvertTo-Json

Write-Host "→ Logging in to create session..." -ForegroundColor White
# Uncomment when ready to test:
# $loginResponse = Invoke-RestMethod -Uri "$BASE_URL/login/verify" -Method POST -Headers $Headers -Body $loginBody
# $sessionToken = $loginResponse.session.token
# Write-Host "✅ Session created: $($loginResponse.session.riskLevel) risk" -ForegroundColor Green
# Write-Host "   Token: $($sessionToken.Substring(0,16))..." -ForegroundColor Gray

# For demo purposes (replace with actual token):
$sessionToken = "demo_token_abc123_replace_with_real"

# ========================================
# Test 2: Protected Route Access
# ========================================
Write-Host "`n📋 Test 2: Protected Route Access" -ForegroundColor Yellow
Write-Host "-" * 50 -ForegroundColor Gray

$authHeaders = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer $sessionToken"
}

Write-Host "→ Accessing /profile with session token..." -ForegroundColor White
try {
    $profileResponse = Invoke-RestMethod -Uri "$BASE_URL/profile" -Method GET -Headers $authHeaders
    Write-Host "✅ Profile accessed successfully" -ForegroundColor Green
    Write-Host "   User: $($profileResponse.user.email)" -ForegroundColor Gray
    Write-Host "   Device: $($profileResponse.session.deviceName)" -ForegroundColor Gray
    Write-Host "   Risk: $($profileResponse.session.riskLevel)" -ForegroundColor Gray
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    Write-Host "❌ Access denied: Status $statusCode" -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        $errorData = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Host "   Reason: $($errorData.reason)" -ForegroundColor Red
    }
}

# ========================================
# Test 3: Session Status Check
# ========================================
Write-Host "`n📋 Test 3: Session Status Check" -ForegroundColor Yellow
Write-Host "-" * 50 -ForegroundColor Gray

Write-Host "→ Checking session status..." -ForegroundColor White
try {
    $statusResponse = Invoke-RestMethod -Uri "$BASE_URL/session-status" -Method GET -Headers $authHeaders
    Write-Host "✅ Session active" -ForegroundColor Green
    Write-Host "   Device: $($statusResponse.currentSession.deviceName)" -ForegroundColor Gray
    Write-Host "   Risk Level: $($statusResponse.currentSession.riskLevel)" -ForegroundColor Gray
    Write-Host "   Limited Access: $($statusResponse.currentSession.limitedAccess)" -ForegroundColor Gray
    Write-Host "   Total Sessions: $($statusResponse.user.totalActiveSessions)" -ForegroundColor Gray
    
    if ($statusResponse.allSessions.Count -gt 0) {
        Write-Host "`n   All Active Sessions:" -ForegroundColor Cyan
        foreach ($session in $statusResponse.allSessions) {
            Write-Host "   - $($session.deviceName) | Risk: $($session.riskLevel) | Last: $($session.lastActivity)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "❌ Session check failed" -ForegroundColor Red
}

# ========================================
# Test 4: Sensitive Action (with rotation)
# ========================================
Write-Host "`n📋 Test 4: Sensitive Action + Session Rotation" -ForegroundColor Yellow
Write-Host "-" * 50 -ForegroundColor Gray

Write-Host "→ Performing sensitive action..." -ForegroundColor White
try {
    $actionResponse = Invoke-RestMethod -Uri "$BASE_URL/sensitive-action" -Method POST -Headers $authHeaders -Body "{}"
    Write-Host "✅ Action completed successfully" -ForegroundColor Green
    Write-Host "   Message: $($actionResponse.message)" -ForegroundColor Gray
    
    if ($actionResponse.newSessionToken) {
        Write-Host "`n🔄 Session rotated!" -ForegroundColor Cyan
        Write-Host "   Old token invalidated" -ForegroundColor Gray
        Write-Host "   New token: $($actionResponse.newSessionToken.Substring(0,16))..." -ForegroundColor Gray
        $sessionToken = $actionResponse.newSessionToken
    }
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    Write-Host "❌ Action blocked: Status $statusCode" -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        $errorData = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Host "   Reason: $($errorData.error)" -ForegroundColor Red
        Write-Host "   Risk Level: $($errorData.riskLevel)" -ForegroundColor Red
        if ($errorData.suggestReAuth) {
            Write-Host "   💡 Suggest re-authentication" -ForegroundColor Yellow
        }
    }
}

# ========================================
# Test 5: Old Token Validation (Should Fail)
# ========================================
if ($actionResponse -and $actionResponse.newSessionToken) {
    Write-Host "`n📋 Test 5: Old Token Validation (Should Fail)" -ForegroundColor Yellow
    Write-Host "-" * 50 -ForegroundColor Gray
    
    $oldAuthHeaders = @{
        "Content-Type" = "application/json"
        "Authorization" = "Bearer demo_token_abc123_replace_with_real"
    }
    
    Write-Host "→ Trying to use old token after rotation..." -ForegroundColor White
    try {
        $oldTokenResponse = Invoke-RestMethod -Uri "$BASE_URL/profile" -Method GET -Headers $oldAuthHeaders
        Write-Host "⚠️  SECURITY ISSUE: Old token still works!" -ForegroundColor Red
    } catch {
        Write-Host "✅ Old token correctly rejected" -ForegroundColor Green
        if ($_.ErrorDetails.Message) {
            $errorData = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Host "   Reason: $($errorData.reason)" -ForegroundColor Gray
        }
    }
}

# ========================================
# Test 6: No Token (Should Fail)
# ========================================
Write-Host "`n📋 Test 6: Access Without Token (Should Fail)" -ForegroundColor Yellow
Write-Host "-" * 50 -ForegroundColor Gray

Write-Host "→ Trying to access protected route without token..." -ForegroundColor White
try {
    $noTokenResponse = Invoke-RestMethod -Uri "$BASE_URL/profile" -Method GET -Headers $Headers
    Write-Host "⚠️  SECURITY ISSUE: Access granted without token!" -ForegroundColor Red
} catch {
    Write-Host "✅ Access correctly denied without token" -ForegroundColor Green
}

# ========================================
# Summary
# ========================================
Write-Host "`n" + ("=" * 50) -ForegroundColor Gray
Write-Host "🎯 TEST SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 50) -ForegroundColor Gray

Write-Host "`n✅ Expected Results:" -ForegroundColor Green
Write-Host "   - Sessions created with device binding" -ForegroundColor White
Write-Host "   - Protected routes require valid session token" -ForegroundColor White
Write-Host "   - Session status shows device and risk info" -ForegroundColor White
Write-Host "   - Sensitive actions trigger session rotation" -ForegroundColor White
Write-Host "   - Old tokens rejected after rotation" -ForegroundColor White
Write-Host "   - Requests without tokens denied" -ForegroundColor White

Write-Host "`n📸 Screenshot Points:" -ForegroundColor Yellow
Write-Host "   1. Session creation response with token + risk level" -ForegroundColor White
Write-Host "   2. Protected route success with session info" -ForegroundColor White
Write-Host "   3. Session status showing multiple sessions" -ForegroundColor White
Write-Host "   4. Sensitive action with session rotation" -ForegroundColor White
Write-Host "   5. Old token rejection" -ForegroundColor White
Write-Host "   6. Device mismatch error (test from different device)" -ForegroundColor White

Write-Host "`n🔍 For Device Mismatch Test:" -ForegroundColor Cyan
Write-Host "   Run this script from a DIFFERENT device/browser" -ForegroundColor White
Write-Host "   Use the same session token" -ForegroundColor White
Write-Host "   → Should see: 'DEVICE_MISMATCH' error" -ForegroundColor White

Write-Host "`n" + ("=" * 50) + "`n" -ForegroundColor Gray
