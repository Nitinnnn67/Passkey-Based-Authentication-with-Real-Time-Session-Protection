# 🚀 Quick Start Guide

## Instant Setup (3 Steps)

### Step 1: Install Dependencies
```powershell
npm install
```

### Step 2: Initialize Database
```powershell
npm run init-db
```

### Step 3: Start the Application
```powershell
npm run dev
```

That's it! Open your browser to **http://localhost:5173**

---

## 🎯 Testing Checklist

### ✅ Test 1: Registration & Passkey Login
- [ ] Open http://localhost:5173
- [ ] Click "Create Account"
- [ ] Enter email: `demo@example.com`, username: `demo`
- [ ] Complete biometric verification (Face ID/Touch ID/Windows Hello)
- [ ] **Expected**: Registration successful, redirected to login
- [ ] Click "Login with Passkey"
- [ ] Complete biometric verification
- [ ] **Expected**: Logged in with "Full Access" badge
- [ ] **Screenshot**: Dashboard showing access level

### ✅ Test 2: Risk-Based Access
- [ ] Note the "Access Level" badge on dashboard
- [ ] Check "Risk Score" displayed (should be low for known device)
- [ ] **Expected**: Risk Score: ~20/100, Access Level: Full Access
- [ ] **Screenshot**: Access level and risk info

### ✅ Test 3: Step-Up Authentication
- [ ] Click "Change Email" button
- [ ] **Expected**: Verification modal appears
- [ ] Check PowerShell console for OTP code
- [ ] Copy the 6-digit OTP
- [ ] Enter OTP in modal
- [ ] **Expected**: Success message "Action completed"
- [ ] **Screenshot**: Step-up modal

### ✅ Test 4: OTP Fallback
- [ ] Logout from dashboard
- [ ] Click "Login with OTP (Fallback)"
- [ ] Enter email: `demo@example.com`
- [ ] **Expected**: Message "OTP sent to your email"
- [ ] Check PowerShell console for OTP
- [ ] Enter the 6-digit OTP
- [ ] **Expected**: Logged in (may have higher risk score)
- [ ] **Screenshot**: OTP login screen

### ✅ Test 5: Fallback Abuse Detection
- [ ] Logout
- [ ] Request OTP 6 times in a row
- [ ] **Expected**: After 5+ requests, system blocks with abuse warning
- [ ] **Screenshot**: Abuse detection message

### ✅ Test 6: Security Audit Logs
- [ ] From dashboard, click "Security Logs"
- [ ] **Expected**: List of all your activities:
  - Registration
  - Passkey logins
  - OTP requests
  - Step-up authentications
  - Risk assessments
- [ ] **Screenshot**: Audit log display

---

## 📸 Expected Console Output

### During OTP Login:
```
📧 OTP Email (login):
To: demo@example.com
OTP: 123456
Expires in: 10 minutes
```

### During Step-Up:
```
📧 OTP Email (stepup):
To: demo@example.com
OTP: 789012
Expires in: 10 minutes
```

---

## 🎬 Demo Flow (2 Minutes)

1. **Registration** (30 seconds)
   - Create account with passkey
   - Biometric verification

2. **Passkey Login** (30 seconds)
   - Login with biometric
   - View dashboard with risk score

3. **Step-Up Auth** (30 seconds)
   - Click sensitive action
   - Verify with OTP
   - Action completed

4. **View Logs** (30 seconds)
   - Click "Security Logs"
   - See all events tracked

---

## ⚡ Troubleshooting

### Issue: "Challenge not found"
**Fix**: Refresh the page and try again

### Issue: Biometric not prompting
**Fix**: Ensure you're using HTTPS or localhost (required for WebAuthn)

### Issue: OTP not showing
**Fix**: Check the PowerShell console where server is running

### Issue: "Credential not found"
**Fix**: Register first before attempting login

---

## 🎯 Success Indicators

✅ **Frontend Working**: Login screen loads with buttons  
✅ **Passkey Working**: Biometric prompt appears  
✅ **Risk System Working**: Access level badge shown  
✅ **Step-Up Working**: OTP modal appears for sensitive actions  
✅ **Fallback Working**: OTP code in console  
✅ **Logs Working**: Events displayed in logs section  

---

## 📊 What to Demonstrate

### Feature 1: Modern Authentication
Show the passkey login with biometric verification

### Feature 2: Intelligent Security
Show the risk score and access level determination

### Feature 3: Enhanced Protection
Show step-up authentication for sensitive actions

### Feature 4: Fallback Mechanism
Show OTP login when passkey unavailable

### Feature 5: Abuse Prevention
Show the system blocking excessive fallback usage

### Feature 6: Complete Audit Trail
Show comprehensive security logs

---

**Ready to impress? Let's go! 🚀**
