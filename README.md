# 🔐 Passkey-Based Secure Authentication System

A comprehensive authentication system implementing WebAuthn (Passkeys), risk-based access control, step-up authentication, and security audit logging.

## 🎯 Features Implemented

### ✅ Step 1: Frontend Execution
- **Login Interface** with two authentication methods:
  - 🔑 Login with Passkey (Primary)
  - 📱 Login with OTP (Fallback)
- Beautiful, modern UI with gradient backgrounds
- Responsive design for all devices
- Real-time notifications and feedback

### ✅ Step 2: Passkey Authentication
- **WebAuthn Integration** using SimpleWebAuthn library
- Biometric authentication (fingerprint, face recognition)
- Device-based cryptographic verification
- Public key cryptography for secure authentication
- Platform authenticator support (Windows Hello, Touch ID, etc.)

### ✅ Step 3: Risk-Based Access Control
- **Intelligent Risk Assessment** based on:
  - Device recognition (known vs unknown)
  - Device trust level tracking
  - Location analysis
  - Time-of-day patterns
  - Recent failed attempts
  - Fallback usage frequency
- **Dynamic Access Levels**:
  - 🟢 **Full Access** (Risk Score: 0-39)
  - 🟡 **Limited Access** (Risk Score: 40-69)
  - 🔴 **Restricted** (Risk Score: 70-100)

### ✅ Step 4: Step-Up Authentication
- **Additional Verification** for sensitive actions:
  - Change Email
  - Export Data
  - Other high-risk operations
- OTP-based step-up challenge
- Time-limited verification codes (10 minutes)
- Audit trail for all step-up events

### ✅ Step 5: Fallback Abuse Detection
- **Intelligent Monitoring** of OTP usage:
  - Tracks fallback authentication frequency
  - Detects abuse patterns (>5 uses in 7 days)
  - Automatic alerts for excessive usage
  - Rate limiting on OTP requests
- **Security Actions**:
  - High severity: Account review required
  - Medium severity: Recommend passkey re-registration

### ✅ Step 6: Security Audit Logs
- **Comprehensive Logging** of all events:
  - Login successes/failures
  - Registration events
  - Risk assessments
  - Step-up authentication attempts
  - Fallback usage
  - Device changes
- **Log Details Include**:
  - Timestamp
  - User information
  - Event type
  - Risk scores
  - IP address and location
  - User agent
  - Success/failure status

## 🏗️ Project Structure

```
authentication-system/
├── client/                 # Frontend (Vite + Vanilla JS)
│   ├── index.html         # Main UI with all screens
│   ├── style.css          # Modern, responsive styling
│   └── app.js             # Frontend logic & WebAuthn
├── server/                # Backend (Express.js)
│   ├── database/
│   │   ├── db.js          # SQLite database setup
│   │   └── init.js        # Database initialization
│   ├── routes/
│   │   ├── auth.js        # Authentication endpoints
│   │   └── logs.js        # Audit log endpoints
│   ├── utils/
│   │   ├── riskAssessment.js  # Risk calculation
│   │   ├── auditLogger.js     # Security logging
│   │   └── otpService.js      # OTP generation/verification
│   └── server.js          # Express server setup
├── package.json
├── vite.config.js
├── .env
└── README.md
```

## 📊 Database Schema

### Tables Created:
1. **users** - User accounts
2. **credentials** - WebAuthn passkey credentials
3. **known_devices** - Device fingerprints and trust levels
4. **otps** - One-time passwords
5. **fallback_usage** - OTP usage tracking
6. **audit_logs** - Security event logs
7. **risk_events** - Risk assessment history

## 🚀 Getting Started

### Prerequisites
- Node.js (v18 or higher)
- Modern browser with WebAuthn support (Chrome, Edge, Safari, Firefox)

### Installation

1. **Install Dependencies**
```powershell
npm install
```

2. **Initialize Database**
```powershell
npm run init-db
```

3. **Configure Environment**
Edit `.env` file:
```env
PORT=3000
RP_NAME=Passkey Auth System
RP_ID=localhost
RP_ORIGIN=http://localhost:5173

# Optional: Configure email for OTP
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
```

### Running the Application

**Option 1: Run Everything Together**
```powershell
npm run dev
```

**Option 2: Run Separately**
```powershell
# Terminal 1 - Backend
npm run server

# Terminal 2 - Frontend
npm run client
```

### Access the Application
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:3000/api

## 🔄 User Flow

### Registration Flow
1. User clicks "Create Account"
2. Enters email and username
3. System prompts for biometric verification
4. Device creates cryptographic key pair
5. Public key stored on server
6. Device registered with trust level 100

### Passkey Login Flow
1. User clicks "Login with Passkey"
2. Device performs biometric verification
3. Cryptographic proof sent to server
4. Server verifies using stored public key
5. Risk assessment performed
6. Access level determined
7. User logged in with appropriate permissions

### OTP Fallback Flow
1. User clicks "Login with OTP"
2. Enters email address
3. System checks fallback abuse
4. OTP sent to email (6-digit code)
5. User enters OTP
6. Higher risk score applied
7. Fallback usage tracked

### Step-Up Authentication Flow
1. User attempts sensitive action
2. System requires additional verification
3. OTP sent to email
4. User verifies with OTP
5. Action authorized
6. Event logged

## 📈 Risk Scoring System

### Risk Factors & Points:
- **Unknown Device**: +40 points
- **Low Device Trust**: +20 points
- **Unusual Location**: +30 points
- **Unusual Time (2-6 AM)**: +15 points
- **Recent Failures**: +5 points per failure (max 15)
- **Excessive Fallback**: +20 points
- **Multiple Fallback**: +10 points
- **Many Devices**: +10 points

### Risk Levels:
- **Low Risk (0-39)**: Full access granted
- **Medium Risk (40-69)**: Limited access
- **High Risk (70-100)**: Restricted access

## 🔒 Security Features

### Passkey Security
✅ FIDO2/WebAuthn compliant  
✅ Phishing-resistant  
✅ No shared secrets  
✅ Cryptographic authentication  
✅ Device-bound credentials  

### Additional Security
✅ Rate limiting on OTP requests  
✅ Time-limited verification codes  
✅ Session management  
✅ Audit logging  
✅ Device fingerprinting  
✅ Abuse detection  

## 📱 Testing the System

### Test Scenario 1: New User Registration
1. Go to http://localhost:5173
2. Click "Create Account"
3. Enter email: `test@example.com`
4. Enter username: `testuser`
5. Complete biometric verification
6. ✅ Check: Registration logged in audit logs

### Test Scenario 2: Passkey Login
1. Click "Login with Passkey"
2. Complete biometric verification
3. ✅ Check: Access level shown (should be "Full Access")
4. ✅ Check: Risk score displayed
5. Click "Security Logs" to view audit trail

### Test Scenario 3: OTP Fallback
1. Click "Login with OTP (Fallback)"
2. Enter registered email
3. Check console for OTP (since email not configured)
4. Enter the 6-digit OTP
5. ✅ Check: Higher risk score due to fallback usage
6. ✅ Check: Fallback tracked in logs

### Test Scenario 4: Step-Up Authentication
1. Login successfully
2. Click "Change Email" or "Export Data"
3. System prompts for additional verification
4. Check console for step-up OTP
5. Enter OTP
6. ✅ Check: Action completed
7. ✅ Check: Step-up event in audit logs

### Test Scenario 5: Fallback Abuse Detection
1. Request OTP multiple times (6+ times)
2. ✅ Check: System blocks after threshold
3. ✅ Check: Abuse alert in audit logs
4. ✅ Check: Error message suggests passkey registration

## 📸 Execution Proof Points

### ✅ Proof 1: Login Screen
- Shows "Login with Passkey" button
- Shows "Login with OTP (Fallback)" button
- Modern gradient UI

### ✅ Proof 2: Passkey Authentication
- Browser prompts for biometric verification
- Console logs show WebAuthn flow
- Successful login response with user data

### ✅ Proof 3: Risk-Based Access
- Dashboard shows access level badge
- Risk score displayed (e.g., "Risk Score: 25/100")
- Device status shown (Known/Unknown)

### ✅ Proof 4: Step-Up Authentication
- Modal appears for sensitive actions
- OTP requirement shown
- Success message after verification

### ✅ Proof 5: Fallback Abuse Detection
- Counter increments with each fallback
- Alert shown after threshold
- Fallback usage tracked in database

### ✅ Proof 6: Security Audit Logs
- All events logged with timestamps
- Risk scores recorded
- Success/failure status indicated
- Color-coded log entries (green/yellow/red)

## 🛠️ API Endpoints

### Authentication
- `POST /api/auth/register/options` - Get registration options
- `POST /api/auth/register/verify` - Verify registration
- `POST /api/auth/login/options` - Get authentication options
- `POST /api/auth/login/verify` - Verify authentication
- `POST /api/auth/otp/request` - Request OTP
- `POST /api/auth/otp/verify` - Verify OTP
- `POST /api/auth/stepup/request` - Request step-up auth
- `POST /api/auth/stepup/verify` - Verify step-up auth
- `GET /api/auth/session` - Check session
- `POST /api/auth/logout` - Logout

### Logs
- `GET /api/logs/audit` - Get user's audit logs
- `GET /api/logs/audit/all` - Get all audit logs

## 🎨 UI Features

- **Modern Design**: Gradient backgrounds, smooth animations
- **Responsive**: Works on desktop, tablet, mobile
- **Interactive**: Real-time notifications and feedback
- **Accessible**: Clear labels and keyboard navigation
- **Visual Feedback**: Color-coded badges and status indicators

## 🔍 Monitoring & Analytics

The system tracks:
- Login success/failure rates
- Risk score distribution
- Fallback usage trends
- Device trust levels over time
- Geographic access patterns
- Step-up authentication frequency

## 📝 Notes

### Email Configuration (Optional)
If you want actual emails instead of console logs:
1. Get Gmail App Password (for Gmail users)
2. Update `.env` with your credentials
3. Restart the server

### Production Deployment
For production:
1. Use HTTPS (required for WebAuthn)
2. Update `RP_ID` to your domain
3. Use secure session storage (Redis)
4. Enable proper CORS configuration
5. Use environment-specific secrets
6. Configure proper email service

## 🎯 Success Criteria Met

✅ **Step 1**: Frontend with login options  
✅ **Step 2**: Passkey authentication working  
✅ **Step 3**: Risk-based access control implemented  
✅ **Step 4**: Step-up authentication functional  
✅ **Step 5**: Fallback abuse detection active  
✅ **Step 6**: Security audit logs comprehensive  

## 🚀 Next Steps

To test the complete system:
1. Run `npm install`
2. Run `npm run init-db`
3. Run `npm run dev`
4. Open http://localhost:5173
5. Create account and test all features!

## 📞 Support

For issues or questions:
- Check console logs for detailed error messages
- Review audit logs for security events
- Verify `.env` configuration
- Ensure modern browser with WebAuthn support

---

**Built with ❤️ using WebAuthn, Express.js, and Vanilla JavaScript**
#   P a s s k e y - B a s e d - A u t h e n t i c a t i o n - w i t h - R e a l - T i m e - S e s s i o n - P r o t e c t i o n  
 