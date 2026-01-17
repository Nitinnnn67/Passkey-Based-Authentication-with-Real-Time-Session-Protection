# 🚀 Render Deployment Guide

Complete guide to deploy your Passkey Authentication System on Render.

## 📋 Prerequisites

1. **GitHub Account**: Your code needs to be in a GitHub repository
2. **Render Account**: Sign up at [render.com](https://render.com) (free tier available)
3. **Gmail Account**: For OTP email functionality (with App Password enabled)

---

## 🎯 Deployment Methods

### Method 1: Using Blueprint (render.yaml) - Recommended ✅

This is the easiest method as everything is pre-configured.

#### Step 1: Push Code to GitHub

```bash
# Initialize git (if not already done)
git init
git add .
git commit -m "Initial commit - Passkey Authentication System"

# Add your GitHub repository
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
git branch -M main
git push -u origin main
```

#### Step 2: Deploy on Render

1. **Login to Render**: Go to [dashboard.render.com](https://dashboard.render.com)

2. **Create New Blueprint**:
   - Click **"New +"** → **"Blueprint"**
   - Connect your GitHub repository
   - Select the repository with your authentication system
   - Render will detect `render.yaml` automatically

3. **Configure Environment Variables**:
   
   Render will prompt you to fill in these variables:
   
   ```bash
   # Required Variables
   RP_ID = your-app-name.onrender.com
   RP_NAME = Passkey Authentication System
   RP_ORIGIN = https://your-app-name.onrender.com
   
   # Email for OTP (Gmail)
   EMAIL_USER = your-email@gmail.com
   EMAIL_PASS = your-gmail-app-password
   
   # Auto-generated
   SESSION_SECRET = (Render generates this automatically)
   NODE_ENV = production (Already set in render.yaml)
   PORT = 10000 (Already set in render.yaml)
   ```

4. **Deploy**:
   - Click **"Apply"**
   - Wait 2-5 minutes for build and deployment
   - Your app will be live at `https://your-app-name.onrender.com`

---

### Method 2: Manual Web Service Creation

If you prefer manual setup:

#### Step 1: Create Web Service

1. Go to Render Dashboard
2. Click **"New +"** → **"Web Service"**
3. Connect GitHub repository
4. Configure:
   - **Name**: `passkey-auth-system`
   - **Region**: Singapore (or nearest to you)
   - **Branch**: `main`
   - **Runtime**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`

#### Step 2: Set Environment Variables

Go to **Environment** tab and add:

| Key | Value |
|-----|-------|
| `NODE_ENV` | `production` |
| `PORT` | `10000` |
| `RP_ID` | `your-app-name.onrender.com` |
| `RP_NAME` | `Passkey Authentication System` |
| `RP_ORIGIN` | `https://your-app-name.onrender.com` |
| `SESSION_SECRET` | (Use Render's "Generate" button) |
| `EMAIL_USER` | `your-email@gmail.com` |
| `EMAIL_PASS` | `your-gmail-app-password` |

---

## 🔐 Setting Up Gmail for OTP

Your app sends OTP emails, so you need Gmail App Password:

### Step 1: Enable 2-Factor Authentication
1. Go to [myaccount.google.com](https://myaccount.google.com)
2. Security → 2-Step Verification → Turn On

### Step 2: Generate App Password
1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Select **"Mail"** and **"Other (Custom name)"**
3. Enter **"Passkey Auth System"**
4. Click **"Generate"**
5. Copy the 16-character password (e.g., `abcd efgh ijkl mnop`)
6. Use this as `EMAIL_PASS` in Render environment variables

---

## ✅ Post-Deployment Checks

After deployment completes:

### 1. Check Health Endpoint
```bash
curl https://your-app-name.onrender.com/api/health
```

Should return:
```json
{
  "status": "healthy",
  "timestamp": "2026-01-17T12:00:00.000Z"
}
```

### 2. Test Frontend
- Open `https://your-app-name.onrender.com` in Chrome/Safari
- You should see the login page
- Try registering with a passkey

### 3. Verify Environment Variables
In Render Dashboard → Your Service → Environment:
- All variables should have green checkmarks
- `RP_ID` should match your Render URL (without https://)
- `RP_ORIGIN` should match your full URL (with https://)

---

## 🐛 Troubleshooting

### Issue 1: "Invalid RP ID" Error
**Problem**: Passkey registration fails with RP ID mismatch

**Solution**: 
- Check `RP_ID` = `your-app-name.onrender.com` (no https://, no trailing slash)
- Check `RP_ORIGIN` = `https://your-app-name.onrender.com` (with https://)
- Redeploy after fixing environment variables

### Issue 2: OTP Email Not Sending
**Problem**: Users don't receive OTP emails

**Solution**:
- Verify `EMAIL_USER` is correct Gmail address
- Verify `EMAIL_PASS` is the 16-character App Password (not your Gmail password)
- Check Render logs: Dashboard → Logs → Look for email errors

### Issue 3: "Service Unavailable" or 503 Error
**Problem**: App doesn't start

**Solution**:
- Check Render logs for errors
- Verify `npm start` command works locally
- Ensure all dependencies are in `package.json` (not just devDependencies)

### Issue 4: Static Files Not Loading
**Problem**: Blank page or 404 errors

**Solution**:
- Verify `client/` folder exists in repository
- Check `server/server.js` has static file serving code (already added)
- Ensure `NODE_ENV=production` is set in environment variables

### Issue 5: Free Tier Sleep Mode
**Problem**: App is slow on first load

**Explanation**: Render free tier apps sleep after 15 minutes of inactivity
- First request after sleep takes 30-60 seconds to wake up
- Subsequent requests are fast
- Upgrade to paid plan ($7/month) to prevent sleeping

---

## 📊 Monitoring Your App

### View Logs
Render Dashboard → Your Service → Logs
- Real-time logs
- Error tracking
- Request logs

### View Metrics
Render Dashboard → Your Service → Metrics
- CPU usage
- Memory usage
- Response times
- HTTP requests

### Set Up Alerts
Render Dashboard → Your Service → Settings → Notifications
- Email alerts for crashes
- Deployment status notifications

---

## 🔄 Updating Your Deployed App

After making code changes:

### Automatic Deployment (Recommended)
```bash
git add .
git commit -m "Your update message"
git push origin main
```
Render automatically detects the push and redeploys (takes 2-5 minutes)

### Manual Deployment
Render Dashboard → Your Service → Manual Deploy → **"Deploy latest commit"**

---

## 💾 Database Considerations

### Current Setup (JSON Files)
- ✅ Works fine for demos and small projects
- ✅ Data persists across deployments
- ⚠️ Not scalable for production
- ⚠️ No concurrent write support

### Production Recommendation
For real production apps, migrate to PostgreSQL:

1. **Add Render PostgreSQL** (free tier available):
   - Dashboard → New → PostgreSQL
   - Get connection string

2. **Update your code**:
   - Install: `npm install pg`
   - Replace `db.js` with PostgreSQL queries
   - Use `DATABASE_URL` environment variable

---

## 🌐 Custom Domain (Optional)

Want to use your own domain instead of `.onrender.com`?

1. **Buy Domain**: From Namecheap, GoDaddy, etc.
2. **Add to Render**: 
   - Dashboard → Your Service → Settings → Custom Domains
   - Add your domain (e.g., `auth.yourdomain.com`)
3. **Update DNS**:
   - Add CNAME record in your domain registrar
   - Point to Render's URL
4. **Update Environment Variables**:
   - `RP_ID` = `auth.yourdomain.com`
   - `RP_ORIGIN` = `https://auth.yourdomain.com`
5. **Redeploy**

---

## 📱 Testing on Mobile Devices

After deployment, test on different devices:

### iOS (iPhone/iPad)
- Open Safari (Chrome doesn't support passkeys on iOS)
- Go to your Render URL
- Test passkey registration
- Biometric authentication should work (Face ID/Touch ID)

### Android
- Open Chrome or Samsung Internet
- Go to your Render URL
- Test passkey registration
- Biometric authentication should work (Fingerprint/Face Unlock)

### Desktop
- Chrome 108+ ✅
- Edge 108+ ✅
- Safari 16+ ✅
- Firefox 119+ ✅

---

## 💰 Pricing

### Free Tier (Current)
- ✅ 750 hours/month (enough for 1 app running 24/7)
- ✅ Automatic HTTPS
- ✅ Custom domains
- ⚠️ Sleeps after 15 min inactivity
- ⚠️ 512 MB RAM
- ⚠️ Shared CPU

### Starter Plan ($7/month)
- ✅ No sleeping
- ✅ 1 GB RAM
- ✅ Shared CPU
- ✅ Better performance

### Standard Plan ($25/month)
- ✅ 4 GB RAM
- ✅ Dedicated CPU
- ✅ Priority support
- ✅ Production-ready

---

## 🎓 For Your Hackathon

### Live Demo URL
After deployment, you'll have:
```
https://your-app-name.onrender.com
```

### Judges Can Test:
1. Register with passkey (biometric auth)
2. See session monitoring dashboard
3. Test device fingerprinting (login from different browser)
4. View security logs
5. Experience real-time session protection

### Presentation Tips:
- **Show live deployment**: "This is running on Render's cloud"
- **Demo on phone**: "Works with Face ID/Touch ID"
- **Share URL**: Judges can test themselves
- **Show logs**: Real-time security monitoring

---

## 📞 Support

### Render Documentation
- [Render Docs](https://render.com/docs)
- [Node.js on Render](https://render.com/docs/deploy-node-express-app)

### Your App Issues
- Check [INTERVIEW_EXPLANATION_GUIDE.md](./INTERVIEW_EXPLANATION_GUIDE.md) for technical details
- Check [SESSION_PROTECTION_GUIDE.md](./SESSION_PROTECTION_GUIDE.md) for session management

---

## ✨ Quick Deployment Checklist

Before deploying, verify:

- [ ] Code pushed to GitHub
- [ ] `render.yaml` exists in repository root
- [ ] Gmail App Password generated
- [ ] Render account created
- [ ] Repository connected to Render
- [ ] Environment variables configured
- [ ] Deployment successful (check logs)
- [ ] Health endpoint returns 200 OK
- [ ] Frontend loads correctly
- [ ] Passkey registration works
- [ ] OTP emails sending (if on unsupported device)
- [ ] Session monitoring displays data

---

## 🎉 You're Live!

Once deployed, your authentication system is:
- ✅ Running 24/7 on Render's cloud
- ✅ Accessible from anywhere in the world
- ✅ Protected with automatic HTTPS
- ✅ Ready for hackathon demo
- ✅ Ready for live testing

**Your Live URL**: `https://your-app-name.onrender.com`

Share this URL with judges, team members, or anyone who wants to test your secure authentication system!

---

**Deployment Date**: January 17, 2026
**Team LEET**: Nitin, Ayush, Durgesh
**College**: Saket College of Science
