import nodemailer from 'nodemailer';
import crypto from 'crypto';
import db from '../database/db.js';

// Email transporter (configure with your SMTP settings)
let transporter;

try {
  transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.EMAIL_PORT) || 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
} catch (error) {
  console.warn('⚠️  Email transporter not configured. OTP emails will be logged to console.');
}

/**
 * Generate OTP
 */
export function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

/**
 * Store OTP in database
 */
export function storeOTP(email, otp, purpose = 'login', expiresInMinutes = 10) {
  const expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000).toISOString();
  
  const stmt = db.prepare(`
    INSERT INTO otps (email, otp, purpose, expires_at)
    VALUES (?, ?, ?, ?)
  `);

  stmt.run(email, otp, purpose, expiresAt);
}

/**
 * Verify OTP
 */
export function verifyOTP(email, otp, purpose = 'login') {
  const stmt = db.prepare(`
    SELECT * FROM otps
    WHERE email = ?
    AND otp = ?
    AND purpose = ?
    AND used = 0
    AND expires_at > datetime('now')
    ORDER BY created_at DESC
    LIMIT 1
  `);

  const otpRecord = stmt.get(email, otp, purpose);

  if (!otpRecord) {
    return { valid: false, reason: 'Invalid or expired OTP' };
  }

  // Mark as used
  const updateStmt = db.prepare('UPDATE otps SET used = 1 WHERE id = ?');
  updateStmt.run(otpRecord.id);

  return { valid: true, otpRecord };
}

/**
 * Send OTP email
 */
export async function sendOTPEmail(email, otp, purpose = 'login') {
  const subject = purpose === 'stepup' 
    ? '🔒 Verification Required' 
    : '🔑 Your Login OTP';
  
  const message = purpose === 'stepup'
    ? `Your verification code is: ${otp}\n\nThis code will expire in 10 minutes.\n\nIf you didn't request this, please secure your account immediately.`
    : `Your one-time password is: ${otp}\n\nThis code will expire in 10 minutes.\n\nIf you didn't request this, please ignore this email.`;

  try {
    if (!transporter || !process.env.EMAIL_USER) {
      // Fallback: log to console
      console.log(`\n📧 OTP Email (${purpose}):`);
      console.log(`To: ${email}`);
      console.log(`OTP: ${otp}`);
      console.log(`Expires in: 10 minutes\n`);
      return { success: true, fallback: true };
    }

    await transporter.sendMail({
      from: `"Passkey Auth System" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: subject,
      text: message,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #6366f1;">${subject}</h2>
          <p>Your verification code is:</p>
          <div style="background: #f1f5f9; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
            <h1 style="color: #1e293b; font-size: 32px; letter-spacing: 8px; margin: 0;">${otp}</h1>
          </div>
          <p>This code will expire in <strong>10 minutes</strong>.</p>
          <p style="color: #64748b; font-size: 14px;">If you didn't request this, please ignore this email.</p>
        </div>
      `
    });

    return { success: true };
  } catch (error) {
    console.error('Email send error:', error);
    // Fallback to console
    console.log(`\n📧 OTP Email (${purpose}) - Fallback:`);
    console.log(`To: ${email}`);
    console.log(`OTP: ${otp}\n`);
    return { success: true, fallback: true };
  }
}

/**
 * Clean expired OTPs
 */
export function cleanExpiredOTPs() {
  const stmt = db.prepare(`
    DELETE FROM otps
    WHERE expires_at < datetime('now')
    OR (used = 1 AND created_at < datetime('now', '-1 day'))
  `);

  const result = stmt.run();
  return result.changes;
}

// Run cleanup on module load and periodically
cleanExpiredOTPs();
setInterval(cleanExpiredOTPs, 60 * 60 * 1000); // Every hour
