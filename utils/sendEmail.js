const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ── OTP Email (Signup Verification) ──────────────────────
async function sendOtpMail(toEmail, username, otp) {
  await transporter.sendMail({
    from: `"Shayari App" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: `${otp} — Shayari App Email Verify OTP`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;
                  padding:32px;border-radius:12px;border:1px solid #e0e0e0;">
        <h2 style="color:#2e7d32;margin-bottom:4px;">🌿 Shayari App</h2>
        <p>Hello <b>${username}</b>,</p>
        <p>To verify your email, use the OTP provided below:</p>
        <div style="font-size:36px;font-weight:bold;color:#2e7d32;letter-spacing:8px;
                    background:#f1f8e9;padding:20px;border-radius:10px;
                    text-align:center;margin:20px 0;">
          ${otp}
        </div>
        <p style="color:#e53935;font-weight:bold;">
          ⏰ This OTP is valid for only 10 minutes.
        </p>
        <p style="color:#777;font-size:13px;">
          If you haven't signed up, please ignore this email.
        </p>
      </div>
    `,
  });
}

// ── Password Reset Email ──────────────────────────────────
async function sendResetMail(toEmail, username, resetLink) {
  await transporter.sendMail({
    from: `"Shayari App" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: '🔐 Reset Your Password — Shayari App',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;
                  padding:32px;border-radius:12px;border:1px solid #e0e0e0;">
        <h2 style="color:#2e7d32;">🌿 Shayari App</h2>
        <p>Hello <b>${username}</b>,</p>
        <p>Reset your password by clicking on the button below.<br>
           This link will expire in <b>15 minutes</b>.</p>
        <a href="${resetLink}"
           style="display:inline-block;margin-top:16px;padding:14px 28px;
                  background:#2e7d32;color:#fff;border-radius:8px;
                  text-decoration:none;font-weight:bold;font-size:15px;">
          Reset Password
        </a>
        <p style="margin-top:20px;color:#777;font-size:12px;">
          If you didn't make the request, then ignore it.<br>
          Direct link: ${resetLink}
        </p>
      </div>
    `,
  });
}

// ── Username Reminder Email ───────────────────────────────
async function sendUsernameMail(toEmail, username) {
  await transporter.sendMail({
    from: `"Shayari App" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: '🔑 Your Shayari Username',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;
                  padding:32px;border-radius:12px;border:1px solid #e0e0e0;">
        <h2 style="color:#2e7d32;">🌿 Shayari App</h2>
        <p>Tumhara registered username:</p>
        <div style="font-size:24px;font-weight:bold;color:#2e7d32;letter-spacing:3px;
                    background:#f1f8e9;padding:16px;border-radius:8px;text-align:center;">
          ${username}
        </div>
        <p style="margin-top:20px;color:#777;font-size:13px;">
          Agar aapne request nahi ki toh ignore karo.
        </p>
      </div>
    `,
  });
}

module.exports = { sendOtpMail, sendResetMail, sendUsernameMail };
