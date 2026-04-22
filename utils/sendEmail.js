const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,   // Gmail App Password
  },
});

// Username reminder email
async function sendUsernameMail(toEmail, username) {
  await transporter.sendMail({
    from: `"Shayari App" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: '🔑 Your Shayari Username',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px;
                  border-radius:12px;border:1px solid #e0e0e0;">
        <h2 style="color:#2e7d32;">Shayari App 🌿</h2>
        <p>Your registered username is:</p>
        <div style="font-size:24px;font-weight:bold;color:#2e7d32;
                    background:#f1f8e9;padding:16px;border-radius:8px;
                    text-align:center;letter-spacing:2px;">
          ${username}
        </div>
        <p style="margin-top:24px;color:#777;font-size:13px;">
          If you did not request this, please ignore this email.
        </p>
      </div>
    `,
  });
}

// Password reset email
async function sendResetMail(toEmail, username, resetLink) {
  await transporter.sendMail({
    from: `"Shayari App" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: '🔐 Reset Your Password — Shayari App',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px;
                  border-radius:12px;border:1px solid #e0e0e0;">
        <h2 style="color:#2e7d32;">Shayari App 🌿</h2>
        <p>Hello <b>${username}</b>,</p>
        <p>Click the button below to reset your password.<br>
           This link will expire in <b>15 minutes</b>.</p>
        <a href="${resetLink}"
           style="display:inline-block;margin-top:16px;padding:14px 28px;
                  background:#2e7d32;color:#fff;border-radius:8px;
                  text-decoration:none;font-weight:bold;font-size:15px;">
          Reset Password
        </a>
        <p style="margin-top:24px;color:#777;font-size:13px;">
          If you did not request this, please ignore this email.<br>
          Link: ${resetLink}
        </p>
      </div>
    `,
  });
}

module.exports = { sendUsernameMail, sendResetMail };
