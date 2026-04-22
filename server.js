const express = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const crypto   = require('crypto');
require('dotenv').config();

const User    = require('./models/User');
const Shayari = require('./models/Shayari');
const { sendOtpMail, sendResetMail, sendUsernameMail } = require('./utils/sendEmail');

const app        = express();
const JWT_SECRET = process.env.JWT_SECRET || 'shayari_secret_key';

// ─── Middleware ───────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // HTML form ke liye

// ─── MongoDB ──────────────────────────────────────────────
const mongoose = require('mongoose');
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => { console.error('❌ MongoDB FAILED:', err.message); process.exit(1); });

// ─── Helpers ──────────────────────────────────────────────
const cleanUsername = (u) => u.trim().toLowerCase();
const cleanEmail    = (e) => e.trim().toLowerCase();

// Gmail check — sirf @gmail.com allowed
const isGmail = (email) => cleanEmail(email).endsWith('@gmail.com');

// 5 digit random OTP
const generateOtp = () => Math.floor(10000 + Math.random() * 90000).toString();

// ─── JWT Middleware ───────────────────────────────────────
function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Token nahi mila' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid ya expired token' });
  }
}

// ══════════════════════════════════════════════════════════
//  HEALTH CHECK
// ══════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.json({
    status: '✅ Server chal raha hai',
    db: mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected',
  });
});

// ══════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════

// ── POST /api/signup ──────────────────────────────────────
// Account banao → OTP bhejo → verify karo
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;
  console.log('📩 Signup:', username, email);

  if (!username || !email || !password)
    return res.status(400).json({ error: 'Username, Email aur Password teenon chahiye' });

  const u = cleanUsername(username);
  const e = cleanEmail(email);

  // ✅ Sirf Gmail allowed
  if (!isGmail(e))
    return res.status(400).json({ error: 'Only Gmail (@gmail.com) allowed' });

  if (u.length < 3)
    return res.status(400).json({ error: 'Username min 3 characters ka hona chahiye' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Password min 6 characters ka hona chahiye' });

  try {
    // Check karo pehle se exist karta hai
    const existUser  = await User.findOne({ username: u });
    if (existUser)
      return res.status(400).json({ error: 'Username Taken' });

    const existEmail = await User.findOne({ email: e });

    // Agar email hai lekin verify nahi — OTP dobara bhejo
    if (existEmail && !existEmail.isVerified) {
      const otp    = generateOtp();
      const expiry = new Date(Date.now() + 10 * 60 * 1000);
      existEmail.otp       = otp;
      existEmail.otpExpiry = expiry;
      existEmail.username  = u; // username update karo agar naya dala
      await existEmail.save();
      await sendOtpMail(e, u, otp);
      console.log('📧 OTP dobara bheja:', e, otp);
      return res.status(200).json({ message: 'Again OTP Sent!', requiresOtp: true, email: e });
    }

    if (existEmail)
      return res.status(400).json({ error: 'Email already registered' });

    // Naya user banao
    const hash = await bcrypt.hash(password, 10);
    const otp    = generateOtp();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);

    await User.create({
      username: u,
      email: e,
      password: hash,
      isVerified: false,
      otp,
      otpExpiry: expiry,
    });

    await sendOtpMail(e, u, otp);
    console.log('✅ User bana, OTP bheja:', u, otp);

    res.status(201).json({
      message: 'OTP sent! Check your Email.',
      requiresOtp: true,
      email: e,
    });
  } catch (err) {
    console.error('❌ Signup error:', err.message);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ── POST /api/verify-otp ──────────────────────────────────
// OTP verify karo → account activate karo
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  console.log('📩 OTP verify:', email, otp);

  if (!email || !otp)
    return res.status(400).json({ error: 'Email or OTP needed' });

  try {
    const user = await User.findOne({ email: cleanEmail(email) });

    if (!user)
      return res.status(404).json({ error: 'User not found' });

    if (user.isVerified)
      return res.status(400).json({ error: 'Email already verified' });

    if (!user.otp || !user.otpExpiry)
      return res.status(400).json({ error: 'Signup Again' });

    // OTP expire check
    if (new Date() > user.otpExpiry)
      return res.status(400).json({ error: 'OTP expired.' });

    // OTP match check
    if (user.otp !== otp.toString())
      return res.status(400).json({ error: 'OTP Wrong.' });

    // ✅ Verify karo
    user.isVerified = true;
    user.otp        = null;
    user.otpExpiry  = null;
    await user.save();

    console.log('✅ Email verified:', user.username);
    res.json({ message: 'Email verified! Please Sign In.' });
  } catch (err) {
    console.error('❌ OTP verify error:', err.message);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ── POST /api/resend-otp ──────────────────────────────────
// OTP dobara bhejo
app.post('/api/resend-otp', async (req, res) => {
  const { email } = req.body;

  if (!email)
    return res.status(400).json({ error: 'Email chahiye' });

  try {
    const user = await User.findOne({ email: cleanEmail(email) });

    if (!user)
      return res.status(404).json({ error: 'User nahi mila' });

    if (user.isVerified)
      return res.status(400).json({ error: 'Email pehle se verify hai' });

    const otp    = generateOtp();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);
    user.otp       = otp;
    user.otpExpiry = expiry;
    await user.save();

    await sendOtpMail(user.email, user.username, otp);
    console.log('📧 OTP resend:', user.email, otp);

    res.json({ message: 'Naya OTP bheja gaya!' });
  } catch (err) {
    console.error('❌ Resend OTP error:', err.message);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ── POST /api/signin ──────────────────────────────────────
// Username YA Email + Password
app.post('/api/signin', async (req, res) => {
  const { login, password } = req.body;
  console.log('📩 Signin:', login);

  if (!login || !password)
    return res.status(400).json({ error: 'Username/Email or Password needed' });

  const loginClean = login.trim().toLowerCase();

  try {
    const user = await User.findOne({
      $or: [{ email: loginClean }, { username: loginClean }],
    });

    if (!user)
      return res.status(400).json({ error: 'Username ya Email galat hai' });

    // ✅ Verify check
    if (!user.isVerified)
      return res.status(403).json({
        error: 'Email verify nahi hui hai',
        requiresOtp: true,
        email: user.email,
      });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ error: 'Password galat hai' });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('✅ Logged in:', user.username);
    res.json({ token, username: user.username, userId: user._id });
  } catch (err) {
    console.error('❌ Signin error:', err.message);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ── POST /api/forgot-password ─────────────────────────────
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email daalo' });

  try {
    const user = await User.findOne({ email: cleanEmail(email) });
    if (!user)
      return res.status(404).json({ error: 'Is email se koi account nahi mila' });

    if (!user.isVerified)
      return res.status(403).json({ error: 'Email verify nahi hui, pehle verify karo' });

    // Reset token banao
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetToken       = resetToken;
    user.resetTokenExpiry = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();

    const resetLink = `${process.env.APP_URL}/api/reset-password/${resetToken}`;
    await sendResetMail(user.email, user.username, resetLink);

    console.log('✅ Reset email bheja:', user.email);
    res.json({
      message: 'Password reset link email pe bhej di!',
      username: user.username,
    });
  } catch (err) {
    console.error('❌ Forgot password error:', err.message);
    res.status(500).json({ error: 'Email nahi bhej paya: ' + err.message });
  }
});

// ── GET /api/reset-password/:token ───────────────────────
// Email ke link se aane par HTML form dikhao
app.get('/api/reset-password/:token', async (req, res) => {
  const { token } = req.params;

  const user = await User.findOne({
    resetToken: token,
    resetTokenExpiry: { $gt: new Date() },
  });

  if (!user) {
    return res.send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:60px;background:#f9f9f9">
        <h2 style="color:#e53935">❌ Expire/Invalid Link</h2>
        <p>Try Again Forgot Password.</p>
      </body></html>
    `);
  }

  // ✅ Token ko form mein hidden field ki jagah URL se pass karo
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Reset Password — Shayari App</title>
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: sans-serif; background: #f1f8e9;
               display: flex; justify-content: center; align-items: center;
               min-height: 100vh; padding: 20px; }
        .card { background: white; padding: 40px; border-radius: 16px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                width: 100%; max-width: 400px; }
        h2 { color: #2e7d32; text-align: center; margin-bottom: 4px; }
        .sub { text-align: center; color: #555; margin-bottom: 24px; font-size: 14px; }
        label { display: block; font-weight: 600; margin-bottom: 6px; color: #333; }
        input { width: 100%; padding: 12px 14px; border: 1.5px solid #ccc;
                border-radius: 8px; font-size: 15px; margin-bottom: 16px;
                outline: none; transition: border 0.2s; }
        input:focus { border-color: #2e7d32; }
        button { width: 100%; padding: 14px; background: #2e7d32; color: white;
                 border: none; border-radius: 8px; font-size: 16px;
                 font-weight: bold; cursor: pointer; }
        button:disabled { background: #aaa; cursor: not-allowed; }
        #msg { text-align: center; margin-top: 14px; font-size: 14px; min-height: 20px; }
        .success { color: #2e7d32; font-weight: bold; font-size: 18px;
                   text-align: center; padding: 20px; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>🌿 Shayari App</h2>
        <p class="sub">Hello <b>${user.username}</b>, naya password set karo</p>

        <div id="formArea">
          <label>New Password</label>
          <input type="password" id="np" placeholder="Min 6 characters">

          <label>Confirm Password</label>
          <input type="password" id="cp" placeholder="Dobara daalo">

          <button id="btn" onclick="resetPass()">Reset Password</button>
          <p id="msg"></p>
        </div>
      </div>

      <script>
        async function resetPass() {
          const np  = document.getElementById('np').value;
          const cp  = document.getElementById('cp').value;
          const msg = document.getElementById('msg');
          const btn = document.getElementById('btn');

          msg.style.color = 'red';

          if (np.length < 6) { msg.textContent = 'Password min 6 characters ka hona chahiye'; return; }
          if (np !== cp)     { msg.textContent = 'Dono password match nahi kar rahe'; return; }

          btn.disabled    = true;
          btn.textContent = 'Resetting...';

          try {
            // ✅ Token URL se aata hai — body mein bhi bhejo
            const res = await fetch('/api/reset-password/${token}', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ newPassword: np })
              // token URL se server khud uthayega
            });
            const data = await res.json();

            if (res.ok) {
              document.getElementById('formArea').innerHTML =
                '<div class="success">✅ Password reset ho gaya!<br><br>App pe wapas jao aur Sign In karo.</div>';
            } else {
              msg.textContent = '❌ ' + data.error;
              btn.disabled    = false;
              btn.textContent = 'Reset Password';
            }
          } catch(e) {
            msg.textContent = '❌ Network error, dobara try karo';
            btn.disabled    = false;
            btn.textContent = 'Reset Password';
          }
        }
      </script>
    </body>
    </html>
  `);
});

// ── POST /api/reset-password/:token ──────────────────────
// ✅ FIX: token URL se aata hai body se nahi
app.post('/api/reset-password/:token', async (req, res) => {
  const { token }       = req.params;   // URL se token
  const { newPassword } = req.body;     // body se sirf password

  if (!newPassword)
    return res.status(400).json({ error: 'Naya password chahiye' });

  if (newPassword.length < 6)
    return res.status(400).json({ error: 'Password min 6 characters ka hona chahiye' });

  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: new Date() },
    });

    if (!user)
      return res.status(400).json({ error: 'Link expire/invalid. try again.' });

    user.password         = await bcrypt.hash(newPassword, 10);
    user.resetToken       = null;
    user.resetTokenExpiry = null;
    await user.save();

    console.log('✅ Password reset:', user.username);
    res.json({ message: 'Password reset ho gaya! Ab Sign In karo.' });
  } catch (err) {
    console.error('❌ Reset error:', err.message);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  SHAYARI ROUTES
// ══════════════════════════════════════════════════════════

app.get('/api/shayaris', async (req, res) => {
  try {
    const shayaris = await Shayari.find().populate('author', 'username').sort('-createdAt');
    res.json(shayaris);
  } catch (err) {
    res.status(500).json({ error: 'Shayaris not loaded' });
  }
});

app.get('/api/my-shayaris', verifyToken, async (req, res) => {
  try {
    const shayaris = await Shayari.find({ author: req.user.id }).sort('-createdAt');
    res.json(shayaris);
  } catch (err) {
    res.status(500).json({ error: 'Your Shayaris not loaded' });
  }
});

app.post('/api/shayaris', verifyToken, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim() === '')
    return res.status(400).json({ error: 'Please Enter Shayari' });
  try {
    const shayari  = await Shayari.create({ content: content.trim(), author: req.user.id });
    const populated = await shayari.populate('author', 'username');
    res.status(201).json(populated);
  } catch (err) {
    res.status(500).json({ error: 'Shayari post nahi ho paya' });
  }
});

app.put('/api/shayaris/:id', verifyToken, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim() === '')
    return res.status(400).json({ error: 'Please Enter Shayari' });
  try {
    const shayari = await Shayari.findOne({ _id: req.params.id, author: req.user.id });
    if (!shayari) return res.status(404).json({ error: 'Shayari Not found' });
    shayari.content = content.trim();
    await shayari.save();
    res.json({ message: 'Updated!', shayari });
  } catch (err) {
    res.status(500).json({ error: 'Not Updated' });
  }
});

app.delete('/api/shayaris/:id', verifyToken, async (req, res) => {
  try {
    const result = await Shayari.deleteOne({ _id: req.params.id, author: req.user.id });
    if (result.deletedCount === 0)
      return res.status(404).json({ error: 'Shayari Not found' });
    res.json({ message: 'Deleted Successfully ✅' });
  } catch (err) {
    res.status(500).json({ error: 'Not Deleted' });
  }
});

// ─── Server Start ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🔑 JWT_SECRET : ${!!process.env.JWT_SECRET}`);
  console.log(`🗄️  MONGO_URI  : ${!!process.env.MONGO_URI}`);
  console.log(`📧 EMAIL_USER : ${!!process.env.EMAIL_USER}`);
});
