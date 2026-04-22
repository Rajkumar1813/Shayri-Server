const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const dns = require("dns");

dns.setServers([
  '1.1.1.1',
  '8.8.8.8'
]);
require('dotenv').config();



const User = require('./models/User');
const Shayari = require('./models/Shayari');
const { sendUsernameMail, sendResetMail } = require('./utils/sendEmail');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'shayari_secret_key';

// ─── Middleware ───────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ─── MongoDB ──────────────────────────────────────────────
const mongoose = require('mongoose');
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB FAILED:', err.message);
    process.exit(1);
  });

// ─── Helpers ──────────────────────────────────────────────
const cleanUsername = (u) => u.trim().toLowerCase();
const cleanEmail    = (e) => e.trim().toLowerCase();

// ─── JWT Middleware ───────────────────────────────────────
function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Token nahi mila' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid ya expired token' });
  }
}

// ══════════════════════════════════════════════════════════
//  HEALTH CHECK
// ══════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.json({
    status: '✅ Server chal raha hai',
    db: mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected'
  });
});

// ══════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════

// ── POST /api/signup ──────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password)
    return res.status(400).json({ error: 'Username, Email aur Password teenon chahiye' });

  const u = cleanUsername(username);
  const e = cleanEmail(email);

  if (u.length < 3)
    return res.status(400).json({ error: 'Username min 3 characters ka hona chahiye' });

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e))
    return res.status(400).json({ error: 'Valid email address daalo' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Password min 6 characters ka hona chahiye' });

  try {
    const existingUser = await User.findOne({ username: u });
    if (existingUser)
      return res.status(400).json({ error: 'Ye username already le liya gaya hai' });

    const existingEmail = await User.findOne({ email: e });
    if (existingEmail)
      return res.status(400).json({ error: 'Ye email already registered hai' });

    const hash = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username: u, email: e, password: hash });
    console.log('✅ New user:', newUser.username);

    res.status(201).json({ message: 'Account ban gaya! Ab Sign In karo.' });
  } catch (err) {
    console.error('❌ Signup error:', err.message);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ── POST /api/signin ──────────────────────────────────────
// Username YA Email dono se login ho sakta hai
app.post('/api/signin', async (req, res) => {
  const { login, password } = req.body;
  // login field mein username ya email dono accept karo

  if (!login || !password)
    return res.status(400).json({ error: 'Username/Email aur Password chahiye' });

  const loginClean = login.trim().toLowerCase();

  try {
    // Pehle email se dhundo, phir username se
    const user = await User.findOne({
      $or: [{ email: loginClean }, { username: loginClean }]
    });

    if (!user)
      return res.status(400).json({ error: 'Username ya Email galat hai' });

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
// Email daalo → username show karo + reset link bhejo
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email)
    return res.status(400).json({ error: 'Email daalo' });

  const e = cleanEmail(email);

  try {
    const user = await User.findOne({ email: e });

    // Security: chahe user mile ya na mile, same message dikhao
    // Lekin Flutter mein username bhi dikhana hai, isliye yahan bhejte hain
    if (!user)
      return res.status(404).json({ error: 'Is email se koi account nahi mila' });

    // Reset token banao (random 32 bytes)
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    user.resetToken = resetToken;
    user.resetTokenExpiry = expiry;
    await user.save();

    const resetLink = `${process.env.APP_URL}/api/reset-password/${resetToken}`;

    // Email bhejo
    await sendResetMail(user.email, user.username, resetLink);

    console.log('✅ Reset email bheja:', user.email);

    // Flutter ko username bhi bhejo taaki screen pe show kar sake
    res.json({
      message: 'Reset link email pe bhej diya!',
      username: user.username,   // ← Flutter isko screen pe dikhayega
    });
  } catch (err) {
    console.error('❌ Forgot password error:', err.message);
    res.status(500).json({ error: 'Email nahi bhej paya: ' + err.message });
  }
});

// ── POST /api/reset-password ──────────────────────────────
// Naya password set karo token se
app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword)
    return res.status(400).json({ error: 'Token aur naya password chahiye' });

  if (newPassword.length < 6)
    return res.status(400).json({ error: 'Password min 6 characters ka hona chahiye' });

  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: new Date() }, // expire nahi hona chahiye
    });

    if (!user)
      return res.status(400).json({ error: 'Link invalid ya expire ho gayi. Dobara try karo.' });

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    console.log('✅ Password reset:', user.username);
    res.json({ message: 'Password reset ho gaya! Ab sign in karo.' });
  } catch (err) {
    console.error('❌ Reset password error:', err.message);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ── GET /api/reset-password/:token (Web browser ke liye) ──
// Email ka link click karne par ye page khulega
app.get('/api/reset-password/:token', async (req, res) => {
  const { token } = req.params;

  const user = await User.findOne({
    resetToken: token,
    resetTokenExpiry: { $gt: new Date() },
  });

  if (!user) {
    return res.send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:60px">
        <h2 style="color:red">❌ Link Invalid ya Expire Ho Gayi</h2>
        <p>App se dobara forgot password try karo.</p>
      </body></html>
    `);
  }

  // Simple HTML form dikhao
  res.send(`
    <html>
    <head><title>Reset Password - Shayari App</title></head>
    <body style="font-family:sans-serif;display:flex;justify-content:center;
                 align-items:center;min-height:100vh;margin:0;background:#f1f8e9;">
      <div style="background:white;padding:40px;border-radius:16px;
                  box-shadow:0 4px 20px rgba(0,0,0,0.1);width:100%;max-width:400px;">
        <h2 style="color:#2e7d32;text-align:center;">🌿 Shayari App</h2>
        <h3 style="text-align:center;">Reset Password</h3>
        <p style="text-align:center;color:#555;">Hello <b>${user.username}</b></p>
        <form id="f">
          <input type="hidden" id="token" value="${token}">
          <div style="margin-bottom:16px;">
            <label style="display:block;margin-bottom:6px;font-weight:bold;">New Password</label>
            <input type="password" id="np" placeholder="Min 6 characters"
              style="width:100%;padding:12px;border:1px solid #ccc;border-radius:8px;
                     box-sizing:border-box;font-size:15px;">
          </div>
          <div style="margin-bottom:24px;">
            <label style="display:block;margin-bottom:6px;font-weight:bold;">Confirm Password</label>
            <input type="password" id="cp" placeholder="Dobara daalo"
              style="width:100%;padding:12px;border:1px solid #ccc;border-radius:8px;
                     box-sizing:border-box;font-size:15px;">
          </div>
          <button onclick="reset()" type="button"
            style="width:100%;padding:14px;background:#2e7d32;color:white;
                   border:none;border-radius:8px;font-size:16px;
                   font-weight:bold;cursor:pointer;">
            Reset Password
          </button>
          <p id="msg" style="text-align:center;margin-top:16px;"></p>
        </form>
        <script>
          async function reset() {
            const np = document.getElementById('np').value;
            const cp = document.getElementById('cp').value;
            const msg = document.getElementById('msg');
            if (np.length < 6) { msg.style.color='red'; msg.textContent='Min 6 characters chahiye'; return; }
            if (np !== cp) { msg.style.color='red'; msg.textContent='Dono password match nahi kar rahe'; return; }
            const res = await fetch('/api/reset-password', {
              method: 'POST',
              headers: {'Content-Type':'application/json'},
              body: JSON.stringify({ token: '${token}', newPassword: np })
            });
            const data = await res.json();
            if (res.ok) {
              msg.style.color = 'green';
              msg.textContent = '✅ ' + data.message;
              document.getElementById('f').innerHTML = '<p style="color:green;text-align:center;font-size:18px">✅ Password reset ho gaya!<br>App pe jaake sign in karo.</p>';
            } else {
              msg.style.color = 'red';
              msg.textContent = '❌ ' + data.error;
            }
          }
        </script>
      </div>
    </body></html>
  `);
});

// ══════════════════════════════════════════════════════════
//  SHAYARI ROUTES
// ══════════════════════════════════════════════════════════

app.get('/api/shayaris', async (req, res) => {
  try {
    const shayaris = await Shayari.find()
      .populate('author', 'username')
      .sort('-createdAt');
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
    const shayari = await Shayari.create({ content: content.trim(), author: req.user.id });
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
  console.log(`🔑 JWT_SECRET: ${!!process.env.JWT_SECRET}`);
  console.log(`🗄️  MONGO_URI: ${!!process.env.MONGO_URI}`);
  console.log(`📧 EMAIL: ${!!process.env.EMAIL_USER}`);
});
