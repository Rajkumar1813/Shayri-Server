const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// DNS required
const dns = require("dns");

dns.setServers([
  '1.1.1.1',
  '8.8.8.8'
]);

require('dotenv').config();
require('./db')();

const User = require('./models/User');
const Shayari = require('./models/Shayari');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'shayari_secret_key';




// ─── Middleware ───────────────────────────────────────────
app.use(cors());             // Flutter app cross-origin request allow karo
app.use(express.json());     // JSON body parse karo

// ─── JWT Verify Middleware ────────────────────────────────
function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  if (!header)
    return res.status(401).json({ error: 'Token nahi mila' });

  const token = header.split(' ')[1]; // "Bearer TOKEN" se token nikalo
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid ya expired token' });
  }
}

// ══════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════

// POST /api/signup — Naya account banao
app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'Username aur password dono chahiye' });

  if (username.trim().length < 3)
    return res.status(400).json({ error: 'Username kam se kam 3 characters ka hona chahiye' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Password kam se kam 6 characters ka hona chahiye' });

  try {
    const exists = await User.findOne({ username: username.trim() });
    if (exists)
      return res.status(400).json({ error: 'Ye username already le liya gaya hai' });

    const hash = await bcrypt.hash(password, 10);
    await User.create({ username: username.trim(), password: hash });

    res.status(201).json({ message: 'Account ban gaya! Ab sign in karo.' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error, dobara try karo' });
  }
});

// POST /api/signin — Login karo, token lo
app.post('/api/signin', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'Username aur password chahiye' });

  try {
    const user = await User.findOne({ username: username.trim() });
    if (!user)
      return res.status(400).json({ error: 'Ye username exist nahi karta' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ error: 'Password galat hai' });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }   // 7 din tak valid rahega
    );

    res.json({
      token,
      username: user.username,
      userId: user._id
    });
  } catch (err) {
    console.error('Signin error:', err);
    res.status(500).json({ error: 'Server error, dobara try karo' });
  }
});

// ══════════════════════════════════════════════════════════
//  SHAYARI ROUTES
// ══════════════════════════════════════════════════════════

// GET /api/shayaris — Sabki shayaris dekho (bina login ke)
app.get('/api/shayaris', async (req, res) => {
  try {
    const shayaris = await Shayari.find()
      .populate('author', 'username')  // sirf username lao, password nahi
      .sort('-createdAt');             // naya pehle

    res.json(shayaris);
  } catch (err) {
    console.error('Get shayaris error:', err);
    res.status(500).json({ error: 'Shayaris load nahi huin' });
  }
});

// GET /api/my-shayaris — Sirf meri shayaris (login zaroori)
app.get('/api/my-shayaris', verifyToken, async (req, res) => {
  try {
    const shayaris = await Shayari.find({ author: req.user.id })
      .sort('-createdAt');

    res.json(shayaris);
  } catch (err) {
    console.error('My shayaris error:', err);
    res.status(500).json({ error: 'Tumhari shayaris load nahi huin' });
  }
});

// POST /api/shayaris — Nai shayari post karo (login zaroori)
app.post('/api/shayaris', verifyToken, async (req, res) => {
  const { content } = req.body;

  if (!content || content.trim() === '')
    return res.status(400).json({ error: 'Shayari ka content empty nahi ho sakta' });

  try {
    const shayari = await Shayari.create({
      content: content.trim(),
      author: req.user.id
    });

    // author ka username bhi return karo
    const populated = await shayari.populate('author', 'username');
    res.status(201).json(populated);
  } catch (err) {
    console.error('Post shayari error:', err);
    res.status(500).json({ error: 'Shayari post nahi ho paya' });
  }
});

// PUT /api/shayaris/:id — Shayari edit karo (sirf apni)
app.put('/api/shayaris/:id', verifyToken, async (req, res) => {
  const { content } = req.body;

  if (!content || content.trim() === '')
    return res.status(400).json({ error: 'Content empty nahi ho sakta' });

  try {
    const shayari = await Shayari.findOne({
      _id: req.params.id,
      author: req.user.id   // sirf apni shayari edit kar sakte ho
    });

    if (!shayari)
      return res.status(404).json({ error: 'Shayari nahi mili ya tumhari nahi hai' });

    shayari.content = content.trim();
    await shayari.save();

    res.json({ message: 'Shayari update ho gayi!', shayari });
  } catch (err) {
    console.error('Edit shayari error:', err);
    res.status(500).json({ error: 'Update nahi hua' });
  }
});

// DELETE /api/shayaris/:id — Shayari delete karo (sirf apni)
app.delete('/api/shayaris/:id', verifyToken, async (req, res) => {
  try {
    const result = await Shayari.deleteOne({
      _id: req.params.id,
      author: req.user.id   // sirf apni shayari delete kar sakte ho
    });

    if (result.deletedCount === 0)
      return res.status(404).json({ error: 'Shayari nahi mili ya tumhari nahi hai' });

    res.json({ message: 'Shayari delete ho gayi!' });
  } catch (err) {
    console.error('Delete shayari error:', err);
    res.status(500).json({ error: 'Delete nahi hua' });
  }
});

// ─── Health Check ─────────────────────────────────────────
// Render pe deploy karne ke baad check karne ke liye
app.get('/', (req, res) => {
  res.json({ status: 'Server chal raha hai ✅', message: 'Shayari API ready hai!' });
});

// ─── Server Start ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server chal raha hai: http://localhost:${PORT}`);
});