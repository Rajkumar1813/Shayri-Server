const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const User = require('./models/User');
const Shayari = require('./models/Shayari');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'shayari_secret_key';

// ─── Middleware ───────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ─── MongoDB connect ──────────────────────────────────────
const mongoose = require('mongoose');

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection FAILED:', err.message);
    process.exit(1); // server band kar do agar DB connect na ho
  });

// ─── JWT Middleware ───────────────────────────────────────
function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  if (!header)
    return res.status(401).json({ error: 'Token nahi mila' });

  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    console.error('Token verify error:', err.message);
    res.status(401).json({ error: 'Invalid ya expired token' });
  }
}

// ══════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════

// Health check
app.get('/', (req, res) => {
  res.json({
    status: '✅ Server chal raha hai',
    dbStatus: mongoose.connection.readyState === 1 ? '✅ DB connected' : '❌ DB disconnected'
  });
});

// POST /api/signup
app.post('/api/signup', async (req, res) => {
  console.log('📩 Signup request aaya:', req.body);

  const { username, password } = req.body;

  if (!username || !password) {
    console.log('❌ Username ya password missing');
    return res.status(400).json({ error: 'Username aur password dono chahiye' });
  }

  if (username.trim().length < 3)
    return res.status(400).json({ error: 'Username kam se kam 3 characters ka hona chahiye' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Password kam se kam 6 characters ka hona chahiye' });

  try {
    const exists = await User.findOne({ username: username.trim() });
    if (exists) {
      console.log('❌ Username already exists:', username);
      return res.status(400).json({ error: 'Ye username already le liya gaya hai' });
    }

    const hash = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username: username.trim(), password: hash });
    console.log('✅ New user bana:', newUser.username);

    res.status(201).json({ message: 'Account ban gaya! Ab sign in karo.' });
  } catch (err) {
    console.error('❌ Signup error:', err.message);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// POST /api/signin
app.post('/api/signin', async (req, res) => {
  console.log('📩 Signin request aaya:', req.body?.username);

  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'Username aur password chahiye' });

  try {
    const user = await User.findOne({ username: username.trim() });
    if (!user) {
      console.log('❌ User nahi mila:', username);
      return res.status(400).json({ error: 'Ye username exist nahi karta' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('❌ Password galat hai for:', username);
      return res.status(400).json({ error: 'Password galat hai' });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('✅ User logged in:', user.username);
    res.json({ token, username: user.username, userId: user._id });
  } catch (err) {
    console.error('❌ Signin error:', err.message);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  SHAYARI ROUTES
// ══════════════════════════════════════════════════════════

// GET /api/shayaris — Sabki shayaris (public)
app.get('/api/shayaris', async (req, res) => {
  try {
    const shayaris = await Shayari.find()
      .populate('author', 'username')
      .sort('-createdAt');
    res.json(shayaris);
  } catch (err) {
    console.error('❌ Get shayaris error:', err.message);
    res.status(500).json({ error: 'Shayaris load nahi huin' });
  }
});

// GET /api/my-shayaris — Meri shayaris (login zaroori)
app.get('/api/my-shayaris', verifyToken, async (req, res) => {
  try {
    const shayaris = await Shayari.find({ author: req.user.id }).sort('-createdAt');
    res.json(shayaris);
  } catch (err) {
    console.error('❌ My shayaris error:', err.message);
    res.status(500).json({ error: 'Tumhari shayaris load nahi huin' });
  }
});

// POST /api/shayaris — Nai shayari (login zaroori)
app.post('/api/shayaris', verifyToken, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim() === '')
    return res.status(400).json({ error: 'Shayari ka content empty nahi ho sakta' });

  try {
    const shayari = await Shayari.create({ content: content.trim(), author: req.user.id });
    const populated = await shayari.populate('author', 'username');
    console.log('✅ Shayari post hui by:', req.user.username);
    res.status(201).json(populated);
  } catch (err) {
    console.error('❌ Post shayari error:', err.message);
    res.status(500).json({ error: 'Shayari post nahi ho paya' });
  }
});

// PUT /api/shayaris/:id — Edit (login zaroori)
app.put('/api/shayaris/:id', verifyToken, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim() === '')
    return res.status(400).json({ error: 'Content empty nahi ho sakta' });

  try {
    const shayari = await Shayari.findOne({ _id: req.params.id, author: req.user.id });
    if (!shayari)
      return res.status(404).json({ error: 'Shayari nahi mili ya tumhari nahi hai' });

    shayari.content = content.trim();
    await shayari.save();
    console.log('✅ Shayari edit hui:', req.params.id);
    res.json({ message: 'Shayari update ho gayi!', shayari });
  } catch (err) {
    console.error('❌ Edit error:', err.message);
    res.status(500).json({ error: 'Update nahi hua' });
  }
});

// DELETE /api/shayaris/:id — Delete (login zaroori)
app.delete('/api/shayaris/:id', verifyToken, async (req, res) => {
  try {
    const result = await Shayari.deleteOne({ _id: req.params.id, author: req.user.id });
    if (result.deletedCount === 0)
      return res.status(404).json({ error: 'Shayari nahi mili ya tumhari nahi hai' });

    console.log('✅ Shayari delete hui:', req.params.id);
    res.json({ message: 'Shayari delete ho gayi!' });
  } catch (err) {
    console.error('❌ Delete error:', err.message);
    res.status(500).json({ error: 'Delete nahi hua' });
  }
});

// ─── Server Start ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server chal raha hai port ${PORT} pe`);
  console.log(`🔑 JWT_SECRET set: ${!!process.env.JWT_SECRET}`);
  console.log(`🗄️  MONGO_URI set: ${!!process.env.MONGO_URI}`);
});
