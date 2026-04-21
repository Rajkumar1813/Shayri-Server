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
    process.exit(1);
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

// ─── Username Clean Helper ────────────────────────────────
// trim + lowercase ek jagah define kar diya
const cleanUsername = (u) => u.trim().toLowerCase();

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
    return res.status(400).json({ error: 'Please enter Username or password' });
  }

  const finalUsername = cleanUsername(username); // ✅ lowercase ho gaya

  if (finalUsername.length < 3)
    return res.status(400).json({ error: 'Username min should be 3 characters.!' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Password min should be 6 characters.!' });

  try {
    const exists = await User.findOne({ username: finalUsername });
    if (exists) {
      console.log('❌ Username already exists:', finalUsername);
      return res.status(400).json({ error: 'This username already taken.' });
    }

    const hash = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username: finalUsername, password: hash });
    console.log('✅ New user bana:', newUser.username);

    res.status(201).json({ message: 'Account Created✅! Pls Sign in.' });
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
    return res.status(400).json({ error: 'Please enter Username or password' });

  const finalUsername = cleanUsername(username); // ✅ lowercase ho gaya

  try {
    const user = await User.findOne({ username: finalUsername });
    if (!user) {
      console.log('❌ User nahi mila:', finalUsername);
      return res.status(400).json({ error: 'Username Invalid' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('❌ Password galat hai for:', finalUsername);
      return res.status(400).json({ error: 'Password Invalid' });
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
    res.status(500).json({ error: 'Shayaris not loaded' });
  }
});

// GET /api/my-shayaris — Meri shayaris (login zaroori)
app.get('/api/my-shayaris', verifyToken, async (req, res) => {
  try {
    const shayaris = await Shayari.find({ author: req.user.id }).sort('-createdAt');
    res.json(shayaris);
  } catch (err) {
    console.error('❌ My shayaris error:', err.message);
    res.status(500).json({ error: 'Your Shayaris not loaded' });
  }
});

// POST /api/shayaris — Nai shayari (login zaroori)
app.post('/api/shayaris', verifyToken, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim() === '')
    return res.status(400).json({ error: 'Please Enter Shayari' });

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
    return res.status(400).json({ error: 'Please Enter Shayari' });

  try {
    const shayari = await Shayari.findOne({ _id: req.params.id, author: req.user.id });
    if (!shayari)
      return res.status(404).json({ error: 'Shayari Not found' });

    shayari.content = content.trim();
    await shayari.save();
    console.log('✅ Shayari edit hui:', req.params.id);
    res.json({ message: 'Shayari update ho gayi!', shayari });
  } catch (err) {
    console.error('❌ Edit error:', err.message);
    res.status(500).json({ error: 'Not Update' });
  }
});

// DELETE /api/shayaris/:id — Delete (login zaroori)
app.delete('/api/shayaris/:id', verifyToken, async (req, res) => {
  try {
    const result = await Shayari.deleteOne({ _id: req.params.id, author: req.user.id });
    if (result.deletedCount === 0)
      return res.status(404).json({ error: 'Shayari Not found' });

    console.log('✅ Shayari delete hui:', req.params.id);
    res.json({ message: 'Deleted Successfully✅.!' });
  } catch (err) {
    console.error('❌ Delete error:', err.message);
    res.status(500).json({ error: 'Not Delete' });
  }
});

// ─── Server Start ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server chal raha hai port ${PORT} pe`);
  console.log(`🔑 JWT_SECRET set: ${!!process.env.JWT_SECRET}`);
  console.log(`🗄️  MONGO_URI set: ${!!process.env.MONGO_URI}`);
});
