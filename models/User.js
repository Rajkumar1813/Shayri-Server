const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
  },

  // ── Email OTP Verification ──
  isVerified: {
    type: Boolean,
    default: false,       // signup ke baad false rahega jab tak OTP verify na ho
  },
  otp: {
    type: String,
    default: null,
  },
  otpExpiry: {
    type: Date,
    default: null,        // OTP 10 min mein expire hoga
  },

  // ── Password Reset ──
  resetToken: {
    type: String,
    default: null,
  },
  resetTokenExpiry: {
    type: Date,
    default: null,        // Reset link 15 min mein expire hogi
  },

}, { timestamps: true });

// Case-insensitive unique index
userSchema.index({ username: 1 }, { unique: true, collation: { locale: 'en', strength: 2 } });
userSchema.index({ email: 1 },    { unique: true, collation: { locale: 'en', strength: 2 } });

module.exports = mongoose.model('User', userSchema);
