const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,   // ✅ save hone se pehle automatically lowercase ho jayega
  },
  password: {
    type: String,
    required: true
  }
});

// ✅ Case-insensitive unique index
// "Rahul", "RAHUL", "rahul" — teeno ek hi maane jayenge
userSchema.index(
  { username: 1 },
  { unique: true, collation: { locale: 'en', strength: 2 } }
);

module.exports = mongoose.model('User', userSchema);
