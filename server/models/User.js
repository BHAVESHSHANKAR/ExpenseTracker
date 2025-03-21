const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  verified: { type: Boolean, default: false },
  salary: { type: String, default: '0' }, // Hashed string
  expenses: [{ // Array of hashed expense objects
    id: String,
    expenses: String, // Hashed JSON string of expenses object
    date: Date,
  }],
  lastImageContent: { type: String, default: '' }, // Hashed string
});

module.exports = mongoose.model('User', userSchema);