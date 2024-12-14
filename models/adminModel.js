const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Import the User model for admin-specific actions on users
const User = require('./userModel');

const adminSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Please provide a username!'],
    unique: true
  },
  password: {
    type: String,
    required: [true, 'Please provide a password!'],
    minlength: 8,
    select: false
  },
  role: {
    type: String,
    enum: ['admin'],
    default: 'admin'
  },
  lastLogin: {
    type: Date,
    default: null
  }
});

// Middleware to hash the password before saving
adminSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Instance method to verify password
adminSchema.methods.correctPassword = async function (candidatePassword, adminPassword) {
  return await bcrypt.compare(candidatePassword, adminPassword);
};

// Instance method to update the last login timestamp
adminSchema.methods.updateLastLogin = async function () {
  this.lastLogin = new Date();
  await this.save();
};

// Admin-specific actions on users

// Static method to get all users
adminSchema.statics.getAllUsers = async function () {
  return await User.find({}, { name: 1, email: 1, phone: 1, address: 1, permissions: 1 });
};

// Static method to get a single user by ID
adminSchema.statics.getUserById = async function (userId) {
  return await User.findById(userId, { name: 1, email: 1, phone: 1, address: 1, permissions: 1 });
};

// Static method to update a user by ID
adminSchema.statics.updateUserById = async function (userId, updateData) {
  return await User.findByIdAndUpdate(userId, updateData, {
    new: true,
    runValidators: true
  });
};

// Static method to delete a specific user
adminSchema.statics.deleteUserById = async function (userId) {
  return await User.findByIdAndDelete(userId);
};

// Static method to search users by name, email, or username
adminSchema.statics.searchUsers = async function (query) {
  return await User.find({
    $or: [
      { name: { $regex: query, $options: 'i' } },
      { email: { $regex: query, $options: 'i' } },
      { username: { $regex: query, $options: 'i' } }
    ]
  });
};

const Admin = mongoose.model('Admin', adminSchema);

module.exports = Admin;