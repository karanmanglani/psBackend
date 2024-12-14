const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const factory = require('./handlerFactory');
const AuditLog = require('../models/auditLog');
const geoip = require('geoip-lite');

// Get current logged-in user (sets user id for the next middleware)
exports.getMe = (req, res, next) => {
  req.params.id = req.user.id; // Set user id from JWT
  next();
};

// Update user preferences (email, phone, address, permissions)
exports.updatePreferences = catchAsync(async (req, res, next) => {
  const email = req.body.email === 'true';
  const phone = req.body.phone === 'true';
  const address = req.body.address === 'true';

  const updatedUser = await User.findByIdAndUpdate(
    req.user.id,
    {
      'permissions.email': email,
      'permissions.phone': phone,
      'permissions.address': address
    },
    {
      new: true,
      runValidators: true
    }
  );

  if (!updatedUser) {
    return next(new AppError('User not found!', 404));
  }

  res.status(200).json({
    status: 'success',
    message: 'Preferences updated successfully!',
    data: updatedUser,
  });
});

// Update user field (name, email, phone, address)
exports.updateField = catchAsync(async (req, res, next) => {
  const fieldName = req.params.fieldName; // e.g., 'name', 'email', 'phone', 'address'
  let { value } = req.body;

  if (!value) {
    return next(new AppError('No value provided!', 400));
  }

  if (fieldName === 'phone') {
    value = encryptPhoneNumber(value);
  }

  const permissionField = `permissions.${fieldName}`;
  const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;

  const user = await User.findById(req.user.id);
  const previousValue = user[fieldName];

  const updatedUser = await User.findByIdAndUpdate(
    req.user.id,
    {
      [fieldName]: value,
      [permissionField]: true,
      ipAddress, // Update IP address
    },
    {
      new: true,
      runValidators: true,
    }
  );

  if (!updatedUser) {
    return next(new AppError('User not found!', 404));
  }

  // Add update action to AuditLog
  await AuditLog.create({
    user: updatedUser._id,
    action: 'update',
    field: fieldName,
    previousValue,
    newValue: value,
    ipAddress,
  });

  res.status(200).json({
    status: 'success',
    message: `${fieldName} updated successfully!`,
  });
});

// Delete user field (email, phone, address)
exports.deleteField = catchAsync(async (req, res, next) => {
  const fieldName = req.params.fieldName; // e.g., 'email', 'phone', or 'address'
  const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;

  const user = await User.findById(req.user.id);
  const previousValue = user[fieldName];

  const updatedUser = await User.findByIdAndUpdate(
    req.user.id,
    {
      [fieldName]: null,
      [`permissions.${fieldName}`]: false,
      ipAddress, // Update IP address
    },
    { new: true }
  );

  if (!updatedUser) {
    return next(new AppError('User not found!', 404));
  }

  // Add delete action to AuditLog
  await AuditLog.create({
    user: updatedUser._id,
    action: 'delete',
    field: fieldName,
    previousValue,
    newValue: null,
    ipAddress,
  });

  res.status(200).json({
    status: 'success',
    message: `${fieldName} removed successfully!`,
  });
});

// Get user preferences (email, phone, address permissions)
exports.getPreferences = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);

  if (!user) {
    return next(new AppError('User not found!', 404));
  }

  res.status(200).json({
    status: 'success',
    data: user,
  });
});

// Check if username is available
exports.checkUsernameAvailability = catchAsync(async (req, res, next) => {
  const { username } = req.params;

  // Check if the username already exists in the database (exact match)
  const existingUser = await User.findOne({ username: username });

  if (existingUser) {
    return res.status(200).json({
      status: 'success',
      data: { isAvailable: false }  // Username is already taken
    });
  }

  return res.status(200).json({
    status: 'success',
    data: { isAvailable: true }  // Username is available
  });
});

// Soft delete user account (set active to false)
exports.deleteMe = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(req.user.id, { active: false });

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null
  });
});

// Get all users (admin view for managing user data)
exports.getAllUsers = factory.getAll(User);

// Admin can update user details, excluding password
exports.updateUser = factory.updateOne(User);

// Admin can delete user by ID
exports.deleteUser = factory.deleteOne(User);

// Utility function to filter allowed fields for updates
const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

// Encryption for phone numbers (XOR-based example)
const encryptPhoneNumber = (phone) => {
  const SIMPLE_KEY = "mySimpleEncryptionKey"; // Use your consistent key
  const key = Buffer.from(SIMPLE_KEY);
  const textBuffer = Buffer.from(phone, 'utf8');
  const encrypted = textBuffer.map((byte, i) => byte ^ key[i % key.length]);
  return encrypted.toString('base64');
};

