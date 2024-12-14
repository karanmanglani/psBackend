const User = require('./../models/userModel');
const Admin = require('./../models/adminModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const jwt = require('jsonwebtoken');

// Utility function to create JWT
const signToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

// Admin Signup
exports.signup = catchAsync(async (req, res, next) => {
  const { username, password, passwordConfirm, role = 'admin' } = req.body;

  // Check if username already exists
  const existingAdmin = await Admin.findOne({ username });
  if (existingAdmin) {
    return next(new AppError('Username already exists. Please choose another.', 400));
  }

  // Check if passwords match
  if (password !== passwordConfirm) {
    return next(new AppError('Passwords do not match!', 400));
  }

  // Create a new admin
  const newAdmin = await Admin.create({
    username,
    password,
    passwordConfirm,
    role,
  });

  // Send token to admin after successful signup
  const token = signToken(newAdmin._id, newAdmin.role);
  res.status(201).json({
    status: 'success',
    token,
    data: { admin: newAdmin },
  });
});

// Admin Login
exports.login = catchAsync(async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return next(new AppError('Please provide a username and password!', 400));
  }

  const admin = await Admin.findOne({ username }).select('+password');

  if (!admin || !(await admin.correctPassword(password, admin.password))) {
    return next(new AppError('Incorrect username or password', 401));
  }

  // Create and send JWT
  const token = signToken(admin._id, admin.role);
  res.status(200).json({
    status: 'success',
    token,
    data: { admin },
  });
});

// Admin Dashboard (Returns JSON for React Native)
exports.getAdminDashboard = catchAsync(async (req, res, next) => {
  const admin = req.user;

  res.status(200).json({
    status: 'success',
    data: { admin },
  });
});

// Get All Users (Returns JSON for React Native)
exports.getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find();
  res.status(200).json({
    status: 'success',
    data: { users },
  });
});

// Get User by ID (Returns JSON for React Native)
exports.getUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: { user },
  });
});

// Update User (Returns JSON for React Native)
exports.updateUser = catchAsync(async (req, res, next) => {
  if (req.body.password || req.body.passwordConfirm) {
    return next(new AppError('This route is not for password updates. Please use /updateMyPassword.', 400));
  }

  const filteredBody = filterObj(req.body, 'name', 'email', 'phone', 'address', 'role');

  const updatedUser = await User.findByIdAndUpdate(req.params.id, filteredBody, {
    new: true,
    runValidators: true,
  });

  if (!updatedUser) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: { user: updatedUser },
  });
});

// Delete User (Returns JSON for React Native)
exports.deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndDelete(req.params.id);

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

// Utility function to filter allowed fields
const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

// Check Username Availability (Returns JSON for React Native)
exports.checkUsernameAvailability = catchAsync(async (req, res, next) => {
  const { username } = req.params;

  // Check if the username already exists in the database (exact match)
  const existingUser = await Admin.findOne({ username: username });

  return res.status(200).json({
    status: 'success',
    data: { isAvailable: !existingUser }, // Username is available if not found
  });
});
