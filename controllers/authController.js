const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const Admin = require('./../models/adminModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const AuditLog = require('./../models/auditLog');

// Utility function to sign JWT
const signToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN // Token expiration
  });
};

// Function to create and send the JWT cookie to the user
const createSendToken = (user, statusCode, req, res) => {
  const token = signToken(user._id, user.role);
  const expiresIn = process.env.JWT_EXPIRES_IN;
  const days = parseInt(expiresIn, 10);

  // Set the JWT cookie with the token
  res.cookie('jwt', token, {
    expires: new Date(Date.now() + days * 24 * 60 * 60 * 1000),  // Adjust expiration date
    httpOnly: true,  // Ensures the cookie is not accessible via JS
    secure: false    // Ensure it's secure for HTTPS if you enable HTTPS
  });

  // Remove password from the user object before sending it
  user.password = undefined;

  // Send the response with status and token data (success response)
  res.status(statusCode).json({
    status: 'success',
    data: { user }
  });
};

// Signup for regular users
exports.signup = catchAsync(async (req, res, next) => {
  const {
    username,
    name,
    email,
    phone,
    address,
    password,
    passwordConfirm,
    emailPermission,
    phonePermission,
    addressPermission,
  } = req.body;

  const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;

  // Create a new user
  const newUser = await User.create({
    username,
    name,
    email: emailPermission === 'true' ? email : null,
    phone: phonePermission === 'true' ? phone : null,
    address: addressPermission === 'true' ? address : null,
    password,
    passwordConfirm,
    permissions: {
      email: emailPermission === 'true',
      phone: phonePermission === 'true',
      address: addressPermission === 'true',
    },
    ipAddress,
  });

  // Add creation to AuditLog
  await AuditLog.create({
    user: newUser._id,
    action: 'create',
    field: 'user',
    previousValue: null,
    newValue: {
      username: newUser.username,
      name: newUser.name,
    },
    ipAddress,
  });

  createSendToken(newUser, 201, req, res);
});

// Login for users
exports.login = catchAsync(async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return next(new AppError('Please provide a username and password!', 400));
  }

  // Find user by username
  const user = await User.findOne({ username }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect username or password', 401));
  }

  // If everything is ok, send token and data
  createSendToken(user, 200, req, res);
});

// Logout
exports.logout = (req, res) => {
  res.status(200).json({ status: 'success', message: 'User logged out' });
};

// Protect middleware (for React Native, token passed in Authorization header)
exports.protect = catchAsync(async (req, res, next) => {
  if (req.originalUrl.startsWith('/api/v1/users/check-username')) {
    return next();  // Skip authentication for the check-username route
  }

  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1]; // Extract token from Authorization header
  }

  if (!token) {
    return next(new AppError('You are not logged in! Please log in to get access.', 401));
  }

  try {
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    const model = decoded.role === 'admin' ? Admin : User;
    const currentUser = await model.findById(decoded.id);

    if (!currentUser) {
      return next(new AppError('The user belonging to this token does no longer exist.', 401));
    }

    req.user = currentUser;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return next(new AppError('Your session has expired. Please log in again.', 401));
    }
    return next(err);
  }
});

// Restrict routes to specific roles
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new AppError('You do not have permission to perform this action', 403));
    }
    next();
  };
};

// Admin-specific functions
exports.getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find({}, { username: 1, name: 1, email: 1, phone: 1, address: 1, permissions: 1 });
  res.status(200).json({
    status: 'success',
    results: users.length,
    data: { users }
  });
});

// Delete User
exports.deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndDelete(req.params.id);
  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }
  res.status(204).json({ status: 'success', data: null });
});

// Check if the user is logged in (checks for a valid JWT) - Adjusted for React Native
exports.isLoggedIn = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1]; // Extract token from Authorization header
  }

  if (token) {
    try {
      // 1) Verify the token
      const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

      // 2) Check if the user still exists
      const currentUser = await User.findById(decoded.id);
      if (!currentUser) return next(); // Proceed if no user found

      // 3) Check if the user changed password after the token was issued
      if (currentUser.changedPasswordAfter(decoded.iat)) return next(); // Proceed if password was changed

      // 4) Add the user to res.locals for use in views
      req.user = currentUser;
      res.locals.user = currentUser;
      return next(); // Proceed to next middleware/route
    } catch (err) {
      return next(); // Proceed if error occurs (user might not be logged in)
    }
  } else {
    return next(); // No JWT token, proceed without user
  }
};
