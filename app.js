const path = require('path');
const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const cors = require('cors');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const userRouter = require('./routes/userRoutes');
const adminRouter = require('./routes/adminRoutes');
const catchAsync = require('./utils/catchAsync');
const User = require('./models/userModel');
const AuditLog = require('./models/auditLog');
const authController = require('./controllers/authController');


const encryptPhoneNumber = (phone) => {
  const SIMPLE_KEY = "mySimpleEncryptionKey"; // Use your consistent key
  const key = Buffer.from(SIMPLE_KEY);
  const textBuffer = Buffer.from(phone, 'utf8');
  const encrypted = textBuffer.map((byte, i) => byte ^ key[i % key.length]);
  return encrypted.toString('base64');
};

// Start express app
const app = express();

app.enable('trust proxy'); // For handling proxy in production (e.g., Heroku)

// 1) GLOBAL MIDDLEWARES
// Implement CORS (Cross-Origin Resource Sharing)
app.use(cors());


// Serving static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Set security HTTP headers (Helmet helps protect against various attacks)
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP
}));

// Development logging (Only enable for development environment)
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Limit requests from the same API to prevent abuse (rate-limiting)
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000, // 1 hour
  message: 'Too many requests from this IP, please try again in an hour!'
});
app.use('/api', limiter); // Apply rate limiter to API routes

// Body parser middleware to read data from the body into req.body
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser()); // Parse cookies

// Data sanitization against NoSQL query injection (e.g., MongoDB)
app.use(mongoSanitize());

// Data sanitization against XSS (cross-site scripting) attacks
app.use(xss());

// Prevent HTTP parameter pollution
app.use(hpp());

// Enable gzip compression for better performance (compress response bodies)
app.use(compression());

// Test middleware for logging request time (development only)
if (process.env.NODE_ENV === 'development') {
  app.use((req, res, next) => {
    req.requestTime = new Date().toISOString();
    next();
  });
}

// 2) ROUTES
// API Routes
app.use('/api/v1/users', userRouter);
app.use('/api/v1/admin', adminRouter);
// New routes for updating and deleting
app.post(
  '/update-:fieldName',
  authController.protect,
  catchAsync(async (req, res, next) => {
    const fieldName = req.params.fieldName; // e.g., 'email', 'phone', or 'address'
    let { value, userId } = req.body;

    if (!value) {
      return next(new AppError('No value provided!', 400));
    }

    if (!userId) {
      return next(new AppError('User ID is required!', 400));
    }

    if (fieldName === 'phone') {
      value = encryptPhoneNumber(value);
    }

    const permissionField = `permissions.${fieldName}`;
    const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    // Fetch the previous value for the field
    const user = await User.findById(userId);
    if (!user) {
      return next(new AppError('User not found!', 404));
    }
    const previousValue = user[fieldName];

    // Update the user
    const updatedUser = await User.findByIdAndUpdate(
      userId,
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
      return next(new AppError('Failed to update user!', 400));
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
  })
);

// Inline implementation of deleteField
app.post(
  '/delete-:fieldName',
  authController.protect,
  catchAsync(async (req, res, next) => {
    const fieldName = req.params.fieldName; // e.g., 'email', 'phone', or 'address'
    const { userId } = req.body;

    if (!userId) {
      return next(new AppError('User ID is required!', 400));
    }

    const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    // Fetch the previous value for the field
    const user = await User.findById(userId);
    if (!user) {
      return next(new AppError('User not found!', 404));
    }
    const previousValue = user[fieldName];

    // Update the user to clear the field and its permission
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        [fieldName]: null,
        [`permissions.${fieldName}`]: false,
        ipAddress, // Update IP address
      },
      { new: true }
    );

    if (!updatedUser) {
      return next(new AppError('Failed to update user!', 400));
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
  })
);

// Handle undefined routes (404 errors)
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// Global error handler (catch errors from controllers and middleware)
app.use(globalErrorHandler);

// Export the app for use in the server file
module.exports = app;
