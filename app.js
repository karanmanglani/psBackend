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

// Handle undefined routes (404 errors)
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// Global error handler (catch errors from controllers and middleware)
app.use(globalErrorHandler);

// Export the app for use in the server file
module.exports = app;
