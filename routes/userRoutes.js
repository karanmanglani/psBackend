const express = require('express');
const userController = require('./../controllers/userController');
const authController = require('./../controllers/authController');

const router = express.Router();

// Signup and login routes
router.post('/signup', authController.signup);  // Handle signup via POST (returns JSON)
router.post('/login', authController.login);    // Handle login via POST (returns JSON)
router.get('/logout', authController.logout);   // Handle logout via GET (returns JSON)

// Protect all routes after this middleware
router.use(authController.protect);

// User-specific routes (returns JSON)
router.delete('/deleteMe', userController.deleteMe); // Soft delete user (deactivate account) (returns JSON)

// Route to check username availability (returns JSON)
router.get('/check-username/:username', userController.checkUsernameAvailability);

module.exports = router;
