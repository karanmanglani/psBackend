const express = require('express');
const adminController = require('../controllers/adminController');
const authController = require('../controllers/authController');
const AuditLog = require('../models/auditLog');
const User = require('../models/userModel');

const router = express.Router();

// Admin Signup and Login (Separate)
router.post('/login', adminController.login);  // Admin login handler
router.post('/signup', adminController.signup);  // Admin signup handler
router.get('/check-username/:username', adminController.checkUsernameAvailability);  // Check username availability

// // Admin Dashboard (for logged-in admins)
router.get('/admin', authController.protect, authController.restrictTo('admin'), adminController.getAdminDashboard);

// // User management routes for admin
router.get('/users', authController.protect, authController.restrictTo('admin'), adminController.getAllUsers);  // List all users
router.get('/users/:id', authController.protect, authController.restrictTo('admin'), adminController.getUser);  // Get specific user details
router.patch('/users/:id', authController.protect, authController.restrictTo('admin'), adminController.updateUser);  // Update user data
router.delete('/users/:id', authController.protect, authController.restrictTo('admin'), adminController.deleteUser);  // Delete user

// Admin endpoints for audit logs and user IPs
// Endpoint to fetch audit logs
router.get('/admin/audit-logs', authController.protect, authController.restrictTo('admin'), async (req, res) => {
  try {
    const logs = await AuditLog.find({});
    res.json(logs);
  } catch (error) {
    res.status(500).send('Error fetching audit logs');
  }
});

// Fetch user IPs (IPs of users who have set IP addresses)
router.get('/admin/user-ips', authController.protect, authController.restrictTo('admin'), async (req, res) => {
  try {
    const usersWithIps = await User.find({ ipAddress: { $ne: null } }).select('ipAddress');
    res.status(200).json(usersWithIps.map(user => user.ipAddress));
  } catch (error) {
    res.status(500).send("Error fetching user IPs");
  }
});

// Fetch username by user ID
router.get('/admin/get-username/:userId', authController.protect, authController.restrictTo('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.userId, 'username');
    res.json({ username: user ? user.username : 'Unknown' });
  } catch (error) {
    res.status(500).send('Error fetching username');
  }
});

module.exports = router;
