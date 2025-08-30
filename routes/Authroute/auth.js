// ==================== SECURE AUTH ROUTES - FIXED SECURITY ====================
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { User } = require('../../Schema/Schema');
const { body, validationResult } = require('express-validator');

// ==================== HELPER FUNCTIONS ====================

// Generate JWT Token
const generateToken = (userId) => {
  return jwt.sign(
    { id: userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

// Verify JWT Token (for protected routes)
const verifyToken = async (req, res, next) => {
  try {
    let token;
    
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized'
      });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-password');
    
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }
    
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }
};

// Admin only middleware
const adminOnly = async (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Admin access required'
    });
  }
  next();
};

// Generate unique username from email
const generateUsername = async (email) => {
  let baseUsername = email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
  let username = baseUsername;
  let counter = 1;
  
  while (await User.findOne({ username })) {
    username = `${baseUsername}${counter}`;
    counter++;
  }
  
  return username;
};

// Generate referral code
const generateReferralCode = async () => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code;
  let exists = true;
  
  while (exists) {
    code = '';
    for (let i = 0; i < 6; i++) {
      code += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    exists = await User.findOne({ referralCode: code });
  }
  
  return code;
};

// Generate invite code for privileged roles
const generateInviteCode = () => {
  return crypto.randomBytes(16).toString('hex');
};

// Format user response (remove sensitive data)
const formatUserResponse = (user) => {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    phoneNumber: user.phoneNumber,
    username: user.username,
    role: user.role,
    walletBalance: user.walletBalance,
    agentProfit: user.agentProfit,
    referralCode: user.referralCode,
    emailVerified: user.emailVerified,
    phoneVerified: user.phoneVerified,
    approvalStatus: user.approvalStatus,
    createdAt: user.createdAt
  };
};

// ==================== VALIDATION MIDDLEWARE ====================

// Validation for signup (NO ROLE FIELD ALLOWED!)
const validateSignup = [
  body('name')
    .trim()
    .notEmpty().withMessage('Name is required')
    .isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s]+$/).withMessage('Name can only contain letters and spaces'),
  
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email')
    .normalizeEmail(),
  
  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
    .matches(/\d/).withMessage('Password must contain at least one number'),
  
  body('confirmPassword')
    .notEmpty().withMessage('Please confirm your password')
    .custom((value, { req }) => value === req.body.password)
    .withMessage('Passwords do not match'),
  
  body('phoneNumber')
    .trim()
    .notEmpty().withMessage('Phone number is required')
    .matches(/^(\+233|0)[2-9]\d{8}$/)
    .withMessage('Please provide a valid Ghana phone number'),
  
  // FIXED: Only validate referral code if not empty
  body('referredBy')
    .optional({ checkFalsy: true }) // This treats empty strings as optional
    .trim()
    .isLength({ min: 6, max: 6 })
    .withMessage('Referral code must be 6 characters'),
  
  // SECURITY: Block any attempt to set role
  body('role')
    .custom((value) => {
      if (value) {
        throw new Error('Unauthorized field');
      }
      return true;
    })
];

// Validation for login
const validateLogin = [
  body('emailOrPhone')
    .trim()
    .notEmpty().withMessage('Email or phone number is required'),
  
  body('password')
    .notEmpty().withMessage('Password is required')
];

// Check validation errors
const checkValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(err => ({
        field: err.path,
        message: err.msg
      }))
    });
  }
  next();
};

// ==================== PUBLIC SIGNUP - ALWAYS CREATES USER ROLE ====================
router.post('/signup', validateSignup, checkValidation, async (req, res) => {
  try {
    // SECURITY: Remove any role field if somehow passed
    delete req.body.role;
    delete req.body.isAdmin;
    delete req.body.approvalStatus;
    delete req.body.walletBalance;
    delete req.body.agentProfit;
    
    const { 
      name, 
      email, 
      password, 
      phoneNumber,
      referredBy 
    } = req.body;

    // Check if email already exists
    const emailExists = await User.findOne({ email: email.toLowerCase() });
    if (emailExists) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered',
        field: 'email'
      });
    }

    // Check if phone number already exists
    const phoneExists = await User.findOne({ phoneNumber });
    if (phoneExists) {
      return res.status(400).json({
        success: false,
        message: 'Phone number already registered',
        field: 'phoneNumber'
      });
    }

    // Validate referral code if provided
    let referrer = null;
    if (referredBy && referredBy.trim()) {
      referrer = await User.findOne({ referralCode: referredBy.toUpperCase() });
      if (!referrer) {
        return res.status(400).json({
          success: false,
          message: 'Invalid referral code',
          field: 'referredBy'
        });
      }
    }

    // Generate unique username
    const username = await generateUsername(email);

    // Generate referral code for new user
    const referralCode = await generateReferralCode();

    // SECURITY: All public signups are USERS only
    const user = await User.create({
      name,
      email: email.toLowerCase(),
      password,
      phoneNumber,
      username,
      role: 'user', // ALWAYS USER - no exceptions
      referralCode,
      referredBy: referredBy && referredBy.trim() ? referredBy.toUpperCase() : null,
      approvalStatus: 'approved', // Users are auto-approved
      walletBalance: 0,
      agentProfit: 0,
      emailVerified: false,
      phoneVerified: false
    });

    // Update referrer's stats if applicable
    if (referrer) {
      referrer.totalReferrals = (referrer.totalReferrals || 0) + 1;
      await referrer.save();
    }

    // Generate token
    const token = generateToken(user._id);

    // Send response
    res.status(201).json({
      success: true,
      message: 'Registration successful',
      token,
      user: formatUserResponse(user)
    });

  } catch (error) {
    console.error('Signup error:', error);
    
    if (error.code === 11000) {
      const field = Object.keys(error.keyValue)[0];
      return res.status(400).json({
        success: false,
        message: `${field} already exists`,
        field
      });
    }

    res.status(500).json({
      success: false,
      message: 'Registration failed. Please try again.',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== LOGIN ROUTE ====================
router.post('/login', validateLogin, checkValidation, async (req, res) => {
  try {
    const { emailOrPhone, password } = req.body;

    // Find user by email or phone number
    let user;
    
    if (emailOrPhone.includes('@')) {
      user = await User.findOne({ email: emailOrPhone.toLowerCase() });
    } else {
      let normalizedPhone = emailOrPhone;
      if (emailOrPhone.startsWith('0')) {
        normalizedPhone = emailOrPhone;
      }
      user = await User.findOne({ phoneNumber: normalizedPhone });
    }

    // Check if user exists
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
        await user.save();
        
        return res.status(423).json({
          success: false,
          message: 'Account locked. Try again in 30 minutes.'
        });
      }
      
      await user.save();
      
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        attemptsRemaining: 5 - user.loginAttempts
      });
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const minutesRemaining = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({
        success: false,
        message: `Account locked. Try again in ${minutesRemaining} minutes.`
      });
    }

    // Check if account is disabled
    if (user.isDisabled) {
      return res.status(403).json({
        success: false,
        message: 'Account disabled',
        reason: user.disableReason
      });
    }

    // Reset login attempts
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    
    // Update last login
    user.lastLogin = {
      timestamp: new Date(),
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      deviceId: req.get('x-device-id') || 'unknown'
    };
    
    await user.save();

    // Generate token
    const token = generateToken(user._id);

    // Check if user has an agent store (optional - remove if not needed)
    let hasStore = false;
    if (['agent', 'super_agent', 'dealer'].includes(user.role)) {
      // Only check if AgentStore model exists
      try {
        const { AgentStore } = require('../../Schema/Schema');
        const store = await AgentStore.findOne({ agent: user._id });
        hasStore = !!store;
      } catch (err) {
        // AgentStore model might not exist yet
        hasStore = false;
      }
    }

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: formatUserResponse(user),
      hasStore
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
});

// ==================== PROTECTED ADMIN ROUTES ====================

// Create privileged user (Admin only)
router.post('/admin/create-user', verifyToken, adminOnly, async (req, res) => {
  try {
    const { 
      name, 
      email, 
      password,
      phoneNumber,
      role // Admin can set any role
    } = req.body;

    // Validate role
    if (!['user', 'agent', 'super_agent', 'dealer', 'admin'].includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role'
      });
    }

    // Check if email exists
    const emailExists = await User.findOne({ email: email.toLowerCase() });
    if (emailExists) {
      return res.status(400).json({
        success: false,
        message: 'Email already exists'
      });
    }

    // Check if phone exists
    const phoneExists = await User.findOne({ phoneNumber });
    if (phoneExists) {
      return res.status(400).json({
        success: false,
        message: 'Phone number already exists'
      });
    }

    const username = await generateUsername(email);
    const referralCode = await generateReferralCode();

    const user = await User.create({
      name,
      email: email.toLowerCase(),
      password,
      phoneNumber,
      username,
      role, // Admin can set role
      referralCode,
      approvalStatus: 'approved',
      walletBalance: 0,
      emailVerified: true, // Auto-verify admin-created users
      phoneVerified: true
    });

    res.status(201).json({
      success: true,
      message: `${role} created successfully`,
      user: formatUserResponse(user)
    });

  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create user'
    });
  }
});

// Upgrade user role (Admin only)
router.patch('/admin/upgrade-role', verifyToken, adminOnly, async (req, res) => {
  try {
    const { userId, newRole } = req.body;

    if (!['user', 'agent', 'super_agent', 'dealer'].includes(newRole)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role'
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Don't allow changing admin role
    if (user.role === 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Cannot change admin role'
      });
    }

    user.role = newRole;
    user.approvalStatus = 'approved';
    await user.save();

    res.json({
      success: true,
      message: `User upgraded to ${newRole}`,
      user: formatUserResponse(user)
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to upgrade role'
    });
  }
});

// ==================== USER UPGRADE REQUEST (Safe way for users) ====================

// Request role upgrade (Users request, admin approves)
router.post('/request-upgrade', verifyToken, async (req, res) => {
  try {
    const { requestedRole, businessInfo } = req.body;

    // Only allow upgrade requests to agent, super_agent, or dealer
    if (!['agent', 'super_agent', 'dealer'].includes(requestedRole)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role request'
      });
    }

    // Check if user already has this role
    if (req.user.role === requestedRole) {
      return res.status(400).json({
        success: false,
        message: 'You already have this role'
      });
    }

    // Update user with pending approval
    req.user.approvalStatus = 'pending';
    // Store the requested role in a separate field or notification
    // You might want to add a 'requestedRole' field to your User schema
    req.user.requestedRole = requestedRole;
    await req.user.save();

    // In production, you'd create a notification for admin
    // await createNotificationForAdmin(req.user, requestedRole, businessInfo);

    res.json({
      success: true,
      message: 'Upgrade request submitted. Awaiting admin approval.',
      requestedRole
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to submit upgrade request'
    });
  }
});

// ==================== FIRST ADMIN CREATION (One-time setup) ====================
// This route should be disabled after creating the first admin
router.post('/create-first-admin', async (req, res) => {
  try {
    // Check if any admin exists
    const adminExists = await User.findOne({ role: 'admin' });
    if (adminExists) {
      return res.status(403).json({
        success: false,
        message: 'Admin already exists'
      });
    }

    // Verify secret key (set this in environment)
    const { secretKey, email, password, name, phoneNumber } = req.body;
    
    if (secretKey !== process.env.ADMIN_CREATION_SECRET) {
      return res.status(403).json({
        success: false,
        message: 'Invalid secret key'
      });
    }

    const username = await generateUsername(email);
    const referralCode = await generateReferralCode();

    const admin = await User.create({
      name,
      email: email.toLowerCase(),
      password,
      phoneNumber,
      username,
      role: 'admin',
      referralCode,
      approvalStatus: 'approved',
      walletBalance: 0,
      emailVerified: true,
      phoneVerified: true
    });

    const token = generateToken(admin._id);

    res.status(201).json({
      success: true,
      message: 'First admin created successfully',
      token,
      user: formatUserResponse(admin)
    });

  } catch (error) {
    console.error('Create first admin error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create admin'
    });
  }
});

// ==================== EXPORT ROUTER ====================
module.exports = router;