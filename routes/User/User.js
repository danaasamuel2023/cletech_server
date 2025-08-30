// ==================== routes/profile.js ====================
// Complete User Profile Routes with View & Update

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const { body, validationResult } = require('express-validator');
const { 
  User, 
  DataPurchase, 
  Transaction, 
  AgentStore,
  Notification,
  AgentProfit ,
  ApiKey

} = require('../../Schema/Schema');
const { protect, asyncHandler } = require('../../middleware/middleware');

// ==================== FILE UPLOAD CONFIGURATION ====================
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/profiles/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'profile-' + req.user._id + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// ==================== VALIDATION MIDDLEWARE ====================
const validateProfileUpdate = [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('username')
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscores and hyphens'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('phoneNumber')
    .optional()
    .matches(/^(\+233|0)[2-9]\d{8}$/)
    .withMessage('Please provide a valid Ghana phone number')
];

const validatePasswordChange = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  body('confirmPassword')
    .custom((value, { req }) => value === req.body.newPassword)
    .withMessage('Passwords do not match')
];

const validateSecuritySettings = [
  body('twoFactorEnabled')
    .optional()
    .isBoolean()
    .withMessage('Two factor enabled must be a boolean')
];

// ==================== MAIN ROUTES ====================

// 1. GET USER PROFILE - Complete user information
router.get('/profile', protect, asyncHandler(async (req, res) => {
  try {
    // Get user with populated fields
    const user = await User.findById(req.user._id)
      .select('-password -resetPasswordOTP -resetPasswordOTPExpiry')
      .populate('parentAgent', 'name email phoneNumber role')
      .populate('agentStore');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Get additional statistics
    const [purchaseStats, transactionStats, agentProfitStats, unreadNotifications] = await Promise.all([
      // Purchase statistics
      DataPurchase.aggregate([
        { $match: { userId: user._id } },
        {
          $group: {
            _id: null,
            totalPurchases: { $sum: 1 },
            totalSpent: { $sum: '$price' },
            completedPurchases: {
              $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
            },
            pendingPurchases: {
              $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
            }
          }
        }
      ]),

      // Transaction statistics
      Transaction.aggregate([
        { $match: { userId: user._id, status: 'completed' } },
        {
          $group: {
            _id: '$type',
            count: { $sum: 1 },
            total: { $sum: '$amount' }
          }
        }
      ]),

      // Agent profit statistics (if user is an agent)
      user.role === 'agent' || user.role === 'super_agent' ? 
        AgentProfit.aggregate([
          { $match: { agentId: user._id } },
          {
            $group: {
              _id: null,
              totalProfit: { $sum: '$profit' },
              pendingProfit: {
                $sum: { $cond: [{ $eq: ['$status', 'pending'] }, '$profit', 0] }
              },
              creditedProfit: {
                $sum: { $cond: [{ $eq: ['$status', 'credited'] }, '$profit', 0] }
              },
              totalSales: { $sum: 1 }
            }
          }
        ]) : null,

      // Unread notifications count
      Notification.countDocuments({ 
        userId: user._id, 
        read: false 
      })
    ]);

    // Format transaction stats
    const transactionSummary = {};
    transactionStats.forEach(stat => {
      transactionSummary[stat._id] = {
        count: stat.count,
        total: stat.total
      };
    });

    // Build response object
    const profileData = {
      // Basic Information
      id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
      phoneNumber: user.phoneNumber,
      profilePicture: user.profilePicture,
      
      // Role & Hierarchy
      role: user.role,
      parentAgent: user.parentAgent,
      
      // Financial Information
      walletBalance: user.walletBalance,
      commission: user.commission,
      agentProfit: user.agentProfit,
      totalEarnings: user.totalEarnings,
      creditLimit: user.creditLimit,
      
      // Account Status
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneVerified,
      twoFactorEnabled: user.twoFactorEnabled,
      approvalStatus: user.approvalStatus,
      isDisabled: user.isDisabled,
      disableReason: user.disableReason,
      
      // API Access
      apiAccess: user.apiAccess,
      
      // Store Information (if agent)
      store: user.agentStore || null,
      
      // Statistics
      statistics: {
        purchases: purchaseStats[0] || {
          totalPurchases: 0,
          totalSpent: 0,
          completedPurchases: 0,
          pendingPurchases: 0
        },
        transactions: transactionSummary,
        agentProfits: agentProfitStats?.[0] || null,
        unreadNotifications
      },
      
      // Timestamps
      memberSince: user.createdAt,
      lastLogin: user.lastLogin,
      lastUpdated: user.updatedAt
    };

    res.json({
      success: true,
      data: profileData
    });

  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 2. UPDATE USER PROFILE - Update basic information
router.put('/profile', protect, validateProfileUpdate, asyncHandler(async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const userId = req.user._id;
    const allowedUpdates = ['name', 'username', 'email', 'phoneNumber'];
    const updates = {};

    // Filter allowed fields
    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    // Check if username is already taken
    if (updates.username) {
      const existingUsername = await User.findOne({ 
        username: updates.username.toLowerCase(),
        _id: { $ne: userId }
      });

      if (existingUsername) {
        return res.status(400).json({
          success: false,
          message: 'Username is already taken'
        });
      }
    }

    // Check if email is already taken
    if (updates.email) {
      const existingEmail = await User.findOne({ 
        email: updates.email.toLowerCase(),
        _id: { $ne: userId }
      });

      if (existingEmail) {
        return res.status(400).json({
          success: false,
          message: 'Email is already registered'
        });
      }

      // Mark email as unverified if changed
      updates.emailVerified = false;
    }

    // Check if phone number is already taken
    if (updates.phoneNumber) {
      const existingPhone = await User.findOne({ 
        phoneNumber: updates.phoneNumber,
        _id: { $ne: userId }
      });

      if (existingPhone) {
        return res.status(400).json({
          success: false,
          message: 'Phone number is already registered'
        });
      }

      // Mark phone as unverified if changed
      updates.phoneVerified = false;
    }

    // Update user
    const user = await User.findByIdAndUpdate(
      userId,
      { 
        $set: updates,
        updatedAt: new Date()
      },
      { 
        new: true, 
        runValidators: true 
      }
    ).select('-password -resetPasswordOTP -resetPasswordOTPExpiry');

    // Create notification
    await Notification.create({
      userId,
      title: 'Profile Updated',
      message: 'Your profile information has been successfully updated',
      type: 'success',
      category: 'account'
    });

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        id: user._id,
        username: user.username,
        name: user.name,
        email: user.email,
        phoneNumber: user.phoneNumber,
        emailVerified: user.emailVerified,
        phoneVerified: user.phoneVerified
      }
    });

  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 3. UPDATE PROFILE PICTURE
router.post('/profile/picture', protect, upload.single('profilePicture'), asyncHandler(async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'Please upload an image file'
      });
    }

    // Update user's profile picture
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { 
        profilePicture: `/uploads/profiles/${req.file.filename}`,
        updatedAt: new Date()
      },
      { new: true }
    ).select('profilePicture name');

    res.json({
      success: true,
      message: 'Profile picture updated successfully',
      data: {
        profilePicture: user.profilePicture
      }
    });

  } catch (error) {
    console.error('Profile picture update error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update profile picture',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 4. CHANGE PASSWORD
router.put('/profile/password', protect, validatePasswordChange, asyncHandler(async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const { currentPassword, newPassword } = req.body;
    const userId = req.user._id;

    // Get user with password
    const user = await User.findById(userId).select('+password');

    // Check current password
    const isPasswordCorrect = await user.comparePassword(currentPassword);
    if (!isPasswordCorrect) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Update password
    user.password = newPassword;
    user.lastPasswordReset = new Date();
    await user.save();

    // Create notification
    await Notification.create({
      userId,
      title: 'Password Changed',
      message: 'Your password has been successfully changed. If you did not make this change, please contact support immediately.',
      type: 'warning',
      category: 'security',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Password changed successfully. Please login with your new password.'
    });

  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to change password',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 5. UPDATE SECURITY SETTINGS
router.put('/profile/security', protect, validateSecuritySettings, asyncHandler(async (req, res) => {
  try {
    const { twoFactorEnabled } = req.body;
    const userId = req.user._id;

    const updates = {};
    
    if (twoFactorEnabled !== undefined) {
      updates.twoFactorEnabled = twoFactorEnabled;
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { 
        $set: updates,
        updatedAt: new Date()
      },
      { new: true }
    ).select('twoFactorEnabled emailVerified phoneVerified');

    // Create notification
    await Notification.create({
      userId,
      title: 'Security Settings Updated',
      message: `Two-factor authentication has been ${twoFactorEnabled ? 'enabled' : 'disabled'}`,
      type: 'info',
      category: 'security'
    });

    res.json({
      success: true,
      message: 'Security settings updated successfully',
      data: {
        twoFactorEnabled: user.twoFactorEnabled,
        emailVerified: user.emailVerified,
        phoneVerified: user.phoneVerified
      }
    });

  } catch (error) {
    console.error('Security settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update security settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 6. GET ACCOUNT SUMMARY - Quick overview
router.get('/profile/summary', protect, asyncHandler(async (req, res) => {
  try {
    const userId = req.user._id;

    // Get recent purchases
    const recentPurchases = await DataPurchase.find({ userId })
      .sort({ createdAt: -1 })
      .limit(5)
      .select('network capacity price status createdAt phoneNumber');

    // Get recent transactions
    const recentTransactions = await Transaction.find({ userId })
      .sort({ createdAt: -1 })
      .limit(5)
      .select('type amount status description createdAt');

    // Get today's spending
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const todaySpending = await DataPurchase.aggregate([
      {
        $match: {
          userId,
          createdAt: { $gte: today },
          status: 'completed'
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$price' }
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        quickStats: {
          walletBalance: req.user.walletBalance,
          totalEarnings: req.user.totalEarnings,
          agentProfit: req.user.agentProfit,
          todaySpending: todaySpending[0]?.total || 0
        },
        recentPurchases,
        recentTransactions
      }
    });

  } catch (error) {
    console.error('Summary error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch account summary',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 7. DELETE PROFILE PICTURE
router.delete('/profile/picture', protect, asyncHandler(async (req, res) => {
  try {
    await User.findByIdAndUpdate(
      req.user._id,
      { 
        $unset: { profilePicture: 1 },
        updatedAt: new Date()
      }
    );

    res.json({
      success: true,
      message: 'Profile picture removed successfully'
    });

  } catch (error) {
    console.error('Picture deletion error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove profile picture',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 8. REQUEST ACCOUNT VERIFICATION
router.post('/profile/request-verification', protect, asyncHandler(async (req, res) => {
  try {
    const { verificationType } = req.body;

    if (!['email', 'phone'].includes(verificationType)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid verification type'
      });
    }

    // Generate verification code (implement actual sending logic)
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store verification code with expiry (implement in schema if needed)
    // For now, just create a notification
    await Notification.create({
      userId: req.user._id,
      title: 'Verification Code',
      message: `Your verification code is: ${verificationCode}`,
      type: 'info',
      category: 'account',
      priority: 'high',
      expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });

    res.json({
      success: true,
      message: `Verification code sent to your ${verificationType}`,
      data: {
        verificationType,
        expiresIn: '10 minutes'
      }
    });

  } catch (error) {
    console.error('Verification request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send verification code',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 9. GET REFERRAL INFO (if user is under an agent)
router.get('/profile/referral', protect, asyncHandler(async (req, res) => {
  try {
    if (!req.user.parentAgent) {
      return res.json({
        success: true,
        data: {
          hasReferrer: false
        }
      });
    }

    const referrer = await User.findById(req.user.parentAgent)
      .select('name email phoneNumber role');

    const referralBenefits = await DataPurchase.aggregate([
      {
        $match: {
          userId: req.user._id,
          agentId: req.user.parentAgent,
          status: 'completed'
        }
      },
      {
        $group: {
          _id: null,
          totalPurchases: { $sum: 1 },
          totalCommissionGenerated: { $sum: '$pricing.agentProfit' }
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        hasReferrer: true,
        referrer,
        benefits: referralBenefits[0] || {
          totalPurchases: 0,
          totalCommissionGenerated: 0
        }
      }
    });

  } catch (error) {
    console.error('Referral info error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch referral information',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 10. GET ACTIVITY LOG
router.get('/profile/activity', protect, asyncHandler(async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Combine purchases and transactions into activity feed
    const [purchases, transactions] = await Promise.all([
      DataPurchase.find({ userId: req.user._id })
        .sort({ createdAt: -1 })
        .limit(parseInt(limit))
        .skip(skip)
        .lean(),
      
      Transaction.find({ userId: req.user._id })
        .sort({ createdAt: -1 })
        .limit(parseInt(limit))
        .skip(skip)
        .lean()
    ]);

    // Merge and sort activities
    const activities = [
      ...purchases.map(p => ({
        type: 'purchase',
        description: `Purchased ${p.capacity}GB ${p.network} for ${p.phoneNumber}`,
        amount: p.price,
        status: p.status,
        timestamp: p.createdAt,
        reference: p.reference
      })),
      ...transactions.map(t => ({
        type: 'transaction',
        description: t.description || `${t.type} transaction`,
        amount: t.amount,
        status: t.status,
        timestamp: t.createdAt,
        reference: t.reference
      }))
    ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
     .slice(0, parseInt(limit));

    res.json({
      success: true,
      data: activities,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        hasMore: activities.length === parseInt(limit)
      }
    });

  } catch (error) {
    console.error('Activity log error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch activity log',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));


// Add these routes to your routes/profile.js file

// Import crypto for generating secure keys
const crypto = require('crypto');

// ==================== API KEY MANAGEMENT ROUTES ====================

// 11. GENERATE NEW API KEY
router.post('/profile/api-keys', protect, asyncHandler(async (req, res) => {
  try {
    const { name, description, permissions, webhookUrl } = req.body;
    const userId = req.user._id;

    // Validate input
    if (!name || name.trim().length < 3) {
      return res.status(400).json({
        success: false,
        message: 'API key name must be at least 3 characters'
      });
    }

    // Check if user has API access enabled
    if (!req.user.apiAccess?.enabled) {
      return res.status(403).json({
        success: false,
        message: 'API access is not enabled for your account. Please contact support.'
      });
    }

    // Check API key limit based on tier
    const existingKeysCount = await ApiKey.countDocuments({ 
      userId, 
      isActive: true 
    });

    const keyLimits = {
      basic: 3,
      premium: 10,
      enterprise: 50
    };

    const userTier = req.user.apiAccess?.tier || 'basic';
    const maxKeys = keyLimits[userTier];

    if (existingKeysCount >= maxKeys) {
      return res.status(400).json({
        success: false,
        message: `You have reached the maximum number of API keys (${maxKeys}) for your ${userTier} tier`
      });
    }

    // Generate secure API key
    const apiKey = `sk_${userTier}_${crypto.randomBytes(32).toString('hex')}`;

    // Set default permissions based on user role
    let defaultPermissions = ['read:products', 'read:balance'];
    
    if (req.user.role === 'admin') {
      defaultPermissions = ['read:all', 'write:all'];
    } else if (req.user.role === 'agent' || req.user.role === 'super_agent') {
      defaultPermissions = ['read:products', 'write:purchases', 'read:transactions', 'read:balance'];
    } else {
      defaultPermissions = ['read:products', 'write:purchases', 'read:transactions'];
    }

    // Create API key
    const newApiKey = await ApiKey.create({
      userId,
      key: apiKey,
      name: name.trim(),
      description: description?.trim(),
      permissions: permissions || defaultPermissions,
      rateLimit: {
        requests: req.user.apiAccess?.rateLimit || 100,
        period: '1m'
      },
      webhooks: webhookUrl ? {
        url: webhookUrl,
        secret: crypto.randomBytes(32).toString('hex'),
        events: ['purchase.completed', 'purchase.failed']
      } : undefined,
      expiresAt: userTier === 'basic' ? 
        new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) : // 1 year for basic
        null // No expiry for premium/enterprise
    });

    // Create notification
    await Notification.create({
      userId,
      title: 'API Key Created',
      message: `New API key "${name}" has been created successfully`,
      type: 'success',
      category: 'account'
    });

    res.status(201).json({
      success: true,
      message: 'API key generated successfully',
      data: {
        id: newApiKey._id,
        key: apiKey, // Only show this once during creation
        name: newApiKey.name,
        description: newApiKey.description,
        permissions: newApiKey.permissions,
        rateLimit: newApiKey.rateLimit,
        webhookSecret: newApiKey.webhooks?.secret,
        expiresAt: newApiKey.expiresAt,
        createdAt: newApiKey.createdAt
      },
      warning: 'Please save this API key securely. You will not be able to see it again.'
    });

  } catch (error) {
    console.error('API key generation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate API key',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 12. GET USER'S API KEYS
router.get('/profile/api-keys', protect, asyncHandler(async (req, res) => {
  try {
    const userId = req.user._id;
    const { page = 1, limit = 10, includeInactive = false } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Build filter
    const filter = { userId };
    if (!includeInactive) {
      filter.isActive = true;
    }

    // Get API keys (hide the actual key value)
    const apiKeys = await ApiKey.find(filter)
      .select('-key -webhooks.secret')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const total = await ApiKey.countDocuments(filter);

    // Add masked keys for display
    const keysWithMasked = apiKeys.map(key => {
      const keyObj = key.toObject();
      return {
        ...keyObj,
        keyPreview: `sk_${req.user.apiAccess?.tier || 'basic'}_****${key._id.toString().slice(-4)}`
      };
    });

    res.json({
      success: true,
      data: {
        apiKeys: keysWithMasked,
        pagination: {
          currentPage: parseInt(page),
          perPage: parseInt(limit),
          totalItems: total,
          totalPages: Math.ceil(total / parseInt(limit))
        },
        limits: {
          tier: req.user.apiAccess?.tier || 'basic',
          maxKeys: req.user.apiAccess?.tier === 'enterprise' ? 50 : 
                   req.user.apiAccess?.tier === 'premium' ? 10 : 3,
          currentKeys: total
        }
      }
    });

  } catch (error) {
    console.error('API keys fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch API keys',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 13. UPDATE API KEY
router.put('/profile/api-keys/:keyId', protect, asyncHandler(async (req, res) => {
  try {
    const { keyId } = req.params;
    const { name, description, permissions, ipWhitelist, webhookUrl, isActive } = req.body;
    const userId = req.user._id;

    // Find API key
    const apiKey = await ApiKey.findOne({ 
      _id: keyId, 
      userId 
    });

    if (!apiKey) {
      return res.status(404).json({
        success: false,
        message: 'API key not found'
      });
    }

    // Update allowed fields
    if (name) apiKey.name = name.trim();
    if (description !== undefined) apiKey.description = description?.trim();
    if (permissions && Array.isArray(permissions)) {
      // Validate permissions based on user role
      const allowedPermissions = req.user.role === 'admin' ? 
        ['read:all', 'write:all'] : 
        ['read:products', 'write:purchases', 'read:transactions', 'read:balance'];
      
      apiKey.permissions = permissions.filter(p => 
        allowedPermissions.includes(p) || p.includes('read:')
      );
    }
    if (ipWhitelist && Array.isArray(ipWhitelist)) {
      apiKey.ipWhitelist = ipWhitelist;
    }
    if (webhookUrl !== undefined) {
      if (webhookUrl) {
        apiKey.webhooks = {
          url: webhookUrl,
          secret: apiKey.webhooks?.secret || crypto.randomBytes(32).toString('hex'),
          events: ['purchase.completed', 'purchase.failed']
        };
      } else {
        apiKey.webhooks = undefined;
      }
    }
    if (typeof isActive === 'boolean') {
      apiKey.isActive = isActive;
    }

    await apiKey.save();

    res.json({
      success: true,
      message: 'API key updated successfully',
      data: {
        id: apiKey._id,
        name: apiKey.name,
        description: apiKey.description,
        permissions: apiKey.permissions,
        ipWhitelist: apiKey.ipWhitelist,
        webhookUrl: apiKey.webhooks?.url,
        isActive: apiKey.isActive,
        updatedAt: apiKey.updatedAt
      }
    });

  } catch (error) {
    console.error('API key update error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update API key',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 14. DELETE/REVOKE API KEY
router.delete('/profile/api-keys/:keyId', protect, asyncHandler(async (req, res) => {
  try {
    const { keyId } = req.params;
    const userId = req.user._id;

    // Find and delete API key
    const apiKey = await ApiKey.findOneAndDelete({ 
      _id: keyId, 
      userId 
    });

    if (!apiKey) {
      return res.status(404).json({
        success: false,
        message: 'API key not found'
      });
    }

    // Create notification
    await Notification.create({
      userId,
      title: 'API Key Deleted',
      message: `API key "${apiKey.name}" has been permanently deleted`,
      type: 'warning',
      category: 'security',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'API key deleted successfully',
      data: {
        deletedKey: apiKey.name
      }
    });

  } catch (error) {
    console.error('API key deletion error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete API key',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 15. REGENERATE API KEY
router.post('/profile/api-keys/:keyId/regenerate', protect, asyncHandler(async (req, res) => {
  try {
    const { keyId } = req.params;
    const userId = req.user._id;

    // Find API key
    const apiKey = await ApiKey.findOne({ 
      _id: keyId, 
      userId 
    });

    if (!apiKey) {
      return res.status(404).json({
        success: false,
        message: 'API key not found'
      });
    }

    // Generate new key
    const newKey = `sk_${req.user.apiAccess?.tier || 'basic'}_${crypto.randomBytes(32).toString('hex')}`;
    
    // Update key
    apiKey.key = newKey;
    apiKey.usageStats = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0
    };
    apiKey.lastUsed = null;
    await apiKey.save();

    // Create notification
    await Notification.create({
      userId,
      title: 'API Key Regenerated',
      message: `API key "${apiKey.name}" has been regenerated. Please update your applications.`,
      type: 'warning',
      category: 'security',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'API key regenerated successfully',
      data: {
        id: apiKey._id,
        key: newKey, // Only show once during regeneration
        name: apiKey.name
      },
      warning: 'Please save this new API key securely. The old key will no longer work.'
    });

  } catch (error) {
    console.error('API key regeneration error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to regenerate API key',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// 16. GET API KEY STATISTICS
router.get('/profile/api-keys/:keyId/stats', protect, asyncHandler(async (req, res) => {
  try {
    const { keyId } = req.params;
    const { period = '7d' } = req.query;
    const userId = req.user._id;

    // Find API key
    const apiKey = await ApiKey.findOne({ 
      _id: keyId, 
      userId 
    });

    if (!apiKey) {
      return res.status(404).json({
        success: false,
        message: 'API key not found'
      });
    }

    // Calculate date range
    let startDate = new Date();
    switch(period) {
      case '24h':
        startDate.setHours(startDate.getHours() - 24);
        break;
      case '7d':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(startDate.getDate() - 30);
        break;
      default:
        startDate.setDate(startDate.getDate() - 7);
    }

    // Get purchases made with this API key
    const purchases = await DataPurchase.aggregate([
      {
        $match: {
          'metadata.apiKeyId': apiKey._id,
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: null,
          totalPurchases: { $sum: 1 },
          totalAmount: { $sum: '$price' },
          successful: {
            $sum: { $cond: [{ $in: ['$status', ['completed', 'processing']] }, 1, 0] }
          },
          failed: {
            $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
          }
        }
      }
    ]);

    const stats = purchases[0] || {
      totalPurchases: 0,
      totalAmount: 0,
      successful: 0,
      failed: 0
    };

    res.json({
      success: true,
      data: {
        keyName: apiKey.name,
        period,
        usage: apiKey.usageStats,
        purchases: stats,
        lastUsed: apiKey.lastUsed,
        rateLimit: apiKey.rateLimit,
        isActive: apiKey.isActive
      }
    });

  } catch (error) {
    console.error('API key stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch API key statistics',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

module.exports = router;