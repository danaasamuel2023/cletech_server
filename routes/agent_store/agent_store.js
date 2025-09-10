// ==================== routes/agentStore.js ====================
// Complete Agent Store Management Routes File with Paystack Withdrawal Integration

const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');
const { 
  AgentStore, 
  User, 
  DataPricing, 
  AgentProfit,
  DataPurchase,
  Transaction 
} = require('../../Schema/Schema');
const SystemSettings = require('../../settingsSchema/schema');

// ==================== MIDDLEWARE ====================
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

// Authentication middleware
const protect = async (req, res, next) => {
  try {
    let token;
    
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Please login to access this route'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
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

// Check if user has a store
const hasStore = async (req, res, next) => {
  try {
    const store = await AgentStore.findOne({ agent: req.user._id });
    
    if (!store) {
      return res.status(404).json({
        success: false,
        message: 'You do not have a store. Please create one first.'
      });
    }

    req.store = store;
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Error checking store'
    });
  }
};

// ==================== PAYSTACK CONFIGURATION ====================
// Get Paystack configuration from settings (uses regular API key for withdrawals)
const getPaystackConfig = async () => {
  try {
    const settings = await SystemSettings.getSettings();
    
    if (!settings.paymentGateway?.paystack?.enabled) {
      throw new Error('Paystack payment gateway is disabled');
    }
    
    // Use regular secret key for withdrawals (not stores API key)
    const secretKey = settings.paymentGateway.paystack.secretKey || process.env.PAYSTACK_SECRET_KEY;
    const publicKey = settings.paymentGateway.paystack.publicKey || process.env.PAYSTACK_PUBLIC_KEY;
    
    if (!secretKey || !publicKey) {
      throw new Error('Paystack keys not configured');
    }
    
    return {
      secretKey,
      publicKey,
      webhookUrl: settings.paymentGateway.paystack.webhookUrl,
      transactionFee: settings.paymentGateway.paystack.transactionFee || 1.95,
      capAt: settings.paymentGateway.paystack.capAt || 100
    };
  } catch (error) {
    console.error('Paystack config error:', error);
    // Fallback to environment variables
    return {
      secretKey: process.env.PAYSTACK_SECRET_KEY,
      publicKey: process.env.PAYSTACK_PUBLIC_KEY,
      webhookUrl: process.env.PAYSTACK_WEBHOOK_URL,
      transactionFee: 1.95,
      capAt: 100
    };
  }
};

// Create Paystack API instance
const getPaystackAPI = async () => {
  const config = await getPaystackConfig();
  
  return axios.create({
    baseURL: 'https://api.paystack.co',
    headers: {
      'Authorization': `Bearer ${config.secretKey}`,
      'Content-Type': 'application/json'
    }
  });
};

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/stores/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// ==================== VALIDATION ====================
const validateStoreCreation = [
  body('storeName')
    .trim()
    .notEmpty().withMessage('Store name is required')
    .isLength({ min: 3, max: 50 }).withMessage('Store name must be 3-50 characters'),
  body('subdomain')
    .trim()
    .notEmpty().withMessage('Subdomain is required')
    .isLength({ min: 3, max: 30 }).withMessage('Subdomain must be 3-30 characters')
    .matches(/^[a-z0-9-]+$/).withMessage('Subdomain can only contain lowercase letters, numbers, and hyphens'),
  body('whatsappNumber')
    .trim()
    .notEmpty().withMessage('WhatsApp number is required')
    .matches(/^(\+233|0)[2-9]\d{8}$/).withMessage('Invalid Ghana WhatsApp number'),
  body('whatsappGroupLink')
    .trim()
    .notEmpty().withMessage('WhatsApp group link is required')
    .matches(/^https:\/\/chat\.whatsapp\.com\/[A-Za-z0-9]+$/).withMessage('Invalid WhatsApp group link format. Must be a valid WhatsApp group invite link'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 }).withMessage('Description must not exceed 500 characters'),
  body('contactEmail')
    .optional()
    .trim()
    .isEmail().withMessage('Invalid email format'),
  body('alternativePhone')
    .optional()
    .trim()
    .matches(/^(\+233|0)[2-9]\d{8}$/).withMessage('Invalid Ghana phone number')
];

const validatePricing = [
  body('network')
    .isIn(['YELLO', 'MTN', 'TELECEL', 'AT_PREMIUM', 'AIRTELTIGO', 'AT'])
    .withMessage('Invalid network'),
  body('capacity')
    .isFloat({ min: 0.1, max: 100 })
    .withMessage('Invalid capacity'),
  body('price')
    .isFloat({ min: 0 })
    .withMessage('Price must be a positive number')
];

const validateBankAccount = [
  body('accountNumber')
    .trim()
    .notEmpty().withMessage('Account number is required')
    .matches(/^\d{10,}$/).withMessage('Invalid account number format'),
  body('bankCode')
    .trim()
    .notEmpty().withMessage('Bank code is required'),
  body('accountName')
    .trim()
    .notEmpty().withMessage('Account name is required')
];

const validateWithdrawal = [
  body('amount')
    .isFloat({ min: 10 }).withMessage('Minimum withdrawal amount is 10 GHS'),
  body('reason')
    .optional()
    .trim()
    .isLength({ max: 200 }).withMessage('Reason must not exceed 200 characters')
];

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

// ==================== STORE MANAGEMENT ROUTES ====================

// 1. Create store
router.post('/create', protect, validateStoreCreation, checkValidation, async (req, res) => {
  try {
    const { 
      storeName, 
      subdomain, 
      whatsappNumber,
      whatsappGroupLink,
      description,
      contactEmail,
      alternativePhone 
    } = req.body;

    // Check if user already has a store
    const existingStore = await AgentStore.findOne({ agent: req.user._id });
    if (existingStore) {
      return res.status(400).json({
        success: false,
        message: 'You already have a store',
        store: {
          id: existingStore._id,
          storeName: existingStore.storeName,
          subdomain: existingStore.subdomain,
          url: `${process.env.BASE_URL || 'http://localhost:5000'}/${existingStore.subdomain}`,
          whatsappGroupLink: existingStore.whatsappGroupLink
        }
      });
    }

    // Check subdomain availability
    const subdomainTaken = await AgentStore.findOne({ 
      subdomain: subdomain.toLowerCase() 
    });
    
    if (subdomainTaken) {
      return res.status(400).json({
        success: false,
        message: 'This subdomain is already taken. Please choose another.'
      });
    }

    // Create store
    const store = await AgentStore.create({
      agent: req.user._id,
      storeName,
      subdomain: subdomain.toLowerCase(),
      whatsappNumber,
      whatsappGroupLink,
      description: description || '',
      contactEmail: contactEmail || req.user.email,
      alternativePhone: alternativePhone || '',
      operatingStatus: {
        isOpen: true,
        temporarilyClosed: false
      },
      settings: {
        showPrices: true,
        allowBulkOrders: true,
        minimumOrder: 1,
        autoReplyEnabled: false,
        requireRegistration: false,
        maintenanceMode: false
      },
      statistics: {
        totalSales: 0,
        totalOrders: 0,
        totalCustomers: 0,
        totalRevenue: 0,
        totalProfit: 0,
        todayProfit: 0,
        weekProfit: 0,
        monthProfit: 0,
        rating: 0,
        reviewCount: 0
      },
      isActive: true,
      verificationStatus: 'pending'
    });

    console.log(`New store created: ${store.subdomain} by user: ${req.user._id}`);

    res.status(201).json({
      success: true,
      message: 'Store created successfully',
      data: {
        id: store._id,
        storeName: store.storeName,
        subdomain: store.subdomain,
        url: `${process.env.BASE_URL || 'http://localhost:5000'}/${store.subdomain}`,
        whatsappNumber: store.whatsappNumber,
        whatsappGroupLink: store.whatsappGroupLink,
        isActive: store.isActive,
        verificationStatus: store.verificationStatus
      }
    });

  } catch (error) {
    console.error('Store creation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create store',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 2. Get my store details
router.get('/my-store', protect, async (req, res) => {
  try {
    const store = await AgentStore.findOne({ agent: req.user._id });
    
    if (!store) {
      return res.status(404).json({
        success: false,
        message: 'Store not found. Please create a store first.'
      });
    }

    // Get store with populated statistics
    const storeData = store.toObject();

    // Get today's profit
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const todayProfit = await AgentProfit.aggregate([
      {
        $match: {
          agentId: req.user._id,
          status: 'credited',
          creditedAt: { $gte: today }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$profit' }
        }
      }
    ]);

    // Get this week's profit
    const weekStart = new Date();
    weekStart.setDate(weekStart.getDate() - weekStart.getDay());
    weekStart.setHours(0, 0, 0, 0);
    
    const weekProfit = await AgentProfit.aggregate([
      {
        $match: {
          agentId: req.user._id,
          status: 'credited',
          creditedAt: { $gte: weekStart }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$profit' }
        }
      }
    ]);

    // Get this month's profit
    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);
    
    const monthProfit = await AgentProfit.aggregate([
      {
        $match: {
          agentId: req.user._id,
          status: 'credited',
          creditedAt: { $gte: monthStart }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$profit' }
        }
      }
    ]);

    // Add profit statistics
    storeData.profitStats = {
      today: todayProfit[0]?.total || 0,
      week: weekProfit[0]?.total || 0,
      month: monthProfit[0]?.total || 0,
      total: storeData.statistics?.totalProfit || 0
    };

    // Include bank details if available
    storeData.bankDetails = req.user.bankDetails ? {
      hasAccount: true,
      accountNumber: req.user.bankDetails.accountNumber?.slice(0, 3) + '****' + req.user.bankDetails.accountNumber?.slice(-3),
      accountName: req.user.bankDetails.accountName,
      bankCode: req.user.bankDetails.bankCode,
      isVerified: req.user.bankDetails.isVerified
    } : { hasAccount: false };

    res.json({
      success: true,
      data: storeData
    });

  } catch (error) {
    console.error('Get store error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch store details',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 3. Update store settings
router.patch('/settings', protect, hasStore, async (req, res) => {
  try {
    const allowedUpdates = [
      'storeName',
      'description',
      'whatsappNumber',
      'whatsappGroupLink',
      'contactEmail',
      'alternativePhone',
      'businessHours',
      'location',
      'settings'
    ];

    const updates = {};
    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    // Validate WhatsApp group link if it's being updated
    if (updates.whatsappGroupLink) {
      const whatsappGroupRegex = /^https:\/\/chat\.whatsapp\.com\/[A-Za-z0-9]+$/;
      if (!whatsappGroupRegex.test(updates.whatsappGroupLink)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid WhatsApp group link format'
        });
      }
    }

    // Validate WhatsApp number if it's being updated
    if (updates.whatsappNumber) {
      const phoneRegex = /^(\+233|0)[2-9]\d{8}$/;
      if (!phoneRegex.test(updates.whatsappNumber)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid Ghana WhatsApp number'
        });
      }
    }

    // Validate email if it's being updated
    if (updates.contactEmail) {
      const emailRegex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
      if (!emailRegex.test(updates.contactEmail)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid email format'
        });
      }
    }

    // Update store
    Object.assign(req.store, updates);
    await req.store.save();

    res.json({
      success: true,
      message: 'Store settings updated successfully',
      data: {
        id: req.store._id,
        storeName: req.store.storeName,
        subdomain: req.store.subdomain,
        whatsappNumber: req.store.whatsappNumber,
        whatsappGroupLink: req.store.whatsappGroupLink,
        contactEmail: req.store.contactEmail,
        alternativePhone: req.store.alternativePhone,
        description: req.store.description,
        businessHours: req.store.businessHours,
        location: req.store.location,
        settings: req.store.settings
      }
    });

  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update store settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 4. Upload store images (logo and banner)
router.post('/upload-images', protect, hasStore, upload.fields([
  { name: 'logo', maxCount: 1 },
  { name: 'banner', maxCount: 1 }
]), async (req, res) => {
  try {
    const updates = {};
    
    if (req.files.logo) {
      updates.logo = `/uploads/stores/${req.files.logo[0].filename}`;
    }
    
    if (req.files.banner) {
      updates.bannerImage = `/uploads/stores/${req.files.banner[0].filename}`;
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No images provided'
      });
    }

    Object.assign(req.store, updates);
    await req.store.save();

    res.json({
      success: true,
      message: 'Images uploaded successfully',
      data: {
        logo: req.store.logo,
        bannerImage: req.store.bannerImage
      }
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload images',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 5. Set/Update custom pricing
router.post('/pricing', protect, hasStore, validatePricing, checkValidation, async (req, res) => {
  try {
    const { network, capacity, price } = req.body;

    // Get system pricing for this product
    const systemPricing = await DataPricing.findOne({ 
      network, 
      capacity,
      isActive: true
    });

    if (!systemPricing) {
      return res.status(404).json({
        success: false,
        message: 'This product is not available in the system'
      });
    }

    // Get user's system price based on their role
    const roleMap = {
      'admin': systemPricing.prices.adminCost,
      'dealer': systemPricing.prices.dealer,
      'super_agent': systemPricing.prices.superAgent,
      'agent': systemPricing.prices.agent,
      'user': systemPricing.prices.user
    };
    
    const systemPrice = roleMap[req.user.role] || systemPricing.prices.user;

    // Validate price
    if (price < systemPrice) {
      return res.status(400).json({
        success: false,
        message: 'Your selling price cannot be below your system price',
        data: {
          systemPrice,
          yourPrice: price,
          minimumAllowed: systemPrice
        }
      });
    }

    // Check if pricing already exists
    const existingPricing = req.store.customPricing.find(
      p => p.network === network && p.capacity === capacity
    );

    if (existingPricing) {
      // Update existing pricing
      existingPricing.systemPrice = systemPrice;
      existingPricing.agentPrice = price;
      existingPricing.profit = price - systemPrice;
      existingPricing.isActive = true;
    } else {
      // Add new pricing
      req.store.customPricing.push({
        network,
        capacity,
        systemPrice,
        agentPrice: price,
        profit: price - systemPrice,
        isActive: true
      });
    }

    await req.store.save();

    const profit = price - systemPrice;
    const profitMargin = ((profit / systemPrice) * 100).toFixed(2);

    res.json({
      success: true,
      message: 'Pricing updated successfully',
      data: {
        network,
        capacity,
        systemPrice,
        yourPrice: price,
        profit,
        profitMargin: `${profitMargin}%`
      }
    });

  } catch (error) {
    console.error('Pricing error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update pricing',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 6. Get all custom pricing
router.get('/pricing', protect, hasStore, async (req, res) => {
  try {
    const { isActive } = req.query;
    
    let pricing = req.store.customPricing;
    
    if (isActive !== undefined) {
      pricing = pricing.filter(p => p.isActive === (isActive === 'true'));
    }

    // Sort by network and capacity
    pricing.sort((a, b) => {
      if (a.network !== b.network) {
        return a.network.localeCompare(b.network);
      }
      return a.capacity - b.capacity;
    });

    res.json({
      success: true,
      data: pricing,
      total: pricing.length
    });

  } catch (error) {
    console.error('Get pricing error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch pricing',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 7. Toggle pricing status
router.patch('/pricing/:network/:capacity/toggle', protect, hasStore, async (req, res) => {
  try {
    const { network, capacity } = req.params;
    
    const pricing = req.store.customPricing.find(
      p => p.network === network && p.capacity === parseFloat(capacity)
    );

    if (!pricing) {
      return res.status(404).json({
        success: false,
        message: 'Pricing not found'
      });
    }

    pricing.isActive = !pricing.isActive;
    await req.store.save();

    res.json({
      success: true,
      message: `Pricing ${pricing.isActive ? 'activated' : 'deactivated'}`,
      data: pricing
    });

  } catch (error) {
    console.error('Toggle pricing error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to toggle pricing',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 8. Open/Close store
router.patch('/toggle-status', protect, hasStore, async (req, res) => {
  try {
    const { isOpen, reason, reopenAt } = req.body;

    req.store.operatingStatus.isOpen = isOpen;
    
    if (!isOpen) {
      req.store.operatingStatus.closedReason = reason || 'Temporarily closed';
      req.store.operatingStatus.closedAt = new Date();
      req.store.operatingStatus.reopenAt = reopenAt ? new Date(reopenAt) : null;
    } else {
      req.store.operatingStatus.closedReason = null;
      req.store.operatingStatus.closedAt = null;
      req.store.operatingStatus.reopenAt = null;
    }

    await req.store.save();

    res.json({
      success: true,
      message: `Store ${isOpen ? 'opened' : 'closed'} successfully`,
      data: req.store.operatingStatus
    });

  } catch (error) {
    console.error('Toggle status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to toggle store status',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== PROFIT MANAGEMENT ROUTES ====================

// 9. Get agent profits
router.get('/profits', protect, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      status, 
      from, 
      to,
      network 
    } = req.query;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Build filter
    const filter = { agentId: req.user._id };
    if (status) filter.status = status;
    if (network) filter.network = network;
    
    if (from || to) {
      filter.createdAt = {};
      if (from) filter.createdAt.$gte = new Date(from);
      if (to) filter.createdAt.$lte = new Date(to);
    }

    // Get profits
    const profits = await AgentProfit.find(filter)
      .populate('purchaseId', 'reference phoneNumber')
      .populate('customerId', 'name phoneNumber email')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const total = await AgentProfit.countDocuments(filter);

    // Calculate summary
    const summary = await AgentProfit.aggregate([
      { $match: filter },
      {
        $group: {
          _id: null,
          totalProfit: { $sum: '$profit' },
          totalSales: { $sum: 1 },
          averageProfit: { $avg: '$profit' },
          pendingProfit: {
            $sum: {
              $cond: [{ $eq: ['$status', 'pending'] }, '$profit', 0]
            }
          },
          creditedProfit: {
            $sum: {
              $cond: [{ $eq: ['$status', 'credited'] }, '$profit', 0]
            }
          },
          withdrawnProfit: {
            $sum: {
              $cond: [{ $eq: ['$status', 'withdrawn'] }, '$profit', 0]
            }
          }
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        profits,
        summary: summary[0] || {
          totalProfit: 0,
          totalSales: 0,
          averageProfit: 0,
          pendingProfit: 0,
          creditedProfit: 0,
          withdrawnProfit: 0
        }
      },
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('Get profits error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profits',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== BANK ACCOUNT MANAGEMENT ROUTES ====================

// 10. Add bank account to user profile
router.post('/bank-account', protect, validateBankAccount, checkValidation, async (req, res) => {
  try {
    const { 
      accountNumber, 
      bankCode, 
      accountName 
    } = req.body;

    const paystackAPI = await getPaystackAPI();

    // Verify bank account with Paystack
    const verifyResponse = await paystackAPI.get(
      `/bank/resolve?account_number=${accountNumber}&bank_code=${bankCode}`
    );

    if (!verifyResponse.data.status) {
      return res.status(400).json({
        success: false,
        message: 'Unable to verify bank account'
      });
    }

    const verifiedAccountName = verifyResponse.data.data.account_name;

    // Create transfer recipient on Paystack
    const recipientResponse = await paystackAPI.post('/transferrecipient', {
      type: 'nuban',
      name: verifiedAccountName,
      account_number: accountNumber,
      bank_code: bankCode,
      currency: 'GHS', // Ghana Cedis
      description: `Agent withdrawal account for ${req.user.name}`
    });

    if (!recipientResponse.data.status) {
      return res.status(400).json({
        success: false,
        message: 'Failed to create transfer recipient'
      });
    }

    // Save bank details to user profile
    req.user.bankDetails = {
      accountNumber,
      bankCode,
      accountName: verifiedAccountName,
      recipientCode: recipientResponse.data.data.recipient_code,
      isVerified: true,
      addedAt: new Date()
    };

    await req.user.save();

    res.json({
      success: true,
      message: 'Bank account added successfully',
      data: {
        accountNumber: accountNumber.slice(0, 3) + '****' + accountNumber.slice(-3),
        accountName: verifiedAccountName,
        bankCode
      }
    });

  } catch (error) {
    console.error('Bank account error:', error.response?.data || error);
    res.status(500).json({
      success: false,
      message: error.response?.data?.message || 'Failed to add bank account'
    });
  }
});

// 11. Get saved bank accounts
router.get('/bank-accounts', protect, async (req, res) => {
  try {
    if (!req.user.bankDetails) {
      return res.status(404).json({
        success: false,
        message: 'No bank account found'
      });
    }

    res.json({
      success: true,
      data: {
        accountNumber: req.user.bankDetails.accountNumber.slice(0, 3) + '****' + req.user.bankDetails.accountNumber.slice(-3),
        accountName: req.user.bankDetails.accountName,
        bankCode: req.user.bankDetails.bankCode,
        isVerified: req.user.bankDetails.isVerified
      }
    });

  } catch (error) {
    console.error('Get bank accounts error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch bank accounts'
    });
  }
});

// 12. Get list of banks
router.get('/banks', protect, async (req, res) => {
  try {
    const paystackAPI = await getPaystackAPI();
    const response = await paystackAPI.get('/bank?country=ghana');
    
    if (!response.data.status) {
      throw new Error('Failed to fetch banks');
    }

    const banks = response.data.data.map(bank => ({
      id: bank.id,
      name: bank.name,
      code: bank.code,
      slug: bank.slug
    }));

    res.json({
      success: true,
      data: banks
    });

  } catch (error) {
    console.error('Get banks error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch banks'
    });
  }
});

// ==================== WITHDRAWAL ROUTES WITH PAYSTACK ====================

// 13. Withdraw profits via Paystack
// 13. Withdraw profits via Paystack - UPDATED VERSION
router.post('/withdraw-profit', protect, validateWithdrawal, checkValidation, async (req, res) => {
  try {
    const { 
      amount, 
      reason = 'Agent profit withdrawal',
      useSavedAccount = true,
      accountNumber,
      bankCode 
    } = req.body;

    // Check minimum withdrawal amount (10 GHS)
    const MIN_WITHDRAWAL = 10;
    if (amount < MIN_WITHDRAWAL) {
      return res.status(400).json({
        success: false,
        message: `Minimum withdrawal amount is ${MIN_WITHDRAWAL} GHS`
      });
    }

    // IMPORTANT FIX: Calculate actual available balance from AgentProfit records
    const actualBalanceResult = await AgentProfit.aggregate([
      {
        $match: {
          agentId: req.user._id,
          status: 'credited'
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$profit' }
        }
      }
    ]);

    const availableBalance = actualBalanceResult[0]?.total || 0;
    
    console.log(`Withdrawal attempt - Requested: ${amount}, Available: ${availableBalance}`);

    // Check against ACTUAL calculated balance, not user field
    if (amount > availableBalance) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient profit balance',
        data: {
          requested: amount,
          available: availableBalance
        }
      });
    }

    const paystackAPI = await getPaystackAPI();
    
    // Get recipient code
    let recipientCode;

    if (useSavedAccount) {
      // Use saved bank account
      if (!req.user.bankDetails || !req.user.bankDetails.recipientCode) {
        return res.status(400).json({
          success: false,
          message: 'No bank account found. Please add a bank account first.'
        });
      }
      recipientCode = req.user.bankDetails.recipientCode;
    } else {
      // Create one-time recipient
      if (!accountNumber || !bankCode) {
        return res.status(400).json({
          success: false,
          message: 'Please provide account number and bank code'
        });
      }

      // Verify account
      const verifyResponse = await paystackAPI.get(
        `/bank/resolve?account_number=${accountNumber}&bank_code=${bankCode}`
      );

      if (!verifyResponse.data.status) {
        return res.status(400).json({
          success: false,
          message: 'Unable to verify bank account'
        });
      }

      // Create temporary recipient
      const recipientResponse = await paystackAPI.post('/transferrecipient', {
        type: 'nuban',
        name: verifyResponse.data.data.account_name,
        account_number: accountNumber,
        bank_code: bankCode,
        currency: 'GHS'
      });

      if (!recipientResponse.data.status) {
        return res.status(400).json({
          success: false,
          message: 'Failed to create transfer recipient'
        });
      }

      recipientCode = recipientResponse.data.data.recipient_code;
    }

    // Generate unique reference
    const reference = `PROFIT-WD-${Date.now()}-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;

    // Create withdrawal record (pending) - use actual balance
    const withdrawal = await Transaction.create({
      userId: req.user._id,
      type: 'agent_profit_withdrawal',
      amount,
      balanceBefore: availableBalance,
      balanceAfter: availableBalance - amount,
      reference,
      gateway: 'paystack',
      status: 'pending',
      description: reason,
      withdrawalDetails: {
        recipientCode,
        accountNumber: req.user.bankDetails?.accountNumber || accountNumber,
        bankCode: req.user.bankDetails?.bankCode || bankCode
      }
    });

    // Initiate transfer with Paystack
    try {
      const transferResponse = await paystackAPI.post('/transfer', {
        source: 'balance',
        amount: amount * 100, // Convert to pesewas
        recipient: recipientCode,
        reason,
        reference
      });

      if (transferResponse.data.status && transferResponse.data.data.status === 'success') {
        // Transfer successful
        
        // Update agent profit records - mark the exact amount as withdrawn
        let remainingAmount = amount;
        const profitsToUpdate = await AgentProfit.find({
          agentId: req.user._id,
          status: 'credited'
        }).sort({ createdAt: 1 }); // Process oldest first

        for (const profit of profitsToUpdate) {
          if (remainingAmount <= 0) break;
          
          if (profit.profit <= remainingAmount) {
            // Withdraw entire profit record
            profit.status = 'withdrawn';
            profit.withdrawnAt = new Date();
            profit.withdrawalReference = reference;
            await profit.save();
            remainingAmount -= profit.profit;
          } else {
            // Partial withdrawal - split the record
            const withdrawnAmount = remainingAmount;
            const remainingProfit = profit.profit - withdrawnAmount;
            
            // Update original to withdrawn with partial amount
            profit.profit = withdrawnAmount;
            profit.status = 'withdrawn';
            profit.withdrawnAt = new Date();
            profit.withdrawalReference = reference;
            await profit.save();
            
            // Create new record for remaining credited amount
            await AgentProfit.create({
              agentId: profit.agentId,
              purchaseId: profit.purchaseId,
              customerId: profit.customerId,
              network: profit.network,
              capacity: profit.capacity,
              profit: remainingProfit,
              status: 'credited',
              creditedAt: profit.creditedAt
            });
            
            remainingAmount = 0;
          }
        }

        // Sync user's agentProfit field with actual balance
        const newBalanceResult = await AgentProfit.aggregate([
          {
            $match: {
              agentId: req.user._id,
              status: 'credited'
            }
          },
          {
            $group: {
              _id: null,
              total: { $sum: '$profit' }
            }
          }
        ]);
        
        req.user.agentProfit = newBalanceResult[0]?.total || 0;
        await req.user.save();

        // Update withdrawal record
        withdrawal.status = 'completed';
        withdrawal.gatewayResponse = transferResponse.data.data;
        withdrawal.completedAt = new Date();
        await withdrawal.save();

        res.json({
          success: true,
          message: 'Withdrawal successful',
          data: {
            reference,
            amount,
            status: 'success',
            transferCode: transferResponse.data.data.transfer_code,
            remainingProfit: req.user.agentProfit
          }
        });

      } else if (transferResponse.data.data.status === 'pending') {
        // Transfer pending (requires OTP or approval)
        withdrawal.status = 'processing';
        withdrawal.gatewayResponse = transferResponse.data.data;
        await withdrawal.save();

        res.json({
          success: true,
          message: 'Withdrawal is being processed',
          data: {
            reference,
            amount,
            status: 'pending',
            transferCode: transferResponse.data.data.transfer_code,
            message: 'Your withdrawal is being processed and will be completed shortly'
          }
        });

      } else {
        // Transfer failed
        throw new Error(transferResponse.data.message || 'Transfer failed');
      }

    } catch (transferError) {
      // Update withdrawal record as failed
      withdrawal.status = 'failed';
      withdrawal.failureReason = transferError.response?.data?.message || transferError.message;
      await withdrawal.save();

      throw transferError;
    }

  } catch (error) {
    console.error('Withdraw profit error:', error.response?.data || error);
    res.status(500).json({
      success: false,
      message: error.response?.data?.message || 'Failed to process withdrawal',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Add this new route to sync profit balances
router.post('/sync-profit-balance', protect, async (req, res) => {
  try {
    // Calculate actual credited profit from AgentProfit collection
    const profitSum = await AgentProfit.aggregate([
      {
        $match: {
          agentId: req.user._id,
          status: 'credited'
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$profit' }
        }
      }
    ]);

    const actualCreditedProfit = profitSum[0]?.total || 0;
    
    // Update user's agentProfit field to match
    req.user.agentProfit = actualCreditedProfit;
    await req.user.save();

    console.log(`Synced profit balance for user ${req.user._id}: ${actualCreditedProfit}`);

    res.json({
      success: true,
      message: 'Profit balance synchronized',
      data: {
        previousBalance: req.user.agentProfit,
        syncedBalance: actualCreditedProfit,
        userId: req.user._id
      }
    });
  } catch (error) {
    console.error('Sync profit balance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to sync profit balance',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 14. Webhook to handle Paystack transfer events
router.post('/webhook/paystack', async (req, res) => {
  try {
    const config = await getPaystackConfig();
    
    // Verify webhook signature
    const hash = crypto
      .createHmac('sha512', config.secretKey)
      .update(JSON.stringify(req.body))
      .digest('hex');

    if (hash !== req.headers['x-paystack-signature']) {
      return res.status(401).json({
        success: false,
        message: 'Invalid signature'
      });
    }

    const { event, data } = req.body;

    if (event === 'transfer.success') {
      // Update transaction status
      const transaction = await Transaction.findOne({
        reference: data.reference
      });

      if (transaction && transaction.status === 'processing') {
        transaction.status = 'completed';
        transaction.completedAt = new Date();
        transaction.gatewayResponse = data;
        await transaction.save();

        // Update user profit balance
        const user = await User.findById(transaction.userId);
        if (user) {
          user.agentProfit -= transaction.amount;
          await user.save();

          // Update agent profit records
          await AgentProfit.updateMany(
            {
              agentId: user._id,
              status: 'credited'
            },
            {
              status: 'withdrawn',
              withdrawnAt: new Date(),
              withdrawalReference: data.reference
            }
          );
        }
      }
    } else if (event === 'transfer.failed' || event === 'transfer.reversed') {
      // Handle failed or reversed transfer
      const transaction = await Transaction.findOne({
        reference: data.reference
      });

      if (transaction) {
        transaction.status = 'failed';
        transaction.failureReason = data.reason || 'Transfer failed';
        transaction.gatewayResponse = data;
        await transaction.save();
      }
    }

    res.json({ success: true });

  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({
      success: false,
      message: 'Webhook processing failed'
    });
  }
});

// 15. Get withdrawal history
router.get('/withdrawals', protect, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      status 
    } = req.query;

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const filter = {
      userId: req.user._id,
      type: 'agent_profit_withdrawal'
    };

    if (status) filter.status = status;

    const withdrawals = await Transaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const total = await Transaction.countDocuments(filter);

    res.json({
      success: true,
      data: withdrawals,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('Get withdrawals error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch withdrawals'
    });
  }
});

// ==================== ANALYTICS ROUTES ====================

// 16. Get store analytics
router.get('/analytics', protect, hasStore, async (req, res) => {
  try {
    const { period = '7days' } = req.query;

    let startDate = new Date();
    switch(period) {
      case 'today':
        startDate.setHours(0, 0, 0, 0);
        break;
      case '7days':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case '30days':
        startDate.setDate(startDate.getDate() - 30);
        break;
      case 'all':
        startDate = new Date(0);
        break;
    }

    // Get sales data
    const salesData = await DataPurchase.aggregate([
      {
        $match: {
          agentId: req.user._id,
          status: 'completed',
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }
          },
          sales: { $sum: 1 },
          revenue: { $sum: '$price' },
          profit: { $sum: '$pricing.agentProfit' }
        }
      },
      { $sort: { '_id.date': 1 } }
    ]);

    // Get top products
    const topProducts = await DataPurchase.aggregate([
      {
        $match: {
          agentId: req.user._id,
          status: 'completed',
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            network: '$network',
            capacity: '$capacity'
          },
          count: { $sum: 1 },
          revenue: { $sum: '$price' },
          profit: { $sum: '$pricing.agentProfit' }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);

    // Get customer analytics
    const customerData = await DataPurchase.aggregate([
      {
        $match: {
          agentId: req.user._id,
          status: 'completed',
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$phoneNumber',
          purchases: { $sum: 1 },
          totalSpent: { $sum: '$price' }
        }
      }
    ]);

    const repeatCustomers = customerData.filter(c => c.purchases > 1).length;
    const newCustomers = customerData.filter(c => c.purchases === 1).length;

    res.json({
      success: true,
      data: {
        period,
        salesChart: salesData,
        topProducts,
        customerMetrics: {
          total: customerData.length,
          new: newCustomers,
          repeat: repeatCustomers,
          repeatRate: customerData.length > 0 
            ? ((repeatCustomers / customerData.length) * 100).toFixed(2) 
            : 0
        },
        summary: {
          totalSales: salesData.reduce((sum, day) => sum + day.sales, 0),
          totalRevenue: salesData.reduce((sum, day) => sum + day.revenue, 0),
          totalProfit: salesData.reduce((sum, day) => sum + day.profit, 0)
        }
      }
    });

  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch analytics',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== PUBLIC ROUTES ====================

// 17. Get public store info
router.get('/public/:subdomain', async (req, res) => {
  try {
    const { subdomain } = req.params;

    const store = await AgentStore.findOne({
      subdomain: subdomain.toLowerCase(),
      isActive: true
    })
    .populate('agent', 'name phoneNumber')
    .select('-statistics -profitStats');

    if (!store) {
      return res.status(404).json({
        success: false,
        message: 'Store not found'
      });
    }

    // Filter out inactive pricing
    const activePricing = store.customPricing.filter(p => p.isActive);

    res.json({
      success: true,
      data: {
        id: store._id,
        storeName: store.storeName,
        description: store.description,
        logo: store.logo,
        bannerImage: store.bannerImage,
        whatsappNumber: store.whatsappNumber,
        whatsappGroupLink: store.whatsappGroupLink,
        contactEmail: store.contactEmail,
        alternativePhone: store.alternativePhone,
        businessHours: store.businessHours,
        location: store.location,
        pricing: activePricing,
        operatingStatus: store.operatingStatus,
        settings: {
          showPrices: store.settings.showPrices,
          allowBulkOrders: store.settings.allowBulkOrders,
          minimumOrder: store.settings.minimumOrder
        },
        agent: {
          name: store.agent.name,
          phoneNumber: store.agent.phoneNumber
        },
        rating: store.statistics.rating,
        reviewCount: store.statistics.reviewCount
      }
    });

  } catch (error) {
    console.error('Public store error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch store',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 18. Get store products (public)
router.get('/public/:subdomain/products', async (req, res) => {
  try {
    const { subdomain } = req.params;
    const { network } = req.query;

    const store = await AgentStore.findOne({
      subdomain: subdomain.toLowerCase(),
      isActive: true,
      'operatingStatus.isOpen': true
    });

    if (!store) {
      return res.status(404).json({
        success: false,
        message: 'Store not found or closed'
      });
    }

    // Get active pricing
    let pricing = store.customPricing.filter(p => p.isActive);
    
    if (network) {
      pricing = pricing.filter(p => p.network === network);
    }

    // Group by network
    const grouped = pricing.reduce((acc, item) => {
      if (!acc[item.network]) {
        acc[item.network] = [];
      }
      acc[item.network].push({
        id: `${item.network}-${item.capacity}`,
        capacity: item.capacity,
        price: item.agentPrice,
        network: item.network
      });
      return acc;
    }, {});

    res.json({
      success: true,
      data: {
        products: pricing.map(p => ({
          id: `${p.network}-${p.capacity}`,
          network: p.network,
          capacity: p.capacity,
          price: p.agentPrice
        })),
        grouped,
        total: pricing.length
      }
    });

  } catch (error) {
    console.error('Store products error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch products',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;