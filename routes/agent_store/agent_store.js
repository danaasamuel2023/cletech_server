// ==================== routes/agentStore.js ====================
// Complete Agent Store Management Routes File with Required WhatsApp Group Link

const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const { 
  AgentStore, 
  User, 
  DataPricing, 
  AgentProfit,
  DataPurchase,
  Transaction 
} = require('../../Schema/Schema');

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

// 1. Create store - UPDATED WITH REQUIRED WHATSAPP GROUP LINK
router.post('/create', protect, validateStoreCreation, checkValidation, async (req, res) => {
  try {
    const { 
      storeName, 
      subdomain, 
      whatsappNumber,
      whatsappGroupLink, // Required field
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

    // Create store with required WhatsApp group link
    const store = await AgentStore.create({
      agent: req.user._id,
      storeName,
      subdomain: subdomain.toLowerCase(),
      whatsappNumber,
      whatsappGroupLink, // Required field
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

    // Log store creation
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

// 2. Get my store details - UPDATED TO INCLUDE WHATSAPP GROUP LINK
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

    // Ensure WhatsApp group link is included
    storeData.whatsappGroupLink = store.whatsappGroupLink;

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

// 3. Update store settings - UPDATED TO INCLUDE WHATSAPP GROUP LINK
router.patch('/settings', protect, hasStore, async (req, res) => {
  try {
    const allowedUpdates = [
      'storeName',
      'description',
      'whatsappNumber',
      'whatsappGroupLink', // Allow updating WhatsApp group link
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

// 10. Withdraw profits to wallet
router.post('/withdraw-profit', protect, async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid amount'
      });
    }

    // Check available profit
    if (req.user.agentProfit < amount) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient profit balance',
        data: {
          requested: amount,
          available: req.user.agentProfit
        }
      });
    }

    // Process withdrawal
    const balanceBefore = req.user.walletBalance;
    const profitBefore = req.user.agentProfit;

    // Update user balances
    req.user.agentProfit -= amount;
    req.user.walletBalance += amount;
    await req.user.save();

    // Create transaction record
    const reference = `PROFIT-${Date.now()}-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;
    
    await Transaction.create({
      userId: req.user._id,
      type: 'agent_profit',
      amount,
      balanceBefore,
      balanceAfter: req.user.walletBalance,
      reference,
      gateway: 'system',
      status: 'completed',
      description: `Agent profit withdrawal: ${amount} GHS`,
      profitDetails: {
        profit: amount
      }
    });

    // Update agent profit records
    await AgentProfit.updateMany(
      {
        agentId: req.user._id,
        status: 'credited'
      },
      {
        status: 'withdrawn',
        withdrawnAt: new Date(),
        withdrawalReference: reference
      }
    );

    res.json({
      success: true,
      message: 'Profit withdrawn to wallet successfully',
      data: {
        amount,
        reference,
        walletBalance: req.user.walletBalance,
        remainingProfit: req.user.agentProfit,
        previousWalletBalance: balanceBefore,
        previousProfit: profitBefore
      }
    });

  } catch (error) {
    console.error('Withdraw profit error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to withdraw profit',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== ANALYTICS ROUTES ====================

// 11. Get store analytics
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

// 12. Get public store info - UPDATED TO INCLUDE WHATSAPP GROUP LINK
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
        whatsappGroupLink: store.whatsappGroupLink, // Include WhatsApp group link
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

// 13. Get store products (public)
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