// ==================== AUTH MIDDLEWARE ====================
const jwt = require('jsonwebtoken');
const { User } = require('../Schema/Schema');

// Generate JWT Token
const generateToken = (userId) => {
  return jwt.sign(
    { id: userId },
    process.env.JWT_SECRET || 'your-secret-key',
    { expiresIn: '7d' }
  );
};

// Verify user is logged in
const protect = async (req, res, next) => {
  try {
    let token;

    // Get token from header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Please login to access this route'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Get user
    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if account is disabled
    if (user.isDisabled) {
      return res.status(403).json({
        success: false,
        message: 'Your account has been disabled'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }
};

// ==================== PRICING MIDDLEWARE ====================
const { DataPricing } = require('../Schema/Schema');

// Get user's price based on their role
const getUserPrice = async (req, res, next) => {
  try {
    const { network, capacity } = req.body;
    
    if (!network || !capacity) {
      return next(); // Skip if not a purchase request
    }

    // Find pricing for this product
    const pricing = await DataPricing.findOne({
      network,
      capacity,
      isActive: true
    });

    if (!pricing) {
      return res.status(404).json({
        success: false,
        message: 'Pricing not found for this product'
      });
    }

    // Get price based on user role (roles are only for pricing)
    let userPrice;
    switch(req.user.role) {
      case 'admin':
        userPrice = pricing.prices.adminCost;
        break;
      case 'dealer':
        userPrice = pricing.prices.dealer;
        break;
      case 'super_agent':
        userPrice = pricing.prices.superAgent;
        break;
      case 'agent':
        userPrice = pricing.prices.agent;
        break;
      default:
        userPrice = pricing.prices.user;
    }

    req.pricing = pricing;
    req.userPrice = userPrice;
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Error getting pricing'
    });
  }
};

// ==================== API KEY MIDDLEWARE ====================
const { ApiKey } = require('../Schema/Schema');

const checkApiKey = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
      return res.status(401).json({
        success: false,
        message: 'API key required'
      });
    }

    const key = await ApiKey.findOne({ 
      key: apiKey, 
      isActive: true 
    }).populate('userId');

    if (!key) {
      return res.status(401).json({
        success: false,
        message: 'Invalid API key'
      });
    }

    // Update usage
    key.lastUsed = new Date();
    key.usageStats.totalRequests += 1;
    await key.save();

    req.user = key.userId;
    req.apiKey = key;
    
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'API key error'
    });
  }
};

// ==================== VALIDATION MIDDLEWARE ====================
const { body, validationResult } = require('express-validator');

// Check validation errors
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array()
    });
  }
  next();
};

// Validate purchase request
const validatePurchase = [
  body('phoneNumber')
    .matches(/^(\+233|0)[2-9]\d{8}$/)
    .withMessage('Invalid Ghana phone number'),
  body('network')
    .isIn(['YELLO', 'MTN', 'TELECEL', 'AT_PREMIUM', 'AIRTELTIGO', 'AT'])
    .withMessage('Invalid network'),
  body('capacity')
    .isNumeric()
    .isFloat({ min: 0.1, max: 100 })
    .withMessage('Invalid capacity'),
  validate
];

// Validate user registration
const validateRegister = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be 2-50 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters'),
  body('phoneNumber')
    .matches(/^(\+233|0)[2-9]\d{8}$/)
    .withMessage('Invalid phone number'),
  validate
];

// ==================== AGENT STORE MIDDLEWARE ====================
const { AgentStore } = require('../Schema/Schema');

// Check if user has a store
const hasStore = async (req, res, next) => {
  try {
    const store = await AgentStore.findOne({ 
      agent: req.user._id,
      isActive: true
    });

    if (!store) {
      return res.status(404).json({
        success: false,
        message: 'Store not found'
      });
    }

    req.store = store;
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Store error'
    });
  }
};

// Get store by subdomain for public access
const getStore = async (req, res, next) => {
  try {
    const { subdomain } = req.params;
    
    const store = await AgentStore.findOne({ 
      subdomain,
      isActive: true
    }).populate('agent', 'name phoneNumber');

    if (!store) {
      return res.status(404).json({
        success: false,
        message: 'Store not found'
      });
    }

    if (!store.operatingStatus.isOpen) {
      return res.status(200).json({
        success: false,
        message: 'Store is temporarily closed',
        reason: store.operatingStatus.closedReason
      });
    }

    req.store = store;
    req.storeAgent = store.agent;
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Error finding store'
    });
  }
};

// Calculate agent profit for store purchases
const calculateProfit = async (req, res, next) => {
  try {
    if (!req.store) return next();

    const { network, capacity } = req.body;

    // Find agent's custom pricing
    const customPrice = req.store.customPricing.find(
      p => p.network === network && 
           p.capacity === capacity && 
           p.isActive
    );

    if (!customPrice) {
      return res.status(400).json({
        success: false,
        message: 'Product not available in this store'
      });
    }

    // Agent profit = Agent's selling price - Agent's system price
    const profit = customPrice.agentPrice - customPrice.systemPrice;

    req.agentPricing = {
      systemPrice: customPrice.systemPrice,
      agentPrice: customPrice.agentPrice,
      profit: profit
    };

    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Error calculating pricing'
    });
  }
};

// ==================== STOCK MIDDLEWARE ====================
const { DataInventory } = require('../Schema/Schema');

const checkStock = async (req, res, next) => {
  try {
    const { network, capacity, method = 'web' } = req.body;

    // Check network inventory
    const inventory = await DataInventory.findOne({ network });
    
    if (!inventory || !inventory.inStock) {
      return res.status(400).json({
        success: false,
        message: `${network} is out of stock`
      });
    }

    // Check pricing exists and stock status
    const pricing = await DataPricing.findOne({
      network,
      capacity,
      isActive: true
    });

    if (!pricing) {
      return res.status(400).json({
        success: false,
        message: `${capacity}GB ${network} not available`
      });
    }

    // Check stock
    if (!pricing.stock.overallInStock) {
      return res.status(400).json({
        success: false,
        message: `${capacity}GB ${network} is out of stock`
      });
    }

    if (method === 'web' && !pricing.stock.webInStock) {
      return res.status(400).json({
        success: false,
        message: 'Out of stock for web'
      });
    }

    if (method === 'api' && !pricing.stock.apiInStock) {
      return res.status(400).json({
        success: false,
        message: 'Out of stock for API'
      });
    }

    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Stock check error'
    });
  }
};

// ==================== WALLET MIDDLEWARE ====================
const checkBalance = async (req, res, next) => {
  try {
    const { gateway } = req.body;
    
    // Skip if not wallet payment
    if (gateway !== 'wallet') return next();

    const price = req.userPrice || req.agentPricing?.agentPrice;

    if (!price) {
      return res.status(400).json({
        success: false,
        message: 'Price not determined'
      });
    }

    if (req.user.walletBalance < price) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient wallet balance',
        required: price,
        balance: req.user.walletBalance
      });
    }

    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Balance check error'
    });
  }
};

// ==================== RATE LIMITING ====================
const rateLimit = require('express-rate-limit');

// FIX: General limiter - remove custom keyGenerator or let it use default
const generalLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // No custom keyGenerator - will use default which handles IPv6 properly
});

// FIX: Purchase limiter - no custom keyGenerator needed
const purchaseLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,
  message: 'Too many purchase attempts',
  standardHeaders: true,
  legacyHeaders: false,
  // No custom keyGenerator - will use default
});

// FIX: API limiter - properly handle custom key generation with IPv6 support
const apiLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: 'API rate limit exceeded',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // First check for API key
    if (req.apiKey && req.apiKey.key) {
      return req.apiKey.key;
    }
    
    // Fall back to IP address - express-rate-limit will handle IPv6 properly
    // when we return undefined/null for IP-based limiting
    return req.ip;
  },
  // Alternative: skip custom keyGenerator and use skip condition
  // skip: (req) => req.apiKey && req.apiKey.key,
});

// Alternative implementation using skip for API keys
const apiLimitAlternative = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: 'API rate limit exceeded',
  standardHeaders: true,
  legacyHeaders: false,
  // This will use the default IP-based key generator
  // but skip rate limiting if API key is present
  skip: (req) => {
    // You can implement custom logic here
    // For example, premium API keys might have no limits
    if (req.apiKey && req.apiKey.isPremium) {
      return true; // Skip rate limiting for premium keys
    }
    return false;
  }
});

// ==================== ERROR HANDLER ====================
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);

  // Mongoose duplicate key
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(400).json({
      success: false,
      message: `${field} already exists`
    });
  }

  // Validation error
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors).map(e => e.message).join(', ');
    return res.status(400).json({
      success: false,
      message
    });
  }

  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || 'Server error'
  });
};

// ==================== ASYNC WRAPPER ====================
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// ==================== ADMIN CHECK (Simple) ====================
// Only admin can access certain routes like setting prices
const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Admin access only'
    });
  }
  next();
};

// ==================== EXPORTS ====================
module.exports = {
  // Auth
  generateToken,
  protect,
  adminOnly,
  
  // Pricing
  getUserPrice,
  
  // API
  checkApiKey,
  
  // Validation
  validate,
  validatePurchase,
  validateRegister,
  
  // Store
  hasStore,
  getStore,
  calculateProfit,
  
  // Stock & Wallet
  checkStock,
  checkBalance,
  
  // Rate Limiting
  generalLimit,
  purchaseLimit,
  apiLimit,
  
  // Utils
  errorHandler,
  asyncHandler
};