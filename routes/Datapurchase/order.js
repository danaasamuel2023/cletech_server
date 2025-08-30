// ==================== routes/purchase.js ====================
// Complete Purchase Routes File with Bulk Purchase Features
const { adminOnly, asyncHandler, validate } = require('../../middleware/middleware');

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const multer = require('multer');
const XLSX = require('xlsx');

const { 
  DataPurchase, 
  User, 
  Transaction, 
  DataPricing, 
  DataInventory, 
  AgentStore, 
  AgentProfit 
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

// Optional authentication (for guest purchases)
const optionalAuth = async (req, res, next) => {
  try {
    let token;
    
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
      req.user = await User.findById(decoded.id).select('-password');
    }
    
    next();
  } catch (error) {
    // Continue without user
    next();
  }
};

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-excel',
      'text/csv'
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only Excel and CSV files are allowed.'));
    }
  }
});

// ==================== VALIDATION ====================
const validatePurchase = [
  body('phoneNumber')
    .trim()
    .matches(/^(\+233|0)[2-9]\d{8}$/)
    .withMessage('Invalid Ghana phone number format'),
  body('network')
    .isIn(['YELLO', 'MTN', 'TELECEL', 'AT_PREMIUM', 'AIRTELTIGO', 'AT'])
    .withMessage('Invalid network selected'),
  body('capacity')
    .isFloat({ min: 0.1, max: 100 })
    .withMessage('Capacity must be between 0.1 and 100 GB'),
  body('gateway')
    .isIn(['paystack', 'wallet'])
    .withMessage('Invalid payment method')
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

// ==================== HELPER FUNCTIONS ====================

// Generate unique reference
const generateReference = (prefix = 'REF') => {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 9).toUpperCase();
  return `${prefix}-${timestamp}-${random}`;
};

// Get user's price based on role
const getUserPrice = (pricing, userRole) => {
  const roleMap = {
    'admin': pricing.prices.adminCost,
    'dealer': pricing.prices.dealer,
    'super_agent': pricing.prices.superAgent,
    'agent': pricing.prices.agent,
    'user': pricing.prices.user
  };
  return roleMap[userRole] || pricing.prices.user;
};

// Check stock availability
const checkStockAvailability = async (network, capacity, method = 'web') => {
  try {
    // Check network-level inventory
    const inventory = await DataInventory.findOne({ network });
    if (!inventory || !inventory.inStock) {
      return { 
        available: false, 
        message: `${network} is currently out of stock` 
      };
    }

    // Check method-specific stock
    if (method === 'web' && !inventory.webInStock) {
      return { 
        available: false, 
        message: `${network} is out of stock for web purchases` 
      };
    }

    if (method === 'api' && !inventory.apiInStock) {
      return { 
        available: false, 
        message: `${network} is out of stock for API purchases` 
      };
    }

    // Check specific product pricing and stock
    const pricing = await DataPricing.findOne({
      network,
      capacity,
      isActive: true
    });

    if (!pricing) {
      return { 
        available: false, 
        message: `${capacity}GB for ${network} is not available` 
      };
    }

    if (!pricing.stock.overallInStock) {
      return { 
        available: false, 
        message: `${capacity}GB for ${network} is out of stock` 
      };
    }

    if (method === 'web' && !pricing.stock.webInStock) {
      return { 
        available: false, 
        message: `${capacity}GB for ${network} is out of stock for web purchases` 
      };
    }

    if (method === 'api' && !pricing.stock.apiInStock) {
      return { 
        available: false, 
        message: `${capacity}GB for ${network} is out of stock for API purchases` 
      };
    }

    return { available: true, pricing };
  } catch (error) {
    console.error('Stock check error:', error);
    return { 
      available: false, 
      message: 'Error checking stock availability' 
    };
  }
};

// Process wallet payment
const processWalletPayment = async (userId, amount, reference, purchase) => {
  try {
    const user = await User.findById(userId);
    
    if (user.walletBalance < amount) {
      throw new Error('Insufficient wallet balance');
    }

    // Deduct from wallet
    user.walletBalance -= amount;
    await user.save();

    // Create transaction record
    await Transaction.create({
      userId,
      type: 'purchase',
      amount,
      balanceBefore: user.walletBalance + amount,
      balanceAfter: user.walletBalance,
      reference,
      gateway: 'wallet',
      status: 'completed',
      relatedPurchaseId: purchase._id,
      description: `Data purchase: ${purchase.capacity}GB ${purchase.network}`
    });

    // Update purchase status to processing (not completed)
    purchase.status = 'processing';
    await purchase.save();

    return { success: true, newBalance: user.walletBalance };
  } catch (error) {
    throw error;
  }
};

// ==================== MAIN PURCHASE ROUTES ====================

// 1. Purchase data (authenticated users)
router.post('/buy', protect, validatePurchase, checkValidation, async (req, res) => {
  try {
    const { phoneNumber, network, capacity, gateway } = req.body;
    const userId = req.user._id;

    // Check stock availability
    const stockCheck = await checkStockAvailability(network, capacity, 'web');
    if (!stockCheck.available) {
      return res.status(400).json({
        success: false,
        message: stockCheck.message
      });
    }

    // Get user's price based on role
    const userPrice = getUserPrice(stockCheck.pricing, req.user.role);

    // Validate wallet balance if wallet payment
    if (gateway === 'wallet') {
      if (req.user.walletBalance < userPrice) {
        return res.status(400).json({
          success: false,
          message: 'Insufficient wallet balance',
          required: userPrice,
          currentBalance: req.user.walletBalance
        });
      }
    }

    // Generate reference
    const reference = generateReference('PURCHASE');

    // Create purchase record
    const purchase = await DataPurchase.create({
      userId,
      phoneNumber,
      network,
      capacity,
      gateway,
      method: 'web',
      price: userPrice,
      pricing: {
        systemPrice: userPrice,
        customerPrice: userPrice,
        agentProfit: 0
      },
      reference,
      status: gateway === 'wallet' ? 'processing' : 'pending'
    });

    // Process based on payment method
    if (gateway === 'wallet') {
      // Process wallet payment immediately
      const walletResult = await processWalletPayment(userId, userPrice, reference, purchase);
      
      res.json({
        success: true,
        message: 'Purchase successful',
        data: {
          reference: purchase.reference,
          amount: userPrice,
          network,
          capacity,
          phoneNumber,
          status: 'processing',  // Changed from 'completed' to 'processing'
          newBalance: walletResult.newBalance
        }
      });
    } else {
      // Initialize Paystack payment
      const paystackResponse = await axios.post(
        'https://api.paystack.co/transaction/initialize',
        {
          email: req.user.email,
          amount: userPrice * 100, // Convert to pesewas
          reference,
          metadata: {
            purchaseId: purchase._id,
            userId,
            network,
            capacity,
            phoneNumber
          },
          callback_url: `${process.env.FRONTEND_URL}/purchase/verify/${reference}`
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
          }
        }
      );

      res.json({
        success: true,
        message: 'Payment initialized',
        data: {
          reference: purchase.reference,
          amount: userPrice,
          network,
          capacity,
          phoneNumber,
          status: purchase.status,
          paymentUrl: paystackResponse.data.data.authorization_url,
          accessCode: paystackResponse.data.data.access_code
        }
      });
    }

  } catch (error) {
    console.error('Purchase error:', error);
    res.status(500).json({
      success: false,
      message: 'Purchase failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 2. Purchase through agent store (can be guest)
router.post('/store/:subdomain', optionalAuth, validatePurchase, checkValidation, async (req, res) => {
  try {
    const { subdomain } = req.params;
    const { phoneNumber, network, capacity, gateway, customerEmail, customerName } = req.body;

    // Find and validate agent store
    const store = await AgentStore.findOne({ 
      subdomain: subdomain.toLowerCase(),
      isActive: true
    }).populate('agent');

    if (!store) {
      return res.status(404).json({
        success: false,
        message: 'Store not found'
      });
    }

    // Check if store is open
    if (!store.operatingStatus.isOpen) {
      return res.status(400).json({
        success: false,
        message: 'Store is currently closed',
        reason: store.operatingStatus.closedReason,
        reopenAt: store.operatingStatus.reopenAt
      });
    }

    // Check stock availability
    const stockCheck = await checkStockAvailability(network, capacity, 'web');
    if (!stockCheck.available) {
      return res.status(400).json({
        success: false,
        message: stockCheck.message
      });
    }

    // Find agent's custom pricing for this product
    const customPricing = store.customPricing.find(
      p => p.network === network && 
           p.capacity === capacity && 
           p.isActive === true
    );

    if (!customPricing) {
      return res.status(400).json({
        success: false,
        message: 'This product is not available in this store'
      });
    }

    // Calculate pricing
    const systemPrice = customPricing.systemPrice;
    const agentPrice = customPricing.agentPrice;
    const agentProfit = agentPrice - systemPrice;

    // Generate reference
    const reference = generateReference('STORE');

    // Create purchase record
    const purchase = await DataPurchase.create({
      userId: req.user?._id || null,
      agentId: store.agent._id,
      phoneNumber,
      network,
      capacity,
      gateway,
      method: 'agent_store',
      price: agentPrice,
      pricing: {
        systemPrice,
        agentPrice,
        customerPrice: agentPrice,
        agentProfit
      },
      reference,
      status: 'pending',
      storeInfo: {
        storeId: store._id,
        storeName: store.storeName,
        subdomain: store.subdomain
      },
      customerInfo: {
        name: customerName || 'Guest',
        email: customerEmail || 'guest@customer.com'
      }
    });

    // Create pending agent profit record
    const agentProfitRecord = await AgentProfit.create({
      agentId: store.agent._id,
      purchaseId: purchase._id,
      customerId: req.user?._id || null,
      network,
      capacity,
      systemPrice,
      agentPrice,
      profit: agentProfit,
      profitPercentage: (agentProfit / systemPrice) * 100,
      status: 'pending'
    });

    // Update store statistics
    store.statistics.totalOrders += 1;
    await store.save();

    // Initialize Paystack payment
    const paystackResponse = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: customerEmail || req.user?.email || `guest_${Date.now()}@customer.com`,
        amount: agentPrice * 100, // Convert to pesewas
        reference,
        metadata: {
          purchaseId: purchase._id,
          agentId: store.agent._id,
          agentProfitId: agentProfitRecord._id,
          network,
          capacity,
          phoneNumber,
          storeName: store.storeName
        },
        callback_url: `${process.env.FRONTEND_URL}/store/${subdomain}/verify/${reference}`
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
        }
      }
    );

    res.json({
      success: true,
      message: 'Payment initialized',
      data: {
        reference: purchase.reference,
        amount: agentPrice,
        network,
        capacity,
        phoneNumber,
        storeName: store.storeName,
        status: purchase.status,
        paymentUrl: paystackResponse.data.data.authorization_url,
        accessCode: paystackResponse.data.data.access_code
      }
    });

  } catch (error) {
    console.error('Store purchase error:', error);
    res.status(500).json({
      success: false,
      message: 'Purchase failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 3. Verify payment (Paystack callback)
router.get('/verify/:reference', async (req, res) => {
  try {
    const { reference } = req.params;

    // Find purchase or check for batch reference
    let purchases = await DataPurchase.find({ batchReference: reference });
    
    if (!purchases || purchases.length === 0) {
      const singlePurchase = await DataPurchase.findOne({ reference });
      if (!singlePurchase) {
        return res.status(404).json({
          success: false,
          message: 'Purchase not found'
        });
      }
      purchases = [singlePurchase];
    }

    // If already processing or completed, return success
    if (purchases.every(p => p.status === 'processing' || p.status === 'completed')) {
      return res.json({
        success: true,
        message: 'Payment already verified',
        data: {
          reference,
          status: 'processing',
          amount: purchases.reduce((sum, p) => sum + p.price, 0)
        }
      });
    }

    // Verify with Paystack
    const verifyResponse = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
        }
      }
    );

    const paymentData = verifyResponse.data.data;

    if (paymentData.status === 'success') {
      // Update all purchases status to processing (not completed)
      for (const purchase of purchases) {
        purchase.status = 'processing';  // Changed from 'completed' to 'processing'
        purchase.paystackReference = paymentData.reference;
        await purchase.save();

        // Handle agent profit if it's a store purchase
        if (purchase.method === 'agent_store' && purchase.agentId) {
          // Credit agent profit
          const agent = await User.findById(purchase.agentId);
          agent.agentProfit += purchase.pricing.agentProfit;
          agent.totalEarnings += purchase.pricing.agentProfit;
          await agent.save();

          // Update agent profit record
          await AgentProfit.findOneAndUpdate(
            { purchaseId: purchase._id },
            { 
              status: 'credited',
              creditedAt: new Date()
            }
          );

          // Update store statistics
          await AgentStore.findOneAndUpdate(
            { agent: purchase.agentId },
            {
              $inc: {
                'statistics.totalSales': 1,
                'statistics.totalRevenue': purchase.price,
                'statistics.totalProfit': purchase.pricing.agentProfit,
                'statistics.totalCustomers': 1
              },
              'statistics.lastSaleDate': new Date()
            }
          );
        }
      }

      // Create transaction record
      const totalAmount = purchases.reduce((sum, p) => sum + p.price, 0);
      await Transaction.create({
        userId: purchases[0].userId || purchases[0].agentId,
        type: purchases.length > 1 ? 'bulk_purchase' : 'purchase',
        amount: totalAmount,
        reference,
        gateway: 'paystack',
        status: 'completed',
        relatedPurchaseId: purchases[0]._id,
        description: purchases.length > 1 
          ? `Bulk data purchase: ${purchases.length} items`
          : `Data purchase: ${purchases[0].capacity}GB ${purchases[0].network}`
      });

      res.json({
        success: true,
        message: 'Payment verified successfully',
        data: {
          reference,
          status: 'processing',  // Changed from 'completed' to 'processing'
          amount: totalAmount,
          totalItems: purchases.length,
          purchases: purchases.map(p => ({
            network: p.network,
            capacity: p.capacity,
            phoneNumber: p.phoneNumber,
            price: p.price
          }))
        }
      });
    } else {
      // Payment failed
      for (const purchase of purchases) {
        purchase.status = 'failed';
        await purchase.save();
      }

      res.status(400).json({
        success: false,
        message: 'Payment verification failed',
        status: paymentData.status
      });
    }

  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Verification failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 4. Get purchase history
router.get('/history', protect, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, network, from, to } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Build filter
    const filter = { userId: req.user._id };
    if (status) filter.status = status;
    if (network) filter.network = network;
    
    if (from || to) {
      filter.createdAt = {};
      if (from) filter.createdAt.$gte = new Date(from);
      if (to) filter.createdAt.$lte = new Date(to);
    }

    // Get purchases
    const purchases = await DataPurchase.find(filter)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip)
      .populate('agentId', 'name phoneNumber')
      .select('reference phoneNumber network capacity price status method createdAt storeInfo batchReference');

    const total = await DataPurchase.countDocuments(filter);

    // Calculate summary
    const summary = await DataPurchase.aggregate([
      { $match: filter },
      {
        $group: {
          _id: null,
          totalSpent: { $sum: '$price' },
          totalPurchases: { $sum: 1 },
          completedPurchases: {
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
          }
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        purchases,
        summary: summary[0] || {
          totalSpent: 0,
          totalPurchases: 0,
          completedPurchases: 0
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
    console.error('History error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch purchase history',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 5. Get single purchase details
router.get('/details/:reference', protect, async (req, res) => {
  try {
    const { reference } = req.params;

    const purchase = await DataPurchase.findOne({ 
      reference,
      $or: [
        { userId: req.user._id },
        { agentId: req.user._id }
      ]
    })
    .populate('userId', 'name email phoneNumber')
    .populate('agentId', 'name email phoneNumber')
    .populate('storeInfo.storeId');

    if (!purchase) {
      return res.status(404).json({
        success: false,
        message: 'Purchase not found'
      });
    }

    res.json({
      success: true,
      data: purchase
    });

  } catch (error) {
    console.error('Details error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch purchase details',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 6. Get available products with pricing
router.get('/products', optionalAuth, async (req, res) => {
  try {
    const { network, inStockOnly = 'true' } = req.query;

    // Build filter
    const filter = { isActive: true };
    if (network) filter.network = network;
    if (inStockOnly === 'true') {
      filter['stock.overallInStock'] = true;
    }

    // Get products
    const products = await DataPricing.find(filter)
      .select('network capacity prices stock description tags isPopular promoPrice')
      .sort({ network: 1, capacity: 1 });

    // Format products with user's price
    const userRole = req.user?.role || 'user';
    
    const formattedProducts = products.map(product => {
      const userPrice = getUserPrice(product, userRole);
      const hasPromo = product.promoPrice && product.promoPrice < userPrice;
      
      return {
        id: product._id,
        network: product.network,
        capacity: product.capacity,
        price: hasPromo ? product.promoPrice : userPrice,
        originalPrice: hasPromo ? userPrice : null,
        description: product.description,
        tags: product.tags,
        isPopular: product.isPopular,
        inStock: product.stock.overallInStock,
        stockStatus: {
          web: product.stock.webInStock,
          api: product.stock.apiInStock
        }
      };
    });

    // Group by network
    const groupedProducts = formattedProducts.reduce((acc, product) => {
      if (!acc[product.network]) {
        acc[product.network] = [];
      }
      acc[product.network].push(product);
      return acc;
    }, {});

    res.json({
      success: true,
      data: {
        products: formattedProducts,
        grouped: groupedProducts,
        userRole,
        total: formattedProducts.length
      }
    });

  } catch (error) {
    console.error('Products error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch products',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 7. Cancel pending purchase
router.post('/cancel/:reference', protect, async (req, res) => {
  try {
    const { reference } = req.params;

    const purchase = await DataPurchase.findOne({
      reference,
      userId: req.user._id,
      status: 'pending'
    });

    if (!purchase) {
      return res.status(404).json({
        success: false,
        message: 'Pending purchase not found'
      });
    }

    // Update status
    purchase.status = 'cancelled';
    await purchase.save();

    res.json({
      success: true,
      message: 'Purchase cancelled successfully',
      data: {
        reference: purchase.reference,
        status: purchase.status
      }
    });

  } catch (error) {
    console.error('Cancel error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to cancel purchase',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 8. Retry failed purchase
router.post('/retry/:reference', protect, async (req, res) => {
  try {
    const { reference } = req.params;

    const purchase = await DataPurchase.findOne({
      reference,
      userId: req.user._id,
      status: 'failed'
    });

    if (!purchase) {
      return res.status(404).json({
        success: false,
        message: 'Failed purchase not found'
      });
    }

    // Generate new reference
    const newReference = generateReference('RETRY');
    
    // Create new purchase with same details
    const newPurchase = await DataPurchase.create({
      ...purchase.toObject(),
      _id: undefined,
      reference: newReference,
      status: 'pending',
      createdAt: new Date()
    });

    // Initialize new payment
    const paystackResponse = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: req.user.email,
        amount: purchase.price * 100,
        reference: newReference,
        metadata: {
          purchaseId: newPurchase._id,
          retry: true,
          originalReference: reference
        }
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
        }
      }
    );

    res.json({
      success: true,
      message: 'Retry initiated',
      data: {
        reference: newReference,
        amount: purchase.price,
        paymentUrl: paystackResponse.data.data.authorization_url
      }
    });

  } catch (error) {
    console.error('Retry error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retry purchase',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 9. Bulk Purchase Route
router.post('/bulk', protect, async (req, res) => {
  try {
    console.log('Bulk purchase request received');
    console.log('Request body:', req.body);
    console.log('User:', req.user.email, req.user._id);
    
    const { purchases, network, gateway = 'wallet' } = req.body;
    
    if (!purchases || !Array.isArray(purchases) || purchases.length === 0) {
      console.log('Invalid purchases array:', purchases);
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid purchases array'
      });
    }

    if (purchases.length > 100) {
      return res.status(400).json({
        success: false,
        message: 'Maximum 100 purchases allowed per request'
      });
    }

    // Validate and prepare purchases
    const validatedPurchases = [];
    const errors = [];
    let totalCost = 0;

    for (let i = 0; i < purchases.length; i++) {
      const purchase = purchases[i];
      console.log(`Processing purchase ${i + 1}:`, purchase);
      
      // Validate phone number - be more flexible with format
      let phoneNumber = purchase.phoneNumber?.toString().trim();
      if (!phoneNumber) {
        errors.push({
          index: i,
          phoneNumber: purchase.phoneNumber,
          error: 'Missing phone number'
        });
        continue;
      }

      // Clean phone number
      phoneNumber = phoneNumber.replace(/\D/g, '');
      if (phoneNumber.startsWith('233')) {
        phoneNumber = '0' + phoneNumber.substring(3);
      } else if (!phoneNumber.startsWith('0')) {
        phoneNumber = '0' + phoneNumber;
      }

      // Validate format
      if (!/^0[2-9]\d{8}$/.test(phoneNumber)) {
        errors.push({
          index: i,
          phoneNumber: purchase.phoneNumber,
          error: 'Invalid phone number format'
        });
        continue;
      }

      // Validate capacity
      const capacity = parseFloat(purchase.capacity);
      if (!capacity || capacity < 0.1 || capacity > 100) {
        errors.push({
          index: i,
          phoneNumber: phoneNumber,
          error: 'Invalid capacity (must be between 0.1 and 100 GB)'
        });
        continue;
      }

      // Use network from purchase or fall back to provided network
      const purchaseNetwork = purchase.network || network || 'MTN';
      
      // Check stock and get pricing
      const stockCheck = await checkStockAvailability(purchaseNetwork, capacity, 'web');
      
      if (!stockCheck.available) {
        errors.push({
          index: i,
          phoneNumber: phoneNumber,
          error: stockCheck.message
        });
        continue;
      }

      const userPrice = getUserPrice(stockCheck.pricing, req.user.role);
      totalCost += userPrice;

      validatedPurchases.push({
        phoneNumber: phoneNumber,
        network: purchaseNetwork,
        capacity,
        price: userPrice,
        pricing: stockCheck.pricing
      });
    }

    console.log('Validation complete:', {
      valid: validatedPurchases.length,
      errors: errors.length,
      totalCost
    });

    // Check if any valid purchases
    if (validatedPurchases.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid purchases found',
        errors
      });
    }

    // Check wallet balance if wallet payment
    if (gateway === 'wallet') {
      // Refresh user data to get latest balance
      const user = await User.findById(req.user._id);
      console.log('User wallet balance:', user.walletBalance, 'Total cost:', totalCost);
      
      if (user.walletBalance < totalCost) {
        return res.status(400).json({
          success: false,
          message: 'Insufficient wallet balance',
          required: totalCost,
          currentBalance: user.walletBalance,
          validPurchases: validatedPurchases.length,
          errors
        });
      }

      // Generate batch reference
      const batchReference = generateReference('BULK');
      const purchaseIds = [];

      // Create purchase records
      for (const validPurchase of validatedPurchases) {
        const purchase = await DataPurchase.create({
          userId: user._id,
          phoneNumber: validPurchase.phoneNumber,
          network: validPurchase.network,
          capacity: validPurchase.capacity,
          gateway,
          method: 'bulk_web',
          price: validPurchase.price,
          pricing: {
            systemPrice: validPurchase.price,
            customerPrice: validPurchase.price,
            agentProfit: 0
          },
          reference: generateReference('PURCHASE'),
          batchReference,
          status: 'processing'
        });
        purchaseIds.push(purchase._id);
      }

      // Process wallet payment
      user.walletBalance -= totalCost;
      await user.save();

      // Create transaction record
      await Transaction.create({
        userId: user._id,
        type: 'bulk_purchase',
        amount: totalCost,
        balanceBefore: user.walletBalance + totalCost,
        balanceAfter: user.walletBalance,
        reference: batchReference,
        gateway: 'wallet',
        status: 'completed',
        description: `Bulk data purchase: ${validatedPurchases.length} items`
      });

      // Update all purchases to processing (not completed)
      await DataPurchase.updateMany(
        { _id: { $in: purchaseIds } },
        { status: 'processing' }
      );

      res.json({
        success: true,
        message: 'Bulk purchase successful',
        data: {
          batchReference,
          totalPurchases: validatedPurchases.length,
          totalCost,
          newBalance: user.walletBalance,
          purchases: validatedPurchases.map(p => ({
            phoneNumber: p.phoneNumber,
            network: p.network,
            capacity: p.capacity,
            price: p.price
          })),
          errors: errors.length > 0 ? errors : undefined
        }
      });
    } else {
      // Initialize Paystack payment
      const paystackResponse = await axios.post(
        'https://api.paystack.co/transaction/initialize',
        {
          email: req.user.email,
          amount: totalCost * 100,
          reference: batchReference,
          metadata: {
            type: 'bulk_purchase',
            purchaseIds,
            userId: req.user._id,
            totalItems: validatedPurchases.length
          },
          callback_url: `${process.env.FRONTEND_URL}/purchase/verify/${batchReference}`
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
          }
        }
      );

      res.json({
        success: true,
        message: 'Payment initialized',
        data: {
          batchReference,
          totalPurchases: validatedPurchases.length,
          totalCost,
          purchases: validatedPurchases,
          errors: errors.length > 0 ? errors : undefined,
          paymentUrl: paystackResponse.data.data.authorization_url,
          accessCode: paystackResponse.data.data.access_code
        }
      });
    }

  } catch (error) {
    console.error('Bulk purchase error:', error);
    res.status(500).json({
      success: false,
      message: 'Bulk purchase failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 10. Parse Excel/CSV for bulk purchase
router.post('/parse-excel', protect, upload.single('file'), async (req, res) => {
  try {
    // Debug logging
    console.log('File upload request received');
    console.log('File:', req.file);
    console.log('Body:', req.body);

    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded. Make sure the field name is "file"'
      });
    }

    const { network } = req.body;

    // Check file type
    const fileType = req.file.mimetype;
    console.log('File type:', fileType);

    // Parse the file based on type
    let data;
    try {
      if (fileType === 'text/csv' || fileType === 'application/csv' || fileType === 'text/plain') {
        // For CSV files, convert to Excel format first
        const csvText = req.file.buffer.toString('utf8');
        const workbook = XLSX.read(csvText, { type: 'string' });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        data = XLSX.utils.sheet_to_json(sheet, { raw: false });
      } else {
        // For Excel files
        const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        data = XLSX.utils.sheet_to_json(sheet, { raw: false });
      }
    } catch (parseError) {
      console.error('File parsing error:', parseError);
      return res.status(400).json({
        success: false,
        message: 'Failed to parse file. Please ensure it is a valid Excel or CSV file.'
      });
    }

    console.log('Parsed data rows:', data.length);

    if (!data || data.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No data found in file'
      });
    }

    // Process and validate data
    const purchases = [];
    const errors = [];

    for (let i = 0; i < data.length; i++) {
      const row = data[i];
      console.log('Processing row:', i + 1, row);
      
      // Try to extract phone number and capacity from different possible column names
      let phoneNumber = row['Phone Number'] || row['phone'] || row['phoneNumber'] || 
                       row['Phone'] || row['Number'] || row['Mobile'] || row['Tel'];
      
      let capacity = row['Capacity'] || row['capacity'] || row['GB'] || row['Data'] || 
                    row['Amount'] || row['Size'] || row['Package'] || row['Capacity (GB)'];
      
      let rowNetwork = row['Network'] || row['network'] || row['Provider'] || row['Carrier'] ||
                      row['Network (Optional)'];

      // Clean and validate phone number
      if (phoneNumber) {
        phoneNumber = phoneNumber.toString().replace(/\D/g, '');
        if (phoneNumber.startsWith('233')) {
          phoneNumber = '0' + phoneNumber.substring(3);
        } else if (!phoneNumber.startsWith('0')) {
          phoneNumber = '0' + phoneNumber;
        }
      }

      // Parse capacity
      if (capacity) {
        capacity = parseFloat(capacity.toString().replace(/[^\d.]/g, ''));
      }

      // Validate
      if (!phoneNumber) {
        errors.push({
          row: i + 2, // Excel rows start at 1, plus header
          error: 'Missing phone number'
        });
        continue;
      }

      if (!capacity || capacity <= 0) {
        errors.push({
          row: i + 2,
          error: 'Missing or invalid capacity'
        });
        continue;
      }

      // Use provided network or default
      const finalNetwork = rowNetwork || network || 'MTN';

      purchases.push({
        phoneNumber,
        capacity,
        network: finalNetwork
      });
    }

    console.log('Valid purchases:', purchases.length);
    console.log('Errors:', errors.length);

    res.json({
      success: true,
      data: {
        purchases,
        errors,
        totalRows: data.length,
        validPurchases: purchases.length,
        invalidRows: errors.length
      }
    });

  } catch (error) {
    console.error('Excel parsing error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to parse file',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 11. Get bulk purchase template
router.get('/bulk-template', (req, res) => {
  try {
    // Create a sample Excel template
    const templateData = [
      { 'Phone Number': '0241234567', 'Capacity (GB)': '2', 'Network (Optional)': 'MTN' },
      { 'Phone Number': '0551234567', 'Capacity (GB)': '5', 'Network (Optional)': 'TELECEL' },
      { 'Phone Number': '0261234567', 'Capacity (GB)': '1', 'Network (Optional)': 'AT' }
    ];

    const ws = XLSX.utils.json_to_sheet(templateData);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Bulk Purchase Template');

    // Generate buffer
    const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=bulk-purchase-template.xlsx');
    res.send(buffer);

  } catch (error) {
    console.error('Template generation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate template'
    });
  }
});

// Get pricing
router.get('/pricing', asyncHandler(async (req, res) => {
  const { 
    network, 
    capacity, 
    inStockOnly, 
    isActive = 'true',
    sortBy = 'network',
    order = 'asc' 
  } = req.query;

  // Build filter
  const filter = {};
  
  if (network) filter.network = network;
  if (capacity) filter.capacity = parseFloat(capacity);
  if (isActive !== undefined) filter.isActive = isActive === 'true';
  
  if (inStockOnly === 'true') {
    filter['stock.overallInStock'] = true;
  }

  try {
    // Fetch pricing data
    const pricingData = await DataPricing.find(filter)
      .populate('lastUpdatedBy', 'name email')
      .sort({ [sortBy]: order === 'desc' ? -1 : 1 });

    // Get statistics
    const stats = {
      total: pricingData.length,
      inStock: pricingData.filter(p => p.stock?.overallInStock).length,
      outOfStock: pricingData.filter(p => !p.stock?.overallInStock).length,
      webInStock: pricingData.filter(p => p.stock?.webInStock).length,
      apiInStock: pricingData.filter(p => p.stock?.apiInStock).length,
      popular: pricingData.filter(p => p.isPopular).length
    };

    // Calculate average margins
    const margins = pricingData.map(p => {
      const adminCost = p.prices.adminCost;
      const userPrice = p.prices.user;
      return ((userPrice - adminCost) / adminCost) * 100;
    });
    
    stats.avgMargin = margins.length > 0 
      ? (margins.reduce((a, b) => a + b, 0) / margins.length).toFixed(2)
      : 0;

    res.status(200).json({
      success: true,
      data: pricingData,
      stats,
      count: pricingData.length
    });
  } catch (error) {
    console.error('Error fetching pricing:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch pricing data',
      error: error.message
    });
  }
}));

module.exports = router;