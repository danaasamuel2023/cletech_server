// ==================== routes/api/v1/purchase.js ====================
// API Routes for Developer Purchases
const express = require('express');
const router = express.Router();
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

// Import models
const { 
  DataPurchase, 
  User, 
  Transaction, 
  DataPricing, 
  DataInventory, 
  ApiKey,
  Notification
} = require('../../../Schema/Schema');

// Import System Settings
const SystemSettings = require('../../../settingsSchema/schema');

// Import middleware
const { 
  checkApiKey, 
  asyncHandler,
  apiLimit 
} = require('../../../middleware/middleware');

const { body, validationResult } = require('express-validator');

// ==================== HELPER FUNCTIONS ====================

// Get Paystack configuration from settings
const getPaystackConfig = async () => {
  try {
    const settings = await SystemSettings.getSettings();
    
    if (!settings.paymentGateway?.paystack?.enabled) {
      throw new Error('Paystack is not enabled');
    }
    
    if (!settings.paymentGateway?.paystack?.secretKey) {
      throw new Error('Paystack not configured');
    }
    
    return {
      secretKey: settings.paymentGateway.paystack.secretKey,
      publicKey: settings.paymentGateway.paystack.publicKey,
      transactionFee: settings.paymentGateway.paystack.transactionFee || 1.95,
      capAt: settings.paymentGateway.paystack.capAt || 100
    };
  } catch (error) {
    throw error;
  }
};

// Generate unique reference
const generateReference = (prefix = 'API') => {
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

// Check stock availability for API
const checkStockAvailability = async (network, capacity) => {
  try {
    // Check network-level inventory
    const inventory = await DataInventory.findOne({ network });
    if (!inventory || !inventory.inStock || !inventory.apiInStock) {
      return { 
        available: false, 
        message: `${network} is currently out of stock for API purchases` 
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

    if (!pricing.stock.overallInStock || !pricing.stock.apiInStock) {
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
const processWalletPayment = async (user, amount, reference, purchase) => {
  try {
    if (user.walletBalance < amount) {
      throw new Error('Insufficient wallet balance');
    }

    // Deduct from wallet
    user.walletBalance -= amount;
    await user.save();

    // Create transaction record
    await Transaction.create({
      userId: user._id,
      type: 'api_purchase',
      amount,
      balanceBefore: user.walletBalance + amount,
      balanceAfter: user.walletBalance,
      reference,
      gateway: 'wallet',
      status: 'completed',
      relatedPurchaseId: purchase._id,
      description: `API purchase: ${purchase.capacity}GB ${purchase.network}`
    });

    // Update purchase status to processing
    purchase.status = 'processing';
    await purchase.save();

    return { success: true, newBalance: user.walletBalance };
  } catch (error) {
    throw error;
  }
};

// Update API key stats
const updateApiKeyStats = async (apiKey, success = true) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    if (!apiKey.usageStats.dailyRequests) {
      apiKey.usageStats.dailyRequests = {};
    }
    
    const todayKey = today.toISOString().split('T')[0];
    
    if (!apiKey.usageStats.dailyRequests[todayKey]) {
      apiKey.usageStats.dailyRequests[todayKey] = {
        total: 0,
        successful: 0,
        failed: 0
      };
    }
    
    apiKey.usageStats.dailyRequests[todayKey].total += 1;
    
    if (success) {
      apiKey.usageStats.totalPurchases = (apiKey.usageStats.totalPurchases || 0) + 1;
      apiKey.usageStats.dailyRequests[todayKey].successful += 1;
    } else {
      apiKey.usageStats.dailyRequests[todayKey].failed += 1;
    }
    
    apiKey.lastUsed = new Date();
    await apiKey.save();
  } catch (error) {
    console.error('Error updating API key stats:', error);
  }
};

// ==================== API ROUTES ====================

// @route   GET /api/v1/purchase/products
// @desc    Get available products with API pricing
// @access  API Key Required
router.get('/products', apiLimit, checkApiKey, asyncHandler(async (req, res) => {
  const { network, in_stock_only = 'true' } = req.query;

  // Build filter
  const filter = { 
    isActive: true,
    'stock.apiInStock': true // Only show API stock
  };
  
  if (network) {
    filter.network = network.toUpperCase();
  }
  
  if (in_stock_only === 'true') {
    filter['stock.overallInStock'] = true;
  }

  // Get products
  const products = await DataPricing.find(filter)
    .select('network capacity prices stock description')
    .sort({ network: 1, capacity: 1 });

  // Format products with user's price
  const userRole = req.user?.role || 'user';
  
  const formattedProducts = products.map(product => {
    const userPrice = getUserPrice(product, userRole);
    
    return {
      network: product.network,
      capacity: product.capacity,
      price: userPrice,
      currency: 'GHS',
      description: product.description,
      in_stock: product.stock.apiInStock && product.stock.overallInStock
    };
  });

  res.json({
    success: true,
    data: {
      products: formattedProducts,
      total: formattedProducts.length,
      user_role: userRole
    }
  });
}));

// @route   POST /api/v1/purchase/single
// @desc    Make a single purchase via API
// @access  API Key Required
router.post('/single', 
  apiLimit,
  checkApiKey,
  [
    body('phone_number')
      .trim()
      .matches(/^(\+233|0)[2-9]\d{8}$/)
      .withMessage('Invalid Ghana phone number'),
    body('network')
      .isIn(['YELLO', 'MTN', 'TELECEL', 'AT_PREMIUM', 'AIRTELTIGO', 'AT'])
      .withMessage('Invalid network'),
    body('capacity')
      .isFloat({ min: 0.1, max: 100 })
      .withMessage('Capacity must be between 0.1 and 100 GB'),
    body('payment_method')
      .isIn(['wallet', 'paystack'])
      .withMessage('Invalid payment method'),
    body('callback_url')
      .optional()
      .isURL()
      .withMessage('Invalid callback URL')
  ],
  asyncHandler(async (req, res) => {
    // Validate request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      await updateApiKeyStats(req.apiKey, false);
      return res.status(400).json({
        success: false,
        errors: errors.array().map(e => ({
          field: e.param,
          message: e.msg
        }))
      });
    }

    const { phone_number, network, capacity, payment_method, callback_url, reference: customReference } = req.body;

    // Check stock availability
    const stockCheck = await checkStockAvailability(network, capacity);
    if (!stockCheck.available) {
      await updateApiKeyStats(req.apiKey, false);
      return res.status(400).json({
        success: false,
        message: stockCheck.message
      });
    }

    // Get user's price based on role
    const userPrice = getUserPrice(stockCheck.pricing, req.user.role);

    // Generate reference
    const reference = customReference || generateReference('API-PURCHASE');

    // Create purchase record
    const purchase = await DataPurchase.create({
      userId: req.user._id,
      phoneNumber: phone_number,
      network,
      capacity,
      gateway: payment_method,
      method: 'api',
      price: userPrice,
      pricing: {
        systemPrice: userPrice,
        customerPrice: userPrice,
        agentProfit: 0
      },
      reference,
      status: payment_method === 'wallet' ? 'processing' : 'pending',
      metadata: {
        apiKeyId: req.apiKey._id,
        apiKeyName: req.apiKey.name
      }
    });

    // Process based on payment method
    if (payment_method === 'wallet') {
      // Check wallet balance
      if (req.user.walletBalance < userPrice) {
        purchase.status = 'failed';
        await purchase.save();
        await updateApiKeyStats(req.apiKey, false);
        
        return res.status(400).json({
          success: false,
          message: 'Insufficient wallet balance',
          required_amount: userPrice,
          current_balance: req.user.walletBalance
        });
      }

      // Process wallet payment
      const walletResult = await processWalletPayment(req.user, userPrice, reference, purchase);
      await updateApiKeyStats(req.apiKey, true);
      
      res.json({
        success: true,
        message: 'Purchase successful',
        data: {
          reference: purchase.reference,
          amount: userPrice,
          network,
          capacity,
          phone_number,
          status: 'processing',
          new_balance: walletResult.newBalance,
          timestamp: new Date()
        }
      });
    } else {
      // Initialize Paystack payment
      try {
        const paystackConfig = await getPaystackConfig();
        
        const paystackResponse = await axios.post(
          'https://api.paystack.co/transaction/initialize',
          {
            email: req.user.email,
            amount: userPrice * 100, // Convert to pesewas
            reference,
            metadata: {
              purchaseId: purchase._id.toString(),
              userId: req.user._id.toString(),
              network,
              capacity,
              phoneNumber: phone_number,
              apiPurchase: true,
              apiKeyId: req.apiKey._id.toString()
            },
            callback_url: callback_url || `${process.env.FRONTEND_URL}/api/verify/${reference}`
          },
          {
            headers: {
              Authorization: `Bearer ${paystackConfig.secretKey}`
            }
          }
        );

        await updateApiKeyStats(req.apiKey, true);

        res.json({
          success: true,
          message: 'Payment initialized',
          data: {
            reference: purchase.reference,
            amount: userPrice,
            network,
            capacity,
            phone_number,
            status: purchase.status,
            payment_url: paystackResponse.data.data.authorization_url,
            access_code: paystackResponse.data.data.access_code
          }
        });
      } catch (paystackError) {
        // If Paystack initialization fails, delete the purchase record
        await DataPurchase.deleteOne({ _id: purchase._id });
        await updateApiKeyStats(req.apiKey, false);
        
        console.error('Paystack initialization error:', paystackError.response?.data || paystackError.message);
        return res.status(500).json({
          success: false,
          message: 'Failed to initialize payment',
          error: process.env.NODE_ENV === 'development' ? paystackError.message : undefined
        });
      }
    }
  })
);

// @route   POST /api/v1/purchase/bulk
// @desc    Make bulk purchases via API
// @access  API Key Required
router.post('/bulk',
  apiLimit,
  checkApiKey,
  [
    body('purchases').isArray({ min: 1, max: 100 }).withMessage('Purchases must be an array with 1-100 items'),
    body('purchases.*.phone_number').matches(/^(\+233|0)[2-9]\d{8}$/).withMessage('Invalid phone number'),
    body('purchases.*.capacity').isFloat({ min: 0.1, max: 100 }).withMessage('Invalid capacity'),
    body('payment_method').isIn(['wallet']).withMessage('Only wallet payment allowed for bulk'),
    body('network').optional().isIn(['YELLO', 'MTN', 'TELECEL', 'AT_PREMIUM', 'AIRTELTIGO', 'AT'])
  ],
  asyncHandler(async (req, res) => {
    // Validate request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      await updateApiKeyStats(req.apiKey, false);
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const { purchases, network: defaultNetwork, payment_method } = req.body;

    // Validate and prepare purchases
    const validatedPurchases = [];
    const validationErrors = [];
    let totalCost = 0;

    for (let i = 0; i < purchases.length; i++) {
      const purchase = purchases[i];
      const purchaseNetwork = purchase.network || defaultNetwork || 'MTN';
      
      // Check stock and get pricing
      const stockCheck = await checkStockAvailability(purchaseNetwork, purchase.capacity);
      
      if (!stockCheck.available) {
        validationErrors.push({
          index: i,
          phone_number: purchase.phone_number,
          error: stockCheck.message
        });
        continue;
      }

      const userPrice = getUserPrice(stockCheck.pricing, req.user.role);
      totalCost += userPrice;

      validatedPurchases.push({
        phoneNumber: purchase.phone_number,
        network: purchaseNetwork,
        capacity: purchase.capacity,
        price: userPrice
      });
    }

    // Check if any valid purchases
    if (validatedPurchases.length === 0) {
      await updateApiKeyStats(req.apiKey, false);
      return res.status(400).json({
        success: false,
        message: 'No valid purchases found',
        errors: validationErrors
      });
    }

    // Check wallet balance
    if (req.user.walletBalance < totalCost) {
      await updateApiKeyStats(req.apiKey, false);
      return res.status(400).json({
        success: false,
        message: 'Insufficient wallet balance',
        required_amount: totalCost,
        current_balance: req.user.walletBalance,
        valid_purchases: validatedPurchases.length,
        errors: validationErrors
      });
    }

    // Generate batch reference
    const batchReference = generateReference('API-BULK');
    const purchaseIds = [];

    // Create purchase records
    for (const validPurchase of validatedPurchases) {
      const purchase = await DataPurchase.create({
        userId: req.user._id,
        phoneNumber: validPurchase.phoneNumber,
        network: validPurchase.network,
        capacity: validPurchase.capacity,
        gateway: payment_method,
        method: 'api_bulk',
        price: validPurchase.price,
        pricing: {
          systemPrice: validPurchase.price,
          customerPrice: validPurchase.price,
          agentProfit: 0
        },
        reference: generateReference('API-PURCHASE'),
        batchReference,
        status: 'processing',
        metadata: {
          apiKeyId: req.apiKey._id,
          apiKeyName: req.apiKey.name
        }
      });
      purchaseIds.push(purchase._id);
    }

    // Process wallet payment
    req.user.walletBalance -= totalCost;
    await req.user.save();

    // Create transaction record
    await Transaction.create({
      userId: req.user._id,
      type: 'api_bulk_purchase',
      amount: totalCost,
      balanceBefore: req.user.walletBalance + totalCost,
      balanceAfter: req.user.walletBalance,
      reference: batchReference,
      gateway: 'wallet',
      status: 'completed',
      description: `API bulk purchase: ${validatedPurchases.length} items`
    });

    // Update API key stats
    req.apiKey.usageStats.totalPurchases = (req.apiKey.usageStats.totalPurchases || 0) + validatedPurchases.length;
    await updateApiKeyStats(req.apiKey, true);

    res.json({
      success: true,
      message: 'Bulk purchase successful',
      data: {
        batch_reference: batchReference,
        total_purchases: validatedPurchases.length,
        total_cost: totalCost,
        new_balance: req.user.walletBalance,
        purchases: validatedPurchases.map(p => ({
          phone_number: p.phoneNumber,
          network: p.network,
          capacity: p.capacity,
          price: p.price
        })),
        errors: validationErrors.length > 0 ? validationErrors : undefined,
        timestamp: new Date()
      }
    });
  })
);

// @route   GET /api/v1/purchase/verify/:reference
// @desc    Verify payment status
// @access  API Key Required
router.get('/verify/:reference',
  apiLimit,
  checkApiKey,
  asyncHandler(async (req, res) => {
    const { reference } = req.params;

    // Find purchase(s)
    let purchases = await DataPurchase.find({ 
      $or: [
        { reference },
        { batchReference: reference }
      ],
      userId: req.user._id
    });

    if (!purchases || purchases.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Purchase not found'
      });
    }

    // For Paystack payments, verify with Paystack
    if (purchases[0].gateway === 'paystack' && purchases[0].status === 'pending') {
      try {
        const paystackConfig = await getPaystackConfig();
        
        const verifyResponse = await axios.get(
          `https://api.paystack.co/transaction/verify/${reference}`,
          {
            headers: {
              Authorization: `Bearer ${paystackConfig.secretKey}`
            }
          }
        );

        const paymentData = verifyResponse.data.data;

        if (paymentData.status === 'success') {
          // Update purchase status
          for (const purchase of purchases) {
            purchase.status = 'processing';
            purchase.paystackReference = paymentData.reference;
            await purchase.save();
          }
        }
      } catch (error) {
        console.error('Paystack verification error:', error);
      }
    }

    const response = {
      success: true,
      data: {
        reference,
        status: purchases[0].status,
        total_amount: purchases.reduce((sum, p) => sum + p.price, 0),
        purchases: purchases.map(p => ({
          network: p.network,
          capacity: p.capacity,
          phone_number: p.phoneNumber,
          price: p.price,
          status: p.status
        })),
        timestamp: new Date()
      }
    };

    res.json(response);
  })
);

// @route   GET /api/v1/purchase/history
// @desc    Get purchase history
// @access  API Key Required
router.get('/history',
  apiLimit,
  checkApiKey,
  asyncHandler(async (req, res) => {
    const { 
      page = 1, 
      limit = 20, 
      status, 
      network, 
      from_date, 
      to_date 
    } = req.query;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Build filter
    const filter = { 
      userId: req.user._id,
      method: { $in: ['api', 'api_bulk'] }
    };
    
    if (status) filter.status = status;
    if (network) filter.network = network.toUpperCase();
    
    if (from_date || to_date) {
      filter.createdAt = {};
      if (from_date) filter.createdAt.$gte = new Date(from_date);
      if (to_date) filter.createdAt.$lte = new Date(to_date);
    }

    // Get purchases
    const purchases = await DataPurchase.find(filter)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip)
      .select('reference phoneNumber network capacity price status createdAt batchReference');

    const total = await DataPurchase.countDocuments(filter);

    res.json({
      success: true,
      data: {
        purchases: purchases.map(p => ({
          reference: p.reference,
          phone_number: p.phoneNumber,
          network: p.network,
          capacity: p.capacity,
          price: p.price,
          status: p.status,
          created_at: p.createdAt,
          batch_reference: p.batchReference
        })),
        pagination: {
          current_page: parseInt(page),
          per_page: parseInt(limit),
          total_items: total,
          total_pages: Math.ceil(total / parseInt(limit))
        }
      }
    });
  })
);

// @route   GET /api/v1/purchase/stats
// @desc    Get API usage statistics
// @access  API Key Required
router.get('/stats',
  apiLimit,
  checkApiKey,
  asyncHandler(async (req, res) => {
    const { period = '7d' } = req.query;

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

    // Get purchase stats
    const purchases = await DataPurchase.aggregate([
      {
        $match: {
          userId: req.user._id,
          method: { $in: ['api', 'api_bulk'] },
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: null,
          total_purchases: { $sum: 1 },
          total_amount: { $sum: '$price' },
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
      total_purchases: 0,
      total_amount: 0,
      successful: 0,
      failed: 0
    };

    // Get network breakdown
    const networkBreakdown = await DataPurchase.aggregate([
      {
        $match: {
          userId: req.user._id,
          method: { $in: ['api', 'api_bulk'] },
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$network',
          count: { $sum: 1 },
          amount: { $sum: '$price' }
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        period,
        stats: {
          total_purchases: stats.total_purchases,
          total_amount: stats.total_amount,
          successful_purchases: stats.successful,
          failed_purchases: stats.failed,
          success_rate: stats.total_purchases > 0 
            ? ((stats.successful / stats.total_purchases) * 100).toFixed(2) 
            : 0
        },
        network_breakdown: networkBreakdown.map(n => ({
          network: n._id,
          count: n.count,
          amount: n.amount
        })),
        api_key: {
          name: req.apiKey.name,
          total_requests: req.apiKey.usageStats?.totalRequests || 0,
          total_purchases: req.apiKey.usageStats?.totalPurchases || 0
        }
      }
    });
  })
);

// ==================== WEBHOOK ENDPOINT ====================

// @route   POST /api/v1/webhook/paystack
// @desc    Paystack webhook for payment verification
// @access  Public (verified by signature)
router.post('/webhook/paystack', asyncHandler(async (req, res) => {
  const hash = require('crypto')
    .createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
    .update(JSON.stringify(req.body))
    .digest('hex');
    
  if (hash !== req.headers['x-paystack-signature']) {
    return res.status(401).json({
      success: false,
      message: 'Invalid signature'
    });
  }

  const { event, data } = req.body;

  if (event === 'charge.success') {
    const { reference, metadata } = data;
    
    if (metadata?.apiPurchase) {
      // Update purchase status
      await DataPurchase.updateMany(
        { 
          $or: [
            { reference },
            { batchReference: reference }
          ]
        },
        { 
          status: 'processing',
          paystackReference: reference 
        }
      );

      // Create transaction record
      const purchases = await DataPurchase.find({
        $or: [
          { reference },
          { batchReference: reference }
        ]
      });

      const totalAmount = purchases.reduce((sum, p) => sum + p.price, 0);

      await Transaction.create({
        userId: metadata.userId,
        type: 'api_purchase',
        amount: totalAmount,
        reference,
        gateway: 'paystack',
        status: 'completed',
        description: `API purchase via Paystack`
      });
    }
  }

  res.status(200).json({ received: true });
}));

// ==================== ERROR HANDLING ====================

// API-specific error handler
router.use((err, req, res, next) => {
  console.error('API Error:', err);

  // Update API key stats for errors
  if (req.apiKey) {
    updateApiKeyStats(req.apiKey, false).catch(console.error);
  }

  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});

module.exports = router;