// ==================== routes/Datapurchase/order.js ====================
// Complete Purchase Routes with Fixed Telecel Integration

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const crypto = require('crypto');
const cron = require('node-cron');
const multer = require('multer');
const XLSX = require('xlsx');
const { adminOnly, asyncHandler, validate } = require('../../middleware/middleware');

// FIXED: Import TelecelService class and create instance
const TelecelService = require('../../telecelservice/telecel_service');
const telecelService = new TelecelService(); // Create instance here

const { 
  DataPurchase, 
  User, 
  Transaction, 
  DataPricing, 
  DataInventory, 
  AgentStore, 
  AgentProfit,
  Notification 
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

// ==================== TELECEL PROCESSING FUNCTION ====================
const processTelecelPurchase = async (purchase) => {
  try {
    console.log(`[TELECEL PROCESSOR] Processing purchase ${purchase.reference}`);
    console.log(`[TELECEL PROCESSOR] Network: ${purchase.network}, Capacity: ${purchase.capacity}GB`);
    
    // Validate the service is available
    if (!telecelService || typeof telecelService.sendDataBundle !== 'function') {
      console.error('[TELECEL PROCESSOR] TelecelService not properly initialized');
      throw new Error('TelecelService not available');
    }
    
    // Send data bundle via Telecel API
    const result = await telecelService.sendDataBundle(
      purchase.phoneNumber,
      purchase.capacity
    );

    console.log(`[TELECEL PROCESSOR] Result:`, result);

    if (result.success) {
      // Update purchase status to completed
      purchase.status = 'completed';
      purchase.deliveredAt = new Date();
      purchase.deliveryDetails = {
        provider: 'TELECEL',
        transactionId: result.transactionId,
        message: result.message,
        processedAt: new Date()
      };
      await purchase.save();

      console.log(`[TELECEL PROCESSOR] Successfully delivered ${purchase.capacity}GB to ${purchase.phoneNumber}`);
      
      // Create notification for user if exists
      if (purchase.userId) {
        try {
          await Notification.create({
            userId: purchase.userId,
            title: 'Data Bundle Delivered',
            message: `Your ${purchase.capacity}GB TELECEL data bundle has been successfully delivered to ${purchase.phoneNumber}`,
            type: 'success',
            category: 'purchase'
          });
        } catch (notifError) {
          console.error('[TELECEL PROCESSOR] Notification error:', notifError);
        }
      }

      return true;
    } else {
      // Handle failure
      console.error(`[TELECEL PROCESSOR] Failed to deliver: ${result.error}`);
      
      // If token expired, mark for manual processing
      if (result.requiresNewToken) {
        purchase.status = 'failed';
        purchase.failureReason = 'Authentication token expired - requires manual update';
        purchase.adminNotes = 'TELECEL API token needs to be renewed';
      } else {
        purchase.status = 'failed';
        purchase.failureReason = result.error || 'Unknown error';
      }
      
      await purchase.save();
      
      return false;
    }
  } catch (error) {
    console.error('[TELECEL PROCESSOR] Error:', error);
    purchase.status = 'failed';
    purchase.failureReason = error.message;
    await purchase.save();
    return false;
  }
};

// ==================== PAYSTACK CONFIGURATION ====================
const getPaystackConfig = async () => {
  try {
    const settings = await SystemSettings.getSettings();
    
    if (!settings.paymentGateway?.paystack?.enabled) {
      throw new Error('Paystack payment gateway is disabled');
    }
    
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
      capAt: settings.paymentGateway.paystack.capAt || 100,
      splitPayment: settings.paymentGateway.paystack.splitPayment || false,
      subaccountCode: settings.paymentGateway.paystack.subaccountCode
    };
  } catch (error) {
    console.error('Paystack config error:', error);
    // Return default config if settings fail
    return {
      secretKey: process.env.PAYSTACK_SECRET_KEY,
      publicKey: process.env.PAYSTACK_PUBLIC_KEY,
      webhookUrl: process.env.PAYSTACK_WEBHOOK_URL,
      transactionFee: 1.95,
      capAt: 100,
      splitPayment: false,
      subaccountCode: null
    };
  }
};

const getPaystackAPI = async () => {
  const config = await getPaystackConfig();
  
  return axios.create({
    baseURL: 'https://api.paystack.co',
    headers: {
      Authorization: `Bearer ${config.secretKey}`,
      'Content-Type': 'application/json'
    }
  });
};

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
    .optional()
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
const generateReference = (prefix = 'REF') => {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 9).toUpperCase();
  return `${prefix}-${timestamp}-${random}`;
};

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

const checkStockAvailability = async (network, capacity, method = 'web') => {
  try {
    const inventory = await DataInventory.findOne({ network });
    if (!inventory || !inventory.inStock) {
      return { 
        available: false, 
        message: `${network} is currently out of stock` 
      };
    }

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

const processWalletPayment = async (userId, amount, reference, purchase) => {
  try {
    const user = await User.findById(userId);
    
    if (user.walletBalance < amount) {
      throw new Error('Insufficient wallet balance');
    }

    user.walletBalance -= amount;
    await user.save();

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

    purchase.status = 'processing';
    await purchase.save();

    // Process TELECEL purchases immediately
    if (purchase.network === 'TELECEL') {
      console.log('[WALLET] Processing TELECEL purchase automatically');
      await processTelecelPurchase(purchase);
    }

    return { success: true, newBalance: user.walletBalance };
  } catch (error) {
    throw error;
  }
};

const updateStoreStatistics = async (purchase) => {
  try {
    if (purchase.method === 'agent_store' && purchase.agentId) {
      console.log(`[WEBHOOK] Updating store stats for agent: ${purchase.agentId}`);
      
      const agent = await User.findById(purchase.agentId);
      if (agent) {
        const profitAmount = purchase.pricing.agentProfit || 0;
        agent.agentProfit = (agent.agentProfit || 0) + profitAmount;
        agent.totalEarnings = (agent.totalEarnings || 0) + profitAmount;
        await agent.save();
        console.log(`[WEBHOOK] Updated agent profit: +${profitAmount} GHS`);
      }

      await AgentProfit.findOneAndUpdate(
        { purchaseId: purchase._id },
        { 
          status: 'credited',
          creditedAt: new Date()
        }
      );

      const storeUpdate = await AgentStore.findOneAndUpdate(
        { agent: purchase.agentId },
        {
          $inc: {
            'statistics.totalSales': 1,
            'statistics.totalOrders': 1,
            'statistics.totalRevenue': purchase.price,
            'statistics.totalProfit': purchase.pricing.agentProfit || 0,
            'statistics.totalCustomers': 1,
            'statistics.todayProfit': purchase.pricing.agentProfit || 0,
            'statistics.weekProfit': purchase.pricing.agentProfit || 0,
            'statistics.monthProfit': purchase.pricing.agentProfit || 0
          },
          $set: {
            'statistics.lastSaleDate': new Date()
          }
        },
        { new: true }
      );
      
      console.log(`[WEBHOOK] Store stats updated for: ${storeUpdate?.storeName}`);
      return true;
    }
    return false;
  } catch (error) {
    console.error('[WEBHOOK] Error updating store stats:', error);
    return false;
  }
};

const deleteAbandonedOrders = async () => {
  try {
    const cutoffTime = new Date(Date.now() - 5 * 60 * 1000); // 5 minutes ago
    
    console.log(`[CLEANUP] Running cleanup at ${new Date().toISOString()}`);
    
    const abandonedOrders = await DataPurchase.find({
      status: 'pending',
      createdAt: { $lt: cutoffTime }
    }).select('_id reference agentId');

    if (abandonedOrders.length === 0) {
      return 0;
    }

    console.log(`[CLEANUP] Found ${abandonedOrders.length} abandoned orders to delete`);

    const orderIds = abandonedOrders.map(order => order._id);

    const deletedProfits = await AgentProfit.deleteMany({
      purchaseId: { $in: orderIds },
      status: 'pending'
    });
    console.log(`[CLEANUP] Deleted ${deletedProfits.deletedCount} pending profit records`);

    const deletedOrders = await DataPurchase.deleteMany({
      _id: { $in: orderIds }
    });
    console.log(`[CLEANUP] Deleted ${deletedOrders.deletedCount} abandoned orders`);

    return deletedOrders.deletedCount;
  } catch (error) {
    console.error('[CLEANUP ERROR]', error);
    return 0;
  }
};

// Schedule cleanup to run every 2 minutes
cron.schedule('*/2 * * * *', async () => {
  await deleteAbandonedOrders();
});

// Run initial cleanup on startup
deleteAbandonedOrders().then(count => {
  console.log(`[STARTUP] Initial cleanup completed. Deleted ${count} abandoned orders.`);
});

// ==================== MAIN PURCHASE ROUTES ====================

// 1. Purchase data (authenticated users)
router.post('/buy', protect, validatePurchase, checkValidation, async (req, res) => {
  try {
    const { phoneNumber, network, capacity, gateway } = req.body;
    const userId = req.user._id;

    const settings = await SystemSettings.getSettings();
    const paystackConfig = await getPaystackConfig();

    const stockCheck = await checkStockAvailability(network, capacity, 'web');
    if (!stockCheck.available) {
      return res.status(400).json({
        success: false,
        message: stockCheck.message
      });
    }

    const userPrice = getUserPrice(stockCheck.pricing, req.user.role);

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

    const reference = generateReference('PURCHASE');

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

    if (gateway === 'wallet') {
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
          status: purchase.status,
          newBalance: walletResult.newBalance
        }
      });
    } else {
      const paystackAPI = await getPaystackAPI();
      const paystackResponse = await paystackAPI.post('/transaction/initialize', {
        email: req.user.email,
        amount: userPrice * 100,
        reference,
        currency: settings?.platform?.currency || 'GHS',
        metadata: {
          purchaseId: purchase._id,
          userId,
          network,
          capacity,
          phoneNumber
        },
        callback_url: `${process.env.FRONTEND_URL || settings?.platform?.siteUrl}/verify/store/${reference}`,
        ...(paystackConfig.subaccountCode && {
          subaccount: paystackConfig.subaccountCode,
          bearer: 'account'
        })
      });

      res.json({
        success: true,
        message: 'Payment initialized',
        requiresPayment: true,
        data: {
          reference: purchase.reference,
          amount: userPrice,
          network,
          capacity,
          phoneNumber,
          status: purchase.status,
          paymentUrl: paystackResponse.data.data.authorization_url,
          accessCode: paystackResponse.data.data.access_code,
          publicKey: paystackConfig.publicKey
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

// 2. Purchase through agent store
router.post('/store/:subdomain', optionalAuth, validatePurchase, checkValidation, async (req, res) => {
  try {
    const { subdomain } = req.params;
    const { phoneNumber, network, capacity, customerEmail, customerName } = req.body;

    console.log('Store purchase request:', { 
      subdomain, 
      network, 
      capacity, 
      phoneNumber,
      timestamp: new Date().toISOString() 
    });

    const settings = await SystemSettings.getSettings();
    const paystackConfig = await getPaystackConfig();

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

    if (!store.operatingStatus.isOpen) {
      return res.status(400).json({
        success: false,
        message: 'Store is currently closed',
        reason: store.operatingStatus.closedReason,
        reopenAt: store.operatingStatus.reopenAt
      });
    }

    const stockCheck = await checkStockAvailability(network, capacity, 'web');
    if (!stockCheck.available) {
      return res.status(400).json({
        success: false,
        message: stockCheck.message
      });
    }

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

    const systemPrice = customPricing.systemPrice;
    const agentPrice = customPricing.agentPrice;
    const agentProfit = agentPrice - systemPrice;

    console.log('Pricing calculated:', {
      systemPrice,
      agentPrice,
      agentProfit,
      profitMargin: ((agentProfit / systemPrice) * 100).toFixed(2) + '%'
    });

    const reference = generateReference('STORE');

    const purchase = await DataPurchase.create({
      userId: req.user?._id || null,
      agentId: store.agent._id,
      phoneNumber,
      network,
      capacity,
      gateway: 'paystack',
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
        email: customerEmail || req.user?.email || `guest_${Date.now()}@customer.com`,
        phoneNumber: phoneNumber
      }
    });

    console.log('Purchase record created:', {
      id: purchase._id,
      reference: purchase.reference,
      status: purchase.status
    });

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

    console.log('Agent profit record created (pending):', {
      id: agentProfitRecord._id,
      profit: agentProfit,
      status: 'pending'
    });

    console.log('Initializing Paystack payment...');
    
    const paystackPayload = {
      email: customerEmail || req.user?.email || `guest_${Date.now()}@customer.com`,
      amount: Math.round(agentPrice * 100),
      reference,
      currency: settings?.platform?.currency || 'GHS',
      metadata: {
        purchaseId: purchase._id.toString(),
        agentId: store.agent._id.toString(),
        agentProfitId: agentProfitRecord._id.toString(),
        network,
        capacity,
        phoneNumber,
        storeName: store.storeName,
        storeId: store._id.toString(),
        isStorePurchase: true,
        customerName: customerName || 'Guest'
      },
      callback_url: `${process.env.FRONTEND_URL || settings?.platform?.siteUrl}/verify/store/${reference}?subdomain=${subdomain}`,
      channels: ['card', 'bank', 'mobile_money'],
      ...(paystackConfig.subaccountCode && {
        subaccount: paystackConfig.subaccountCode,
        bearer: 'account'
      })
    };

    const paystackAPI = await getPaystackAPI();
    const paystackResponse = await paystackAPI.post('/transaction/initialize', paystackPayload);

    if (!paystackResponse.data.status || !paystackResponse.data.data.authorization_url) {
      await DataPurchase.findByIdAndDelete(purchase._id);
      await AgentProfit.findByIdAndDelete(agentProfitRecord._id);
      
      console.error('Paystack initialization failed:', paystackResponse.data);
      
      return res.status(500).json({
        success: false,
        message: 'Payment initialization failed. Please try again.'
      });
    }

    console.log('Paystack payment initialized successfully');

    res.json({
      success: true,
      message: 'Payment initialization successful',
      requiresPayment: true,
      data: {
        reference: purchase.reference,
        amount: agentPrice,
        network,
        capacity,
        phoneNumber,
        storeName: store.storeName,
        status: 'pending',
        paymentUrl: paystackResponse.data.data.authorization_url,
        accessCode: paystackResponse.data.data.access_code,
        publicKey: paystackConfig.publicKey,
        paymentInfo: {
          currency: settings?.platform?.currency || 'GHS',
          email: paystackPayload.email,
          channels: paystackPayload.channels
        }
      }
    });

  } catch (error) {
    console.error('Store purchase error:', error);
    
    let errorMessage = 'Purchase failed. Please try again.';
    
    if (error.response?.data?.message) {
      errorMessage = error.response.data.message;
    } else if (error.message.includes('PAYSTACK')) {
      errorMessage = 'Payment service temporarily unavailable. Please try again later.';
    }

    res.status(500).json({
      success: false,
      message: errorMessage,
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 3. PAYSTACK WEBHOOK HANDLER - WITH TELECEL PROCESSING
router.post('/webhook/paystack', async (req, res) => {
  try {
    console.log('[WEBHOOK] Received Paystack webhook');
    
    const paystackConfig = await getPaystackConfig();
    
    // Verify webhook signature
    const hash = crypto
      .createHmac('sha512', paystackConfig.secretKey)
      .update(JSON.stringify(req.body))
      .digest('hex');
    
    if (hash !== req.headers['x-paystack-signature']) {
      console.error('[WEBHOOK] Invalid signature');
      return res.status(401).send('Unauthorized');
    }

    const event = req.body;
    console.log(`[WEBHOOK] Event type: ${event.event}`);
    console.log(`[WEBHOOK] Reference: ${event.data?.reference}`);

    switch (event.event) {
      case 'charge.success':
        const successData = event.data;
        const successReference = successData.reference;
        
        console.log(`[WEBHOOK] Processing successful payment: ${successReference}`);
        
        const purchase = await DataPurchase.findOne({ reference: successReference });
        
        if (!purchase) {
          console.error(`[WEBHOOK] Purchase not found: ${successReference}`);
          return res.status(404).send('Purchase not found');
        }

        if (purchase.status === 'processing' || purchase.status === 'completed') {
          console.log(`[WEBHOOK] Purchase already processed: ${successReference}`);
          return res.status(200).send('Already processed');
        }

        // Update purchase to PROCESSING
        purchase.status = 'processing';
        purchase.paystackReference = successData.reference;
        purchase.verifiedAt = new Date();
        purchase.paymentDetails = {
          amount: successData.amount / 100,
          currency: successData.currency,
          channel: successData.channel,
          paidAt: successData.paid_at,
          fees: successData.fees ? successData.fees / 100 : 0,
          customerEmail: successData.customer.email
        };
        await purchase.save();

        console.log(`[WEBHOOK] Purchase updated to processing: ${successReference}`);

        // Process TELECEL purchases automatically
        if (purchase.network === 'TELECEL') {
          console.log(`[WEBHOOK] Processing TELECEL purchase automatically`);
          await processTelecelPurchase(purchase);
        }

        // Update store statistics if it's a store purchase
        if (purchase.method === 'agent_store') {
          await updateStoreStatistics(purchase);
        }

        // Create transaction record
        await Transaction.create({
          userId: purchase.userId || purchase.agentId,
          type: 'purchase',
          amount: purchase.price,
          reference: successReference,
          gateway: 'paystack',
          status: 'completed',
          relatedPurchaseId: purchase._id,
          description: `Data purchase: ${purchase.capacity}GB ${purchase.network}`,
          webhookData: {
            eventType: event.event,
            paystackReference: successData.reference,
            processedAt: new Date()
          }
        });

        console.log(`[WEBHOOK] Transaction created for: ${successReference}`);
        res.status(200).send('OK');
        break;

      case 'charge.failed':
        const failedData = event.data;
        const failedReference = failedData.reference;
        
        console.log(`[WEBHOOK] Processing failed payment: ${failedReference}`);
        
        await DataPurchase.findOneAndUpdate(
          { reference: failedReference },
          { 
            status: 'failed',
            failedAt: new Date(),
            failureReason: failedData.gateway_response || 'Payment failed'
          }
        );

        const failedPurchase = await DataPurchase.findOne({ reference: failedReference });
        if (failedPurchase) {
          await AgentProfit.findOneAndUpdate(
            { purchaseId: failedPurchase._id },
            { 
              status: 'cancelled',
              cancelledAt: new Date()
            }
          );
        }

        console.log(`[WEBHOOK] Purchase marked as failed: ${failedReference}`);
        res.status(200).send('OK');
        break;

      case 'refund.processed':
        const refundData = event.data;
        const refundReference = refundData.transaction_reference;
        
        console.log(`[WEBHOOK] Processing refund: ${refundReference}`);
        
        const refundPurchase = await DataPurchase.findOne({ reference: refundReference });
        
        if (refundPurchase) {
          refundPurchase.status = 'refunded';
          refundPurchase.refundedAt = new Date();
          refundPurchase.refundAmount = refundData.amount / 100;
          await refundPurchase.save();

          if (refundPurchase.method === 'agent_store' && refundPurchase.agentId) {
            const agent = await User.findById(refundPurchase.agentId);
            if (agent) {
              const profitToReverse = refundPurchase.pricing.agentProfit || 0;
              agent.agentProfit = Math.max(0, (agent.agentProfit || 0) - profitToReverse);
              agent.totalEarnings = Math.max(0, (agent.totalEarnings || 0) - profitToReverse);
              await agent.save();
            }

            await AgentProfit.findOneAndUpdate(
              { purchaseId: refundPurchase._id },
              { 
                status: 'refunded',
                refundedAt: new Date()
              }
            );

            await AgentStore.findOneAndUpdate(
              { agent: refundPurchase.agentId },
              {
                $inc: {
                  'statistics.totalSales': -1,
                  'statistics.totalOrders': -1,
                  'statistics.totalRevenue': -refundPurchase.price,
                  'statistics.totalProfit': -(refundPurchase.pricing.agentProfit || 0)
                }
              }
            );
          }

          console.log(`[WEBHOOK] Refund processed for: ${refundReference}`);
        }
        
        res.status(200).send('OK');
        break;

      default:
        console.log(`[WEBHOOK] Unhandled event: ${event.event}`);
        res.status(200).send('OK');
    }

  } catch (error) {
    console.error('[WEBHOOK ERROR]', error);
    res.status(500).send('Webhook processing failed');
  }
});

// 4. Verify payment - WITH TELECEL PROCESSING
router.get('/verify/:reference', async (req, res) => {
  try {
    const { reference } = req.params;

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

    if (purchases.every(p => p.status === 'processing' || p.status === 'completed')) {
      return res.json({
        success: true,
        message: 'Payment already verified',
        data: {
          reference,
          status: purchases[0].status,
          amount: purchases.reduce((sum, p) => sum + p.price, 0)
        }
      });
    }

    const paystackAPI = await getPaystackAPI();
    const verifyResponse = await paystackAPI.get(`/transaction/verify/${reference}`);

    const paymentData = verifyResponse.data.data;

    if (paymentData.status === 'success') {
      for (const purchase of purchases) {
        purchase.status = 'processing';
        purchase.paystackReference = paymentData.reference;
        await purchase.save();

        // Process TELECEL purchases automatically
        if (purchase.network === 'TELECEL') {
          console.log(`[VERIFY] Processing TELECEL purchase automatically`);
          await processTelecelPurchase(purchase);
        }

        if (purchase.method === 'agent_store') {
          await updateStoreStatistics(purchase);
        }
      }

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
          status: purchases[0].status,
          amount: totalAmount,
          totalItems: purchases.length,
          purchases: purchases.map(p => ({
            network: p.network,
            capacity: p.capacity,
            phoneNumber: p.phoneNumber,
            price: p.price,
            status: p.status
          }))
        }
      });
    } else {
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

// 5. Get purchase history (excluding pending)
router.get('/history', protect, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, network, from, to } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const filter = { 
      userId: req.user._id,
      status: { $ne: 'pending' } // Exclude pending orders
    };
    if (status && status !== 'pending') filter.status = status;
    if (network) filter.network = network;
    
    if (from || to) {
      filter.createdAt = {};
      if (from) filter.createdAt.$gte = new Date(from);
      if (to) filter.createdAt.$lte = new Date(to);
    }

    const purchases = await DataPurchase.find(filter)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip)
      .populate('agentId', 'name phoneNumber')
      .select('reference phoneNumber network capacity price status method createdAt storeInfo batchReference');

    const total = await DataPurchase.countDocuments(filter);

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

// 6. Get single purchase details
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

// 7. Get available products with pricing
router.get('/products', optionalAuth, async (req, res) => {
  try {
    const { network, inStockOnly = 'true' } = req.query;

    const filter = { isActive: true };
    if (network) filter.network = network;
    if (inStockOnly === 'true') {
      filter['stock.overallInStock'] = true;
    }

    const products = await DataPricing.find(filter)
      .select('network capacity prices stock description tags isPopular promoPrice')
      .sort({ network: 1, capacity: 1 });

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

// 8. Cancel pending purchase
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

// 9. Retry failed purchase
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

    const settings = await SystemSettings.getSettings();
    const paystackConfig = await getPaystackConfig();

    const newReference = generateReference('RETRY');
    
    const newPurchase = await DataPurchase.create({
      ...purchase.toObject(),
      _id: undefined,
      reference: newReference,
      status: 'pending',
      createdAt: new Date()
    });

    const paystackAPI = await getPaystackAPI();
    const paystackResponse = await paystackAPI.post('/transaction/initialize', {
      email: req.user.email,
      amount: purchase.price * 100,
      reference: newReference,
      currency: settings.platform?.currency || 'GHS',
      metadata: {
        purchaseId: newPurchase._id,
        retry: true,
        originalReference: reference
      },
      ...(paystackConfig.subaccountCode && {
        subaccount: paystackConfig.subaccountCode,
        bearer: 'account'
      })
    });

    res.json({
      success: true,
      message: 'Retry initiated',
      data: {
        reference: newReference,
        amount: purchase.price,
        paymentUrl: paystackResponse.data.data.authorization_url,
        publicKey: paystackConfig.publicKey
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

// 10. Bulk Purchase Route - UPDATED WITH TELECEL PROCESSING
router.post('/bulk', protect, async (req, res) => {
  try {
    console.log('Bulk purchase request received');
    console.log('Request body:', req.body);
    console.log('User:', req.user.email, req.user._id);
    
    const { purchases, network, gateway = 'wallet' } = req.body;
    
    const settings = await SystemSettings.getSettings();
    const paystackConfig = await getPaystackConfig();
    
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

    const validatedPurchases = [];
    const errors = [];
    let totalCost = 0;

    for (let i = 0; i < purchases.length; i++) {
      const purchase = purchases[i];
      console.log(`Processing purchase ${i + 1}:`, purchase);
      
      let phoneNumber = purchase.phoneNumber?.toString().trim();
      if (!phoneNumber) {
        errors.push({
          index: i,
          phoneNumber: purchase.phoneNumber,
          error: 'Missing phone number'
        });
        continue;
      }

      phoneNumber = phoneNumber.replace(/\D/g, '');
      if (phoneNumber.startsWith('233')) {
        phoneNumber = '0' + phoneNumber.substring(3);
      } else if (!phoneNumber.startsWith('0')) {
        phoneNumber = '0' + phoneNumber;
      }

      if (!/^0[2-9]\d{8}$/.test(phoneNumber)) {
        errors.push({
          index: i,
          phoneNumber: purchase.phoneNumber,
          error: 'Invalid phone number format'
        });
        continue;
      }

      const capacity = parseFloat(purchase.capacity);
      if (!capacity || capacity < 0.1 || capacity > 100) {
        errors.push({
          index: i,
          phoneNumber: phoneNumber,
          error: 'Invalid capacity (must be between 0.1 and 100 GB)'
        });
        continue;
      }

      const purchaseNetwork = purchase.network || network || 'MTN';
      
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

    if (validatedPurchases.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid purchases found',
        errors
      });
    }

    if (gateway === 'wallet') {
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

      const batchReference = generateReference('BULK');
      const purchaseIds = [];

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

        // Process TELECEL purchases immediately
        if (purchase.network === 'TELECEL') {
          await processTelecelPurchase(purchase);
        }
      }

      user.walletBalance -= totalCost;
      await user.save();

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
      const batchReference = generateReference('BULK');
      const purchaseIds = [];

      for (const validPurchase of validatedPurchases) {
        const purchase = await DataPurchase.create({
          userId: req.user._id,
          phoneNumber: validPurchase.phoneNumber,
          network: validPurchase.network,
          capacity: validPurchase.capacity,
          gateway: 'paystack',
          method: 'bulk_web',
          price: validPurchase.price,
          pricing: {
            systemPrice: validPurchase.price,
            customerPrice: validPurchase.price,
            agentProfit: 0
          },
          reference: generateReference('PURCHASE'),
          batchReference,
          status: 'pending'
        });
        purchaseIds.push(purchase._id);
      }

      const paystackAPI = await getPaystackAPI();
      const paystackResponse = await paystackAPI.post('/transaction/initialize', {
        email: req.user.email,
        amount: totalCost * 100,
        reference: batchReference,
        currency: settings.platform?.currency || 'GHS',
        metadata: {
          type: 'bulk_purchase',
          purchaseIds,
          userId: req.user._id,
          totalItems: validatedPurchases.length
        },
        callback_url: `${process.env.FRONTEND_URL || settings.platform?.siteUrl}/purchase/verify/${batchReference}`,
        ...(paystackConfig.subaccountCode && {
          subaccount: paystackConfig.subaccountCode,
          bearer: 'account'
        })
      });

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
          accessCode: paystackResponse.data.data.access_code,
          publicKey: paystackConfig.publicKey
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

// 11. Parse Excel/CSV for bulk purchase
router.post('/parse-excel', protect, upload.single('file'), async (req, res) => {
  try {
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

    const fileType = req.file.mimetype;
    console.log('File type:', fileType);

    let data;
    try {
      if (fileType === 'text/csv' || fileType === 'application/csv' || fileType === 'text/plain') {
        const csvText = req.file.buffer.toString('utf8');
        const workbook = XLSX.read(csvText, { type: 'string' });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        data = XLSX.utils.sheet_to_json(sheet, { raw: false });
      } else {
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

    const purchases = [];
    const errors = [];

    for (let i = 0; i < data.length; i++) {
      const row = data[i];
      console.log('Processing row:', i + 1, row);
      
      let phoneNumber = row['Phone Number'] || row['phone'] || row['phoneNumber'] || 
                       row['Phone'] || row['Number'] || row['Mobile'] || row['Tel'];
      
      let capacity = row['Capacity'] || row['capacity'] || row['GB'] || row['Data'] || 
                    row['Amount'] || row['Size'] || row['Package'] || row['Capacity (GB)'];
      
      let rowNetwork = row['Network'] || row['network'] || row['Provider'] || row['Carrier'] ||
                      row['Network (Optional)'];

      if (phoneNumber) {
        phoneNumber = phoneNumber.toString().replace(/\D/g, '');
        if (phoneNumber.startsWith('233')) {
          phoneNumber = '0' + phoneNumber.substring(3);
        } else if (!phoneNumber.startsWith('0')) {
          phoneNumber = '0' + phoneNumber;
        }
      }

      if (capacity) {
        capacity = parseFloat(capacity.toString().replace(/[^\d.]/g, ''));
      }

      if (!phoneNumber) {
        errors.push({
          row: i + 2,
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

// 12. Get bulk purchase template
router.get('/bulk-template', (req, res) => {
  try {
    const templateData = [
      { 'Phone Number': '0241234567', 'Capacity (GB)': '2', 'Network (Optional)': 'MTN' },
      { 'Phone Number': '0551234567', 'Capacity (GB)': '5', 'Network (Optional)': 'TELECEL' },
      { 'Phone Number': '0261234567', 'Capacity (GB)': '1', 'Network (Optional)': 'AT' }
    ];

    const ws = XLSX.utils.json_to_sheet(templateData);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Bulk Purchase Template');

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

// 13. Get pricing
router.get('/pricing', asyncHandler(async (req, res) => {
  const { 
    network, 
    capacity, 
    inStockOnly, 
    isActive = 'true',
    sortBy = 'network',
    order = 'asc' 
  } = req.query;

  const filter = {};
  
  if (network) filter.network = network;
  if (capacity) filter.capacity = parseFloat(capacity);
  if (isActive !== undefined) filter.isActive = isActive === 'true';
  
  if (inStockOnly === 'true') {
    filter['stock.overallInStock'] = true;
  }

  try {
    const pricingData = await DataPricing.find(filter)
      .populate('lastUpdatedBy', 'name email')
      .sort({ [sortBy]: order === 'desc' ? -1 : 1 });

    const stats = {
      total: pricingData.length,
      inStock: pricingData.filter(p => p.stock?.overallInStock).length,
      outOfStock: pricingData.filter(p => !p.stock?.overallInStock).length,
      webInStock: pricingData.filter(p => p.stock?.webInStock).length,
      apiInStock: pricingData.filter(p => p.stock?.apiInStock).length,
      popular: pricingData.filter(p => p.isPopular).length
    };

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

// 14. Admin cleanup endpoint (manual trigger)
router.delete('/admin/cleanup-pending', protect, adminOnly, async (req, res) => {
  try {
    const deleted = await deleteAbandonedOrders();
    
    res.json({
      success: true,
      message: `Cleanup completed. Deleted ${deleted} abandoned orders.`,
      deletedCount: deleted
    });
  } catch (error) {
    console.error('Manual cleanup error:', error);
    res.status(500).json({
      success: false,
      message: 'Cleanup failed'
    });
  }
});

// 15. Manual TELECEL processing endpoint (for admin)
router.post('/admin/process-telecel/:reference', protect, adminOnly, async (req, res) => {
  try {
    const { reference } = req.params;
    
    const purchase = await DataPurchase.findOne({ reference });
    
    if (!purchase) {
      return res.status(404).json({
        success: false,
        message: 'Purchase not found'
      });
    }

    if (purchase.network !== 'TELECEL') {
      return res.status(400).json({
        success: false,
        message: 'This purchase is not for TELECEL network'
      });
    }

    if (purchase.status === 'completed') {
      return res.json({
        success: true,
        message: 'Purchase already completed'
      });
    }

    const result = await processTelecelPurchase(purchase);
    
    if (result) {
      res.json({
        success: true,
        message: 'TELECEL bundle delivered successfully',
        data: {
          reference: purchase.reference,
          status: purchase.status,
          deliveredAt: purchase.deliveredAt
        }
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Failed to deliver TELECEL bundle',
        error: purchase.failureReason
      });
    }
    
  } catch (error) {
    console.error('Manual TELECEL processing error:', error);
    res.status(500).json({
      success: false,
      message: 'Processing failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;