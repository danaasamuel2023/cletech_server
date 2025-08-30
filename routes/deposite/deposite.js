// routes/Payment/payment.js - Paystack Payment with SystemSettings
const express = require('express');
const router = express.Router();
const axios = require('axios');
const crypto = require('crypto');
const { body, param, query, validationResult } = require('express-validator');

// Import models including SystemSettings
const { 
  User, 
  Transaction,
  DataPurchase,
  Notification
} = require('../../Schema/Schema');

const SystemSettings = require('../../settingsSchema/schema');

const { 
  protect, 
  asyncHandler, 
  validate
} = require('../../middleware/middleware');

// ==================== HELPER FUNCTIONS ====================

// Get Paystack configuration from SystemSettings
const getPaystackConfig = async () => {
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
};

// Create Paystack API instance with dynamic config
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

// Generate unique reference
const generateReference = () => {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 8);
  return `DEP-${timestamp}-${random}`.toUpperCase();
};

// Verify Paystack webhook signature
const verifyPaystackSignature = async (payload, signature) => {
  const config = await getPaystackConfig();
  const hash = crypto
    .createHmac('sha512', config.secretKey)
    .update(JSON.stringify(payload))
    .digest('hex');
  return hash === signature;
};

// ==================== DEPOSIT/FUNDING ROUTES ====================

// @route   POST /api/payments/initialize
// @desc    Initialize Paystack payment for wallet funding
// @access  Private
router.post('/initialize', protect, [
  body('amount').isNumeric().isFloat({ min: 1, max: 100000 }),
  body('email').optional().isEmail(),
  body('callback_url').optional().isURL(),
  validate
], asyncHandler(async (req, res) => {
  const { amount, email, callback_url } = req.body;
  
  try {
    // Get system settings for payment configuration
    const settings = await SystemSettings.getSettings();
    const paystackConfig = await getPaystackConfig();
    
    // Check if Paystack is enabled
    if (!settings.paymentGateway?.paystack?.enabled) {
      return res.status(400).json({
        success: false,
        message: 'Paystack payments are currently disabled'
      });
    }
    
    // Check transaction limits from settings
    const minTransaction = settings.financial?.transactions?.minTransaction || 1;
    const maxTransaction = settings.financial?.transactions?.maxTransaction || 10000;
    
    if (amount < minTransaction || amount > maxTransaction) {
      return res.status(400).json({
        success: false,
        message: `Amount must be between ${settings.platform?.currencySymbol || 'GHS'} ${minTransaction} and ${maxTransaction}`
      });
    }
    
    // Use user's email if not provided
    const paymentEmail = email || req.user.email;
    
    // Generate unique reference
    const reference = generateReference();
    
    // Convert amount to kobo/pesewas (smallest currency unit)
    const amountInKobo = Math.round(amount * 100);
    
    // Calculate fees if applicable
    let totalAmount = amount;
    if (paystackConfig.transactionFee > 0) {
      const fee = Math.min((amount * paystackConfig.transactionFee / 100), paystackConfig.capAt);
      totalAmount = amount + fee;
    }
    
    // Create pending transaction in database
    const transaction = await Transaction.create({
      userId: req.user._id,
      type: 'deposit',
      amount: amount,
      balanceBefore: req.user.walletBalance,
      balanceAfter: req.user.walletBalance, // Will be updated on success
      status: 'pending',
      reference: reference,
      gateway: 'paystack',
      description: `Wallet deposit of ${settings.platform?.currencySymbol || 'GHS'} ${amount}`,
      metadata: {
        email: paymentEmail,
        initiatedAt: new Date(),
        fee: totalAmount - amount,
        currency: settings.platform?.currency || 'GHS'
      }
    });

    // Initialize payment with Paystack
    const paystackAPI = await getPaystackAPI();
    const response = await paystackAPI.post('/transaction/initialize', {
      email: paymentEmail,
      amount: Math.round(totalAmount * 100), // Include fees
      reference: reference,
      currency: settings.platform?.currency || 'GHS',
      callback_url: callback_url || `${process.env.FRONTEND_URL || settings.platform?.siteUrl}/payment/callback`,
      metadata: {
        userId: req.user._id.toString(),
        userName: req.user.name,
        transactionId: transaction._id.toString(),
        type: 'wallet_funding',
        originalAmount: amount,
        fee: totalAmount - amount
      },
      channels: ['card', 'bank', 'ussd', 'mobile_money', 'bank_transfer'],
      ...(paystackConfig.subaccountCode && {
        subaccount: paystackConfig.subaccountCode,
        bearer: 'account'
      })
    });

    if (response.data.status) {
      // Update transaction with Paystack reference
      transaction.paystackReference = response.data.data.reference;
      transaction.metadata.paystackAccessCode = response.data.data.access_code;
      await transaction.save();

      res.status(200).json({
        success: true,
        message: 'Payment initialized successfully',
        data: {
          authorizationUrl: response.data.data.authorization_url,
          accessCode: response.data.data.access_code,
          reference: reference,
          amount: amount,
          totalAmount: totalAmount,
          fee: totalAmount - amount,
          transactionId: transaction._id,
          publicKey: paystackConfig.publicKey // Send public key for inline payments
        }
      });
    } else {
      // Paystack returned an error
      transaction.status = 'failed';
      transaction.metadata.error = response.data.message;
      await transaction.save();

      res.status(400).json({
        success: false,
        message: response.data.message || 'Failed to initialize payment'
      });
    }
  } catch (error) {
    console.error('Paystack initialization error:', error.response?.data || error.message);
    
    res.status(500).json({
      success: false,
      message: error.message || 'Error initializing payment',
      error: process.env.NODE_ENV === 'development' ? error.response?.data : undefined
    });
  }
}));

// @route   GET /api/payments/verify/:reference
// @desc    Verify Paystack payment
// @access  Private
router.get('/verify/:reference', protect, asyncHandler(async (req, res) => {
  const { reference } = req.params;
  
  try {
    // Get Paystack configuration
    const paystackAPI = await getPaystackAPI();
    const settings = await SystemSettings.getSettings();
    
    // Find the transaction
    const transaction = await Transaction.findOne({ 
      reference: reference,
      userId: req.user._id
    });

    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }

    // Check if already processed
    if (transaction.status === 'completed') {
      return res.status(200).json({
        success: true,
        message: 'Transaction already verified',
        data: {
          status: transaction.status,
          amount: transaction.amount,
          reference: transaction.reference,
          balance: req.user.walletBalance
        }
      });
    }

    // Verify with Paystack
    const response = await paystackAPI.get(`/transaction/verify/${reference}`);

    if (response.data.status && response.data.data.status === 'success') {
      const paystackData = response.data.data;
      
      // Calculate actual amount (remove fees)
      const amountReceived = paystackData.amount / 100;
      const originalAmount = transaction.amount;
      
      // Update transaction
      transaction.status = 'completed';
      transaction.balanceAfter = req.user.walletBalance + originalAmount;
      transaction.metadata.paystackResponse = {
        id: paystackData.id,
        paidAt: paystackData.paid_at,
        channel: paystackData.channel,
        currency: paystackData.currency,
        ipAddress: paystackData.ip_address,
        fees: paystackData.fees,
        amountReceived: amountReceived
      };
      await transaction.save();

      // Update user balance
      req.user.walletBalance += originalAmount;
      
      // Update total earnings if configured
      if (settings.financial?.wallet?.trackEarnings !== false) {
        req.user.totalEarnings = (req.user.totalEarnings || 0) + originalAmount;
      }
      
      await req.user.save();

      // Send notification based on settings
      if (settings.notifications?.preferences?.paymentSuccess?.email) {
        await Notification.create({
          userId: req.user._id,
          title: 'Wallet Funded Successfully',
          message: `Your wallet has been credited with ${settings.platform?.currencySymbol || 'GHS'} ${originalAmount}`,
          type: 'success',
          category: 'transaction'
        });
      }

      res.status(200).json({
        success: true,
        message: 'Payment verified successfully',
        data: {
          status: 'completed',
          amount: originalAmount,
          reference: transaction.reference,
          newBalance: req.user.walletBalance,
          paidAt: paystackData.paid_at
        }
      });
    } else {
      // Payment failed
      transaction.status = 'failed';
      transaction.metadata.paystackResponse = response.data.data;
      await transaction.save();

      res.status(400).json({
        success: false,
        message: 'Payment verification failed',
        data: {
          status: response.data.data.status,
          reference: reference
        }
      });
    }
  } catch (error) {
    console.error('Payment verification error:', error.response?.data || error.message);
    
    res.status(500).json({
      success: false,
      message: 'Error verifying payment',
      error: process.env.NODE_ENV === 'development' ? error.response?.data : undefined
    });
  }
}));

// @route   POST /api/payments/webhook
// @desc    Handle Paystack webhooks
// @access  Public (but verified with signature)
router.post('/webhook', asyncHandler(async (req, res) => {
  try {
    // Verify webhook signature
    const signature = req.headers['x-paystack-signature'];
    const isValid = await verifyPaystackSignature(req.body, signature);
    
    if (!isValid) {
      console.warn('Invalid Paystack webhook signature');
      return res.status(401).json({
        success: false,
        message: 'Invalid signature'
      });
    }

    const event = req.body;
    console.log('Paystack webhook received:', event.event);

    // Get system settings
    const settings = await SystemSettings.getSettings();

    switch (event.event) {
      case 'charge.success':
        await handleChargeSuccess(event.data, settings);
        break;
        
      case 'transfer.success':
        await handleTransferSuccess(event.data, settings);
        break;
        
      case 'transfer.failed':
      case 'transfer.reversed':
        await handleTransferFailed(event.data, settings);
        break;
        
      case 'refund.processed':
        await handleRefund(event.data, settings);
        break;
        
      default:
        console.log('Unhandled webhook event:', event.event);
    }

    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Webhook processing failed' 
    });
  }
}));

// Webhook handler functions
async function handleChargeSuccess(data, settings) {
  const reference = data.reference;
  
  // Find transaction
  const transaction = await Transaction.findOne({ reference });
  
  if (!transaction) {
    console.error('Transaction not found for reference:', reference);
    return;
  }

  // Skip if already processed
  if (transaction.status === 'completed') {
    console.log('Transaction already completed:', reference);
    return;
  }

  // Find user
  const user = await User.findById(transaction.userId);
  if (!user) {
    console.error('User not found for transaction:', transaction._id);
    return;
  }

  // Update transaction
  const originalAmount = transaction.amount;
  transaction.status = 'completed';
  transaction.balanceAfter = user.walletBalance + originalAmount;
  transaction.metadata.paystackWebhook = {
    id: data.id,
    paidAt: data.paid_at,
    channel: data.channel,
    fees: data.fees
  };
  await transaction.save();

  // Update user balance
  user.walletBalance += originalAmount;
  
  // Track earnings if configured
  if (settings.financial?.wallet?.trackEarnings !== false) {
    user.totalEarnings = (user.totalEarnings || 0) + originalAmount;
  }
  
  await user.save();

  // Send notification based on settings
  if (settings.notifications?.preferences?.paymentSuccess?.email) {
    await Notification.create({
      userId: user._id,
      title: 'Payment Successful',
      message: `Your payment of ${settings.platform?.currencySymbol || 'GHS'} ${originalAmount} has been confirmed`,
      type: 'success',
      category: 'transaction'
    });
  }

  console.log('Charge success processed:', reference);
}

async function handleTransferSuccess(data, settings) {
  // Handle successful withdrawals
  console.log('Transfer success:', data);
  // Implementation depends on your withdrawal flow
}

async function handleTransferFailed(data, settings) {
  // Handle failed withdrawals
  console.log('Transfer failed:', data);
  // Implementation depends on your withdrawal flow
}

async function handleRefund(data, settings) {
  // Handle refunds
  console.log('Refund processed:', data);
  
  const reference = data.reference;
  const refundAmount = data.amount / 100;
  
  // Find original transaction
  const transaction = await Transaction.findOne({ reference });
  if (!transaction) {
    console.error('Transaction not found for refund:', reference);
    return;
  }
  
  // Find user
  const user = await User.findById(transaction.userId);
  if (!user) {
    console.error('User not found for refund');
    return;
  }
  
  // Check refund settings
  if (!settings.financial?.refunds?.enabled) {
    console.log('Refunds are disabled in settings');
    return;
  }
  
  // Create refund transaction
  await Transaction.create({
    userId: user._id,
    type: 'refund',
    amount: refundAmount,
    balanceBefore: user.walletBalance,
    balanceAfter: user.walletBalance - refundAmount,
    status: 'completed',
    reference: `REFUND-${reference}`,
    gateway: 'paystack',
    description: `Refund for transaction ${reference}`,
    metadata: {
      originalReference: reference,
      refundData: data
    }
  });
  
  // Update user balance
  user.walletBalance -= refundAmount;
  await user.save();
  
  // Send notification
  await Notification.create({
    userId: user._id,
    title: 'Refund Processed',
    message: `A refund of ${settings.platform?.currencySymbol || 'GHS'} ${refundAmount} has been processed`,
    type: 'info',
    category: 'transaction'
  });
}

// @route   GET /api/payments/config
// @desc    Get payment configuration (public key, etc.)
// @access  Private
router.get('/config', protect, asyncHandler(async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    const paystackConfig = await getPaystackConfig();
    
    res.status(200).json({
      success: true,
      data: {
        paystack: {
          enabled: settings.paymentGateway?.paystack?.enabled || false,
          publicKey: paystackConfig.publicKey,
          currency: settings.platform?.currency || 'GHS',
          currencySymbol: settings.platform?.currencySymbol || '₵',
          channels: ['card', 'bank', 'ussd', 'mobile_money', 'bank_transfer']
        },
        limits: {
          minTransaction: settings.financial?.transactions?.minTransaction || 1,
          maxTransaction: settings.financial?.transactions?.maxTransaction || 10000,
          dailyLimit: settings.financial?.transactions?.dailyLimit || 50000
        },
        fees: {
          transactionFee: paystackConfig.transactionFee,
          capAt: paystackConfig.capAt
        }
      }
    });
  } catch (error) {
    console.error('Error fetching payment config:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching payment configuration'
    });
  }
}));

// @route   GET /api/payments/banks
// @desc    Get list of banks for transfers
// @access  Private
router.get('/banks', protect, asyncHandler(async (req, res) => {
  try {
    const paystackAPI = await getPaystackAPI();
    const settings = await SystemSettings.getSettings();
    const country = settings.platform?.country || 'gh';
    
    const response = await paystackAPI.get(`/bank?country=${country}`);
    
    res.status(200).json({
      success: true,
      data: response.data.data
    });
  } catch (error) {
    console.error('Error fetching banks:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching banks'
    });
  }
}));

router.get('/history', protect, asyncHandler(async (req, res) => {
  try {
    const { 
      limit = 10,
      page = 1,
      status = 'all',
      period = 'all',
      search = ''
    } = req.query;
    
    // Build query - only get deposits
    const query = { 
      userId: req.user._id,
      type: 'deposit'
    };
    
    // Filter by status if specified
    if (status !== 'all') {
      query.status = status;
    }
    
    // Filter by period
    if (period !== 'all') {
      const now = new Date();
      let startDate = new Date();
      
      switch(period) {
        case 'today':
          startDate.setHours(0, 0, 0, 0);
          break;
        case 'week':
          startDate.setDate(now.getDate() - 7);
          break;
        case 'month':
          startDate.setMonth(now.getMonth() - 1);
          break;
        case 'year':
          startDate.setFullYear(now.getFullYear() - 1);
          break;
      }
      
      if (startDate) {
        query.createdAt = { $gte: startDate };
      }
    }
    
    // Search by reference
    if (search) {
      query.reference = { $regex: search, $options: 'i' };
    }
    
    // Pagination
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const skip = (pageNum - 1) * limitNum;
    
    // Get total count
    const totalCount = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limitNum);
    
    // Fetch deposits
    const deposits = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitNum)
      .select('amount status reference gateway createdAt balanceAfter description metadata');
    
    res.status(200).json({
      success: true,
      data: {
        deposits,
        pagination: {
          currentPage: pageNum,
          totalPages,
          totalCount,
          limit: limitNum
        }
      }
    });
  } catch (error) {
    console.error('Error fetching deposit history:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching deposit history'
    });
  }
}));

// @route   GET /api/deposits/recent
// @desc    Get recent deposits
// @access  Private
router.get('/recent', protect, asyncHandler(async (req, res) => {
  try {
    const { limit = 5 } = req.query;
    
    const deposits = await Transaction.find({
      userId: req.user._id,
      type: 'deposit'
    })
    .sort({ createdAt: -1 })
    .limit(parseInt(limit))
    .select('amount status reference createdAt');
    
    res.status(200).json({
      success: true,
      data: deposits
    });
  } catch (error) {
    console.error('Error fetching recent deposits:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching recent deposits'
    });
  }
}));

module.exports = router; 