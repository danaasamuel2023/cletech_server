// ==================== COMPLETE ADMIN ROUTES ====================
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { 
  User, 
  AgentStore, 
  DataInventory, 
  DataPricing, 
  DataPurchase, 
  Transaction, 
  ResultChecker, 
  ApiKey, 
  Notification,
  AgentProfit 
} = require('../../Schema/Schema');
const { protect, adminOnly, asyncHandler, validate } = require('../../middleware/middleware');
const { body, param, query, validationResult } = require('express-validator');

// All routes require admin authentication
router.use(protect, adminOnly);

// ==================== USER MANAGEMENT ROUTES ====================

// @route   GET /api/admin/users
// @desc    Get all users with filters
// @access  Admin
router.get('/users', asyncHandler(async (req, res) => {
  const { 
    role, 
    approvalStatus, 
    isDisabled, 
    page = 1, 
    limit = 50,
    search,
    sortBy = 'createdAt',
    order = 'desc'
  } = req.query;

  const filter = {};
  
  if (role) filter.role = role;
  if (approvalStatus) filter.approvalStatus = approvalStatus;
  if (isDisabled !== undefined) filter.isDisabled = isDisabled === 'true';
  if (search) {
    filter.$or = [
      { name: { $regex: search, $options: 'i' } },
      { email: { $regex: search, $options: 'i' } },
      { phoneNumber: { $regex: search, $options: 'i' } },
      { username: { $regex: search, $options: 'i' } }
    ];
  }

  const users = await User.find(filter)
    .select('-password')
    .populate('parentAgent', 'name email')
    .sort({ [sortBy]: order === 'desc' ? -1 : 1 })
    .limit(limit * 1)
    .skip((page - 1) * limit);

  const total = await User.countDocuments(filter);

  res.status(200).json({
    success: true,
    data: {
      users,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit),
        limit: parseInt(limit)
      }
    }
  });
}));

// @route   PUT /api/admin/users/:userId/approve
// @desc    Approve or reject a user
// @access  Admin
router.put('/users/:userId/approve', [
  body('status').isIn(['approved', 'rejected']),
  body('reason').optional().isString(),
  validate
], asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { status, reason } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  user.approvalStatus = status;
  user.approvedBy = req.user._id;
  user.approvedAt = new Date();
  
  if (status === 'rejected' && reason) {
    user.rejectionReason = reason;
  }

  await user.save();

  // Send notification to user
  await Notification.create({
    userId: user._id,
    title: `Account ${status}`,
    message: status === 'approved' 
      ? 'Your account has been approved. You can now access all features.'
      : `Your account was rejected. Reason: ${reason || 'Not specified'}`,
    type: status === 'approved' ? 'success' : 'error',
    category: 'account'
  });

  res.status(200).json({
    success: true,
    message: `User ${status} successfully`,
    data: user
  });
}));

// @route   PUT /api/admin/users/:userId/disable
// @desc    Disable or enable a user account
// @access  Admin
router.put('/users/:userId/disable', [
  body('disable').isBoolean(),
  body('reason').optional().isString(),
  validate
], asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { disable, reason } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  user.isDisabled = disable;
  if (disable) {
    user.disableReason = reason || 'Account disabled by admin';
    user.disabledAt = new Date();
  } else {
    user.disableReason = null;
    user.disabledAt = null;
  }

  await user.save();

  res.status(200).json({
    success: true,
    message: `User ${disable ? 'disabled' : 'enabled'} successfully`,
    data: user
  });
}));

// @route   PUT /api/admin/users/:userId/role
// @desc    Change user role
// @access  Admin
router.put('/users/:userId/role', [
  body('role').isIn(['admin', 'super_agent', 'dealer', 'agent', 'user', 'reporter', 'worker']),
  validate
], asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { role } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  const oldRole = user.role;
  user.role = role;
  await user.save();

  // Log the role change
  await Notification.create({
    userId: user._id,
    title: 'Role Updated',
    message: `Your role has been changed from ${oldRole} to ${role}`,
    type: 'info',
    category: 'account'
  });

  res.status(200).json({
    success: true,
    message: 'Role updated successfully',
    data: {
      userId: user._id,
      oldRole,
      newRole: role
    }
  });
}));

// @route   PUT /api/admin/users/:userId/parent
// @desc    Set parent agent for hierarchy
// @access  Admin
router.put('/users/:userId/parent', [
  body('parentAgentId').optional().isMongoId(),
  validate
], asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { parentAgentId } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  if (parentAgentId) {
    const parentAgent = await User.findById(parentAgentId);
    if (!parentAgent) {
      return res.status(404).json({
        success: false,
        message: 'Parent agent not found'
      });
    }
    user.parentAgent = parentAgentId;
  } else {
    user.parentAgent = null;
  }

  await user.save();
  
  const updatedUser = await User.findById(userId).populate('parentAgent', 'name email role');

  res.status(200).json({
    success: true,
    message: 'Parent agent updated',
    data: updatedUser
  });
}));

// ==================== PRICING & INVENTORY MANAGEMENT ====================

// @route   POST /api/admin/pricing
// @desc    Create or update pricing for a product
// @access  Admin
router.post('/pricing', [
  body('network').isIn(['YELLO', 'MTN', 'TELECEL', 'AT_PREMIUM', 'AIRTELTIGO', 'AT']),
  body('capacity').isNumeric().isFloat({ min: 0.1, max: 100 }),
  body('prices.adminCost').isNumeric(),
  body('prices.dealer').isNumeric(),
  body('prices.superAgent').isNumeric(),
  body('prices.agent').isNumeric(),
  body('prices.user').isNumeric(),
  validate
], asyncHandler(async (req, res) => {
  const { network, capacity, prices, description, isPopular, tags } = req.body;

  // Validate price hierarchy (admin < dealer < superAgent < agent < user)
  if (prices.adminCost >= prices.dealer || 
      prices.dealer >= prices.superAgent || 
      prices.superAgent >= prices.agent || 
      prices.agent >= prices.user) {
    return res.status(400).json({
      success: false,
      message: 'Invalid price hierarchy. Prices must increase with each role level.'
    });
  }

  let pricing = await DataPricing.findOne({ network, capacity });

  if (pricing) {
    // Update existing
    pricing.prices = prices;
    pricing.description = description || pricing.description;
    pricing.isPopular = isPopular !== undefined ? isPopular : pricing.isPopular;
    pricing.tags = tags || pricing.tags;
    pricing.lastUpdatedBy = req.user._id;
    pricing.updatedAt = new Date();
  } else {
    // Create new with default stock status
    pricing = new DataPricing({
      network,
      capacity,
      prices,
      description,
      isPopular,
      tags,
      lastUpdatedBy: req.user._id,
      stock: {
        webInStock: true,  // Default to in stock
        apiInStock: true,  // Default to in stock
        overallInStock: true  // Default to in stock
      },
      isActive: true
    });
  }

  await pricing.save();

  // Auto-create or update inventory for this network if it doesn't exist
  let inventory = await DataInventory.findOne({ network });
  
  if (!inventory) {
    // Create new inventory record for this network
    inventory = new DataInventory({
      network,
      webInStock: true,  // Default to in stock
      apiInStock: true,  // Default to in stock
      inStock: true,     // Default to in stock
      webLastUpdatedBy: req.user._id,
      apiLastUpdatedBy: req.user._id,
      webLastUpdatedAt: new Date(),
      apiLastUpdatedAt: new Date(),
      updatedAt: new Date()
    });
    
    await inventory.save();
    
    console.log(`Auto-created inventory for network: ${network}`);
  }

  res.status(200).json({
    success: true,
    message: 'Pricing saved successfully',
    data: pricing
  });
}));


// @route   PUT /api/admin/pricing/:pricingId/stock
// @desc    Update stock status for specific capacity
// @access  Admin
router.put('/pricing/:pricingId/stock', [
  body('webInStock').optional().isBoolean(),
  body('apiInStock').optional().isBoolean(),
  body('overallInStock').optional().isBoolean(),
  validate
], asyncHandler(async (req, res) => {
  const { pricingId } = req.params;
  const { webInStock, apiInStock, overallInStock } = req.body;

  const pricing = await DataPricing.findById(pricingId);
  if (!pricing) {
    return res.status(404).json({
      success: false,
      message: 'Pricing not found'
    });
  }

  if (webInStock !== undefined) pricing.stock.webInStock = webInStock;
  if (apiInStock !== undefined) pricing.stock.apiInStock = apiInStock;
  if (overallInStock !== undefined) pricing.stock.overallInStock = overallInStock;
  
  pricing.stockLastUpdatedBy = req.user._id;
  pricing.stockLastUpdatedAt = new Date();

  await pricing.save();

  res.status(200).json({
    success: true,
    message: 'Stock status updated',
    data: pricing
  });
}));

// @route   PUT /api/admin/inventory/:network
// @desc    Update network inventory status
// @access  Admin
router.put('/inventory/:network', [
  body('webInStock').optional().isBoolean(),
  body('apiInStock').optional().isBoolean(),
  body('inStock').optional().isBoolean(),
  validate
], asyncHandler(async (req, res) => {
  const { network } = req.params;
  const { webInStock, apiInStock, inStock } = req.body;

  let inventory = await DataInventory.findOne({ network });

  if (!inventory) {
    inventory = new DataInventory({ network });
  }

  if (webInStock !== undefined) {
    inventory.webInStock = webInStock;
    inventory.webLastUpdatedBy = req.user._id;
    inventory.webLastUpdatedAt = new Date();
  }
  
  if (apiInStock !== undefined) {
    inventory.apiInStock = apiInStock;
    inventory.apiLastUpdatedBy = req.user._id;
    inventory.apiLastUpdatedAt = new Date();
  }
  
  if (inStock !== undefined) {
    inventory.inStock = inStock;
  }

  inventory.updatedAt = new Date();
  await inventory.save();

  res.status(200).json({
    success: true,
    message: 'Inventory updated',
    data: inventory
  });
}));

// @route   POST /api/admin/pricing/promo
// @desc    Set promotional pricing
// @access  Admin
router.post('/pricing/promo', [
  body('network').isIn(['YELLO', 'MTN', 'TELECEL', 'AT_PREMIUM', 'AIRTELTIGO', 'AT']),
  body('capacity').isNumeric(),
  body('promoPrice').isNumeric(),
  body('promoStartDate').isISO8601(),
  body('promoEndDate').isISO8601(),
  validate
], asyncHandler(async (req, res) => {
  const { network, capacity, promoPrice, promoStartDate, promoEndDate } = req.body;

  const pricing = await DataPricing.findOne({ network, capacity });
  if (!pricing) {
    return res.status(404).json({
      success: false,
      message: 'Pricing not found'
    });
  }

  pricing.promoPrice = promoPrice;
  pricing.promoStartDate = new Date(promoStartDate);
  pricing.promoEndDate = new Date(promoEndDate);
  pricing.lastUpdatedBy = req.user._id;

  await pricing.save();

  res.status(200).json({
    success: true,
    message: 'Promotional pricing set',
    data: pricing
  });
}));

// ==================== FINANCIAL MANAGEMENT ====================

// @route   POST /api/admin/wallet/credit
// @desc    Credit user wallet
// @access  Admin
router.post('/wallet/credit', [
  body('userId').isMongoId(),
  body('amount').isNumeric().isFloat({ min: 0.01, max: 100000 }),
  body('description').isString(),
  validate
], asyncHandler(async (req, res) => {
  const { userId, amount, description } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  const oldBalance = user.walletBalance;
  const newBalance = oldBalance + amount;

  // Create transaction
  const transaction = new Transaction({
    userId: userId,
    type: 'admin_credit',
    amount: amount,
    balanceBefore: oldBalance,
    balanceAfter: newBalance,
    status: 'completed',
    reference: `ADMIN-CREDIT-${Date.now()}`,
    gateway: 'admin-deposit',
    description: description || `Admin credit by ${req.user.name}`,
    metadata: {
      adminId: req.user._id,
      adminName: req.user.name,
      reason: description
    }
  });

  // Update user balance
  user.walletBalance = newBalance;
  
  await Promise.all([
    user.save(),
    transaction.save()
  ]);

  // Send notification
  await Notification.create({
    userId: userId,
    title: 'Wallet Credited',
    message: `Your wallet has been credited with GHS ${amount}. ${description || ''}`,
    type: 'success',
    category: 'transaction'
  });

  res.status(200).json({
    success: true,
    message: 'Wallet credited successfully',
    data: {
      userId,
      amount,
      oldBalance,
      newBalance,
      transactionId: transaction._id
    }
  });
}));

// @route   POST /api/admin/wallet/debit
// @desc    Debit user wallet
// @access  Admin
router.post('/wallet/debit', [
  body('userId').isMongoId(),
  body('amount').isNumeric().isFloat({ min: 0.01, max: 100000 }),
  body('description').isString(),
  validate
], asyncHandler(async (req, res) => {
  const { userId, amount, description } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  if (user.walletBalance < amount) {
    return res.status(400).json({
      success: false,
      message: 'Insufficient balance',
      currentBalance: user.walletBalance,
      requestedAmount: amount
    });
  }

  const oldBalance = user.walletBalance;
  const newBalance = oldBalance - amount;

  // Create transaction
  const transaction = new Transaction({
    userId: userId,
    type: 'admin_debit',
    amount: amount,
    balanceBefore: oldBalance,
    balanceAfter: newBalance,
    status: 'completed',
    reference: `ADMIN-DEBIT-${Date.now()}`,
    gateway: 'admin-deduction',
    description: description || `Admin debit by ${req.user.name}`,
    metadata: {
      adminId: req.user._id,
      adminName: req.user.name,
      reason: description
    }
  });

  // Update user balance
  user.walletBalance = newBalance;
  
  await Promise.all([
    user.save(),
    transaction.save()
  ]);

  res.status(200).json({
    success: true,
    message: 'Wallet debited successfully',
    data: {
      userId,
      amount,
      oldBalance,
      newBalance,
      transactionId: transaction._id
    }
  });
}));

// @route   GET /api/admin/transactions
// @desc    Get all transactions with filters
// @access  Admin
router.get('/transactions', asyncHandler(async (req, res) => {
  const { 
    userId,
    type,
    status,
    gateway,
    startDate,
    endDate,
    page = 1,
    limit = 50
  } = req.query;

  const filter = {};
  
  if (userId) filter.userId = userId;
  if (type) filter.type = type;
  if (status) filter.status = status;
  if (gateway) filter.gateway = gateway;
  
  if (startDate || endDate) {
    filter.createdAt = {};
    if (startDate) filter.createdAt.$gte = new Date(startDate);
    if (endDate) filter.createdAt.$lte = new Date(endDate);
  }

  const transactions = await Transaction.find(filter)
    .populate('userId', 'name email phoneNumber')
    .sort({ createdAt: -1 })
    .limit(limit * 1)
    .skip((page - 1) * limit);

  const total = await Transaction.countDocuments(filter);

  // Calculate totals
  const stats = await Transaction.aggregate([
    { $match: filter },
    {
      $group: {
        _id: '$status',
        total: { $sum: '$amount' },
        count: { $sum: 1 }
      }
    }
  ]);

  res.status(200).json({
    success: true,
    data: {
      transactions,
      stats,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    }
  });
}));

// ==================== PURCHASE MANAGEMENT ====================

// @route   GET /api/admin/purchases
// @desc    Get all purchases with filters
// @access  Admin
router.get('/purchases', asyncHandler(async (req, res) => {
  const { 
    status,
    network,
    method,
    userId,
    agentId,
    startDate,
    endDate,
    page = 1,
    limit = 50
  } = req.query;

  const filter = {};
  
  if (status) filter.status = status;
  if (network) filter.network = network;
  if (method) filter.method = method;
  if (userId) filter.userId = userId;
  if (agentId) filter.agentId = agentId;
  
  if (startDate || endDate) {
    filter.createdAt = {};
    if (startDate) filter.createdAt.$gte = new Date(startDate);
    if (endDate) filter.createdAt.$lte = new Date(endDate);
  }

  const purchases = await DataPurchase.find(filter)
    .populate('userId', 'name email phoneNumber')
    .populate('agentId', 'name email')
    .sort({ createdAt: -1 })
    .limit(limit * 1)
    .skip((page - 1) * limit);

  const total = await DataPurchase.countDocuments(filter);

  res.status(200).json({
    success: true,
    data: {
      purchases,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    }
  });
}));

// @route   PUT /api/admin/purchases/:purchaseId
// @desc    Update purchase status
// @access  Admin
router.put('/purchases/:purchaseId', [  
  body('status').isIn(['pending', 'completed', 'failed', 'processing', 'refunded', 'delivered']),
  body('adminNotes').optional().isString(),
  validate
], asyncHandler(async (req, res) => {
  const { purchaseId } = req.params;
  const { status, adminNotes } = req.body;

  const purchase = await DataPurchase.findById(purchaseId);
  if (!purchase) {
    return res.status(404).json({
      success: false,
      message: 'Purchase not found'
    });
  }

  const oldStatus = purchase.status;
  purchase.status = status;
  if (adminNotes) purchase.adminNotes = adminNotes;
  purchase.updatedBy = req.user._id;
  purchase.updatedAt = new Date();

  await purchase.save();

  // Handle refund if status changed to refunded
  if (status === 'refunded' && oldStatus !== 'refunded') {
    const user = await User.findById(purchase.userId);
    const refundAmount = purchase.price;
    
    user.walletBalance += refundAmount;
    await user.save();

    // Create refund transaction
    await Transaction.create({
      userId: purchase.userId,
      type: 'refund',
      amount: refundAmount,
      balanceBefore: user.walletBalance - refundAmount,
      balanceAfter: user.walletBalance,
      status: 'completed',
      reference: `REFUND-${purchase.reference}`,
      gateway: 'wallet-refund',
      relatedPurchaseId: purchase._id,
      description: `Refund for purchase ${purchase.reference}`
    });
  }

  res.status(200).json({
    success: true,
    message: 'Purchase updated successfully',
    data: purchase
  });
}));

// @route   POST /api/admin/purchases/manual
// @desc    Create manual purchase for user
// @access  Admin
router.post('/purchases/manual', [
  body('userId').isMongoId(),
  body('phoneNumber').matches(/^(\+233|0)[2-9]\d{8}$/),
  body('network').isIn(['YELLO', 'MTN', 'TELECEL', 'AT_PREMIUM', 'AIRTELTIGO', 'AT']),
  body('capacity').isNumeric(),
  validate
], asyncHandler(async (req, res) => {
  const { userId, phoneNumber, network, capacity } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  // Get pricing
  const pricing = await DataPricing.findOne({ network, capacity, isActive: true });
  if (!pricing) {
    return res.status(404).json({
      success: false,
      message: 'Pricing not found'
    });
  }

  const reference = `ADMIN-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

  const purchase = new DataPurchase({
    userId,
    phoneNumber,
    network,
    capacity,
    gateway: 'admin',
    method: 'admin',
    price: 0, // Free for admin manual purchase
    pricing: {
      systemPrice: pricing.prices.adminCost,
      customerPrice: 0,
      agentProfit: 0
    },
    reference,
    status: 'completed',
    adminNotes: `Manual purchase by admin ${req.user.name}`
  });

  await purchase.save();

  res.status(200).json({
    success: true,
    message: 'Manual purchase created',
    data: purchase
  });
}));

// ==================== AGENT STORE MANAGEMENT ====================

// @route   GET /api/admin/stores
// @desc    Get all agent stores
// @access  Admin
router.get('/stores', asyncHandler(async (req, res) => {
  const { 
    verificationStatus,
    isActive,
    isPremium,
    page = 1,
    limit = 50
  } = req.query;

  const filter = {};
  
  if (verificationStatus) filter.verificationStatus = verificationStatus;
  if (isActive !== undefined) filter.isActive = isActive === 'true';
  if (isPremium !== undefined) filter.isPremium = isPremium === 'true';

  const stores = await AgentStore.find(filter)
    .populate('agent', 'name email phoneNumber')
    .sort({ createdAt: -1 })
    .limit(limit * 1)
    .skip((page - 1) * limit);

  const total = await AgentStore.countDocuments(filter);

  res.status(200).json({
    success: true,
    data: {
      stores,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    }
  });
}));

// @route   PUT /api/admin/stores/:storeId/verify
// @desc    Verify or reject store
// @access  Admin
router.put('/stores/:storeId/verify', [
  body('status').isIn(['verified', 'rejected']),
  body('reason').optional().isString(),
  validate
], asyncHandler(async (req, res) => {
  const { storeId } = req.params;
  const { status, reason } = req.body;

  const store = await AgentStore.findById(storeId);
  if (!store) {
    return res.status(404).json({
      success: false,
      message: 'Store not found'
    });
  }

  store.verificationStatus = status;
  store.verifiedAt = new Date();
  store.verifiedBy = req.user._id;

  await store.save();

  // Notify agent
  await Notification.create({
    userId: store.agent,
    title: `Store ${status}`,
    message: status === 'verified' 
      ? 'Your store has been verified and is now active!'
      : `Store verification rejected. ${reason || ''}`,
    type: status === 'verified' ? 'success' : 'error',
    category: 'account'
  });

  res.status(200).json({
    success: true,
    message: `Store ${status} successfully`,
    data: store
  });
}));

// @route   PUT /api/admin/stores/:storeId/premium
// @desc    Set store premium status
// @access  Admin
router.put('/stores/:storeId/premium', [
  body('isPremium').isBoolean(),
  validate
], asyncHandler(async (req, res) => {
  const { storeId } = req.params;
  const { isPremium } = req.body;

  const store = await AgentStore.findById(storeId);
  if (!store) {
    return res.status(404).json({
      success: false,
      message: 'Store not found'
    });
  }

  store.isPremium = isPremium;
  await store.save();

  res.status(200).json({
    success: true,
    message: `Store premium status ${isPremium ? 'granted' : 'removed'}`,
    data: store
  });
}));

// ==================== RESULT CHECKER MANAGEMENT ====================

// @route   POST /api/admin/result-checkers/bulk
// @desc    Bulk add result checker cards
// @access  Admin
router.post('/result-checkers/bulk', [
  body('type').isIn(['BECE', 'WASSCE']),
  body('year').isNumeric(),
  body('cards').isArray(),
  body('cards.*.serialNumber').isString(),
  body('cards.*.pin').isString(),
  body('price').isNumeric(),
  validate
], asyncHandler(async (req, res) => {
  const { type, year, cards, price, examType = 'MAY/JUNE' } = req.body;

  const batchNumber = `BATCH-${Date.now()}`;
  const results = [];

  for (const card of cards) {
    try {
      const checker = new ResultChecker({
        type,
        year,
        examType,
        serialNumber: card.serialNumber.toUpperCase(),
        pin: card.pin,
        price,
        status: 'available',
        batchInfo: {
          batchNumber,
          batchDate: new Date(),
          totalInBatch: cards.length
        },
        addedBy: req.user._id
      });

      await checker.save();
      results.push({ success: true, serialNumber: card.serialNumber });
    } catch (error) {
      results.push({ 
        success: false, 
        serialNumber: card.serialNumber, 
        error: error.message 
      });
    }
  }

  const successful = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  res.status(200).json({
    success: true,
    message: `Added ${successful} cards successfully, ${failed} failed`,
    data: {
      batchNumber,
      results,
      summary: {
        total: cards.length,
        successful,
        failed
      }
    }
  });
}));

// @route   GET /api/admin/result-checkers
// @desc    Get result checker inventory
// @access  Admin
router.get('/result-checkers', asyncHandler(async (req, res) => {
  const { type, year, status, page = 1, limit = 50 } = req.query;

  const filter = {};
  if (type) filter.type = type;
  if (year) filter.year = year;
  if (status) filter.status = status;

  const checkers = await ResultChecker.find(filter)
    .populate('soldTo.user', 'name email')
    .populate('addedBy', 'name')
    .sort({ createdAt: -1 })
    .limit(limit * 1)
    .skip((page - 1) * limit);

  const total = await ResultChecker.countDocuments(filter);

  // Get statistics
  const stats = await ResultChecker.aggregate([
    { $match: filter },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
        totalValue: { $sum: '$price' }
      }
    }
  ]);

  res.status(200).json({
    success: true,
    data: {
      checkers,
      stats,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    }
  });
}));

// ==================== NOTIFICATION MANAGEMENT ====================

// @route   POST /api/admin/notifications/global
// @desc    Send global notification
// @access  Admin
router.post('/notifications/global', [
  body('title').isString().isLength({ min: 1, max: 100 }),
  body('message').isString().isLength({ min: 1, max: 500 }),
  body('type').isIn(['info', 'success', 'warning', 'error', 'promotion']),
  validate
], asyncHandler(async (req, res) => {
  const { title, message, type = 'info', actionUrl } = req.body;

  const notification = new Notification({
    isGlobal: true,
    title,
    message,
    type,
    category: 'system',
    actionUrl,
    metadata: {
      sentBy: req.user._id,
      sentByName: req.user.name
    }
  });

  await notification.save();

  res.status(200).json({
    success: true,
    message: 'Global notification sent',
    data: notification
  });
}));

// @route   POST /api/admin/notifications/targeted
// @desc    Send notification to specific users
// @access  Admin
router.post('/notifications/targeted', [
  body('userIds').isArray(),
  body('title').isString(),
  body('message').isString(),
  body('type').isIn(['info', 'success', 'warning', 'error']),
  validate
], asyncHandler(async (req, res) => {
  const { userIds, title, message, type = 'info' } = req.body;

  const notifications = await Promise.all(
    userIds.map(userId => 
      Notification.create({
        userId,
        title,
        message,
        type,
        category: 'system'
      })
    )
  );

  res.status(200).json({
    success: true,
    message: `Sent notifications to ${userIds.length} users`,
    data: notifications
  });
}));

// ==================== REPORTING & ANALYTICS ====================

// @route   GET /api/admin/analytics/dashboard
// @desc    Get admin dashboard analytics
// @access  Admin
router.get('/analytics/dashboard', asyncHandler(async (req, res) => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  const thisMonth = new Date();
  thisMonth.setDate(1);
  thisMonth.setHours(0, 0, 0, 0);

  // User statistics
  const userStats = await User.aggregate([
    {
      $facet: {
        total: [{ $count: 'count' }],
        byRole: [
          { $group: { _id: '$role', count: { $sum: 1 } } }
        ],
        byStatus: [
          { $group: { _id: '$approvalStatus', count: { $sum: 1 } } }
        ],
        newToday: [
          { $match: { createdAt: { $gte: today } } },
          { $count: 'count' }
        ],
        newThisMonth: [
          { $match: { createdAt: { $gte: thisMonth } } },
          { $count: 'count' }
        ]
      }
    }
  ]);

  // Transaction statistics
  const transactionStats = await Transaction.aggregate([
    {
      $facet: {
        todayVolume: [
          { $match: { createdAt: { $gte: today }, status: 'completed' } },
          { $group: { _id: null, total: { $sum: '$amount' }, count: { $sum: 1 } } }
        ],
        monthVolume: [
          { $match: { createdAt: { $gte: thisMonth }, status: 'completed' } },
          { $group: { _id: null, total: { $sum: '$amount' }, count: { $sum: 1 } } }
        ],
        byType: [
          { $match: { status: 'completed' } },
          { $group: { _id: '$type', total: { $sum: '$amount' }, count: { $sum: 1 } } }
        ]
      }
    }
  ]);

  // Purchase statistics
  const purchaseStats = await DataPurchase.aggregate([
    {
      $facet: {
        todayPurchases: [
          { $match: { createdAt: { $gte: today } } },
          { $count: 'count' }
        ],
        byNetwork: [
          { $group: { _id: '$network', count: { $sum: 1 }, revenue: { $sum: '$price' } } }
        ],
        byStatus: [
          { $group: { _id: '$status', count: { $sum: 1 } } }
        ]
      }
    }
  ]);

  // Store statistics
  const storeStats = await AgentStore.aggregate([
    {
      $facet: {
        total: [{ $count: 'count' }],
        active: [
          { $match: { isActive: true } },
          { $count: 'count' }
        ],
        verified: [
          { $match: { verificationStatus: 'verified' } },
          { $count: 'count' }
        ],
        totalSales: [
          { $group: { _id: null, total: { $sum: '$statistics.totalSales' } } }
        ]
      }
    }
  ]);

  res.status(200).json({
    success: true,
    data: {
      users: userStats[0],
      transactions: transactionStats[0],
      purchases: purchaseStats[0],
      stores: storeStats[0],
      timestamp: new Date()
    }
  });
}));

// @route   GET /api/admin/analytics/revenue
// @desc    Get revenue analytics
// @access  Admin
router.get('/analytics/revenue', asyncHandler(async (req, res) => {
  const { startDate, endDate, groupBy = 'day' } = req.query;

  const matchStage = {
    status: 'completed',
    createdAt: {}
  };

  if (startDate) matchStage.createdAt.$gte = new Date(startDate);
  if (endDate) matchStage.createdAt.$lte = new Date(endDate);

  let groupStage;
  switch (groupBy) {
    case 'hour':
      groupStage = {
        $dateToString: { format: '%Y-%m-%d %H:00', date: '$createdAt' }
      };
      break;
    case 'day':
      groupStage = {
        $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
      };
      break;
    case 'month':
      groupStage = {
        $dateToString: { format: '%Y-%m', date: '$createdAt' }
      };
      break;
    default:
      groupStage = {
        $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
      };
  }

  const revenue = await DataPurchase.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: groupStage,
        revenue: { $sum: '$price' },
        orders: { $sum: 1 },
        avgOrderValue: { $avg: '$price' }
      }
    },
    { $sort: { _id: 1 } }
  ]);

  const agentProfits = await AgentProfit.aggregate([
    { $match: { status: 'credited', createdAt: matchStage.createdAt } },
    {
      $group: {
        _id: groupStage,
        totalProfit: { $sum: '$profit' },
        transactions: { $sum: 1 }
      }
    },
    { $sort: { _id: 1 } }
  ]);

  res.status(200).json({
    success: true,
    data: {
      revenue,
      agentProfits,
      period: { startDate, endDate, groupBy }
    }
  });
}));

// @route   GET /api/admin/analytics/agents
// @desc    Get agent performance analytics
// @access  Admin
router.get('/analytics/agents', asyncHandler(async (req, res) => {
  const { startDate, endDate, limit = 20 } = req.query;

  const matchStage = {};
  if (startDate || endDate) {
    matchStage.createdAt = {};
    if (startDate) matchStage.createdAt.$gte = new Date(startDate);
    if (endDate) matchStage.createdAt.$lte = new Date(endDate);
  }

  // Top performing agents
  const topAgents = await DataPurchase.aggregate([
    { $match: { ...matchStage, agentId: { $exists: true } } },
    {
      $group: {
        _id: '$agentId',
        totalSales: { $sum: 1 },
        totalRevenue: { $sum: '$price' },
        totalProfit: { $sum: '$pricing.agentProfit' }
      }
    },
    { $sort: { totalRevenue: -1 } },
    { $limit: parseInt(limit) },
    {
      $lookup: {
        from: 'users',
        localField: '_id',
        foreignField: '_id',
        as: 'agent'
      }
    },
    { $unwind: '$agent' },
    {
      $project: {
        agentName: '$agent.name',
        agentEmail: '$agent.email',
        totalSales: 1,
        totalRevenue: 1,
        totalProfit: 1
      }
    }
  ]);

  res.status(200).json({
    success: true,
    data: {
      topAgents,
      period: { startDate, endDate }
    }
  });
}));

// ==================== API KEY MANAGEMENT ====================

// @route   GET /api/admin/api-keys
// @desc    Get all API keys
// @access  Admin
router.get('/api-keys', asyncHandler(async (req, res) => {
  const { userId, isActive, page = 1, limit = 50 } = req.query;

  const filter = {};
  if (userId) filter.userId = userId;
  if (isActive !== undefined) filter.isActive = isActive === 'true';

  const apiKeys = await ApiKey.find(filter)
    .populate('userId', 'name email')
    .sort({ createdAt: -1 })
    .limit(limit * 1)
    .skip((page - 1) * limit);

  const total = await ApiKey.countDocuments(filter);

  res.status(200).json({
    success: true,
    data: {
      apiKeys: apiKeys.map(key => ({
        ...key.toObject(),
        key: key.key.substring(0, 10) + '...' // Mask the key
      })),
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    }
  });
}));

// @route   PUT /api/admin/api-keys/:keyId/status
// @desc    Enable/disable API key
// @access  Admin
router.put('/api-keys/:keyId/status', [
  body('isActive').isBoolean(),
  validate
], asyncHandler(async (req, res) => {
  const { keyId } = req.params;
  const { isActive } = req.body;

  const apiKey = await ApiKey.findById(keyId);
  if (!apiKey) {
    return res.status(404).json({
      success: false,
      message: 'API key not found'
    });
  }

  apiKey.isActive = isActive;
  await apiKey.save();

  res.status(200).json({
    success: true,
    message: `API key ${isActive ? 'enabled' : 'disabled'}`,
    data: apiKey
  });
}));

// ==================== SYSTEM SETTINGS ====================

// @route   POST /api/admin/system/maintenance
// @desc    Toggle system maintenance mode
// @access  Admin
router.post('/system/maintenance', [
  body('enabled').isBoolean(),
  body('message').optional().isString(),
  validate
], asyncHandler(async (req, res) => {
  const { enabled, message } = req.body;

  // This would typically update a system configuration
  // For now, we'll send a global notification
  if (enabled) {
    await Notification.create({
      isGlobal: true,
      title: 'System Maintenance',
      message: message || 'The system is under maintenance. Please try again later.',
      type: 'warning',
      category: 'system',
      priority: 'urgent'
    });
  }

  res.status(200).json({
    success: true,
    message: `Maintenance mode ${enabled ? 'enabled' : 'disabled'}`,
    data: {
      maintenanceMode: enabled,
      message
    }
  });
}));

// @route   GET /api/admin/system/health
// @desc    Get system health status
// @access  Admin
router.get('/system/health', asyncHandler(async (req, res) => {
  const [
    userCount,
    activeTransactions,
    pendingPurchases,
    lowStockItems
  ] = await Promise.all([
    User.countDocuments(),
    Transaction.countDocuments({ status: 'pending' }),
    DataPurchase.countDocuments({ status: 'pending' }),
    DataPricing.countDocuments({ 'stock.overallInStock': false })
  ]);

  res.status(200).json({
    success: true,
    data: {
      status: 'healthy',
      metrics: {
        totalUsers: userCount,
        pendingTransactions: activeTransactions,
        pendingPurchases,
        outOfStockItems: lowStockItems
      },
      timestamp: new Date()
    }
  });
}));

router.get('/activities/recent', asyncHandler(async (req, res) => {
  const { 
    limit = 20,
    types = ['all'],
    startDate,
    endDate 
  } = req.query;

  const activities = [];
  const dateFilter = {};
  
  if (startDate) dateFilter.$gte = new Date(startDate);
  if (endDate) dateFilter.$lte = new Date(endDate);
  
  const shouldInclude = (type) => types.includes('all') || types.includes(type);

  try {
    // Fetch different types of activities in parallel
    const promises = [];

    // 1. Recent User Registrations
    if (shouldInclude('registration')) {
      promises.push(
        User.find({ 
          createdAt: dateFilter.$gte || dateFilter.$lte ? dateFilter : { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        })
        .select('name email role createdAt approvalStatus')
        .sort({ createdAt: -1 })
        .limit(Math.min(limit, 10))
        .lean()
        .then(users => users.map(user => ({
          type: 'User Registration',
          message: `New ${user.role} registered: ${user.name}`,
          time: user.createdAt,
          status: user.approvalStatus === 'approved' ? 'success' : 'pending',
          category: 'user',
          metadata: {
            userId: user._id,
            userEmail: user.email,
            userRole: user.role
          }
        })))
      );
    }

    // 2. Recent Purchases
    if (shouldInclude('purchase')) {
      promises.push(
        DataPurchase.find({
          createdAt: dateFilter.$gte || dateFilter.$lte ? dateFilter : { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        })
        .populate('userId', 'name')
        .select('network capacity phoneNumber status createdAt price userId')
        .sort({ createdAt: -1 })
        .limit(Math.min(limit, 10))
        .lean()
        .then(purchases => purchases.map(purchase => ({
          type: 'Purchase',
          message: `${purchase.network} ${purchase.capacity}GB purchase ${purchase.status === 'completed' ? 'completed' : purchase.status}`,
          time: purchase.createdAt,
          status: purchase.status === 'completed' ? 'success' : 
                  purchase.status === 'failed' ? 'failed' : 'pending',
          category: 'transaction',
          metadata: {
            purchaseId: purchase._id,
            network: purchase.network,
            capacity: purchase.capacity,
            amount: purchase.price,
            phoneNumber: purchase.phoneNumber,
            userName: purchase.userId?.name || 'Unknown'
          }
        })))
      );
    }

    // 3. Recent Transactions (Deposits & Withdrawals)
    if (shouldInclude('transaction')) {
      promises.push(
        Transaction.find({
          createdAt: dateFilter.$gte || dateFilter.$lte ? dateFilter : { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
          type: { $in: ['deposit', 'withdrawal', 'wallet_funding', 'admin_credit', 'admin_debit'] }
        })
        .populate('userId', 'name')
        .select('type amount status createdAt userId gateway')
        .sort({ createdAt: -1 })
        .limit(Math.min(limit, 10))
        .lean()
        .then(transactions => transactions.map(transaction => {
          let message = '';
          if (transaction.type === 'withdrawal') {
            message = `${transaction.status === 'pending' ? 'Pending' : 'Completed'} withdrawal request GHS ${transaction.amount.toFixed(2)}`;
          } else if (transaction.type === 'deposit' || transaction.type === 'wallet_funding') {
            message = `Wallet funding GHS ${transaction.amount.toFixed(2)} via ${transaction.gateway}`;
          } else if (transaction.type === 'admin_credit') {
            message = `Admin credit GHS ${transaction.amount.toFixed(2)} to ${transaction.userId?.name || 'User'}`;
          } else if (transaction.type === 'admin_debit') {
            message = `Admin debit GHS ${transaction.amount.toFixed(2)} from ${transaction.userId?.name || 'User'}`;
          }
          
          return {
            type: transaction.type === 'withdrawal' ? 'Withdrawal' : 
                  transaction.type === 'admin_credit' || transaction.type === 'admin_debit' ? 'Admin Action' : 'Deposit',
            message,
            time: transaction.createdAt,
            status: transaction.status === 'completed' ? 'success' : 
                    transaction.status === 'failed' ? 'failed' : 'pending',
            category: 'financial',
            metadata: {
              transactionId: transaction._id,
              amount: transaction.amount,
              gateway: transaction.gateway,
              userName: transaction.userId?.name || 'Unknown'
            }
          };
        }))
      );
    }

    // 4. Store Verifications
    if (shouldInclude('store')) {
      promises.push(
        AgentStore.find({
          $or: [
            { createdAt: dateFilter.$gte || dateFilter.$lte ? dateFilter : { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } },
            { verifiedAt: dateFilter.$gte || dateFilter.$lte ? dateFilter : { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } }
          ]
        })
        .populate('agent', 'name')
        .select('storeName verificationStatus createdAt verifiedAt agent')
        .sort({ createdAt: -1 })
        .limit(Math.min(limit, 10))
        .lean()
        .then(stores => stores.map(store => ({
          type: 'Store Verification',
          message: store.verificationStatus === 'pending' ? 
                   `New store pending verification: ${store.storeName}` :
                   `Store ${store.storeName} ${store.verificationStatus}`,
          time: store.verifiedAt || store.createdAt,
          status: store.verificationStatus === 'verified' ? 'success' : 
                  store.verificationStatus === 'rejected' ? 'failed' : 'pending',
          category: 'store',
          metadata: {
            storeId: store._id,
            storeName: store.storeName,
            agentName: store.agent?.name || 'Unknown'
          }
        })))
      );
    }

    // 5. Failed Transactions/Purchases
    if (shouldInclude('failed')) {
      promises.push(
        Transaction.find({
          createdAt: dateFilter.$gte || dateFilter.$lte ? dateFilter : { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
          status: 'failed'
        })
        .populate('userId', 'name')
        .select('type amount createdAt userId reference')
        .sort({ createdAt: -1 })
        .limit(Math.min(limit, 5))
        .lean()
        .then(failed => failed.map(transaction => ({
          type: 'Transaction',
          message: `Failed ${transaction.type} attempt - GHS ${transaction.amount.toFixed(2)}`,
          time: transaction.createdAt,
          status: 'failed',
          category: 'error',
          metadata: {
            transactionId: transaction._id,
            reference: transaction.reference,
            userName: transaction.userId?.name || 'Unknown'
          }
        })))
      );
    }

    // 6. API Key Activities
    if (shouldInclude('api')) {
      promises.push(
        ApiKey.find({
          createdAt: dateFilter.$gte || dateFilter.$lte ? dateFilter : { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        })
        .populate('userId', 'name')
        .select('name isActive createdAt userId')
        .sort({ createdAt: -1 })
        .limit(Math.min(limit, 5))
        .lean()
        .then(keys => keys.map(key => ({
          type: 'API Key',
          message: `New API key created: ${key.name}`,
          time: key.createdAt,
          status: key.isActive ? 'success' : 'pending',
          category: 'system',
          metadata: {
            keyId: key._id,
            keyName: key.name,
            userName: key.userId?.name || 'Unknown'
          }
        })))
      );
    }

    // Execute all promises in parallel
    const results = await Promise.all(promises);
    
    // Flatten and combine all activities
    results.forEach(result => activities.push(...result));

    // Sort all activities by time (most recent first)
    activities.sort((a, b) => new Date(b.time) - new Date(a.time));

    // Limit to requested number
    const limitedActivities = activities.slice(0, parseInt(limit));

    // Format time as relative time (e.g., "2 min ago", "5 hours ago")
    const formattedActivities = limitedActivities.map(activity => ({
      ...activity,
      timeAgo: getRelativeTime(activity.time),
      timestamp: activity.time
    }));

    // Get activity statistics
    const stats = {
      total: formattedActivities.length,
      byStatus: {
        success: formattedActivities.filter(a => a.status === 'success').length,
        pending: formattedActivities.filter(a => a.status === 'pending').length,
        failed: formattedActivities.filter(a => a.status === 'failed').length
      },
      byCategory: {
        user: formattedActivities.filter(a => a.category === 'user').length,
        transaction: formattedActivities.filter(a => a.category === 'transaction').length,
        financial: formattedActivities.filter(a => a.category === 'financial').length,
        store: formattedActivities.filter(a => a.category === 'store').length,
        system: formattedActivities.filter(a => a.category === 'system').length,
        error: formattedActivities.filter(a => a.category === 'error').length
      }
    };

    res.status(200).json({
      success: true,
      data: {
        activities: formattedActivities,
        stats,
        timestamp: new Date()
      }
    });

  } catch (error) {
    console.error('Error fetching recent activities:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching recent activities',
      error: error.message
    });
  }
}));

// @route   GET /api/admin/activities/stream
// @desc    Get activity stream with pagination
// @access  Admin
router.get('/activities/stream', asyncHandler(async (req, res) => {
  const { 
    page = 1,
    limit = 50,
    category,
    status,
    userId,
    startDate,
    endDate
  } = req.query;

  // This would be better implemented with a dedicated Activity collection
  // For now, we'll aggregate from multiple collections
  
  const skip = (page - 1) * limit;
  const activities = [];

  // Build filters
  const dateFilter = {};
  if (startDate || endDate) {
    dateFilter.createdAt = {};
    if (startDate) dateFilter.createdAt.$gte = new Date(startDate);
    if (endDate) dateFilter.createdAt.$lte = new Date(endDate);
  }

  // Fetch from different collections based on category
  if (!category || category === 'all' || category === 'transaction') {
    const purchases = await DataPurchase.find(dateFilter)
      .populate('userId', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    purchases.forEach(p => {
      activities.push({
        id: p._id,
        type: 'purchase',
        category: 'transaction',
        message: `${p.network} ${p.capacity}GB purchase`,
        status: p.status,
        user: p.userId,
        amount: p.price,
        timestamp: p.createdAt
      });
    });
  }

  // Sort and paginate
  activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  const paginatedActivities = activities.slice(0, parseInt(limit));

  res.status(200).json({
    success: true,
    data: {
      activities: paginatedActivities,
      pagination: {
        total: activities.length,
        page: parseInt(page),
        pages: Math.ceil(activities.length / limit),
        limit: parseInt(limit)
      }
    }
  });
}));

// Helper function to get relative time
function getRelativeTime(date) {
  const now = new Date();
  const diff = now - new Date(date);
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return `${seconds} sec ago`;
  if (minutes < 60) return `${minutes} min ago`;
  if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  if (days < 7) return `${days} day${days > 1 ? 's' : ''} ago`;
  
  return new Date(date).toLocaleDateString();


}


// Add these endpoints to your admin routes file (routes/admin.js)
// Place them in the PRICING & INVENTORY MANAGEMENT section

// @route   GET /api/admin/pricing
// @desc    Get all pricing data with filters
// @access  Admin
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

// @route   GET /api/admin/pricing/:id
// @desc    Get single pricing item
// @access  Admin
router.get('/pricing/:id', asyncHandler(async (req, res) => {
  const { id } = req.params;

  const pricing = await DataPricing.findById(id)
    .populate('lastUpdatedBy', 'name email');

  if (!pricing) {
    return res.status(404).json({
      success: false,
      message: 'Pricing not found'
    });
  }

  res.status(200).json({
    success: true,
    data: pricing
  });
}));

// @route   PUT /api/admin/pricing/:id
// @desc    Update existing pricing
// @access  Admin  
router.put('/pricing/:id', [
  body('prices.adminCost').optional().isNumeric(),
  body('prices.dealer').optional().isNumeric(),
  body('prices.superAgent').optional().isNumeric(),
  body('prices.agent').optional().isNumeric(),
  body('prices.user').optional().isNumeric(),
  body('description').optional().isString(),
  body('isPopular').optional().isBoolean(),
  validate
], asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { prices, description, isPopular, tags } = req.body;

  const pricing = await DataPricing.findById(id);
  if (!pricing) {
    return res.status(404).json({
      success: false,
      message: 'Pricing not found'
    });
  }

  // Validate price hierarchy if prices are being updated
  if (prices) {
    const finalPrices = { ...pricing.prices, ...prices };
    
    if (finalPrices.adminCost >= finalPrices.dealer || 
        finalPrices.dealer >= finalPrices.superAgent || 
        finalPrices.superAgent >= finalPrices.agent || 
        finalPrices.agent >= finalPrices.user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid price hierarchy. Prices must increase with each role level.'
      });
    }
    
    pricing.prices = finalPrices;
  }

  if (description !== undefined) pricing.description = description;
  if (isPopular !== undefined) pricing.isPopular = isPopular;
  if (tags !== undefined) pricing.tags = tags;
  
  pricing.lastUpdatedBy = req.user._id;
  pricing.updatedAt = new Date();

  await pricing.save();

  res.status(200).json({
    success: true,
    message: 'Pricing updated successfully',
    data: pricing
  });
}));

// @route   DELETE /api/admin/pricing/:id
// @desc    Delete pricing item
// @access  Admin
router.delete('/pricing/:id', asyncHandler(async (req, res) => {
  const { id } = req.params;

  const pricing = await DataPricing.findById(id);
  if (!pricing) {
    return res.status(404).json({
      success: false,
      message: 'Pricing not found'
    });
  }

  // Soft delete by setting isActive to false
  pricing.isActive = false;
  pricing.deletedBy = req.user._id;
  pricing.deletedAt = new Date();
  await pricing.save();

  // Or hard delete
  // await pricing.remove();

  res.status(200).json({
    success: true,
    message: 'Pricing deleted successfully'
  });
}));

// @route   GET /api/admin/inventory
// @desc    Get all network inventory status
// @access  Admin
router.get('/inventory', asyncHandler(async (req, res) => {
  try {
    const inventory = await DataInventory.find({})
      .populate('webLastUpdatedBy', 'name')
      .populate('apiLastUpdatedBy', 'name')
      .sort({ network: 1 });

    res.status(200).json({
      success: true,
      data: inventory,
      count: inventory.length
    });
  } catch (error) {
    console.error('Error fetching inventory:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch inventory data',
      error: error.message
    });
  }
}));

// @route   POST /api/admin/pricing/bulk
// @desc    Bulk import pricing data
// @access  Admin
router.post('/pricing/bulk', [
  body('pricingData').isArray(),
  body('pricingData.*.network').isIn(['YELLO', 'MTN', 'TELECEL', 'AT_PREMIUM', 'AIRTELTIGO', 'AT']),
  body('pricingData.*.capacity').isNumeric(),
  body('pricingData.*.prices.adminCost').isNumeric(),
  body('pricingData.*.prices.dealer').isNumeric(),
  body('pricingData.*.prices.superAgent').isNumeric(),
  body('pricingData.*.prices.agent').isNumeric(),
  body('pricingData.*.prices.user').isNumeric(),
  validate
], asyncHandler(async (req, res) => {
  const { pricingData } = req.body;
  
  const results = [];
  const errors = [];

  for (const item of pricingData) {
    try {
      // Check if pricing already exists
      let pricing = await DataPricing.findOne({
        network: item.network,
        capacity: item.capacity
      });

      if (pricing) {
        // Update existing
        pricing.prices = item.prices;
        pricing.description = item.description || pricing.description;
        pricing.isPopular = item.isPopular !== undefined ? item.isPopular : pricing.isPopular;
        pricing.tags = item.tags || pricing.tags;
        pricing.lastUpdatedBy = req.user._id;
      } else {
        // Create new
        pricing = new DataPricing({
          ...item,
          lastUpdatedBy: req.user._id
        });
      }

      await pricing.save();
      results.push({
        network: item.network,
        capacity: item.capacity,
        status: 'success'
      });
    } catch (error) {
      errors.push({
        network: item.network,
        capacity: item.capacity,
        error: error.message
      });
    }
  }

  res.status(200).json({
    success: true,
    message: `Bulk import completed. Success: ${results.length}, Failed: ${errors.length}`,
    results,
    errors
  });
}));
// Update in your backend routes/admin.js - Fix the ObjectId usage

// @route   GET /api/admin/users/:userId/purchases
// @desc    Get all purchases for a specific user (today only or all time)
// @access  Admin
router.get('/users/:userId/purchases', asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { 
    todayOnly = 'false',
    network,
    status,
    startDate,
    endDate,
    page = 1,
    limit = 50,
    sortBy = 'createdAt',
    order = 'desc'
  } = req.query;

  // Import mongoose at the top of your file if not already done
  const mongoose = require('mongoose');

  // Verify user exists
  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  // Build filter - Use 'new' when creating ObjectId
  const filter = { userId: new mongoose.Types.ObjectId(userId) };
  
  // Add date filter based on todayOnly flag
  if (todayOnly === 'true') {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    filter.createdAt = {
      $gte: today,
      $lt: tomorrow
    };
  } else if (startDate || endDate) {
    // Custom date range
    filter.createdAt = {};
    if (startDate) filter.createdAt.$gte = new Date(startDate);
    if (endDate) filter.createdAt.$lte = new Date(endDate);
  }

  // Add other filters
  if (network) filter.network = network;
  if (status) filter.status = status;

  // Fetch purchases
  const purchases = await DataPurchase.find(filter)
    .populate('agentId', 'name email')
    .sort({ [sortBy]: order === 'desc' ? -1 : 1 })
    .limit(limit * 1)
    .skip((page - 1) * limit);

  const total = await DataPurchase.countDocuments(filter);

  // Calculate statistics - Fix the aggregation with 'new' ObjectId
  const stats = await DataPurchase.aggregate([
    { $match: { userId: new mongoose.Types.ObjectId(userId) } }, // Use 'new' here
    {
      $group: {
        _id: null,
        totalAmount: { $sum: '$price' },
        totalPurchases: { $sum: 1 },
        avgPurchaseValue: { $avg: '$price' },
        totalCapacity: { $sum: '$capacity' }
      }
    }
  ]);

  // Get breakdown by network - for all purchases
  const networkBreakdown = await DataPurchase.aggregate([
    { $match: { userId: new mongoose.Types.ObjectId(userId) } }, // Use 'new' here
    {
      $group: {
        _id: '$network',
        count: { $sum: 1 },
        totalAmount: { $sum: '$price' },
        totalCapacity: { $sum: '$capacity' }
      }
    },
    { $sort: { totalAmount: -1 } }
  ]);

  // Get breakdown by status - for all purchases
  const statusBreakdown = await DataPurchase.aggregate([
    { $match: { userId: new mongoose.Types.ObjectId(userId) } }, // Use 'new' here
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
        totalAmount: { $sum: '$price' }
      }
    }
  ]);

  // Get today's stats if not filtering by today only
  let todayStats = null;
  if (todayOnly !== 'true') {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    todayStats = await DataPurchase.aggregate([
      {
        $match: {
          userId: new mongoose.Types.ObjectId(userId), // Use 'new' here
          createdAt: { $gte: today, $lt: tomorrow }
        }
      },
      {
        $group: {
          _id: null,
          todayTotal: { $sum: '$price' },
          todayCount: { $sum: 1 }
        }
      }
    ]);
  }

  // Debug logging
  console.log('User purchases stats:', {
    userId,
    totalPurchases: total,
    statsResult: stats,
    networkBreakdown,
    statusBreakdown
  });

  res.status(200).json({
    success: true,
    data: {
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phoneNumber: user.phoneNumber,
        role: user.role,
        walletBalance: user.walletBalance
      },
      purchases,
      statistics: {
        overall: stats[0] || {
          totalAmount: 0,
          totalPurchases: 0,
          avgPurchaseValue: 0,
          totalCapacity: 0
        },
        today: todayOnly === 'true' ? null : (todayStats?.[0] || {
          todayTotal: 0,
          todayCount: 0
        }),
        byNetwork: networkBreakdown || [],
        byStatus: statusBreakdown || []
      },
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit),
        limit: parseInt(limit)
      },
      filters: {
        todayOnly: todayOnly === 'true',
        network,
        status,
        dateRange: startDate || endDate ? { startDate, endDate } : null
      }
    }
  });
}));

// Add this route in the PURCHASE MANAGEMENT section of your admin.js file

// @route   PUT /api/admin/purchases/bulk-status
// @desc    Bulk update purchase status
// @access  Admin
router.put('/purchases/bulk-status', [
  body('purchaseIds').isArray().notEmpty(),
  body('status').isIn(['pending', 'completed', 'failed', 'processing', 'refunded', 'delivered']),
  body('adminNotes').optional().isString(),
  validate
], asyncHandler(async (req, res) => {
  const { purchaseIds, status, adminNotes } = req.body;
  
  const results = {
    successful: [],
    failed: [],
    refunded: []
  };

  for (const purchaseId of purchaseIds) {
    try {
      const purchase = await DataPurchase.findById(purchaseId);
      
      if (!purchase) {
        results.failed.push({
          purchaseId,
          reason: 'Purchase not found'
        });
        continue;
      }

      const oldStatus = purchase.status;
      purchase.status = status;
      if (adminNotes) {
        purchase.adminNotes = (purchase.adminNotes || '') + '\n' + adminNotes;
      }
      purchase.updatedBy = req.user._id;
      purchase.updatedAt = new Date();

      await purchase.save();

      // Handle refund if status changed to refunded
      if (status === 'refunded' && oldStatus !== 'refunded') {
        const user = await User.findById(purchase.userId);
        if (user) {
          const refundAmount = purchase.price;
          
          user.walletBalance += refundAmount;
          await user.save();

          // Create refund transaction
          await Transaction.create({
            userId: purchase.userId,
            type: 'refund',
            amount: refundAmount,
            balanceBefore: user.walletBalance - refundAmount,
            balanceAfter: user.walletBalance,
            status: 'completed',
            reference: `REFUND-${purchase.reference}`,
            gateway: 'wallet-refund',
            relatedPurchaseId: purchase._id,
            description: `Refund for purchase ${purchase.reference}`
          });

          results.refunded.push({
            purchaseId: purchase._id,
            reference: purchase.reference,
            amount: refundAmount,
            userId: purchase.userId
          });

          // Send notification to user
          await Notification.create({
            userId: purchase.userId,
            title: 'Purchase Refunded',
            message: `Your purchase ${purchase.reference} has been refunded. GHS ${refundAmount} has been credited to your wallet.`,
            type: 'success',
            category: 'transaction'
          });
        }
      }

      results.successful.push({
        purchaseId: purchase._id,
        reference: purchase.reference,
        oldStatus,
        newStatus: status
      });

    } catch (error) {
      results.failed.push({
        purchaseId,
        reason: error.message
      });
    }
  }

  res.status(200).json({
    success: true,
    message: `Bulk update completed. ${results.successful.length} successful, ${results.failed.length} failed, ${results.refunded.length} refunded`,
    data: results
  });
}));

router.put('/users/:userId/api-access', [
  body('enabled').isBoolean(),
  body('tier').optional().isIn(['basic', 'premium', 'enterprise']),
  body('rateLimit').optional().isNumeric().isInt({ min: 1, max: 10000 }),
  validate
], asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { enabled, tier = 'basic', rateLimit = 100 } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  // Update API access settings
  user.apiAccess = {
    enabled,
    tier: enabled ? tier : user.apiAccess?.tier || 'basic',
    rateLimit: enabled ? rateLimit : user.apiAccess?.rateLimit || 100
  };

  await user.save();

  // If enabling API access, check if user has an API key
  let apiKey = null;
  if (enabled) {
    apiKey = await ApiKey.findOne({ userId: user._id, isActive: true });
    
    // Create a new API key if none exists
    if (!apiKey) {
      const crypto = require('crypto');
      const keyString = `sk_${crypto.randomBytes(32).toString('hex')}`;
      
      apiKey = new ApiKey({
        userId: user._id,
        key: keyString,
        name: `Default API Key for ${user.name}`,
        description: 'Auto-generated API key',
        permissions: tier === 'enterprise' 
          ? ['read:all', 'write:all'] 
          : tier === 'premium'
          ? ['read:products', 'write:purchases', 'read:transactions', 'read:balance']
          : ['read:products', 'write:purchases'],
        rateLimit: {
          requests: rateLimit,
          period: '1m'
        },
        isActive: true
      });
      
      await apiKey.save();
    }
  } else {
    // Disable all API keys when disabling API access
    await ApiKey.updateMany(
      { userId: user._id },
      { isActive: false }
    );
  }

  // Send notification to user
  await Notification.create({
    userId: user._id,
    title: enabled ? 'API Access Enabled' : 'API Access Disabled',
    message: enabled 
      ? `Your API access has been enabled with ${tier} tier (${rateLimit} requests/minute)`
      : 'Your API access has been disabled',
    type: 'info',
    category: 'account'
  });

  res.status(200).json({
    success: true,
    message: `API access ${enabled ? 'enabled' : 'disabled'} successfully`,
    data: {
      userId: user._id,
      apiAccess: user.apiAccess,
      apiKey: enabled && apiKey ? {
        id: apiKey._id,
        key: apiKey.key.substring(0, 10) + '...',
        name: apiKey.name
      } : null
    }
  });
}));

module.exports = router;