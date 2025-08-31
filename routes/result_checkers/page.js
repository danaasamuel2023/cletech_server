// ==================== RESULT CHECKER ROUTES ====================
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const axios = require('axios');

// Import schemas
const { 
  ResultChecker, 
  User, 
  Transaction,
  Notification 
} = require('../../Schema/Schema');

// Import middleware
const { 
  protect, 
  asyncHandler,
  validate,
  checkBalance,
  generalLimit,
  purchaseLimit
} = require('../../middleware/middleware');

// ==================== VALIDATION MIDDLEWARE ====================
const validateCheckerPurchase = [
  body('type')
    .isIn(['BECE', 'WASSCE'])
    .withMessage('Invalid checker type'),
  body('year')
    .isInt({ min: 2020, max: new Date().getFullYear() })
    .withMessage('Invalid year'),
  body('examType')
    .optional()
    .isIn(['MAY/JUNE', 'NOV/DEC', 'PRIVATE'])
    .withMessage('Invalid exam type'),
  body('phoneNumber')
    .matches(/^(\+233|0)[2-9]\d{8}$/)
    .withMessage('Invalid Ghana phone number'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be 2-100 characters'),
  body('gateway')
    .isIn(['paystack', 'wallet', 'momo'])
    .withMessage('Invalid payment gateway'),
  validate
];

// ==================== PUBLIC ROUTES ====================

// Get available checkers (public)
router.get('/available', 
  generalLimit,
  asyncHandler(async (req, res) => {
    const { type, year, examType } = req.query;
    
    const filter = {
      status: 'available',
      'validity.isActive': true
    };
    
    if (type) filter.type = type;
    if (year) filter.year = parseInt(year);
    if (examType) filter.examType = examType;
    
    // Get count and price info without exposing sensitive data
    const checkers = await ResultChecker.aggregate([
      { $match: filter },
      {
        $group: {
          _id: {
            type: '$type',
            year: '$year',
            examType: '$examType',
            price: '$price'
          },
          count: { $sum: 1 }
        }
      },
      {
        $project: {
          type: '$_id.type',
          year: '$_id.year',
          examType: '$_id.examType',
          price: '$_id.price',
          available: '$count',
          _id: 0
        }
      },
      { $sort: { year: -1, type: 1 } }
    ]);
    
    res.json({
      success: true,
      data: checkers
    });
  })
);

// Get checker price
router.get('/price/:type/:year', 
  generalLimit,
  asyncHandler(async (req, res) => {
    const { type, year } = req.params;
    const { examType = 'MAY/JUNE' } = req.query;
    
    const checker = await ResultChecker.findOne({
      type,
      year: parseInt(year),
      examType,
      status: 'available'
    }).select('price');
    
    if (!checker) {
      return res.status(404).json({
        success: false,
        message: 'Checker not available'
      });
    }
    
    res.json({
      success: true,
      data: {
        type,
        year,
        examType,
        price: checker.price
      }
    });
  })
);

// ==================== AUTHENTICATED ROUTES ====================

// Purchase checker - Main route
router.post('/purchase', 
  protect,
  purchaseLimit,
  validateCheckerPurchase,
  asyncHandler(async (req, res) => {
    const { 
      type, 
      year, 
      examType = 'MAY/JUNE',
      phoneNumber,
      email,
      name,
      gateway,
      quantity = 1
    } = req.body;
    
    const userId = req.user._id;
    
    // Find available checkers
    const availableCheckers = await ResultChecker.find({
      type,
      year,
      examType,
      status: 'available',
      'validity.isActive': true
    }).limit(quantity);
    
    if (availableCheckers.length < quantity) {
      return res.status(400).json({
        success: false,
        message: `Only ${availableCheckers.length} checkers available`
      });
    }
    
    const totalPrice = availableCheckers[0].price * quantity;
    const reference = `CHK-${Date.now()}-${uuidv4().substring(0, 8)}`;
    
    // Handle different payment gateways
    if (gateway === 'wallet') {
      // Check wallet balance
      if (req.user.walletBalance < totalPrice) {
        return res.status(400).json({
          success: false,
          message: 'Insufficient wallet balance',
          required: totalPrice,
          balance: req.user.walletBalance
        });
      }
      
      // Process wallet payment
      const result = await processWalletPayment(
        userId,
        availableCheckers,
        totalPrice,
        reference,
        { phoneNumber, email, name }
      );
      
      return res.json(result);
      
    } else if (gateway === 'paystack') {
      // Initialize Paystack payment
      const paystackResponse = await initializePaystack({
        email: email || req.user.email,
        amount: totalPrice * 100, // Paystack uses pesewas
        reference,
        metadata: {
          userId: userId.toString(),
          type,
          year,
          examType,
          quantity,
          phoneNumber,
          name,
          checkerIds: availableCheckers.map(c => c._id.toString())
        }
      });
      
      return res.json({
        success: true,
        message: 'Payment initialized',
        data: {
          reference,
          authorizationUrl: paystackResponse.authorization_url,
          accessCode: paystackResponse.access_code,
          totalPrice
        }
      });
      
    } else if (gateway === 'momo') {
      // Initialize Mobile Money payment
      const momoResponse = await initializeMomo({
        phoneNumber,
        amount: totalPrice,
        reference,
        metadata: {
          userId: userId.toString(),
          type,
          year,
          examType,
          quantity,
          checkerIds: availableCheckers.map(c => c._id.toString())
        }
      });
      
      return res.json({
        success: true,
        message: 'MoMo payment initiated',
        data: {
          reference,
          totalPrice,
          instructions: 'Please approve the payment request on your phone'
        }
      });
    }
  })
);

// Verify payment and complete purchase
router.post('/verify/:reference',
  protect,
  asyncHandler(async (req, res) => {
    const { reference } = req.params;
    
    // Check if already processed
    const existingTransaction = await Transaction.findOne({ reference });
    if (existingTransaction && existingTransaction.status === 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Payment already processed'
      });
    }
    
    // Verify with payment gateway
    const paymentData = await verifyPayment(reference);
    
    if (!paymentData.success) {
      return res.status(400).json({
        success: false,
        message: 'Payment verification failed'
      });
    }
    
    // Complete the purchase
    const result = await completePurchase(
      paymentData.metadata,
      reference,
      paymentData.gateway
    );
    
    res.json(result);
  })
);

// Get user's purchased checkers
router.get('/my-checkers',
  protect,
  asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { status, type } = req.query;
    
    const filter = {
      'soldTo.user': userId
    };
    
    if (status) filter.status = status;
    if (type) filter.type = type;
    
    const checkers = await ResultChecker.find(filter)
      .select('type year examType serialNumber pin status soldTo usageInfo validity')
      .sort({ 'soldTo.soldAt': -1 });
    
    res.json({
      success: true,
      data: checkers
    });
  })
);

// Use/Activate a checker
router.post('/use/:checkerId',
  protect,
  asyncHandler(async (req, res) => {
    const { checkerId } = req.params;
    const { studentPhoneNumber } = req.body;
    const userId = req.user._id;
    
    const checker = await ResultChecker.findById(checkerId);
    
    if (!checker) {
      return res.status(404).json({
        success: false,
        message: 'Checker not found'
      });
    }
    
    // Verify ownership
    if (checker.soldTo.user.toString() !== userId.toString()) {
      return res.status(403).json({
        success: false,
        message: 'You do not own this checker'
      });
    }
    
    // Check if expired
    if (checker.validity.expiryDate && new Date() > checker.validity.expiryDate) {
      return res.status(400).json({
        success: false,
        message: 'This checker has expired'
      });
    }
    
    // Check usage limit
    if (checker.usageInfo.usageCount >= 5) {
      return res.status(400).json({
        success: false,
        message: 'This checker has reached its usage limit'
      });
    }
    
    // Update usage info
    checker.usageInfo.usageCount += 1;
    checker.usageInfo.lastUsed = new Date();
    if (!checker.usageInfo.firstUsed) {
      checker.usageInfo.firstUsed = new Date();
    }
    checker.usageInfo.usedBy.push({
      phoneNumber: studentPhoneNumber,
      timestamp: new Date()
    });
    
    if (checker.usageInfo.usageCount >= 5) {
      checker.status = 'used';
    }
    
    await checker.save();
    
    res.json({
      success: true,
      message: 'Checker activated successfully',
      data: {
        serialNumber: checker.serialNumber,
        pin: checker.pin,
        usageCount: checker.usageInfo.usageCount,
        remainingUses: 5 - checker.usageInfo.usageCount
      }
    });
  })
);

// ==================== ADMIN ROUTES ====================

// Add checkers in bulk (Admin only)
router.post('/admin/add-bulk',
  protect,
  asyncHandler(async (req, res) => {
    // Check if admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }
    
    const { 
      type, 
      year, 
      examType = 'MAY/JUNE',
      checkers, // Array of { serialNumber, pin, scratchCard }
      price,
      batchNumber,
      supplier
    } = req.body;
    
    const checkersToAdd = checkers.map(checker => ({
      type,
      year,
      examType,
      serialNumber: checker.serialNumber.toUpperCase(),
      pin: checker.pin,
      scratchCard: checker.scratchCard,
      price,
      status: 'available',
      validity: {
        isActive: true,
        activationDate: new Date()
      },
      batchInfo: {
        batchNumber,
        batchDate: new Date(),
        supplier,
        totalInBatch: checkers.length
      },
      addedBy: req.user._id
    }));
    
    try {
      const inserted = await ResultChecker.insertMany(checkersToAdd, { 
        ordered: false 
      });
      
      res.json({
        success: true,
        message: `${inserted.length} checkers added successfully`,
        data: {
          added: inserted.length,
          failed: checkers.length - inserted.length
        }
      });
    } catch (error) {
      if (error.code === 11000) {
        return res.status(400).json({
          success: false,
          message: 'Some checkers already exist',
          duplicates: error.writeErrors?.length || 0
        });
      }
      throw error;
    }
  })
);

// Update checker status (Admin)
router.patch('/admin/update-status/:checkerId',
  protect,
  asyncHandler(async (req, res) => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }
    
    const { checkerId } = req.params;
    const { status, reason } = req.body;
    
    const checker = await ResultChecker.findByIdAndUpdate(
      checkerId,
      {
        status,
        lastModifiedBy: req.user._id,
        updatedAt: new Date()
      },
      { new: true }
    );
    
    if (!checker) {
      return res.status(404).json({
        success: false,
        message: 'Checker not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Checker status updated',
      data: checker
    });
  })
);

// ==================== HELPER FUNCTIONS ====================

async function processWalletPayment(userId, checkers, totalPrice, reference, buyerInfo) {
  const session = await ResultChecker.startSession();
  session.startTransaction();
  
  try {
    // Deduct from wallet
    const user = await User.findById(userId);
    user.walletBalance -= totalPrice;
    await user.save({ session });
    
    // Update checkers
    for (const checker of checkers) {
      checker.status = 'sold';
      checker.soldTo = {
        user: userId,
        phoneNumber: buyerInfo.phoneNumber,
        email: buyerInfo.email,
        name: buyerInfo.name,
        soldAt: new Date(),
        soldBy: userId,
        soldPrice: checker.price
      };
      await checker.save({ session });
    }
    
    // Create transaction record
    await Transaction.create([{
      userId,
      type: 'purchase',
      amount: totalPrice,
      balanceBefore: user.walletBalance + totalPrice,
      balanceAfter: user.walletBalance,
      status: 'completed',
      reference,
      gateway: 'wallet',
      description: `Purchase of ${checkers.length} ${checkers[0].type} checker(s)`,
      metadata: {
        checkerIds: checkers.map(c => c._id),
        type: checkers[0].type,
        year: checkers[0].year
      }
    }], { session });
    
    // Send notification
    await Notification.create([{
      userId,
      title: 'Checker Purchase Successful',
      message: `You have successfully purchased ${checkers.length} ${checkers[0].type} checker(s)`,
      type: 'success',
      category: 'purchase'
    }], { session });
    
    await session.commitTransaction();
    
    return {
      success: true,
      message: 'Purchase successful',
      data: {
        reference,
        checkers: checkers.map(c => ({
          id: c._id,
          serialNumber: c.serialNumber,
          pin: c.pin,
          type: c.type,
          year: c.year
        }))
      }
    };
  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
}

async function initializePaystack(paymentData) {
  const response = await axios.post(
    'https://api.paystack.co/transaction/initialize',
    paymentData,
    {
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json'
      }
    }
  );
  
  return response.data.data;
}

async function initializeMomo(paymentData) {
  // Implement MoMo payment initialization
  // This would connect to your MoMo API provider
  return {
    success: true,
    reference: paymentData.reference
  };
}

async function verifyPayment(reference) {
  try {
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
        }
      }
    );
    
    if (response.data.data.status === 'success') {
      return {
        success: true,
        metadata: response.data.data.metadata,
        gateway: 'paystack',
        amount: response.data.data.amount / 100
      };
    }
    
    return { success: false };
  } catch (error) {
    return { success: false };
  }
}

async function completePurchase(metadata, reference, gateway) {
  const session = await ResultChecker.startSession();
  session.startTransaction();
  
  try {
    const { userId, checkerIds, phoneNumber, email, name } = metadata;
    
    // Update checkers
    const checkers = await ResultChecker.find({
      _id: { $in: checkerIds }
    }).session(session);
    
    for (const checker of checkers) {
      checker.status = 'sold';
      checker.soldTo = {
        user: userId,
        phoneNumber,
        email,
        name,
        soldAt: new Date(),
        soldBy: userId,
        soldPrice: checker.price
      };
      await checker.save({ session });
    }
    
    // Create transaction record
    const totalPrice = checkers.reduce((sum, c) => sum + c.price, 0);
    await Transaction.create([{
      userId,
      type: 'purchase',
      amount: totalPrice,
      status: 'completed',
      reference,
      gateway,
      description: `Purchase of ${checkers.length} checker(s)`,
      metadata
    }], { session });
    
    await session.commitTransaction();
    
    return {
      success: true,
      message: 'Purchase completed',
      data: {
        reference,
        checkers: checkers.map(c => ({
          id: c._id,
          serialNumber: c.serialNumber,
          pin: c.pin,
          type: c.type,
          year: c.year
        }))
      }
    };
  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
}
// ==================== STATS ROUTE ====================
// Add this single route to your existing result checker routes file

// Get result checker statistics (Admin only)
router.get('/admin/stats',
  protect,
  asyncHandler(async (req, res) => {
    // Check if admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Get overall statistics
    const stats = await ResultChecker.aggregate([
      {
        $facet: {
          // Count by status
          statusCounts: [
            {
              $group: {
                _id: '$status',
                count: { $sum: 1 },
                totalValue: { $sum: '$price' }
              }
            }
          ],
          // Total count
          totalCount: [
            {
              $count: 'total'
            }
          ],
          // Revenue from sold items
          revenue: [
            {
              $match: { status: 'sold' }
            },
            {
              $group: {
                _id: null,
                totalRevenue: { $sum: '$soldTo.soldPrice' },
                count: { $sum: 1 }
              }
            }
          ],
          // Recent sales (last 30 days)
          recentSales: [
            {
              $match: {
                status: 'sold',
                'soldTo.soldAt': {
                  $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
                }
              }
            },
            {
              $count: 'count'
            }
          ],
          // Today's sales
          todaySales: [
            {
              $match: {
                status: 'sold',
                'soldTo.soldAt': {
                  $gte: new Date(new Date().setHours(0, 0, 0, 0))
                }
              }
            },
            {
              $count: 'count'
            }
          ]
        }
      }
    ]);

    // Process the aggregation results
    const statusMap = {};
    stats[0].statusCounts.forEach(item => {
      statusMap[item._id] = {
        count: item.count,
        value: item.totalValue
      };
    });

    const result = {
      total: stats[0].totalCount[0]?.total || 0,
      available: statusMap.available?.count || 0,
      sold: statusMap.sold?.count || 0,
      used: statusMap.used?.count || 0,
      expired: statusMap.expired?.count || 0,
      totalValue: Object.values(statusMap).reduce((sum, item) => sum + (item.value || 0), 0),
      totalRevenue: stats[0].revenue[0]?.totalRevenue || 0,
      recentSales: stats[0].recentSales[0]?.count || 0,
      todaySales: stats[0].todaySales[0]?.count || 0
    };

    res.json({
      success: true,
      data: result
    });
  })
);

module.exports = router;