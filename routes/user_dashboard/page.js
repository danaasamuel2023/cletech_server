// ==================== USER DASHBOARD ROUTES ====================
const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const { protect, asyncHandler } = require('../../middleware/middleware');
const { DataPurchase, User, Transaction } = require('../../Schema/Schema');

// ==================== GET USER DASHBOARD SUMMARY ====================
// @route   GET /api/user/dashboard
// @desc    Get user dashboard with today's orders, spending, and balance
// @access  Private
router.get('/dashboard', protect, asyncHandler(async (req, res) => {
  const userId = req.user._id;
  
  // Get start and end of today
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);
  
  const endOfToday = new Date();
  endOfToday.setHours(23, 59, 59, 999);

  // 1. Get today's orders
  const todayOrders = await DataPurchase.find({
    userId,
    createdAt: {
      $gte: startOfToday,
      $lte: endOfToday
    }
  }).sort({ createdAt: -1 });

  // 2. Calculate today's spending - FIX: Use 'new' with ObjectId
  const todaySpending = await DataPurchase.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        createdAt: {
          $gte: startOfToday,
          $lte: endOfToday
        },
        status: { $in: ['completed', 'delivered'] }
      }
    },
    {
      $group: {
        _id: null,
        totalSpent: { $sum: '$price' },
        orderCount: { $sum: 1 }
      }
    }
  ]);

  // 3. Get current user balance
  const user = await User.findById(userId).select('walletBalance name email phoneNumber');

  res.status(200).json({
    success: true,
    data: {
      user: {
        name: user.name,
        email: user.email,
        phoneNumber: user.phoneNumber,
        currentBalance: user.walletBalance
      },
      today: {
        orders: todayOrders,
        totalOrders: todayOrders.length,
        totalSpent: todaySpending[0]?.totalSpent || 0,
        completedOrders: todaySpending[0]?.orderCount || 0
      }
    }
  });
}));

// ==================== GET TODAY'S ORDERS ====================
// @route   GET /api/user/orders/today
// @desc    Get all orders placed today by the user
// @access  Private
router.get('/orders/today', protect, asyncHandler(async (req, res) => {
  const userId = req.user._id;
  
  // Get start and end of today
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);
  
  const endOfToday = new Date();
  endOfToday.setHours(23, 59, 59, 999);

  const orders = await DataPurchase.find({
    userId,
    createdAt: {
      $gte: startOfToday,
      $lte: endOfToday
    }
  })
  .sort({ createdAt: -1 })
  .populate('agentId', 'name phoneNumber');

  // Group orders by status
  const ordersByStatus = {
    pending: orders.filter(o => o.status === 'pending'),
    completed: orders.filter(o => o.status === 'completed' || o.status === 'delivered'),
    failed: orders.filter(o => o.status === 'failed'),
    processing: orders.filter(o => o.status === 'processing')
  };

  res.status(200).json({
    success: true,
    data: {
      totalOrders: orders.length,
      orders,
      ordersByStatus,
      summary: {
        pending: ordersByStatus.pending.length,
        completed: ordersByStatus.completed.length,
        failed: ordersByStatus.failed.length,
        processing: ordersByStatus.processing.length
      }
    }
  });
}));

// ==================== GET AMOUNT SPENT TODAY ====================
// @route   GET /api/user/spending/today
// @desc    Get total amount spent today
// @access  Private
router.get('/spending/today', protect, asyncHandler(async (req, res) => {
  const userId = req.user._id;
  
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);
  
  const endOfToday = new Date();
  endOfToday.setHours(23, 59, 59, 999);

  // Aggregate spending by network and status - FIX: Use 'new' with ObjectId
  const spendingData = await DataPurchase.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        createdAt: {
          $gte: startOfToday,
          $lte: endOfToday
        }
      }
    },
    {
      $group: {
        _id: {
          network: '$network',
          status: '$status'
        },
        totalAmount: { $sum: '$price' },
        count: { $sum: 1 }
      }
    },
    {
      $group: {
        _id: '$_id.network',
        statuses: {
          $push: {
            status: '$_id.status',
            amount: '$totalAmount',
            count: '$count'
          }
        },
        totalNetworkSpending: {
          $sum: {
            $cond: [
              { $in: ['$_id.status', ['completed', 'delivered']] },
              '$totalAmount',
              0
            ]
          }
        }
      }
    }
  ]);

  // Calculate total spending (only completed/delivered orders) - FIX: Use 'new' with ObjectId
  const totalSpent = await DataPurchase.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        createdAt: {
          $gte: startOfToday,
          $lte: endOfToday
        },
        status: { $in: ['completed', 'delivered'] }
      }
    },
    {
      $group: {
        _id: null,
        total: { $sum: '$price' }
      }
    }
  ]);

  res.status(200).json({
    success: true,
    data: {
      totalSpentToday: totalSpent[0]?.total || 0,
      spendingByNetwork: spendingData,
      period: {
        from: startOfToday,
        to: endOfToday
      }
    }
  });
}));

// ==================== GET CURRENT BALANCE ====================
// @route   GET /api/user/balance
// @desc    Get current wallet balance and recent transactions
// @access  Private
router.get('/balance', protect, asyncHandler(async (req, res) => {
  const userId = req.user._id;

  // Get user balance
  const user = await User.findById(userId).select('walletBalance creditLimit');

  // Get last 5 transactions
  const recentTransactions = await Transaction.find({
    userId,
    status: 'completed'
  })
  .sort({ createdAt: -1 })
  .limit(5)
  .select('type amount balanceAfter description createdAt');

  res.status(200).json({
    success: true,
    data: {
      walletBalance: user.walletBalance,
      creditLimit: user.creditLimit,
      availableBalance: user.walletBalance + user.creditLimit,
      recentTransactions
    }
  });
}));

// ==================== GET SPENDING STATISTICS ====================
// @route   GET /api/user/statistics
// @desc    Get spending statistics for different periods
// @access  Private
router.get('/statistics', protect, asyncHandler(async (req, res) => {
  const userId = req.user._id;
  const { period = 'week' } = req.query; // week, month, year

  // Calculate date ranges
  const now = new Date();
  let startDate = new Date();
  
  switch(period) {
    case 'week':
      startDate.setDate(now.getDate() - 7);
      break;
    case 'month':
      startDate.setMonth(now.getMonth() - 1);
      break;
    case 'year':
      startDate.setFullYear(now.getFullYear() - 1);
      break;
    default:
      startDate.setDate(now.getDate() - 7);
  }

  // Get spending statistics - FIX: Use 'new' with ObjectId
  const statistics = await DataPurchase.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        createdAt: { $gte: startDate },
        status: { $in: ['completed', 'delivered'] }
      }
    },
    {
      $group: {
        _id: {
          date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          network: '$network'
        },
        dailySpending: { $sum: '$price' },
        orderCount: { $sum: 1 },
        totalGB: { $sum: '$capacity' }
      }
    },
    {
      $sort: { '_id.date': 1 }
    }
  ]);

  // Get total summary for the period - FIX: Use 'new' with ObjectId
  const summary = await DataPurchase.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        createdAt: { $gte: startDate },
        status: { $in: ['completed', 'delivered'] }
      }
    },
    {
      $group: {
        _id: null,
        totalSpent: { $sum: '$price' },
        totalOrders: { $sum: 1 },
        totalGB: { $sum: '$capacity' },
        avgOrderValue: { $avg: '$price' }
      }
    }
  ]);

  // Get favorite network - FIX: Use 'new' with ObjectId
  const favoriteNetwork = await DataPurchase.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        createdAt: { $gte: startDate },
        status: { $in: ['completed', 'delivered'] }
      }
    },
    {
      $group: {
        _id: '$network',
        count: { $sum: 1 },
        totalSpent: { $sum: '$price' }
      }
    },
    {
      $sort: { count: -1 }
    },
    {
      $limit: 1
    }
  ]);

  res.status(200).json({
    success: true,
    data: {
      period,
      dateRange: {
        from: startDate,
        to: now
      },
      dailyStatistics: statistics,
      summary: summary[0] || {
        totalSpent: 0,
        totalOrders: 0,
        totalGB: 0,
        avgOrderValue: 0
      },
      favoriteNetwork: favoriteNetwork[0] || null
    }
  });
}));

// ==================== GET QUICK STATS ====================
// @route   GET /api/user/quick-stats
// @desc    Get quick stats for user dashboard widget
// @access  Private
router.get('/quick-stats', protect, asyncHandler(async (req, res) => {
  const userId = req.user._id;
  
  // Today's dates
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);
  
  const endOfToday = new Date();
  endOfToday.setHours(23, 59, 59, 999);

  // This week's dates
  const startOfWeek = new Date();
  startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay());
  startOfWeek.setHours(0, 0, 0, 0);

  // Get all stats in parallel for performance
  const [
    userBalance,
    todayStats,
    weekStats,
    pendingOrders
  ] = await Promise.all([
    // User balance
    User.findById(userId).select('walletBalance creditLimit'),
    
    // Today's stats - FIX: Use 'new' with ObjectId
    DataPurchase.aggregate([
      {
        $match: {
          userId: new mongoose.Types.ObjectId(userId),
          createdAt: { $gte: startOfToday, $lte: endOfToday },
          status: { $in: ['completed', 'delivered'] }
        }
      },
      {
        $group: {
          _id: null,
          totalSpent: { $sum: '$price' },
          orderCount: { $sum: 1 }
        }
      }
    ]),
    
    // This week's stats - FIX: Use 'new' with ObjectId
    DataPurchase.aggregate([
      {
        $match: {
          userId: new mongoose.Types.ObjectId(userId),
          createdAt: { $gte: startOfWeek },
          status: { $in: ['completed', 'delivered'] }
        }
      },
      {
        $group: {
          _id: null,
          totalSpent: { $sum: '$price' },
          orderCount: { $sum: 1 }
        }
      }
    ]),
    
    // Pending orders count
    DataPurchase.countDocuments({
      userId,
      status: 'pending'
    })
  ]);

  res.status(200).json({
    success: true,
    data: {
      balance: {
        wallet: userBalance.walletBalance,
        credit: userBalance.creditLimit,
        total: userBalance.walletBalance + userBalance.creditLimit
      },
      today: {
        spent: todayStats[0]?.totalSpent || 0,
        orders: todayStats[0]?.orderCount || 0
      },
      thisWeek: {
        spent: weekStats[0]?.totalSpent || 0,
        orders: weekStats[0]?.orderCount || 0
      },
      pendingOrders
    }
  });
}));

// ==================== EXPORT ROUTER ====================
module.exports = router;