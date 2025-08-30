// routes/users/wallet.js - User Wallet Management Routes
const express = require('express');
const router = express.Router();
const { body, query, validationResult } = require('express-validator');

// Import models
const { 
  User, 
  Transaction,
  DataPurchase,
  AgentProfit
} = require('../../Schema/Schema');

const { 
  protect, 
  asyncHandler, 
  validate
} = require('../../middleware/middleware');

// ==================== WALLET BALANCE ROUTES ====================

// @route   GET /api/users/wallet
// @desc    Get user wallet balance and info
// @access  Private
router.get('/wallet', protect, asyncHandler(async (req, res) => {
  try {
    // Get fresh user data
    const user = await User.findById(req.user._id)
      .select('walletBalance commission agentProfit totalEarnings creditLimit name email phoneNumber role');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Calculate available balance (wallet + credit limit if applicable)
    const availableBalance = user.walletBalance + (user.creditLimit || 0);

    // Get today's spending
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    
    const todaySpending = await Transaction.aggregate([
      {
        $match: {
          userId: user._id,
          type: 'purchase',
          status: 'completed',
          createdAt: { $gte: todayStart }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);

    // Get pending transactions count
    const pendingTransactions = await Transaction.countDocuments({
      userId: user._id,
      status: 'pending'
    });

    res.status(200).json({
      success: true,
      data: {
        balance: user.walletBalance,
        availableBalance: availableBalance,
        commission: user.commission || 0,
        agentProfit: user.agentProfit || 0,
        totalEarnings: user.totalEarnings || 0,
        creditLimit: user.creditLimit || 0,
        todaySpending: todaySpending[0]?.total || 0,
        pendingTransactions: pendingTransactions,
        user: {
          name: user.name,
          email: user.email,
          phoneNumber: user.phoneNumber,
          role: user.role
        }
      }
    });
  } catch (error) {
    console.error('Error fetching wallet:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching wallet information'
    });
  }
}));

// @route   GET /api/users/wallet/transactions
// @desc    Get user wallet transaction history
// @access  Private
router.get('/wallet/transactions', protect, [
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('page').optional().isInt({ min: 1 }),
  query('type').optional().isIn(['all', 'deposit', 'withdrawal', 'purchase', 'refund', 'commission', 'agent_profit']),
  query('status').optional().isIn(['all', 'pending', 'completed', 'failed']),
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  validate
], asyncHandler(async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const page = parseInt(req.query.page) || 1;
    const skip = (page - 1) * limit;
    
    // Build query
    const query = { userId: req.user._id };
    
    if (req.query.type && req.query.type !== 'all') {
      query.type = req.query.type;
    }
    
    if (req.query.status && req.query.status !== 'all') {
      query.status = req.query.status;
    }
    
    if (req.query.startDate || req.query.endDate) {
      query.createdAt = {};
      if (req.query.startDate) {
        query.createdAt.$gte = new Date(req.query.startDate);
      }
      if (req.query.endDate) {
        query.createdAt.$lte = new Date(req.query.endDate);
      }
    }

    // Get transactions
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip)
      .lean();

    // Get total count for pagination
    const totalCount = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    // Get summary statistics
    const stats = await Transaction.aggregate([
      { $match: query },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 },
          total: { $sum: '$amount' }
        }
      }
    ]);

    res.status(200).json({
      success: true,
      data: {
        transactions: transactions,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalCount: totalCount,
          limit: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        },
        statistics: stats
      }
    });
  } catch (error) {
    console.error('Error fetching transactions:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching transaction history'
    });
  }
}));

// @route   GET /api/users/wallet/summary
// @desc    Get detailed wallet summary and statistics
// @access  Private
router.get('/wallet/summary', protect, asyncHandler(async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get date ranges
    const now = new Date();
    const todayStart = new Date(now);
    todayStart.setHours(0, 0, 0, 0);
    
    const weekStart = new Date(now);
    weekStart.setDate(weekStart.getDate() - 7);
    
    const monthStart = new Date(now);
    monthStart.setMonth(monthStart.getMonth() - 1);

    // Get transaction summaries for different periods
    const [todayStats, weekStats, monthStats, allTimeStats] = await Promise.all([
      // Today's stats
      Transaction.aggregate([
        {
          $match: {
            userId: userId,
            createdAt: { $gte: todayStart },
            status: 'completed'
          }
        },
        {
          $group: {
            _id: '$type',
            count: { $sum: 1 },
            total: { $sum: '$amount' }
          }
        }
      ]),
      
      // This week's stats
      Transaction.aggregate([
        {
          $match: {
            userId: userId,
            createdAt: { $gte: weekStart },
            status: 'completed'
          }
        },
        {
          $group: {
            _id: '$type',
            count: { $sum: 1 },
            total: { $sum: '$amount' }
          }
        }
      ]),
      
      // This month's stats
      Transaction.aggregate([
        {
          $match: {
            userId: userId,
            createdAt: { $gte: monthStart },
            status: 'completed'
          }
        },
        {
          $group: {
            _id: '$type',
            count: { $sum: 1 },
            total: { $sum: '$amount' }
          }
        }
      ]),
      
      // All time stats
      Transaction.aggregate([
        {
          $match: {
            userId: userId,
            status: 'completed'
          }
        },
        {
          $group: {
            _id: '$type',
            count: { $sum: 1 },
            total: { $sum: '$amount' }
          }
        }
      ])
    ]);

    // Calculate totals for each period
    const calculateTotals = (stats) => {
      return stats.reduce((acc, stat) => {
        if (stat._id === 'deposit') acc.deposits += stat.total;
        if (stat._id === 'withdrawal') acc.withdrawals += stat.total;
        if (stat._id === 'purchase') acc.purchases += stat.total;
        if (stat._id === 'refund') acc.refunds += stat.total;
        if (stat._id === 'commission') acc.commissions += stat.total;
        if (stat._id === 'agent_profit') acc.agentProfits += stat.total;
        acc.totalTransactions += stat.count;
        return acc;
      }, {
        deposits: 0,
        withdrawals: 0,
        purchases: 0,
        refunds: 0,
        commissions: 0,
        agentProfits: 0,
        totalTransactions: 0
      });
    };

    // Get recent transactions
    const recentTransactions = await Transaction.find({ userId })
      .sort({ createdAt: -1 })
      .limit(5)
      .lean();

    // Get agent profit details if user is an agent
    let agentProfitDetails = null;
    if (['agent', 'super_agent', 'dealer'].includes(req.user.role)) {
      const agentProfits = await AgentProfit.aggregate([
        {
          $match: {
            agentId: userId,
            status: 'credited'
          }
        },
        {
          $group: {
            _id: null,
            totalProfit: { $sum: '$profit' },
            totalSales: { $sum: 1 },
            avgProfit: { $avg: '$profit' },
            avgProfitPercentage: { $avg: '$profitPercentage' }
          }
        }
      ]);
      
      agentProfitDetails = agentProfits[0] || {
        totalProfit: 0,
        totalSales: 0,
        avgProfit: 0,
        avgProfitPercentage: 0
      };
    }

    res.status(200).json({
      success: true,
      data: {
        currentBalance: req.user.walletBalance,
        creditLimit: req.user.creditLimit || 0,
        availableBalance: req.user.walletBalance + (req.user.creditLimit || 0),
        periods: {
          today: calculateTotals(todayStats),
          thisWeek: calculateTotals(weekStats),
          thisMonth: calculateTotals(monthStats),
          allTime: calculateTotals(allTimeStats)
        },
        agentProfitDetails: agentProfitDetails,
        recentTransactions: recentTransactions,
        lastUpdated: new Date()
      }
    });
  } catch (error) {
    console.error('Error fetching wallet summary:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching wallet summary'
    });
  }
}));

// @route   GET /api/users/wallet/deposits/history
// @desc    Get deposit history
// @access  Private
router.get('/wallet/deposits/history', protect, [
  query('limit').optional().isInt({ min: 1, max: 100 }),
  validate
], asyncHandler(async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    
    const deposits = await Transaction.find({
      userId: req.user._id,
      type: 'deposit',
      status: { $in: ['completed', 'pending'] }
    })
    .sort({ createdAt: -1 })
    .limit(limit)
    .select('amount status reference createdAt gateway metadata')
    .lean();

    // Format deposits for frontend
    const formattedDeposits = deposits.map(dep => ({
      id: dep._id,
      amount: dep.amount,
      status: dep.status,
      reference: dep.reference,
      gateway: dep.gateway,
      createdAt: dep.createdAt,
      paidAt: dep.metadata?.paystackResponse?.paidAt || dep.createdAt
    }));

    res.status(200).json({
      success: true,
      data: {
        deposits: formattedDeposits
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

// @route   GET /api/users/wallet/balance-history
// @desc    Get balance history over time
// @access  Private
router.get('/wallet/balance-history', protect, [
  query('period').optional().isIn(['7d', '30d', '90d', '1y', 'all']),
  validate
], asyncHandler(async (req, res) => {
  try {
    const period = req.query.period || '30d';
    
    // Calculate date range
    const endDate = new Date();
    const startDate = new Date();
    
    switch(period) {
      case '7d':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(startDate.getDate() - 30);
        break;
      case '90d':
        startDate.setDate(startDate.getDate() - 90);
        break;
      case '1y':
        startDate.setFullYear(startDate.getFullYear() - 1);
        break;
      case 'all':
        startDate.setFullYear(2020); // Or account creation date
        break;
    }

    // Get all transactions in the period
    const transactions = await Transaction.find({
      userId: req.user._id,
      status: 'completed',
      createdAt: { $gte: startDate, $lte: endDate }
    })
    .sort({ createdAt: 1 })
    .select('type amount balanceAfter createdAt')
    .lean();

    // Create balance history points
    const balanceHistory = transactions.map(tx => ({
      date: tx.createdAt,
      balance: tx.balanceAfter,
      change: tx.type === 'deposit' || tx.type === 'refund' ? tx.amount : -tx.amount,
      type: tx.type
    }));

    res.status(200).json({
      success: true,
      data: {
        period: period,
        startDate: startDate,
        endDate: endDate,
        history: balanceHistory,
        currentBalance: req.user.walletBalance
      }
    });
  } catch (error) {
    console.error('Error fetching balance history:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching balance history'
    });
  }
}));

module.exports = router;