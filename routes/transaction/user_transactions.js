// ==================== routes/transactions.js ====================
// Complete Transaction Routes with Filtering and Statistics

const express = require('express');
const router = express.Router();
const { Transaction, DataPurchase, User } = require('../../Schema/Schema');
const { protect, asyncHandler } = require('../../middleware/middleware');

// ==================== GET USER TRANSACTIONS ====================
router.get('/transactions', protect, asyncHandler(async (req, res) => {
  try {
    const userId = req.user._id;
    const {
      page = 1,
      limit = 20,
      type,
      status,
      gateway,
      from,
      to,
      sortBy = 'createdAt',
      order = 'desc'
    } = req.query;

    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Build filter
    const filter = { userId };

    // Add optional filters
    if (type) {
      // Handle multiple types
      if (type.includes(',')) {
        filter.type = { $in: type.split(',') };
      } else {
        filter.type = type;
      }
    }

    if (status) {
      filter.status = status;
    }

    if (gateway) {
      filter.gateway = gateway;
    }

    // Date range filter
    if (from || to) {
      filter.createdAt = {};
      if (from) {
        filter.createdAt.$gte = new Date(from);
      }
      if (to) {
        const toDate = new Date(to);
        toDate.setHours(23, 59, 59, 999);
        filter.createdAt.$lte = toDate;
      }
    }

    // Get transactions with related purchase info
    const transactions = await Transaction.find(filter)
      .populate('relatedPurchaseId', 'network capacity phoneNumber')
      .sort({ [sortBy]: order === 'desc' ? -1 : 1 })
      .limit(parseInt(limit))
      .skip(skip)
      .lean();

    // Get total count for pagination
    const total = await Transaction.countDocuments(filter);

    // Calculate statistics
    const stats = await Transaction.aggregate([
      { $match: filter },
      {
        $group: {
          _id: null,
          totalTransactions: { $sum: 1 },
          totalDeposits: {
            $sum: {
              $cond: [
                { $in: ['$type', ['deposit', 'admin_credit', 'momo']] },
                '$amount',
                0
              ]
            }
          },
          totalWithdrawals: {
            $sum: {
              $cond: [
                { $eq: ['$type', 'withdrawal'] },
                '$amount',
                0
              ]
            }
          },
          totalPurchases: {
            $sum: {
              $cond: [
                { $eq: ['$type', 'purchase'] },
                '$amount',
                0
              ]
            }
          },
          totalRefunds: {
            $sum: {
              $cond: [
                { $in: ['$type', ['refund', 'wallet-refund']] },
                '$amount',
                0
              ]
            }
          },
          totalCommissions: {
            $sum: {
              $cond: [
                { $in: ['$type', ['commission', 'agent_profit']] },
                '$amount',
                0
              ]
            }
          },
          pendingTransactions: {
            $sum: {
              $cond: [
                { $eq: ['$status', 'pending'] },
                1,
                0
              ]
            }
          },
          completedTransactions: {
            $sum: {
              $cond: [
                { $eq: ['$status', 'completed'] },
                1,
                0
              ]
            }
          },
          failedTransactions: {
            $sum: {
              $cond: [
                { $eq: ['$status', 'failed'] },
                1,
                0
              ]
            }
          }
        }
      }
    ]);

    // Format transactions for frontend
    const formattedTransactions = transactions.map(transaction => ({
      id: transaction._id,
      type: transaction.type,
      amount: transaction.amount,
      balanceBefore: transaction.balanceBefore,
      balanceAfter: transaction.balanceAfter,
      balanceChange: transaction.type === 'withdrawal' || transaction.type === 'purchase' || transaction.type === 'admin-deduction'
        ? -transaction.amount
        : transaction.amount,
      status: transaction.status,
      reference: transaction.reference,
      gateway: transaction.gateway,
      description: transaction.description || getTransactionDescription(transaction),
      relatedPurchase: transaction.relatedPurchaseId,
      timestamp: transaction.createdAt,
      processing: transaction.processing,
      metadata: transaction.metadata
    }));

    res.json({
      success: true,
      data: {
        transactions: formattedTransactions,
        statistics: stats[0] || {
          totalTransactions: 0,
          totalDeposits: 0,
          totalWithdrawals: 0,
          totalPurchases: 0,
          totalRefunds: 0,
          totalCommissions: 0,
          pendingTransactions: 0,
          completedTransactions: 0,
          failedTransactions: 0
        },
        currentBalance: req.user.walletBalance
      },
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
        hasMore: skip + transactions.length < total
      }
    });

  } catch (error) {
    console.error('Transaction fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch transactions',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// ==================== GET TRANSACTION DETAILS ====================
router.get('/transactions/:reference', protect, asyncHandler(async (req, res) => {
  try {
    const { reference } = req.params;

    const transaction = await Transaction.findOne({
      reference,
      userId: req.user._id
    })
    .populate('relatedPurchaseId')
    .populate('userId', 'name email phoneNumber');

    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }

    res.json({
      success: true,
      data: transaction
    });

  } catch (error) {
    console.error('Transaction detail error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch transaction details',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// ==================== GET TRANSACTION SUMMARY ====================
router.get('/transactions/summary/:period', protect, asyncHandler(async (req, res) => {
  try {
    const { period } = req.params; // today, week, month, year
    const userId = req.user._id;

    // Calculate date range
    const now = new Date();
    let startDate;

    switch (period) {
      case 'today':
        startDate = new Date(now.setHours(0, 0, 0, 0));
        break;
      case 'week':
        startDate = new Date(now.setDate(now.getDate() - 7));
        break;
      case 'month':
        startDate = new Date(now.setMonth(now.getMonth() - 1));
        break;
      case 'year':
        startDate = new Date(now.setFullYear(now.getFullYear() - 1));
        break;
      default:
        startDate = new Date(now.setMonth(now.getMonth() - 1));
    }

    // Get transactions for the period
    const transactions = await Transaction.aggregate([
      {
        $match: {
          userId,
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            type: '$type',
            status: '$status'
          },
          count: { $sum: 1 },
          total: { $sum: '$amount' }
        }
      },
      {
        $group: {
          _id: '$_id.type',
          statuses: {
            $push: {
              status: '$_id.status',
              count: '$count',
              total: '$total'
            }
          },
          totalCount: { $sum: '$count' },
          totalAmount: { $sum: '$total' }
        }
      }
    ]);

    // Get daily breakdown for chart
    const dailyBreakdown = await Transaction.aggregate([
      {
        $match: {
          userId,
          createdAt: { $gte: startDate },
          status: 'completed'
        }
      },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
            type: '$type'
          },
          count: { $sum: 1 },
          total: { $sum: '$amount' }
        }
      },
      {
        $sort: { '_id.date': 1 }
      }
    ]);

    // Calculate net flow
    const netFlow = await Transaction.aggregate([
      {
        $match: {
          userId,
          createdAt: { $gte: startDate },
          status: 'completed'
        }
      },
      {
        $group: {
          _id: null,
          inflow: {
            $sum: {
              $cond: [
                { $in: ['$type', ['deposit', 'admin_credit', 'momo', 'refund', 'commission', 'agent_profit']] },
                '$amount',
                0
              ]
            }
          },
          outflow: {
            $sum: {
              $cond: [
                { $in: ['$type', ['withdrawal', 'purchase', 'transfer', 'admin_debit', 'admin-deduction']] },
                '$amount',
                0
              ]
            }
          }
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        period,
        startDate,
        summary: transactions,
        dailyBreakdown,
        netFlow: netFlow[0] || { inflow: 0, outflow: 0 },
        currentBalance: req.user.walletBalance
      }
    });

  } catch (error) {
    console.error('Transaction summary error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch transaction summary',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// ==================== EXPORT TRANSACTION DATA ====================
router.get('/transactions/export/:format', protect, asyncHandler(async (req, res) => {
  try {
    const { format } = req.params; // csv or json
    const { from, to } = req.query;
    const userId = req.user._id;

    // Build filter
    const filter = { userId };
    
    if (from || to) {
      filter.createdAt = {};
      if (from) filter.createdAt.$gte = new Date(from);
      if (to) filter.createdAt.$lte = new Date(to);
    }

    // Get all transactions for export
    const transactions = await Transaction.find(filter)
      .populate('relatedPurchaseId', 'network capacity phoneNumber')
      .sort({ createdAt: -1 })
      .lean();

    if (format === 'csv') {
      // Convert to CSV
      const csv = convertToCSV(transactions);
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=transactions-${Date.now()}.csv`);
      res.send(csv);
    } else {
      // Return as JSON
      res.json({
        success: true,
        data: transactions,
        count: transactions.length,
        exportDate: new Date()
      });
    }

  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to export transactions',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

// ==================== HELPER FUNCTIONS ====================
function getTransactionDescription(transaction) {
  const descriptions = {
    deposit: 'Wallet Deposit',
    withdrawal: 'Wallet Withdrawal',
    transfer: 'Wallet Transfer',
    refund: 'Transaction Refund',
    purchase: 'Data Purchase',
    commission: 'Commission Earned',
    agent_profit: 'Agent Profit',
    admin_credit: 'Admin Credit',
    admin_debit: 'Admin Debit',
    'wallet-refund': 'Wallet Refund',
    'admin-deduction': 'Admin Deduction',
    momo: 'Mobile Money Deposit'
  };

  return descriptions[transaction.type] || transaction.type;
}

function convertToCSV(transactions) {
  const headers = [
    'Date',
    'Reference',
    'Type',
    'Description',
    'Amount',
    'Balance Before',
    'Balance After',
    'Status',
    'Gateway'
  ];

  const rows = transactions.map(t => [
    new Date(t.createdAt).toLocaleString(),
    t.reference,
    t.type,
    t.description || getTransactionDescription(t),
    t.amount,
    t.balanceBefore,
    t.balanceAfter,
    t.status,
    t.gateway
  ]);

  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.join(','))
  ].join('\n');

  return csvContent;
}

module.exports = router;