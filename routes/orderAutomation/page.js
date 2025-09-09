// ==================== routes/monitoring/orderMonitoring.routes.js ====================
// COMPLETE API ROUTES FOR ORDER MONITORING SYSTEM

const express = require('express');
const router = express.Router();
const { 
  OrderAlert, 
  AutomationControl, 
  WhatsAppMessageLog 
} = require('../../auomationSchema/schema');
const { DataPurchase } = require('../../Schema/Schema');
const orderMonitoringService = require('../../services/ordersAutomation');

// ==================== MIDDLEWARE ====================
// You need to import your existing middleware
const jwt = require('jsonwebtoken');

// Simple protect middleware (use your existing one)
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
    const User = require('../../Schema/Schema').User;
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

// Simple adminOnly middleware (use your existing one)
const adminOnly = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({
      success: false,
      message: 'Admin access required'
    });
  }
};

// ==================== AUTOMATION CONTROL ROUTES ====================

// 1. Pause automation (Admin only)
router.post('/pause', protect, adminOnly, async (req, res) => {
  try {
    const { reason } = req.body;
    
    const control = await AutomationControl.findOneAndUpdate(
      { serviceName: 'order_monitoring' },
      {
        isPaused: true,
        pausedBy: req.user._id, 
        pausedAt: new Date()
      },
      { new: true, upsert: true }
    ).populate('pausedBy', 'name email');
    
    // Send WhatsApp notification to admins
    await orderMonitoringService.notifyAdmins(
      'pause',
      `⏸️ *AUTOMATION PAUSED*\n\n` +
      `Paused by: ${req.user.name || req.user.email}\n` +
      `Reason: ${reason || 'Manual pause'}\n\n` +
      `Manual processing required until resumed.`
    );
    
    res.json({
      success: true,
      message: 'Automation paused successfully',
      data: control
    });
  } catch (error) {
    console.error('Pause automation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to pause automation',
      error: error.message
    });
  }
});

// 2. Resume automation (Admin only)
router.post('/resume', protect, adminOnly, async (req, res) => {
  try {
    const control = await AutomationControl.findOneAndUpdate(
      { serviceName: 'order_monitoring' },
      {
        isPaused: false,
        resumedAt: new Date()
      },
      { new: true }
    );
    
    // Send WhatsApp notification
    await orderMonitoringService.notifyAdmins(
      'resume',
      `▶️ *AUTOMATION RESUMED*\n\n` +
      `Resumed by: ${req.user.name || req.user.email}\n` +
      `Time: ${new Date().toLocaleString('en-GB', { timeZone: 'Africa/Accra' })}\n\n` +
      `Automatic alerts will continue.`
    );
    
    res.json({
      success: true,
      message: 'Automation resumed successfully',
      data: control
    });
  } catch (error) {
    console.error('Resume automation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to resume automation',
      error: error.message
    });
  }
});

// 3. Get automation status
router.get('/status', protect, adminOnly, async (req, res) => {
  try {
    const control = await AutomationControl.findOne({ serviceName: 'order_monitoring' })
      .populate('pausedBy', 'name email');
    
    // Get pending orders count
    const pendingOrders = await DataPurchase.countDocuments({
      status: 'processing',
      whatsappAlertSent: { $ne: true }
    });
    
    // Get today's statistics
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    
    const todayAlerts = await OrderAlert.countDocuments({
      createdAt: { $gte: todayStart }
    });
    
    res.json({
      success: true,
      data: {
        control: control || { isPaused: false, isActive: true },
        pendingOrders,
        todayAlerts,
        isRunning: control ? !control.isPaused : true,
        lastCheck: control?.lastCheck,
        nextCheck: control?.nextCheck,
        statistics: control?.statistics
      }
    });
  } catch (error) {
    console.error('Get status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get status',
      error: error.message
    });
  }
});

// ==================== SETTINGS ROUTES ====================

// 4. Update settings (Admin only)
router.put('/settings', protect, adminOnly, async (req, res) => {
  try {
    const { 
      checkInterval, 
      orderCountThreshold, 
      lookbackMinutes,
      adminNumbers,
      enableNotifications 
    } = req.body;
    
    const updateData = {};
    if (checkInterval) updateData['settings.checkInterval'] = checkInterval;
    if (orderCountThreshold) updateData['settings.orderCountThreshold'] = orderCountThreshold;
    if (lookbackMinutes) updateData['settings.lookbackMinutes'] = lookbackMinutes;
    if (adminNumbers) updateData['settings.adminNumbers'] = adminNumbers;
    if (enableNotifications !== undefined) updateData['settings.enableNotifications'] = enableNotifications;
    
    const control = await AutomationControl.findOneAndUpdate(
      { serviceName: 'order_monitoring' },
      { $set: updateData },
      { new: true, upsert: true }
    );
    
    // Restart monitoring with new settings
    await orderMonitoringService.restartMonitoring();
    
    res.json({
      success: true,
      message: 'Settings updated successfully',
      data: control.settings
    });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update settings',
      error: error.message
    });
  }
});

// ==================== ORDER MANAGEMENT ROUTES ====================

// 5. Mark orders as delivered (Admin only)
router.post('/mark-delivered', protect, adminOnly, async (req, res) => {
  try {
    const { alertId, orderReferences, deliveryNotes } = req.body;
    
    if (!orderReferences || !Array.isArray(orderReferences)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide orderReferences array'
      });
    }
    
    // Update orders to completed
    const updateResult = await DataPurchase.updateMany(
      { 
        reference: { $in: orderReferences },
        status: 'processing'
      },
      {
        $set: {
          status: 'completed',
          deliveredAt: new Date(),
          deliveryDetails: {
            method: 'manual_admin',
            deliveredBy: req.user._id,
            alertId: alertId,
            notes: deliveryNotes
          }
        }
      }
    );
    
    // Update alert status if provided
    if (alertId) {
      await OrderAlert.findOneAndUpdate(
        { alertId },
        {
          status: 'processed',
          processedAt: new Date(),
          processedBy: req.user._id
        }
      );
    }
    
    res.json({
      success: true,
      message: `${updateResult.modifiedCount} orders marked as delivered`,
      data: {
        alertId,
        ordersUpdated: updateResult.modifiedCount,
        orderReferences: orderReferences.slice(0, 10) // Return first 10 for confirmation
      }
    });
  } catch (error) {
    console.error('Mark delivered error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to mark orders as delivered',
      error: error.message
    });
  }
});

// 6. Clear alerted status for re-sending (Admin only)
router.post('/reset-alerts', protect, adminOnly, async (req, res) => {
  try {
    const { orderReferences, resetAll } = req.body;
    
    let filter = { status: 'processing' };
    
    if (orderReferences && orderReferences.length > 0) {
      filter.reference = { $in: orderReferences };
    } else if (!resetAll) {
      return res.status(400).json({
        success: false,
        message: 'Please provide orderReferences or set resetAll to true'
      });
    }
    
    const updateResult = await DataPurchase.updateMany(
      filter,
      {
        $unset: {
          whatsappAlertSent: '',
          whatsappAlertAt: '',
          whatsappAlertId: ''
        }
      }
    );
    
    res.json({
      success: true,
      message: `${updateResult.modifiedCount} orders reset for re-alerting`,
      data: {
        ordersReset: updateResult.modifiedCount
      }
    });
  } catch (error) {
    console.error('Reset alerts error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset alerts',
      error: error.message
    });
  }
});

// ==================== MANUAL TRIGGERS ====================

// 7. Manual trigger for testing (Admin only)
router.post('/trigger-check', protect, adminOnly, async (req, res) => {
  try {
    const { forceAlert } = req.body;
    
    const result = await orderMonitoringService.checkHighVolumeOrders(forceAlert);
    
    res.json({
      success: true,
      message: result.message || 'Manual check completed',
      data: result
    });
  } catch (error) {
    console.error('Manual trigger error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to trigger check',
      error: error.message
    });
  }
});

// ==================== REPORTING ROUTES ====================

// 8. Get recent alerts
router.get('/alerts', protect, adminOnly, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      status,
      startDate,
      endDate 
    } = req.query;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const filter = {};
    if (status) filter.status = status;
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    
    const alerts = await OrderAlert.find(filter)
      .populate('processedBy', 'name email')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);
    
    const total = await OrderAlert.countDocuments(filter);
    
    res.json({
      success: true,
      data: alerts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch alerts',
      error: error.message
    });
  }
});

// 9. Get alert details
router.get('/alerts/:alertId', protect, adminOnly, async (req, res) => {
  try {
    const { alertId } = req.params;
    
    const alert = await OrderAlert.findOne({ alertId })
      .populate('processedBy', 'name email');
    
    if (!alert) {
      return res.status(404).json({
        success: false,
        message: 'Alert not found'
      });
    }
    
    // Get order details
    const orderRefs = alert.orders.map(o => o.reference);
    const orders = await DataPurchase.find({
      reference: { $in: orderRefs }
    }).select('reference phoneNumber network capacity status deliveredAt');
    
    res.json({
      success: true,
      data: {
        alert,
        orders
      }
    });
  } catch (error) {
    console.error('Get alert details error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch alert details',
      error: error.message
    });
  }
});

// 10. Get WhatsApp message logs
router.get('/messages', protect, adminOnly, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50,
      status,
      messageType 
    } = req.query;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const filter = {};
    if (status) filter.status = status;
    if (messageType) filter.messageType = messageType;
    
    const messages = await WhatsAppMessageLog.find(filter)
      .sort({ sentAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);
    
    const total = await WhatsAppMessageLog.countDocuments(filter);
    
    res.json({
      success: true,
      data: messages,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch messages',
      error: error.message
    });
  }
});

// 11. Get dashboard statistics
router.get('/dashboard', protect, adminOnly, async (req, res) => {
  try {
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    
    const weekStart = new Date();
    weekStart.setDate(weekStart.getDate() - 7);
    
    const [
      todayAlerts,
      weekAlerts,
      pendingOrders,
      processingOrders,
      control
    ] = await Promise.all([
      OrderAlert.countDocuments({ createdAt: { $gte: todayStart } }),
      OrderAlert.countDocuments({ createdAt: { $gte: weekStart } }),
      DataPurchase.countDocuments({ 
        status: 'processing', 
        whatsappAlertSent: { $ne: true } 
      }),
      DataPurchase.countDocuments({ status: 'processing' }),
      AutomationControl.findOne({ serviceName: 'order_monitoring' })
    ]);
    
    // Calculate capacity in pending orders
    const pendingCapacity = await DataPurchase.aggregate([
      {
        $match: {
          status: 'processing',
          whatsappAlertSent: { $ne: true }
        }
      },
      {
        $group: {
          _id: null,
          totalCapacity: { $sum: '$capacity' }
        }
      }
    ]);
    
    res.json({
      success: true,
      data: {
        automation: {
          isRunning: control ? !control.isPaused : true,
          isPaused: control?.isPaused || false,
          lastCheck: control?.lastCheck,
          settings: control?.settings
        },
        statistics: {
          todayAlerts,
          weekAlerts,
          pendingOrders,
          processingOrders,
          pendingCapacity: pendingCapacity[0]?.totalCapacity || 0,
          totalAlerts: control?.statistics?.totalAlerts || 0,
          totalOrdersProcessed: control?.statistics?.totalOrdersProcessed || 0
        }
      }
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch dashboard data',
      error: error.message
    });
  }
});

// 12. Download alert Excel file
router.get('/download/:alertId', protect, adminOnly, async (req, res) => {
  try {
    const { alertId } = req.params;
    
    const alert = await OrderAlert.findOne({ alertId });
    
    if (!alert) {
      return res.status(404).json({
        success: false,
        message: 'Alert not found'
      });
    }
    
    // Generate Excel file
    const excelData = await orderMonitoringService.generateOrdersExcel(
      alert.orders,
      alert.alertId
    );
    
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=orders_${alertId}.xlsx`);
    res.send(excelData.buffer);
    
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to download file',
      error: error.message
    });
  }
});

// 13. Test WhatsApp connection
router.post('/test-whatsapp', protect, adminOnly, async (req, res) => {
  try {
    const { phoneNumber, message } = req.body;
    
    const testMessage = message || 'Test message from monitoring system';
    const targetNumber = phoneNumber || process.env.ADMIN_WHATSAPP_NUMBERS?.split(',')[0];
    
    const result = await orderMonitoringService.sendWhatsAppAlert(
      targetNumber,
      `🧪 *TEST MESSAGE*\n\n${testMessage}\n\nTime: ${new Date().toLocaleString()}`
    );
    
    res.json({
      success: result.success,
      message: result.success ? 'Test message sent' : 'Failed to send',
      data: result
    });
  } catch (error) {
    console.error('Test WhatsApp error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send test message',
      error: error.message
    });
  }
});

// 14. Get system health
router.get('/health', async (req, res) => {
  try {
    const control = await AutomationControl.findOne({ serviceName: 'order_monitoring' });
    
    res.json({
      success: true,
      data: {
        status: 'healthy',
        monitoring: control ? (control.isPaused ? 'paused' : 'running') : 'not initialized',
        timestamp: new Date()
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'System unhealthy',
      error: error.message
    });
  }
});

module.exports = router;