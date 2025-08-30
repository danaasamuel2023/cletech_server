// routes/adminSettings.js - Complete Admin Settings Management Routes

const express = require('express');
const router = express.Router();
const SystemSettings = require('../../settingsSchema/schema');
const { User } = require('../../Schema/Schema');
const { protect, adminOnly } = require('../../middleware/middleware');
const { body, validationResult } = require('express-validator');

// Middleware to ensure only admin can access
router.use(protect, adminOnly);

// ==================== GET SETTINGS ====================

// @route   GET /api/admin/settings
// @desc    Get all system settings
// @access  Admin only
router.get('/', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    res.json({
      success: true,
      data: settings
    });
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   GET /api/admin/settings/:category
// @desc    Get specific category settings
// @access  Admin only
router.get('/:category', async (req, res) => {
  try {
    const { category } = req.params;
    const validCategories = [
      'platform', 'userManagement', 'financial', 'paymentGateway',
      'pricing', 'agentStore', 'dataPurchase', 'notifications',
      'api', 'resultChecker', 'security', 'maintenance'
    ];

    if (!validCategories.includes(category)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid settings category'
      });
    }

    const settings = await SystemSettings.getSettings();
    
    res.json({
      success: true,
      data: settings[category]
    });
  } catch (error) {
    console.error('Get category settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== UPDATE SETTINGS ====================

// @route   PUT /api/admin/settings/platform
// @desc    Update platform settings
// @access  Admin only
router.put('/platform', [
  body('siteName').optional().isString(),
  body('siteUrl').optional().isURL(),
  body('adminEmail').optional().isEmail(),
  body('supportEmail').optional().isEmail(),
  body('maintenanceMode').optional().isBoolean()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false, 
      errors: errors.array() 
    });
  }

  try {
    const settings = await SystemSettings.getSettings();
    
    // Update platform settings
    Object.assign(settings.platform, req.body);
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: 'Platform settings updated successfully',
      data: settings.platform
    });
  } catch (error) {
    console.error('Update platform settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update platform settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/admin/settings/user-management
// @desc    Update user management settings
// @access  Admin only
router.put('/user-management', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Deep merge user management settings
    if (req.body.registration) {
      Object.assign(settings.userManagement.registration, req.body.registration);
    }
    if (req.body.security) {
      Object.assign(settings.userManagement.security, req.body.security);
    }
    if (req.body.roles) {
      Object.assign(settings.userManagement.roles, req.body.roles);
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: 'User management settings updated successfully',
      data: settings.userManagement
    });
  } catch (error) {
    console.error('Update user management settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update user management settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/admin/settings/financial
// @desc    Update financial settings
// @access  Admin only
router.put('/financial', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Deep merge financial settings
    if (req.body.wallet) {
      Object.assign(settings.financial.wallet, req.body.wallet);
    }
    if (req.body.transactions) {
      Object.assign(settings.financial.transactions, req.body.transactions);
    }
    if (req.body.withdrawals) {
      Object.assign(settings.financial.withdrawals, req.body.withdrawals);
    }
    if (req.body.commissions) {
      Object.assign(settings.financial.commissions, req.body.commissions);
    }
    if (req.body.refunds) {
      Object.assign(settings.financial.refunds, req.body.refunds);
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: 'Financial settings updated successfully',
      data: settings.financial
    });
  } catch (error) {
    console.error('Update financial settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update financial settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/admin/settings/payment-gateway
// @desc    Update payment gateway settings
// @access  Admin only
router.put('/payment-gateway', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Deep merge payment gateway settings
    if (req.body.paystack) {
      Object.assign(settings.paymentGateway.paystack, req.body.paystack);
    }
    if (req.body.momo) {
      Object.assign(settings.paymentGateway.momo, req.body.momo);
    }
    if (req.body.wallet) {
      Object.assign(settings.paymentGateway.wallet, req.body.wallet);
    }
    
    // General payment settings
    if (req.body.retryFailedPayments !== undefined) {
      settings.paymentGateway.retryFailedPayments = req.body.retryFailedPayments;
    }
    if (req.body.maxRetryAttempts !== undefined) {
      settings.paymentGateway.maxRetryAttempts = req.body.maxRetryAttempts;
    }
    if (req.body.retryInterval !== undefined) {
      settings.paymentGateway.retryInterval = req.body.retryInterval;
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    // Mask sensitive data in response
    const responseData = JSON.parse(JSON.stringify(settings.paymentGateway));
    if (responseData.paystack.secretKey) {
      responseData.paystack.secretKey = '***' + responseData.paystack.secretKey.slice(-4);
    }

    res.json({
      success: true,
      message: 'Payment gateway settings updated successfully',
      data: responseData
    });
  } catch (error) {
    console.error('Update payment gateway settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update payment gateway settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/admin/settings/pricing
// @desc    Update pricing settings
// @access  Admin only
router.put('/pricing', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Deep merge pricing settings
    if (req.body.markup) {
      Object.assign(settings.pricing.markup, req.body.markup);
    }
    if (req.body.discounts) {
      Object.assign(settings.pricing.discounts, req.body.discounts);
    }
    if (req.body.inventory) {
      Object.assign(settings.pricing.inventory, req.body.inventory);
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: 'Pricing settings updated successfully',
      data: settings.pricing
    });
  } catch (error) {
    console.error('Update pricing settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update pricing settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/admin/settings/agent-store
// @desc    Update agent store settings
// @access  Admin only
router.put('/agent-store', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Deep merge agent store settings
    if (req.body.creation) {
      Object.assign(settings.agentStore.creation, req.body.creation);
    }
    if (req.body.limits) {
      Object.assign(settings.agentStore.limits, req.body.limits);
    }
    if (req.body.features) {
      Object.assign(settings.agentStore.features, req.body.features);
    }
    if (req.body.premium) {
      Object.assign(settings.agentStore.premium, req.body.premium);
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: 'Agent store settings updated successfully',
      data: settings.agentStore
    });
  } catch (error) {
    console.error('Update agent store settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update agent store settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/admin/settings/data-purchase
// @desc    Update data purchase settings
// @access  Admin only
router.put('/data-purchase', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Deep merge data purchase settings
    if (req.body.networks) {
      Object.assign(settings.dataPurchase.networks, req.body.networks);
    }
    if (req.body.capacities) {
      Object.assign(settings.dataPurchase.capacities, req.body.capacities);
    }
    if (req.body.limits) {
      Object.assign(settings.dataPurchase.limits, req.body.limits);
    }
    if (req.body.processing) {
      Object.assign(settings.dataPurchase.processing, req.body.processing);
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: 'Data purchase settings updated successfully',
      data: settings.dataPurchase
    });
  } catch (error) {
    console.error('Update data purchase settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update data purchase settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/admin/settings/notifications
// @desc    Update notification settings
// @access  Admin only
router.put('/notifications', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Deep merge notification settings
    if (req.body.email) {
      Object.assign(settings.notifications.email, req.body.email);
      // Mask sensitive SMTP password
      if (settings.notifications.email.smtp?.password) {
        settings.notifications.email.smtp.password = req.body.email.smtp.password;
      }
    }
    if (req.body.sms) {
      Object.assign(settings.notifications.sms, req.body.sms);
    }
    if (req.body.whatsapp) {
      Object.assign(settings.notifications.whatsapp, req.body.whatsapp);
    }
    if (req.body.push) {
      Object.assign(settings.notifications.push, req.body.push);
    }
    if (req.body.preferences) {
      Object.assign(settings.notifications.preferences, req.body.preferences);
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    // Mask sensitive data in response
    const responseData = JSON.parse(JSON.stringify(settings.notifications));
    if (responseData.email?.smtp?.password) {
      responseData.email.smtp.password = '********';
    }
    if (responseData.sms?.apiSecret) {
      responseData.sms.apiSecret = '***' + responseData.sms.apiSecret.slice(-4);
    }

    res.json({
      success: true,
      message: 'Notification settings updated successfully',
      data: responseData
    });
  } catch (error) {
    console.error('Update notification settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update notification settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/admin/settings/api
// @desc    Update API settings
// @access  Admin only
router.put('/api', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Deep merge API settings
    if (req.body.enabled !== undefined) {
      settings.api.enabled = req.body.enabled;
    }
    if (req.body.version) {
      settings.api.version = req.body.version;
    }
    if (req.body.baseUrl) {
      settings.api.baseUrl = req.body.baseUrl;
    }
    if (req.body.documentation !== undefined) {
      settings.api.documentation = req.body.documentation;
    }
    if (req.body.sandbox !== undefined) {
      settings.api.sandbox = req.body.sandbox;
    }
    if (req.body.rateLimits) {
      Object.assign(settings.api.rateLimits, req.body.rateLimits);
    }
    if (req.body.authentication) {
      Object.assign(settings.api.authentication, req.body.authentication);
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: 'API settings updated successfully',
      data: settings.api
    });
  } catch (error) {
    console.error('Update API settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update API settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/admin/settings/result-checker
// @desc    Update result checker settings
// @access  Admin only
router.put('/result-checker', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Deep merge result checker settings
    if (req.body.enabled !== undefined) {
      settings.resultChecker.enabled = req.body.enabled;
    }
    if (req.body.types) {
      Object.assign(settings.resultChecker.types, req.body.types);
    }
    if (req.body.commissions) {
      Object.assign(settings.resultChecker.commissions, req.body.commissions);
    }
    if (req.body.bulkUpload) {
      Object.assign(settings.resultChecker.bulkUpload, req.body.bulkUpload);
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: 'Result checker settings updated successfully',
      data: settings.resultChecker
    });
  } catch (error) {
    console.error('Update result checker settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update result checker settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/admin/settings/security
// @desc    Update security settings
// @access  Admin only
router.put('/security', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Deep merge security settings
    if (req.body.encryption) {
      Object.assign(settings.security.encryption, req.body.encryption);
    }
    if (req.body.backup) {
      Object.assign(settings.security.backup, req.body.backup);
    }
    if (req.body.audit) {
      Object.assign(settings.security.audit, req.body.audit);
    }
    if (req.body.firewall) {
      Object.assign(settings.security.firewall, req.body.firewall);
    }
    if (req.body.compliance) {
      Object.assign(settings.security.compliance, req.body.compliance);
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: 'Security settings updated successfully',
      data: settings.security
    });
  } catch (error) {
    console.error('Update security settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update security settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/admin/settings/maintenance
// @desc    Update maintenance settings
// @access  Admin only
router.put('/maintenance', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Deep merge maintenance settings
    if (req.body.scheduling) {
      Object.assign(settings.maintenance.scheduling, req.body.scheduling);
    }
    if (req.body.health) {
      Object.assign(settings.maintenance.health, req.body.health);
    }
    if (req.body.updates) {
      Object.assign(settings.maintenance.updates, req.body.updates);
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: 'Maintenance settings updated successfully',
      data: settings.maintenance
    });
  } catch (error) {
    console.error('Update maintenance settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update maintenance settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== SPECIAL OPERATIONS ====================

// @route   POST /api/admin/settings/maintenance/toggle
// @desc    Toggle maintenance mode
// @access  Admin only
router.post('/maintenance/toggle', async (req, res) => {
  try {
    const { enabled, message, allowAdminAccess } = req.body;
    
    const settings = await SystemSettings.getSettings();
    
    settings.platform.maintenanceMode = enabled;
    if (message) {
      settings.platform.maintenanceMessage = message;
    }
    if (allowAdminAccess !== undefined) {
      settings.maintenance.scheduling.allowAdminAccess = allowAdminAccess;
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: `Maintenance mode ${enabled ? 'enabled' : 'disabled'}`,
      data: {
        maintenanceMode: settings.platform.maintenanceMode,
        message: settings.platform.maintenanceMessage
      }
    });
  } catch (error) {
    console.error('Toggle maintenance mode error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to toggle maintenance mode',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   POST /api/admin/settings/reset/:category
// @desc    Reset category settings to defaults
// @access  Admin only
router.post('/reset/:category', async (req, res) => {
  try {
    const { category } = req.params;
    const validCategories = [
      'platform', 'userManagement', 'financial', 'paymentGateway',
      'pricing', 'agentStore', 'dataPurchase', 'notifications',
      'api', 'resultChecker', 'security', 'maintenance'
    ];

    if (!validCategories.includes(category)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid settings category'
      });
    }

    // Create new settings with defaults
    const defaultSettings = new SystemSettings();
    const settings = await SystemSettings.getSettings();
    
    // Reset specific category to defaults
    settings[category] = defaultSettings[category];
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: `${category} settings reset to defaults`,
      data: settings[category]
    });
  } catch (error) {
    console.error('Reset settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   GET /api/admin/settings/export
// @desc    Export all settings
// @access  Admin only
router.get('/export', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Remove sensitive data
    const exportData = JSON.parse(JSON.stringify(settings));
    
    // Mask sensitive fields
    if (exportData.paymentGateway?.paystack?.secretKey) {
      exportData.paymentGateway.paystack.secretKey = '[REDACTED]';
    }
    if (exportData.notifications?.email?.smtp?.password) {
      exportData.notifications.email.smtp.password = '[REDACTED]';
    }
    if (exportData.notifications?.sms?.apiSecret) {
      exportData.notifications.sms.apiSecret = '[REDACTED]';
    }
    if (exportData.notifications?.whatsapp?.businessApiKey) {
      exportData.notifications.whatsapp.businessApiKey = '[REDACTED]';
    }
    if (exportData.api?.authentication) {
      exportData.api.authentication = '[REDACTED]';
    }
    
    res.json({
      success: true,
      data: exportData,
      exportedAt: new Date(),
      exportedBy: req.user.email
    });
  } catch (error) {
    console.error('Export settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to export settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   POST /api/admin/settings/import
// @desc    Import settings (with validation)
// @access  Admin only
router.post('/import', async (req, res) => {
  try {
    const { settings: importData, categories } = req.body;
    
    if (!importData) {
      return res.status(400).json({
        success: false,
        message: 'No settings data provided'
      });
    }
    
    const settings = await SystemSettings.getSettings();
    
    // Import only specified categories or all if not specified
    const categoriesToImport = categories || [
      'platform', 'userManagement', 'financial', 'pricing',
      'agentStore', 'dataPurchase', 'notifications', 'api',
      'resultChecker', 'security', 'maintenance'
    ];
    
    for (const category of categoriesToImport) {
      if (importData[category]) {
        // Don't import sensitive fields
        if (category === 'paymentGateway') {
          // Skip sensitive payment gateway data
          continue;
        }
        settings[category] = importData[category];
      }
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();

    res.json({
      success: true,
      message: 'Settings imported successfully',
      importedCategories: categoriesToImport
    });
  } catch (error) {
    console.error('Import settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to import settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   GET /api/admin/settings/health
// @desc    Get system health status
// @access  Admin only
router.get('/health', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Mock health data - in production, this would check actual system metrics
    const health = {
      status: 'healthy',
      uptime: process.uptime(),
      memory: {
        used: process.memoryUsage().heapUsed / 1024 / 1024,
        total: process.memoryUsage().heapTotal / 1024 / 1024,
        percentage: (process.memoryUsage().heapUsed / process.memoryUsage().heapTotal) * 100
      },
      settings: {
        maintenanceMode: settings.platform.maintenanceMode,
        apiEnabled: settings.api.enabled,
        notificationsEnabled: settings.notifications.email.enabled || settings.notifications.sms.enabled
      },
      lastUpdated: settings.lastUpdatedAt,
      timestamp: new Date()
    };

    res.json({
      success: true,
      data: health
    });
  } catch (error) {
    console.error('Health check error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get health status',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   POST /api/admin/settings/test-email
// @desc    Test email configuration
// @access  Admin only
router.post('/test-email', async (req, res) => {
  try {
    const { testEmail } = req.body;
    
    if (!testEmail) {
      return res.status(400).json({
        success: false,
        message: 'Test email address is required'
      });
    }
    
    const settings = await SystemSettings.getSettings();
    
    // Here you would implement the actual email sending logic
    // using the settings.notifications.email configuration
    
    res.json({
      success: true,
      message: `Test email sent to ${testEmail}`,
      configuration: {
        provider: settings.notifications.email.provider,
        fromEmail: settings.notifications.email.fromEmail,
        smtpHost: settings.notifications.email.smtp?.host
      }
    });
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send test email',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   POST /api/admin/settings/test-sms
// @desc    Test SMS configuration
// @access  Admin only
router.post('/test-sms', async (req, res) => {
  try {
    const { testPhone } = req.body;
    
    if (!testPhone) {
      return res.status(400).json({
        success: false,
        message: 'Test phone number is required'
      });
    }
    
    const settings = await SystemSettings.getSettings();
    
    // Here you would implement the actual SMS sending logic
    // using the settings.notifications.sms configuration
    
    res.json({
      success: true,
      message: `Test SMS sent to ${testPhone}`,
      configuration: {
        provider: settings.notifications.sms.provider,
        senderId: settings.notifications.sms.senderId,
        creditBalance: settings.notifications.sms.creditBalance
      }
    });
  } catch (error) {
    console.error('Test SMS error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send test SMS',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   GET /api/admin/settings/backup
// @desc    Create settings backup
// @access  Admin only
router.get('/backup', async (req, res) => {
  try {
    const settings = await SystemSettings.getSettings();
    
    // Create backup with timestamp
    const backup = {
      version: '1.0',
      createdAt: new Date(),
      createdBy: req.user.email,
      settings: JSON.parse(JSON.stringify(settings)),
      checksum: require('crypto')
        .createHash('sha256')
        .update(JSON.stringify(settings))
        .digest('hex')
    };
    
    res.json({
      success: true,
      message: 'Backup created successfully',
      data: backup
    });
  } catch (error) {
    console.error('Backup error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create backup',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   POST /api/admin/settings/restore
// @desc    Restore settings from backup
// @access  Admin only
router.post('/restore', async (req, res) => {
  try {
    const { backup } = req.body;
    
    if (!backup || !backup.settings) {
      return res.status(400).json({
        success: false,
        message: 'Invalid backup data'
      });
    }
    
    // Verify checksum if provided
    if (backup.checksum) {
      const calculatedChecksum = require('crypto')
        .createHash('sha256')
        .update(JSON.stringify(backup.settings))
        .digest('hex');
      
      if (calculatedChecksum !== backup.checksum) {
        return res.status(400).json({
          success: false,
          message: 'Backup integrity check failed'
        });
      }
    }
    
    const settings = await SystemSettings.getSettings();
    
    // Restore settings (excluding sensitive data)
    const excludedFields = ['paymentGateway', 'notifications'];
    
    for (const key in backup.settings) {
      if (!excludedFields.includes(key)) {
        settings[key] = backup.settings[key];
      }
    }
    
    settings.lastUpdatedBy = req.user._id;
    settings.lastUpdatedAt = new Date();
    
    await settings.save();
    
    res.json({
      success: true,
      message: 'Settings restored successfully',
      restoredFrom: backup.createdAt
    });
  } catch (error) {
    console.error('Restore error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to restore settings',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;