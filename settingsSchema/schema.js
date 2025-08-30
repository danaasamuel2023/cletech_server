// SettingsSchema/Settings.js - System Settings Schema (FIXED VERSION)

const mongoose = require('mongoose');

// ==================== SYSTEM SETTINGS SCHEMA ====================
const SystemSettingsSchema = new mongoose.Schema({
  // General Platform Settings
  platform: {
    siteName: { type: String, default: 'CLETECH Data Services' },
    siteUrl: { type: String, default: 'https://cletech.com' },
    logo: { type: String },
    favicon: { type: String },
    adminEmail: { type: String, default: 'admin@cletech.com' },
    supportEmail: { type: String, default: 'support@cletech.com' },
    supportPhone: { type: String, default: '+233241234567' },
    companyAddress: { type: String },
    companyRegistration: { type: String },
    timezone: { type: String, default: 'Africa/Accra' },
    currency: { type: String, default: 'GHS' },
    currencySymbol: { type: String, default: '₵' },
    language: { type: String, default: 'en' },
    dateFormat: { type: String, default: 'DD/MM/YYYY' },
    maintenanceMode: { type: Boolean, default: false },
    maintenanceMessage: { type: String, default: 'System under maintenance. Please check back later.' },
    systemAnnouncement: { type: String },
    announcementType: { type: String, enum: ['info', 'warning', 'success', 'error'], default: 'info' },
    announcementActive: { type: Boolean, default: false }
  },

  // User Management Settings
  userManagement: {
    registration: {
      autoApprove: { type: Boolean, default: false },
      defaultRole: { type: String, enum: ['user', 'agent'], default: 'user' },
      requireUsername: { type: Boolean, default: false },
      requireEmailVerification: { type: Boolean, default: true },
      requirePhoneVerification: { type: Boolean, default: true },
      allowGoogleAuth: { type: Boolean, default: true },
      minAge: { type: Number, default: 18 },
      termsVersion: { type: String, default: '1.0' },
      privacyVersion: { type: String, default: '1.0' }
    },
    security: {
      passwordMinLength: { type: Number, default: 8 },
      passwordRequireUppercase: { type: Boolean, default: true },
      passwordRequireLowercase: { type: Boolean, default: true },
      passwordRequireNumbers: { type: Boolean, default: true },
      passwordRequireSymbols: { type: Boolean, default: true },
      passwordExpiryDays: { type: Number, default: 0 }, // 0 means no expiry
      maxLoginAttempts: { type: Number, default: 5 },
      lockoutDuration: { type: Number, default: 30 }, // minutes
      sessionTimeout: { type: Number, default: 60 }, // minutes
      requireTwoFactor: { type: Boolean, default: false },
      otpExpiryMinutes: { type: Number, default: 10 },
      allowMultipleDevices: { type: Boolean, default: true },
      maxDevicesPerUser: { type: Number, default: 5 }
    },
    roles: {
      permissions: {
        admin: { type: [String], default: ['all'] },
        super_agent: { type: [String], default: ['manage_agents', 'view_reports', 'manage_stores'] },
        dealer: { type: [String], default: ['manage_sales', 'view_reports'] },
        agent: { type: [String], default: ['manage_store', 'make_sales'] },
        user: { type: [String], default: ['make_purchases', 'view_history'] },
        reporter: { type: [String], default: ['view_reports', 'export_data'] },
        worker: { type: [String], default: ['process_orders'] }
      },
      hierarchy: {
        enabled: { type: Boolean, default: true },
        allowCrossHierarchySales: { type: Boolean, default: false }
      }
    }
  },

  // Financial Settings
  financial: {
    wallet: {
      minBalance: { type: Number, default: 0 },
      maxBalance: { type: Number, default: 1000000 },
      allowNegativeBalance: { type: Boolean, default: false },
      defaultCreditLimit: {
        admin: { type: Number, default: 0 },
        super_agent: { type: Number, default: 10000 },
        dealer: { type: Number, default: 5000 },
        agent: { type: Number, default: 1000 },
        user: { type: Number, default: 0 }
      }
    },
    transactions: {
      minTransaction: { type: Number, default: 1 },
      maxTransaction: { type: Number, default: 10000 },
      dailyLimit: { type: Number, default: 50000 },
      weeklyLimit: { type: Number, default: 200000 },
      monthlyLimit: { type: Number, default: 500000 },
      requireApprovalAbove: { type: Number, default: 5000 }
    },
    withdrawals: {
      enabled: { type: Boolean, default: true },
      minWithdrawal: { type: Number, default: 10 },
      maxWithdrawal: { type: Number, default: 5000 },
      dailyWithdrawalLimit: { type: Number, default: 10000 },
      withdrawalFee: { type: Number, default: 0 },
      withdrawalFeeType: { type: String, enum: ['fixed', 'percentage'], default: 'fixed' },
      processingTime: { type: Number, default: 24 }, // hours
      autoApproveBelow: { type: Number, default: 100 }
    },
    commissions: {
      enabled: { type: Boolean, default: true },
      structure: {
        super_agent: { type: Number, default: 15 }, // percentage
        dealer: { type: Number, default: 12 },
        agent: { type: Number, default: 10 },
        referral: { type: Number, default: 5 }
      },
      minimumPayout: { type: Number, default: 10 },
      payoutSchedule: { type: String, enum: ['instant', 'daily', 'weekly', 'monthly'], default: 'instant' }
    },
    refunds: {
      enabled: { type: Boolean, default: true },
      timeLimit: { type: Number, default: 24 }, // hours
      requireApproval: { type: Boolean, default: true },
      autoApproveBelow: { type: Number, default: 50 }
    }
  },

  // Payment Gateway Settings
  paymentGateway: {
    paystack: {
      enabled: { type: Boolean, default: true },
      publicKey: { type: String },
      secretKey: { type: String },
      webhookUrl: { type: String },
      transactionFee: { type: Number, default: 1.95 }, // percentage
      capAt: { type: Number, default: 100 }, // cap fee at amount
      splitPayment: { type: Boolean, default: false },
      subaccountCode: { type: String }
    },
    momo: {
      enabled: { type: Boolean, default: true },
      providers: {
        mtn: { 
          enabled: { type: Boolean, default: true }, 
          fee: { type: Number, default: 1 } 
        },
        vodafone: { 
          enabled: { type: Boolean, default: true }, 
          fee: { type: Number, default: 1 } 
        },
        airteltigo: { 
          enabled: { type: Boolean, default: true }, 
          fee: { type: Number, default: 1 } 
        }
      }
    },
    wallet: {
      enabled: { type: Boolean, default: true },
      instantProcessing: { type: Boolean, default: true }
    },
    retryFailedPayments: { type: Boolean, default: true },
    maxRetryAttempts: { type: Number, default: 3 },
    retryInterval: { type: Number, default: 60 } // minutes
  },

  // Pricing & Inventory Settings
  pricing: {
    markup: {
      minimumMarkup: { type: Number, default: 5 }, // percentage
      maximumMarkup: { type: Number, default: 100 },
      defaultMarkup: {
        dealer: { type: Number, default: 10 },
        super_agent: { type: Number, default: 15 },
        agent: { type: Number, default: 20 },
        user: { type: Number, default: 25 }
      }
    },
    discounts: {
      bulkDiscountEnabled: { type: Boolean, default: true },
      bulkThresholds: [
        { 
          quantity: { type: Number, default: 10 }, 
          discount: { type: Number, default: 5 } 
        },
        { 
          quantity: { type: Number, default: 20 }, 
          discount: { type: Number, default: 10 } 
        },
        { 
          quantity: { type: Number, default: 50 }, 
          discount: { type: Number, default: 15 } 
        }
      ],
      promoCodeEnabled: { type: Boolean, default: true },
      maxPromoDiscount: { type: Number, default: 50 }
    },
    inventory: {
      autoDisableOnOutOfStock: { type: Boolean, default: true },
      lowStockThreshold: { type: Number, default: 10 },
      criticalStockThreshold: { type: Number, default: 5 },
      alertOnLowStock: { type: Boolean, default: true },
      preventOverselling: { type: Boolean, default: true }
    }
  },

  // Agent Store Settings
  agentStore: {
    creation: {
      autoApprove: { type: Boolean, default: false },
      requireVerification: { type: Boolean, default: true },
      verificationChecklist: {
        validPhone: { type: Boolean, default: true },
        validEmail: { type: Boolean, default: true },
        hasLogo: { type: Boolean, default: false },
        hasDescription: { type: Boolean, default: true },
        minimumProducts: { type: Number, default: 1 }
      },
      subdomainMinLength: { type: Number, default: 3 },
      subdomainMaxLength: { type: Number, default: 30 }
    },
    limits: {
      maxProductsPerStore: { type: Number, default: 100 },
      maxCustomPricing: { type: Number, default: 50 },
      minimumProfitMargin: { type: Number, default: 5 }, // percentage
      maximumDiscount: { type: Number, default: 30 }
    },
    features: {
      allowCustomDomain: { type: Boolean, default: false },
      allowSocialMedia: { type: Boolean, default: true },
      allowWhatsappIntegration: { type: Boolean, default: true },
      allowBulkOrders: { type: Boolean, default: true },
      requireBusinessHours: { type: Boolean, default: false }
    },
    premium: {
      enabled: { type: Boolean, default: true },
      monthlyFee: { type: Number, default: 50 },
      features: {
        customDomain: { type: Boolean, default: true },
        advancedAnalytics: { type: Boolean, default: true },
        prioritySupport: { type: Boolean, default: true },
        unlimitedProducts: { type: Boolean, default: true },
        marketingTools: { type: Boolean, default: true }
      }
    }
  },

  // Data Purchase Settings
  dataPurchase: {
    networks: {
      MTN: { 
        enabled: { type: Boolean, default: true }, 
        priority: { type: Number, default: 1 } 
      },
      TELECEL: { 
        enabled: { type: Boolean, default: true }, 
        priority: { type: Number, default: 2 } 
      },
      AT: { 
        enabled: { type: Boolean, default: true }, 
        priority: { type: Number, default: 3 } 
      },
      AIRTELTIGO: { 
        enabled: { type: Boolean, default: true }, 
        priority: { type: Number, default: 4 } 
      },
      AT_PREMIUM: { 
        enabled: { type: Boolean, default: true }, 
        priority: { type: Number, default: 5 } 
      },
      YELLO: { 
        enabled: { type: Boolean, default: true }, 
        priority: { type: Number, default: 6 } 
      }
    },
    capacities: {
      min: { type: Number, default: 0.5 },
      max: { type: Number, default: 100 },
      available: { type: [Number], default: [0.5, 1, 2, 3, 5, 10, 15, 20, 25, 30, 50, 100] }
    },
    limits: {
      dailyPurchaseLimit: { type: Number, default: 100 },
      singlePurchaseMax: { type: Number, default: 100 },
      guestPurchaseEnabled: { type: Boolean, default: false },
      guestPurchaseMax: { type: Number, default: 10 }
    },
    processing: {
      autoProcess: { type: Boolean, default: true },
      maxRetries: { type: Number, default: 3 },
      retryDelay: { type: Number, default: 30 }, // seconds
      timeoutDuration: { type: Number, default: 300 }, // seconds
      requirePhoneVerification: { type: Boolean, default: false }
    }
  },

  // Notification Settings - FIXED
  notifications: {
    email: {
      enabled: { type: Boolean, default: true },
      provider: { type: String, enum: ['smtp', 'sendgrid', 'mailgun'], default: 'smtp' },
      smtp: {
        host: { type: String },
        port: { type: Number, default: 587 },
        secure: { type: Boolean, default: false },
        user: { type: String },
        password: { type: String }
      },
      fromEmail: { type: String },
      fromName: { type: String },
      templates: {
        registration: { type: String },
        purchaseConfirmation: { type: String },
        passwordReset: { type: String },
        withdrawal: { type: String }
      }
    },
    sms: {
      enabled: { type: Boolean, default: false },
      provider: { type: String, enum: ['twilio', 'hubtel', 'mnotify'], default: 'hubtel' },
      apiKey: { type: String },
      apiSecret: { type: String },
      senderId: { type: String },
      creditBalance: { type: Number, default: 0 },
      lowBalanceAlert: { type: Number, default: 100 }
    },
    whatsapp: {
      enabled: { type: Boolean, default: false },
      businessApiKey: { type: String },
      phoneNumber: { type: String },
      webhookUrl: { type: String }
    },
    push: {
      enabled: { type: Boolean, default: false },
      vapidPublicKey: { type: String },
      vapidPrivateKey: { type: String }
    },
    // FIXED: Use Mixed type for preferences with default values
    preferences: {
      type: mongoose.Schema.Types.Mixed,
      default: {
        orderConfirmation: { 
          email: true, 
          sms: false, 
          whatsapp: false, 
          push: false 
        },
        paymentSuccess: { 
          email: true, 
          sms: true, 
          whatsapp: false, 
          push: true 
        },
        lowBalance: { 
          email: true, 
          sms: false, 
          whatsapp: false, 
          push: true 
        },
        promotions: { 
          email: true, 
          sms: false, 
          whatsapp: false, 
          push: false 
        }
      }
    }
  },

  // API Settings
  api: {
    enabled: { type: Boolean, default: true },
    version: { type: String, default: 'v1' },
    baseUrl: { type: String, default: '/api/v1' },
    documentation: { type: Boolean, default: true },
    sandbox: { type: Boolean, default: true },
    rateLimits: {
      basic: { 
        requests: { type: Number, default: 100 }, 
        window: { type: Number, default: 60 } 
      }, // per minute
      premium: { 
        requests: { type: Number, default: 500 }, 
        window: { type: Number, default: 60 } 
      },
      enterprise: { 
        requests: { type: Number, default: 2000 }, 
        window: { type: Number, default: 60 } 
      }
    },
    authentication: {
      type: { type: String, enum: ['apikey', 'jwt', 'oauth2'], default: 'apikey' },
      keyExpiry: { type: Number, default: 365 }, // days
      requireHttps: { type: Boolean, default: true },
      allowCors: { type: Boolean, default: true },
      corsOrigins: { type: [String], default: ['*'] }
    }
  },

  // Result Checker Settings
  resultChecker: {
    enabled: { type: Boolean, default: true },
    types: {
      BECE: { 
        enabled: { type: Boolean, default: true },
        price: { type: Number, default: 10 },
        maxUses: { type: Number, default: 5 },
        validityDays: { type: Number, default: 365 }
      },
      WASSCE: {
        enabled: { type: Boolean, default: true },
        price: { type: Number, default: 15 },
        maxUses: { type: Number, default: 5 },
        validityDays: { type: Number, default: 365 }
      }
    },
    commissions: {
      agent: { type: Number, default: 10 }, // percentage
      dealer: { type: Number, default: 12 },
      super_agent: { type: Number, default: 15 }
    },
    bulkUpload: {
      enabled: { type: Boolean, default: true },
      maxBatchSize: { type: Number, default: 1000 },
      requireVerification: { type: Boolean, default: true }
    }
  },

  // Security & Compliance
  security: {
    encryption: {
      enabled: { type: Boolean, default: true },
      algorithm: { type: String, default: 'AES-256' },
      keyRotation: { type: Boolean, default: true },
      keyRotationDays: { type: Number, default: 90 }
    },
    backup: {
      enabled: { type: Boolean, default: true },
      frequency: { type: String, enum: ['hourly', 'daily', 'weekly'], default: 'daily' },
      retention: { type: Number, default: 30 }, // days
      location: { type: String, default: 'local' },
      cloudBackup: { type: Boolean, default: false }
    },
    audit: {
      enabled: { type: Boolean, default: true },
      logLevel: { type: String, enum: ['error', 'warn', 'info', 'debug'], default: 'info' },
      retention: { type: Number, default: 90 }, // days
      sensitiveDataMasking: { type: Boolean, default: true }
    },
    firewall: {
      enabled: { type: Boolean, default: true },
      blockSuspiciousIps: { type: Boolean, default: true },
      maxRequestsPerIp: { type: Number, default: 1000 }, // per hour
      blacklistedIps: { type: [String], default: [] },
      whitelistedIps: { type: [String], default: [] },
      geoBlocking: { type: Boolean, default: false },
      blockedCountries: { type: [String], default: [] }
    },
    compliance: {
      gdprEnabled: { type: Boolean, default: false },
      dataRetention: { type: Number, default: 365 }, // days
      rightToErasure: { type: Boolean, default: true },
      cookieConsent: { type: Boolean, default: true },
      ageVerification: { type: Boolean, default: true },
      kycRequired: { type: Boolean, default: false },
      amlEnabled: { type: Boolean, default: false }
    }
  },

  // System Maintenance
  maintenance: {
    scheduling: {
      enabled: { type: Boolean, default: false },
      schedule: { type: String }, // cron format
      duration: { type: Number, default: 60 }, // minutes
      message: { type: String },
      allowAdminAccess: { type: Boolean, default: true }
    },
    health: {
      checkInterval: { type: Number, default: 5 }, // minutes
      cpuThreshold: { type: Number, default: 80 }, // percentage
      memoryThreshold: { type: Number, default: 85 },
      diskThreshold: { type: Number, default: 90 },
      alertOnThreshold: { type: Boolean, default: true }
    },
    updates: {
      autoUpdate: { type: Boolean, default: false },
      checkForUpdates: { type: Boolean, default: true },
      updateChannel: { type: String, enum: ['stable', 'beta', 'dev'], default: 'stable' }
    }
  },

  // Metadata
  lastUpdatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  lastUpdatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Only one settings document should exist
SystemSettingsSchema.statics.getSettings = async function() {
  let settings = await this.findOne();
  if (!settings) {
    settings = await this.create({});
  }
  return settings;
};

SystemSettingsSchema.statics.updateSettings = async function(updates, adminId) {
  const settings = await this.getSettings();
  Object.assign(settings, updates);
  settings.lastUpdatedBy = adminId;
  settings.lastUpdatedAt = new Date();
  await settings.save();
  return settings;
};

const SystemSettings = mongoose.model('SystemSettings', SystemSettingsSchema);

module.exports = SystemSettings;