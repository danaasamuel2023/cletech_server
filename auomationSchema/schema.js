// ==================== models/orderMonitoring.model.js ====================
// SCHEMAS FOR ORDER MONITORING SYSTEM

const mongoose = require('mongoose');

// ==================== ORDER ALERT SCHEMA ====================
const OrderAlertSchema = new mongoose.Schema({
  alertId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  orders: [{
    purchaseId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'DataPurchase'
    },
    reference: String,
    phoneNumber: String,
    network: String,
    capacity: Number,
    price: Number,
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Usermodal'
    },
    userName: String,
    userEmail: String,
    purchaseTime: Date,
    paymentMethod: String
  }],
  totalCapacity: Number,
  totalAmount: Number,
  totalOrders: Number,
  excelFileUrl: String,
  whatsappMessageIds: [String],
  alertSentAt: Date,
  processedAt: Date,
  processedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Usermodal'
  },
  adminResponses: [{
    adminPhone: String,
    response: String,
    receivedAt: Date
  }],
  status: {
    type: String,
    enum: ['sent', 'acknowledged', 'processed', 'failed'],
    default: 'sent'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes for better query performance
OrderAlertSchema.index({ alertSentAt: -1 });
OrderAlertSchema.index({ status: 1 });

// ==================== AUTOMATION CONTROL SCHEMA ====================
const AutomationControlSchema = new mongoose.Schema({
  serviceName: {
    type: String,
    required: true,
    unique: true,
    default: 'order_monitoring'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isPaused: {
    type: Boolean,
    default: false
  },
  pausedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Usermodal'
  },
  pausedAt: Date,
  resumedAt: Date,
  lastCheck: Date,
  nextCheck: Date,
  settings: {
    checkInterval: {
      type: String,
      default: '*/5 * * * *' // Every 5 minutes
    },
    orderCountThreshold: {
      type: Number,
      default: 40 // Alert when 40 or more orders
    },
    lookbackMinutes: {
      type: Number,
      default: 5 // Check orders from last 5 minutes
    },
    adminNumbers: [{
      type: String
    }],
    enableNotifications: {
      type: Boolean,
      default: true
    }
  },
  statistics: {
    totalAlerts: { 
      type: Number, 
      default: 0 
    },
    totalOrdersProcessed: { 
      type: Number, 
      default: 0 
    },
    totalCapacityProcessed: {
      type: Number,
      default: 0
    },
    lastAlertAt: Date,
    dailyAlerts: [{
      date: Date,
      count: Number,
      ordersCount: Number,
      totalCapacity: Number
    }]
  },
  maintenanceMode: {
    enabled: {
      type: Boolean,
      default: false
    },
    message: String,
    scheduledEnd: Date
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update timestamp on save
AutomationControlSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Static method to get or create control
AutomationControlSchema.statics.getControl = async function() {
  let control = await this.findOne({ serviceName: 'order_monitoring' });
  if (!control) {
    control = await this.create({ 
      serviceName: 'order_monitoring',
      'settings.adminNumbers': process.env.ADMIN_WHATSAPP_NUMBERS?.split(',') || []
    });
  }
  return control;
};

// ==================== WHATSAPP MESSAGE LOG SCHEMA ====================
const WhatsAppMessageLogSchema = new mongoose.Schema({
  messageId: String,
  recipientNumber: String,
  messageType: {
    type: String,
    enum: ['alert', 'notification', 'status_update', 'error'],
    default: 'alert'
  },
  content: String,
  attachments: [{
    type: String,
    url: String,
    fileName: String
  }],
  status: {
    type: String,
    enum: ['sent', 'delivered', 'read', 'failed'],
    default: 'sent'
  },
  relatedAlertId: String,
  error: String,
  sentAt: {
    type: Date,
    default: Date.now
  },
  deliveredAt: Date,
  readAt: Date
});

// Index for quick lookups
WhatsAppMessageLogSchema.index({ messageId: 1 });
WhatsAppMessageLogSchema.index({ relatedAlertId: 1 });
WhatsAppMessageLogSchema.index({ sentAt: -1 });

// ==================== EXPORT MODELS ====================
module.exports = {
  OrderAlert: mongoose.model('OrderAlert', OrderAlertSchema),
  AutomationControl: mongoose.model('AutomationControl', AutomationControlSchema),
  WhatsAppMessageLog: mongoose.model('WhatsAppMessageLog', WhatsAppMessageLogSchema)
};