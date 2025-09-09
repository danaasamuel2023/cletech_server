const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');

// ==================== USER SCHEMA ====================
const UserSchema = new mongoose.Schema({
  // Basic Information
  username: {
    type: String,
    sparse: true,
    unique: true,
    lowercase: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    match: /^[a-zA-Z0-9_-]+$/
  },
  name: { 
    type: String, 
    required: true 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true,
    trim: true
  },
  password: { 
    type: String, 
    required: function() { return !this.googleId; } 
  },
  phoneNumber: { 
    type: String, 
    required: true, 
    unique: true,
    match: /^(\+233|0)[2-9]\d{8}$/
  },
  
  // Role and Hierarchy
  role: { 
    type: String, 
    enum: ["admin", "super_agent", "dealer", "agent", "user", "reporter", "worker"], 
    default: "user" 
  },
  parentAgent: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Usermodal",
    default: null
  },
  
  // Financial
  walletBalance: { 
    type: Number, 
    default: 0,
    min: 0
  },
  commission: {
    type: Number,
    default: 0,
    min: 0
  },
  agentProfit: {
    type: Number,
    default: 0,
    min: 0
  },
  totalEarnings: {
    type: Number,
    default: 0,
    min: 0
  },
  creditLimit: {
    type: Number,
    default: 0,
    min: 0
  },
  
  // Authentication
  googleId: { 
    type: String, 
    sparse: true, 
    unique: true 
  },
  profilePicture: { 
    type: String 
  },
  authProvider: { 
    type: String, 
    enum: ["email", "google"], 
    default: "email" 
  },
  
  // Security
  resetPasswordOTP: { 
    type: String, 
    select: false 
  },
  resetPasswordOTPExpiry: { 
    type: Date, 
    select: false 
  },
  lastPasswordReset: { 
    type: Date 
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  phoneVerified: {
    type: Boolean,
    default: false
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  
  // Account Status
  isDisabled: { 
    type: Boolean, 
    default: false 
  },
  disableReason: { 
    type: String 
  },
  disabledAt: { 
    type: Date 
  },
  
  // Approval System
  approvalStatus: { 
    type: String, 
    enum: ["pending", "approved", "rejected"], 
    default: "pending" 
  },
  approvedBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: "Usermodal" 
  },
  approvedAt: { 
    type: Date 
  },
  rejectionReason: { 
    type: String 
  },
  
  // Device and Login Management
  lastLogin: {
    deviceId: { type: String },
    ipAddress: { type: String },
    userAgent: { type: String },
    timestamp: { type: Date }
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  
  // API Access
  apiAccess: {
    enabled: { type: Boolean, default: false },
    tier: { type: String, enum: ["basic", "premium", "enterprise"], default: "basic" },
    rateLimit: { type: Number, default: 100 }
  },
  
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
UserSchema.index({ email: 1, username: 1 });
UserSchema.index({ role: 1, approvalStatus: 1 });
UserSchema.index({ parentAgent: 1 });
UserSchema.index({ googleId: 1 });

// Virtual for agent store
UserSchema.virtual('agentStore', {
  ref: 'AgentStore',
  localField: '_id',
  foreignField: 'agent',
  justOne: true
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Method to check password
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// ==================== AGENT STORE SCHEMA ====================
const AgentStoreSchema = new mongoose.Schema({
  agent: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Usermodal",
    required: true,
    unique: true
  },
  storeName: {
    type: String,
    required: true,
    trim: true
  },
  subdomain: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    match: /^[a-z0-9-]+$/
  },
  description: {
    type: String,
    maxlength: 500
  },
  logo: {
    type: String,
    default: null
  },
  bannerImage: {
    type: String,
    default: null
  },
  
  // Contact Information
  whatsappNumber: {
    type: String,
    required: true,
    match: /^(\+233|0)[2-9]\d{8}$/
  },
  whatsappGroupLink: {
    type: String,
    match: /^https:\/\/chat\.whatsapp\.com\/[A-Za-z0-9]+$/
  },
  contactEmail: {
    type: String,
    match: /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/
  },
  alternativePhone: {
    type: String,
    match: /^(\+233|0)[2-9]\d{8}$/
  },
  
  // Social Media
  socialMedia: {
    facebook: String,
    twitter: String,
    instagram: String,
    telegram: String,
    tiktok: String
  },
  
  // Business Information
  businessHours: {
    monday: { open: String, close: String, isClosed: { type: Boolean, default: false } },
    tuesday: { open: String, close: String, isClosed: { type: Boolean, default: false } },
    wednesday: { open: String, close: String, isClosed: { type: Boolean, default: false } },
    thursday: { open: String, close: String, isClosed: { type: Boolean, default: false } },
    friday: { open: String, close: String, isClosed: { type: Boolean, default: false } },
    saturday: { open: String, close: String, isClosed: { type: Boolean, default: false } },
    sunday: { open: String, close: String, isClosed: { type: Boolean, default: false } }
  },
  location: {
    address: String,
    city: String,
    region: String,
    gpsCoordinates: {
      latitude: Number,
      longitude: Number
    }
  },
  
  // Custom Pricing - Agent sets their own prices above system price to earn profit
  customPricing: [{
    network: { type: String, enum: ["MTN", "TELECEL", "AT_PREMIUM", "AIRTELTIGO", "AT", "YELLO"], required: true },
    capacity: { type: Number, required: true }, // Always in GB
    systemPrice: { type: Number, required: true }, // From DataPricing based on agent's role
    agentPrice: { type: Number, required: true }, // Agent's selling price (must be >= systemPrice)
    profit: { type: Number }, // agentPrice - systemPrice
    isActive: { type: Boolean, default: true }
  }],
  
  // Payment Configuration (All payments through Paystack)
  paymentConfig: {
    acceptPayments: { type: Boolean, default: true },
    paystackSubaccountCode: String, // For split payments if needed
    instantPayout: { type: Boolean, default: false }
  },
  
  // Store Settings
  settings: {
    autoReplyEnabled: { type: Boolean, default: false },
    autoReplyMessage: String,
    welcomeMessage: String,
    minimumOrder: { type: Number, default: 0 },
    allowBulkOrders: { type: Boolean, default: true },
    bulkOrderDiscount: { type: Number, default: 0 }, // Percentage
    showPrices: { type: Boolean, default: true },
    requireRegistration: { type: Boolean, default: false },
    maintenanceMode: { type: Boolean, default: false },
    maintenanceMessage: { type: String, default: "Store is temporarily closed. Please check back later." }
  },
  
  // Store Operating Status
  operatingStatus: {
    isOpen: { type: Boolean, default: true }, // Agent can close/open store
    closedReason: String,
    closedAt: Date,
    reopenAt: Date, // Scheduled reopen time
    temporarilyClosed: { type: Boolean, default: false }
  },
  
  // Statistics
  statistics: {
    totalSales: { type: Number, default: 0 },
    totalOrders: { type: Number, default: 0 },
    totalCustomers: { type: Number, default: 0 },
    totalRevenue: { type: Number, default: 0 },
    totalProfit: { type: Number, default: 0 }, // Total profit earned from price markup
    todayProfit: { type: Number, default: 0 },
    weekProfit: { type: Number, default: 0 },
    monthProfit: { type: Number, default: 0 },
    rating: { type: Number, default: 0, min: 0, max: 5 },
    reviewCount: { type: Number, default: 0 },
    lastSaleDate: Date
  },
  
  // Store Status
  isActive: {
    type: Boolean,
    default: true
  },
  isPremium: {
    type: Boolean,
    default: false
  },
  verificationStatus: {
    type: String,
    enum: ["pending", "verified", "rejected"],
    default: "pending"
  },
  verifiedAt: Date,
  verifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Usermodal"
  }
}, {
  timestamps: true
});

AgentStoreSchema.index({ subdomain: 1 });
AgentStoreSchema.index({ agent: 1 });
AgentStoreSchema.index({ isActive: 1, verificationStatus: 1 });

// Pre-save hook to validate agent pricing
AgentStoreSchema.pre('save', function(next) {
  // Ensure agent prices are >= system prices
  if (this.customPricing && this.customPricing.length > 0) {
    this.customPricing.forEach(price => {
      if (price.agentPrice < price.systemPrice) {
        return next(new Error(`Agent price (${price.agentPrice}) cannot be less than system price (${price.systemPrice})`));
      }
      // Calculate profit
      price.profit = price.agentPrice - price.systemPrice;
    });
  }
  next();
});

// ==================== DATA INVENTORY SCHEMA ====================
const DataInventorySchema = new mongoose.Schema({
  network: { 
    type: String, 
    enum: ["YELLO", "MTN", "TELECEL", "AT_PREMIUM", "AIRTELTIGO", "AT"], 
    required: true,
    unique: true 
  },
  
  webInStock: { 
    type: Boolean, 
    default: true 
  },
  apiInStock: { 
    type: Boolean, 
    default: true 
  },
  inStock: { 
    type: Boolean, 
    default: true 
  },
  
  updatedAt: { 
    type: Date, 
    default: Date.now 
  },
  
  webLastUpdatedBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: "Usermodal" 
  },
  webLastUpdatedAt: { 
    type: Date 
  },
  apiLastUpdatedBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: "Usermodal" 
  },
  apiLastUpdatedAt: { 
    type: Date 
  }
});

DataInventorySchema.index({ network: 1 });
DataInventorySchema.index({ webInStock: 1 });
DataInventorySchema.index({ apiInStock: 1 });

// ==================== DATA PRICING SCHEMA ====================
// Admin sets prices based on network and user role
const DataPricingSchema = new mongoose.Schema({
  network: {
    type: String,
    required: true,
    enum: ["YELLO", "MTN", "TELECEL", "AT_PREMIUM", "AIRTELTIGO", "AT"]
  },
  capacity: {
    type: Number,
    required: true // Always in GB
  },
  description: String,
  
  // Admin enters different prices for each role
  prices: {
    adminCost: { type: Number, required: true }, // What admin pays
    dealer: { type: Number, required: true }, // Price for dealers
    superAgent: { type: Number, required: true }, // Price for super agents  
    agent: { type: Number, required: true }, // Price for agents (minimum they can sell for)
    user: { type: Number, required: true } // Price for direct users
  },

  // Stock Management - Each capacity can be individually marked as out of stock
  stock: {
    webInStock: { 
      type: Boolean, 
      default: true 
    },
    apiInStock: { 
      type: Boolean, 
      default: true 
    },
    overallInStock: { 
      type: Boolean, 
      default: true 
    }
  },
  
  // Optional promotional pricing
  promoPrice: {
    type: Number,
    default: null
  },
  promoStartDate: Date,
  promoEndDate: Date,
  
  isActive: {
    type: Boolean,
    default: true
  },
  isPopular: {
    type: Boolean,
    default: false
  },
  
  tags: [String],
  
  lastUpdatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Usermodal"
  },
  stockLastUpdatedAt: {
    type: Date
  },
  stockLastUpdatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Usermodal"
  }
}, {
  timestamps: true
});

// Create unique compound index for network + capacity
DataPricingSchema.index({ network: 1, capacity: 1 }, { unique: true });
DataPricingSchema.index({ isActive: 1 });
DataPricingSchema.index({ 'stock.overallInStock': 1 });
DataPricingSchema.index({ 'stock.webInStock': 1, 'stock.apiInStock': 1 });

// ==================== DATA PURCHASE SCHEMA ====================
const DataPurchaseSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: "Usermodal", 
    required: false 
  },
  agentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Usermodal",
    default: null // If purchased through an agent store
  },
  phoneNumber: { 
    type: String, 
    required: true,
    match: /^(\+233|0)[2-9]\d{8}$/
  },
  network: { 
    type: String, 
    enum: ["YELLO", "MTN", "TELECEL", "AT_PREMIUM", "AIRTELTIGO", "AT"], 
    required: true 
  },
  capacity: { 
    type: Number, 
    required: true // Always in GB
  },
  gateway: { 
    type: String, 
    required: true,
    enum: ["paystack", "wallet", "admin", "manual", "system","bulk_web"]
  },
  method: { 
    type: String, 
    enum: ["web", "api", "agent_store", "admin", "bulk_web"], 
    required: true 
  },
  price: { 
    type: Number, 
    required: true 
  },
  
  // Pricing Details for Agent Profit Tracking
  pricing: {
    systemPrice: { type: Number, required: true }, // Price based on user's role from DataPricing
    agentPrice: { type: Number }, // Price set by agent (if through agent store)
    customerPrice: { type: Number, required: true }, // Final price paid by customer
    agentProfit: { type: Number, default: 0 }, // Profit earned by agent (agentPrice - systemPrice)
  },
  
  // Reference Numbers
  reference: { 
    type: String, 
    required: true,
    unique: true
  },
  paystackReference: String,
  
  status: { 
    type: String, 
    enum: ["pending", "completed", "failed", "processing", "refunded", "refund", "delivered", "on", "waiting", "accepted"], 
    default: "pending" 
  },
  processing: { 
    type: Boolean, 
    default: false 
  },
    whatsappAlertSent: {
    type: Boolean,
    default: false
  },
  whatsappAlertAt: {
    type: Date
  },
  whatsappAlertId: {
    type: String
  },
  
  
  // Admin Management
  adminNotes: { 
    type: String 
  },
  updatedBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: "Usermodal" 
  },
  updatedAt: { 
    type: Date 
  },
  
  // Store Information (if purchased through agent store)
  storeInfo: {
    storeId: { type: mongoose.Schema.Types.ObjectId, ref: "AgentStore" },
    storeName: String,
    subdomain: String
  },
  
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
}, {
  timestamps: true
});

DataPurchaseSchema.index({ userId: 1, createdAt: -1 });
DataPurchaseSchema.index({ phoneNumber: 1 });
DataPurchaseSchema.index({ status: 1 });
DataPurchaseSchema.index({ agentId: 1 });
DataPurchaseSchema.index({ reference: 1 });

// ==================== TRANSACTION SCHEMA ====================
const TransactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Usermodal',
    required: true
  },
  type: {
    type: String,
    enum: ['deposit', 'withdrawal', 'transfer', 'refund', 'purchase', 'commission', 'agent_profit', 'admin_credit', 'admin_debit', 'wallet-refund', 'admin-deduction', 'momo','bulk_purchase'],
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  balanceBefore: {
    type: Number,
    required: true,
    default: 0
  },
  balanceAfter: {
    type: Number,
    required: true,
    default: 0
  },
  
  // Agent Profit Tracking
  profitDetails: {
    systemPrice: Number,
    sellingPrice: Number,
    profit: Number,
    relatedPurchase: { type: mongoose.Schema.Types.ObjectId, ref: 'DataPurchase' }
  },
  
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'cancelled', 'processing', 'accepted'],
    default: 'pending'
  },
  reference: {
    type: String,
    required: true,
    unique: true
  },
  gateway: {
    type: String,
    enum: ['paystack', 'manual', 'system', 'wallet', 'admin-deposit', 'wallet-refund', 'admin-deduction', 'momo'],
    default: 'paystack'
  },
  processing: {
    type: Boolean,
    default: false
  },
  description: {
    type: String
  },
  relatedPurchaseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'DataPurchase',
    default: null
  },
  metadata: mongoose.Schema.Types.Mixed,
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

TransactionSchema.index({ userId: 1, createdAt: -1 });
TransactionSchema.index({ reference: 1 });
TransactionSchema.index({ status: 1, type: 1 });

// ==================== RESULT CHECKER SCHEMA ====================
const ResultCheckerSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: ['BECE', 'WASSCE'] // Only BECE and WASSCE
  },
  year: {
    type: Number,
    required: true
  },
  examType: {
    type: String,
    enum: ['MAY/JUNE', 'NOV/DEC', 'PRIVATE'],
    default: 'MAY/JUNE'
  },
  serialNumber: {
    type: String,
    required: true,
    unique: true,
    uppercase: true
  },
  pin: {
    type: String,
    required: true
  },
  scratchCard: {
    type: String,
    unique: true,
    sparse: true
  },
  status: {
    type: String,
    enum: ['available', 'sold', 'used', 'expired', 'reserved'],
    default: 'available'
  },
  price: {
    type: Number,
    required: true
  },
  soldTo: {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "Usermodal" },
    phoneNumber: String,
    email: String,
    name: String,
    soldAt: Date,
    soldBy: { type: mongoose.Schema.Types.ObjectId, ref: "Usermodal" },
    soldPrice: Number
  },
  usageInfo: {
    usageCount: { type: Number, default: 0, max: 5 },
    firstUsed: Date,
    lastUsed: Date,
    usedBy: [{
      phoneNumber: String,
      timestamp: Date
    }]
  },
  validity: {
    activationDate: Date,
    expiryDate: Date,
    isActive: { type: Boolean, default: true }
  },
  batchInfo: {
    batchNumber: String,
    batchDate: Date,
    supplier: String,
    totalInBatch: Number
  },
  addedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Usermodal",
    required: true
  },
  lastModifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Usermodal"
  }
}, {
  timestamps: true
});

ResultCheckerSchema.index({ type: 1, year: 1, status: 1 });
ResultCheckerSchema.index({ serialNumber: 1 });
ResultCheckerSchema.index({ pin: 1 });

// ==================== API KEY SCHEMA ====================
const ApiKeySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Usermodal',
    required: true
  },
  key: {
    type: String, 
    required: true,
    unique: true
  },
  name: {
    type: String,
    required: true
  },
  description: String,
  permissions: [{
    type: String,
    enum: ['read:products', 'write:purchases', 'read:transactions', 'read:balance', 'write:transfers', 'read:all', 'write:all']
  }],
  ipWhitelist: [String],
  rateLimit: {
    requests: { type: Number, default: 100 },
    period: { type: String, default: '1m' }
  },
  webhooks: {
    url: String,
    secret: String,
    events: [String]
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastUsed: {
    type: Date,
    default: null
  },
  usageStats: {
    totalRequests: { type: Number, default: 0 },
    successfulRequests: { type: Number, default: 0 },
    failedRequests: { type: Number, default: 0 }
  },
  expiresAt: {
    type: Date,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

ApiKeySchema.index({ key: 1 });
ApiKeySchema.index({ userId: 1 });

// ==================== NOTIFICATION SCHEMA ====================
const NotificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "UUsermodalser",
    required: function() { return !this.isGlobal; }
  },
  isGlobal: {
    type: Boolean,
    default: false
  },
  title: {
    type: String,
    required: true
  },
  message: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['info', 'success', 'warning', 'error', 'promotion', 'system'],
    default: 'info'
  },
  category: {
    type: String,
    enum: ['transaction', 'system', 'promotion', 'account', 'purchase', 'security'],
    default: 'system'
  },
  priority: {
    type: String,
    enum: ['low', 'normal', 'high', 'urgent'],
    default: 'normal'
  },
  read: {
    type: Boolean,
    default: false
  },
  readAt: Date,
  actionUrl: String,
  metadata: mongoose.Schema.Types.Mixed,
  expiresAt: Date
}, {
  timestamps: true
});

NotificationSchema.index({ userId: 1, read: 1 });
NotificationSchema.index({ isGlobal: 1 });
NotificationSchema.index({ createdAt: -1 });

// ==================== AGENT PROFIT SCHEMA ====================
const AgentProfitSchema = new mongoose.Schema({
  agentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Usermodal",
    required: true
  },
  purchaseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "DataPurchase",
    required: true
  },
  customerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Usermodal",
    required: false
  },
  network: {
    type: String,
    required: true
  },
  capacity: {
    type: Number,
    required: true // Always in GB
  },
  systemPrice: {
    type: Number,
    required: true
  },
  agentPrice: {
    type: Number,
    required: true
  },
  profit: {
    type: Number,
    required: true // agentPrice - systemPrice
  },
  profitPercentage: {
    type: Number // (profit/systemPrice) * 100
  },
  status: {
    type: String,
    enum: ['pending', 'credited', 'withdrawn', 'reversed'],
    default: 'pending'
  },
  creditedAt: Date,
  withdrawnAt: Date,
  withdrawalReference: String,
  notes: String
}, {
  timestamps: true
});

AgentProfitSchema.index({ agentId: 1, createdAt: -1 });
AgentProfitSchema.index({ purchaseId: 1 });
AgentProfitSchema.index({ status: 1 });

// ==================== EXPORT MODELS ====================
const User = mongoose.model("Usermodal", UserSchema);
const AgentStore = mongoose.model("AgentStore", AgentStoreSchema);
const DataInventory = mongoose.model("DataInventory", DataInventorySchema);
const DataPricing = mongoose.model("DataPricing", DataPricingSchema);
const DataPurchase = mongoose.model("DataPurchase", DataPurchaseSchema);
const Transaction = mongoose.model("Transaction", TransactionSchema);
const ResultChecker = mongoose.model("ResultChecker", ResultCheckerSchema);
const ApiKey = mongoose.model("ApiKey", ApiKeySchema);
const Notification = mongoose.model("Notification", NotificationSchema);
const AgentProfit = mongoose.model("AgentProfit", AgentProfitSchema);

module.exports = {
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
};