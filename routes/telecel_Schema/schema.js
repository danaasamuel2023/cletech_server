// ==================== routes/telecel_Schema/schema.js ====================
const mongoose = require('mongoose');

const TelecelTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    default: 'ctefutor@metropolitangh.com'
  },
  phoneNumber: {
    type: String,
    required: true,
    default: '0592404147'
  },
  subscriberMsisdn: {
    type: String,
    required: true,
    default: '233509240147'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  expiresAt: {
    type: Date,
    required: true
  },
  lastRefreshedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Usermodal'
  },
  refreshCount: {
    type: Number,
    default: 0
  },
  lastError: {
    message: String,
    occurredAt: Date
  },
  otpStatus: {
    lastOtpSent: Date,
    lastOtpUsed: String,
    waitingForOtp: { type: Boolean, default: false }
  }
}, {
  timestamps: true
});

// Index for quick active token lookup
TelecelTokenSchema.index({ isActive: 1, expiresAt: 1 });

const TelecelToken = mongoose.model('TelecelToken', TelecelTokenSchema);

// THIS WAS MISSING! - Export the model so it can be imported elsewhere
module.exports = TelecelToken;