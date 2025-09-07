// ==================== routes/telecelauth/auth.js ====================
const axios = require('axios');
const TelecelToken = require('../telecel_Schema/schema');

class TelecelAuthService {
  constructor() {
    this.baseURL = 'https://play.telecel.com.gh';
    this.credentials = {
      email: process.env.TELECEL_EMAIL || 'ctefutor@metropolitangh.com',
      password: process.env.TELECEL_PASSWORD || '$P@ssw0rd@life',
      phoneNumber: process.env.TELECEL_PHONE || '0592404147'
    };
  }

  // Get current active token
  async getActiveToken() {
    const token = await TelecelToken.findOne({
      isActive: true,
      expiresAt: { $gt: new Date() }
    }).sort({ createdAt: -1 });

    if (!token) {
      throw new Error('No active token found. Admin needs to refresh token.');
    }

    // Check if token expires in next 2 hours and send warning
    const twoHoursFromNow = new Date(Date.now() + 2 * 60 * 60 * 1000);
    if (token.expiresAt < twoHoursFromNow) {
      console.warn('[TELECEL AUTH] Token expiring soon:', token.expiresAt);
      // You can trigger notification to admin here
    }

    return token.token;
  }

  // Step 1: Request OTP
  async requestOTP() {
    try {
      console.log('[TELECEL AUTH] Requesting OTP...');
      
      const response = await axios.post(
        `${this.baseURL}/enterprise-request/api/check-login`,
        {
          email: this.credentials.email,
          password: this.credentials.password,
          sms_code: "", // Empty initially
          phone_number: this.maskPhoneNumber(this.credentials.phoneNumber)
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
          },
          timeout: 30000
        }
      );

      // Update OTP status in database
      await TelecelToken.updateMany(
        { isActive: true },
        { 
          $set: { 
            'otpStatus.lastOtpSent': new Date(),
            'otpStatus.waitingForOtp': true
          }
        }
      );

      console.log('[TELECEL AUTH] OTP requested successfully');
      return {
        success: true,
        message: 'OTP sent to registered phone number'
      };

    } catch (error) {
      console.error('[TELECEL AUTH] Error requesting OTP:', error.message);
      throw error;
    }
  }

  // Step 2: Login with OTP
  async loginWithOTP(otpCode) {
    try {
      console.log('[TELECEL AUTH] Logging in with OTP...');
      
      const response = await axios.post(
        `${this.baseURL}/enterprise-request/api/login`,
        {
          email: this.credentials.email,
          password: this.credentials.password,
          sms_code: otpCode,
          phone_number: this.maskPhoneNumber(this.credentials.phoneNumber)
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
          },
          timeout: 30000
        }
      );

      if (response.data && response.data.token) {
        // Deactivate old tokens
        await TelecelToken.updateMany(
          { isActive: true },
          { $set: { isActive: false } }
        );

        // Calculate expiry (12 hours from now, adjust as needed)
        const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000);

        // Save new token
        const newToken = new TelecelToken({
          token: response.data.token,
          email: this.credentials.email,
          phoneNumber: this.credentials.phoneNumber,
          subscriberMsisdn: response.data.subscriberMsisdn || '233509240147',
          isActive: true,
          expiresAt: expiresAt,
          otpStatus: {
            lastOtpUsed: otpCode,
            waitingForOtp: false
          }
        });

        await newToken.save();

        console.log('[TELECEL AUTH] Login successful, token saved');
        return {
          success: true,
          token: response.data.token,
          expiresAt: expiresAt
        };
      }

      throw new Error('No token received from login response');

    } catch (error) {
      console.error('[TELECEL AUTH] Login error:', error.message);
      
      // Log error in database
      try {
        await TelecelToken.updateMany(
          { isActive: true },
          { 
            $set: { 
              'lastError.message': error.message,
              'lastError.occurredAt': new Date(),
              'otpStatus.waitingForOtp': false
            }
          }
        );
      } catch (dbError) {
        console.log('[TELECEL AUTH] Could not update error in DB:', dbError.message);
      }

      throw error;
    }
  }

  // Helper to mask phone number
  maskPhoneNumber(phone) {
    // Format: "059******4"
    if (phone.startsWith('0')) {
      return phone.substring(0, 3) + '******' + phone.substring(9);
    }
    return phone;
  }

  // Check token status
  async checkTokenStatus() {
    try {
      const activeToken = await TelecelToken.findOne({
        isActive: true
      }).sort({ createdAt: -1 });

      if (!activeToken) {
        return {
          status: 'no_token',
          message: 'No token configured',
          needsRefresh: true
        };
      }

      const now = new Date();
      
      if (!activeToken.expiresAt || activeToken.expiresAt < now) {
        return {
          status: 'expired',
          message: 'Token has expired',
          expiredAt: activeToken.expiresAt,
          needsRefresh: true
        };
      }

      const hoursRemaining = Math.floor((activeToken.expiresAt - now) / (1000 * 60 * 60));
      
      return {
        status: 'active',
        expiresAt: activeToken.expiresAt,
        hoursRemaining: hoursRemaining,
        needsRefresh: hoursRemaining < 2
      };
    } catch (error) {
      console.error('[TELECEL AUTH] Error checking token status:', error);
      // Return a default status if database error
      return {
        status: 'no_token',
        message: 'Could not check token status',
        needsRefresh: true
      };
    }
  }
}

// Export the class so it can be imported elsewhere
module.exports = TelecelAuthService;