// ==================== telecelservice/telecel_service.js ====================
const axios = require('axios'); // REQUIRED IMPORT
const TelecelAuthService = require('../routes/telecelauth/auth');
const TelecelToken = require('../routes/telecel_Schema/schema');

class TelecelService {
  constructor() {
    this.baseURL = 'https://play.telecel.com.gh';
    this.authService = new TelecelAuthService();
    this.subscriberMsisdn = '233509240147';
  }

  // Get token with automatic error handling
  async getAuthToken() {
    try {
      // Try to get active token from TelecelAuthService
      return await this.authService.getActiveToken();
    } catch (error) {
      console.error('[TELECEL] Token error:', error.message);
      
      // Check if we have any token in database (even expired)
      try {
        const anyToken = await TelecelToken.findOne().sort({ createdAt: -1 });
        if (anyToken && anyToken.token) {
          console.log('[TELECEL] Using last known token (may be expired)');
          return anyToken.token;
        }
      } catch (dbError) {
        console.error('[TELECEL] Database error:', dbError.message);
      }
      
      // For development/testing, use mock token
      if (process.env.NODE_ENV === 'development' || process.env.USE_MOCK_TELECEL === 'true') {
        console.log('[TELECEL] Using mock token for development');
        return 'mock_development_token';
      }
      
      // In production, throw error to stop purchase
      throw new Error('Authentication token expired. Please contact admin to refresh token.');
    }
  }

  // Main method to send data bundle
  async sendDataBundle(phoneNumber, capacity) {
    try {
      // Get active token
      const authToken = await this.getAuthToken();
      
      const formattedPhone = this.formatPhoneNumber(phoneNumber);
      const bundlePlan = this.getBundlePlan(capacity);
      const transactionId = this.generateTransactionId();

      console.log(`[TELECEL] Processing bundle request:`);
      console.log(`[TELECEL] - Phone: ${formattedPhone}`);
      console.log(`[TELECEL] - Capacity: ${capacity}GB`);
      console.log(`[TELECEL] - Plan: ${bundlePlan}`);
      console.log(`[TELECEL] - Transaction ID: ${transactionId}`);
      console.log(`[TELECEL] - Token: ${authToken ? 'Present' : 'Missing'}`);

      const requestData = {
        beneficiaryMsisdn: formattedPhone,
        volume: capacity.toString(),
        plan: bundlePlan,
        transactionId: transactionId,
        subscriberMsisdn: this.subscriberMsisdn,
        beneficiaryName: formattedPhone
      };

      // MOCK MODE CHECK - For development/testing
      if (authToken === 'mock_development_token' || authToken.startsWith('mock_')) {
        console.log('[TELECEL] Running in MOCK MODE - simulating successful delivery');
        
        // Simulate processing delay
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        return {
          success: true,
          transactionId: transactionId,
          data: { 
            mock: true,
            status: 'success',
            message: 'Mock delivery successful'
          },
          message: `[MOCK] Successfully sent ${capacity}GB to ${formattedPhone}`
        };
      }

      // PRODUCTION API CALL
      console.log('[TELECEL] Making API request to Telecel...');
      
      const response = await axios.post(
        `${this.baseURL}/enterprise-request/api/data-sharer/prepaid/add-beneficiary`,
        requestData,
        {
          headers: {
            'Authorization': `Bearer ${authToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Origin': this.baseURL,
            'Referer': `${this.baseURL}/enterprise-request/app/bundle-sharer/beneficiaries/`
          },
          timeout: 30000 // 30 seconds timeout
        }
      );

      console.log('[TELECEL] API Response received:', response.status);
      console.log('[TELECEL] Bundle sent successfully');

      return {
        success: true,
        transactionId: transactionId,
        data: response.data,
        message: `Successfully sent ${capacity}GB to ${formattedPhone}`,
        apiResponse: response.data
      };

    } catch (error) {
      console.error('[TELECEL] Error sending bundle:', error.message);
      
      // Handle 401 Unauthorized - Token expired
      if (error.response?.status === 401) {
        console.error('[TELECEL] 401 Unauthorized - Token expired');
        
        // Mark token as expired in database
        try {
          await TelecelToken.updateMany(
            { isActive: true },
            { 
              $set: { 
                isActive: false,
                'lastError.message': 'Token expired - 401 response',
                'lastError.occurredAt': new Date()
              }
            }
          );
          console.log('[TELECEL] Token marked as expired in database');
        } catch (dbError) {
          console.error('[TELECEL] Could not update token status:', dbError.message);
        }

        return {
          success: false,
          error: 'Authentication failed - token expired. Admin has been notified.',
          requiresNewToken: true,
          statusCode: 401
        };
      }

      // Handle 400 Bad Request - Insufficient balance or invalid request
      if (error.response?.status === 400) {
        console.error('[TELECEL] 400 Bad Request:', error.response.data);
        return {
          success: false,
          error: 'Insufficient balance or invalid request',
          details: error.response.data,
          statusCode: 400
        };
      }

      // Handle timeout
      if (error.code === 'ECONNABORTED') {
        console.error('[TELECEL] Request timeout');
        return {
          success: false,
          error: 'Request timeout - Telecel API is not responding',
          statusCode: 408
        };
      }

      // Handle network errors
      if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
        console.error('[TELECEL] Network error:', error.code);
        return {
          success: false,
          error: 'Cannot connect to Telecel API - Network error',
          statusCode: 503
        };
      }

      // Generic error
      return {
        success: false,
        error: error.message || 'Failed to send data bundle',
        details: error.response?.data,
        statusCode: error.response?.status || 500
      };
    }
  }

  // Generate unique transaction ID
  generateTransactionId() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 7).toUpperCase();
    return `ERP${random}${timestamp}`;
  }

  // Format phone number for Telecel API
  formatPhoneNumber(phoneNumber) {
    // Remove all non-numeric characters
    let cleaned = phoneNumber.replace(/\D/g, '');
    
    // Convert international format to local
    if (cleaned.startsWith('233')) {
      cleaned = '0' + cleaned.substring(3);
    } 
    // Add leading 0 if missing
    else if (!cleaned.startsWith('0')) {
      cleaned = '0' + cleaned;
    }
    
    // Validate format
    if (!/^0[2-9]\d{8}$/.test(cleaned)) {
      console.warn(`[TELECEL] Invalid phone number format: ${phoneNumber} -> ${cleaned}`);
    }
    
    return cleaned;
  }

  // Get bundle plan name based on capacity
  getBundlePlan(capacity) {
    // For now, always return 5500GB plan
    // In future, this could map different capacities to different plans
    return 'Bundle Sharer 5500GB';
    
    /* Future implementation example:
    const capacityNum = parseFloat(capacity);
    if (capacityNum <= 10) return 'Bundle Sharer 100GB';
    if (capacityNum <= 100) return 'Bundle Sharer 1000GB';
    return 'Bundle Sharer 5500GB';
    */
  }

  // Check if service is in mock mode
  isMockMode() {
    return process.env.NODE_ENV === 'development' || 
           process.env.USE_MOCK_TELECEL === 'true';
  }

  // Validate request before sending
  validateRequest(phoneNumber, capacity) {
    const errors = [];
    
    // Validate phone number
    const cleaned = phoneNumber.replace(/\D/g, '');
    if (!cleaned || cleaned.length < 9) {
      errors.push('Invalid phone number');
    }
    
    // Validate capacity
    const capacityNum = parseFloat(capacity);
    if (isNaN(capacityNum) || capacityNum <= 0 || capacityNum > 5500) {
      errors.push('Invalid capacity (must be between 0.1 and 5500 GB)');
    }
    
    return {
      valid: errors.length === 0,
      errors
    };
  }

  // Get service status
  async getServiceStatus() {
    try {
      const tokenStatus = await this.authService.checkTokenStatus();
      
      return {
        service: 'TELECEL',
        status: tokenStatus.status === 'active' ? 'operational' : 'degraded',
        mockMode: this.isMockMode(),
        tokenStatus: tokenStatus,
        subscriberMsisdn: this.subscriberMsisdn,
        baseURL: this.baseURL
      };
    } catch (error) {
      return {
        service: 'TELECEL',
        status: 'error',
        mockMode: this.isMockMode(),
        error: error.message
      };
    }
  }
}

// REQUIRED EXPORT - Export the class
module.exports = TelecelService;

/* Alternative singleton pattern (if preferred):
const telecelService = new TelecelService();
module.exports = telecelService;
*/