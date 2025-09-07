// ==================== telecelservice/telecel_service.js ====================
// PRODUCTION VERSION - REAL API ONLY - NO SIMULATION
const axios = require('axios');
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
      // Get active token from TelecelAuthService
      return await this.authService.getActiveToken();
    } catch (error) {
      console.error('[TELECEL] Token error:', error.message);
      
      // Check if we have any token in database (even expired)
      try {
        const anyToken = await TelecelToken.findOne().sort({ createdAt: -1 });
        if (anyToken && anyToken.token) {
          console.log('[TELECEL] WARNING: Using potentially expired token from database');
          return anyToken.token;
        }
      } catch (dbError) {
        console.error('[TELECEL] Database error:', dbError.message);
      }
      
      // No token available - throw error
      throw new Error('Authentication token not available. Please contact admin to generate a new token.');
    }
  }

  // Main method to send data bundle - REAL API ONLY
  async sendDataBundle(phoneNumber, capacity) {
    try {
      // Validate request first
      const validation = this.validateRequest(phoneNumber, capacity);
      if (!validation.valid) {
        throw new Error(`Validation failed: ${validation.errors.join(', ')}`);
      }

      // Get active token
      const authToken = await this.getAuthToken();
      
      if (!authToken) {
        throw new Error('No authentication token available');
      }
      
      const formattedPhone = this.formatPhoneNumber(phoneNumber);
      const bundlePlan = this.getBundlePlan(capacity);
      const transactionId = this.generateTransactionId();

      console.log(`[TELECEL] Processing REAL bundle request:`);
      console.log(`[TELECEL] - Phone: ${formattedPhone}`);
      console.log(`[TELECEL] - Capacity: ${capacity}GB`);
      console.log(`[TELECEL] - Plan: ${bundlePlan}`);
      console.log(`[TELECEL] - Transaction ID: ${transactionId}`);
      console.log(`[TELECEL] - Token Status: ${authToken ? 'Active' : 'Missing'}`);

      const requestData = {
        beneficiaryMsisdn: formattedPhone,
        volume: capacity.toString(),
        plan: bundlePlan,
        transactionId: transactionId,
        subscriberMsisdn: this.subscriberMsisdn,
        beneficiaryName: formattedPhone
      };

      // REAL API CALL TO TELECEL
      console.log('[TELECEL] Making LIVE API request to Telecel...');
      
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
          timeout: 30000, // 30 seconds timeout
          validateStatus: function (status) {
            return status >= 200 && status < 500; // Don't throw on 4xx errors
          }
        }
      );

      // Check response status
      if (response.status === 200 || response.status === 201) {
        console.log('[TELECEL] ✅ Bundle sent successfully');
        console.log('[TELECEL] API Response:', JSON.stringify(response.data));

        return {
          success: true,
          transactionId: transactionId,
          data: response.data,
          message: `Successfully sent ${capacity}GB to ${formattedPhone}`,
          apiResponse: response.data,
          statusCode: response.status
        };
      }

      // Handle specific error responses
      if (response.status === 401) {
        console.error('[TELECEL] ❌ 401 Unauthorized - Token expired or invalid');
        
        // Mark token as expired in database
        try {
          await TelecelToken.updateMany(
            { isActive: true },
            { 
              $set: { 
                isActive: false,
                'lastError.message': 'Token expired - 401 Unauthorized',
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
          error: 'Authentication failed - token expired. Admin needs to refresh the token.',
          requiresNewToken: true,
          statusCode: 401
        };
      }

      if (response.status === 400) {
        console.error('[TELECEL] ❌ 400 Bad Request:', response.data);
        return {
          success: false,
          error: response.data?.message || 'Invalid request or insufficient balance',
          details: response.data,
          statusCode: 400
        };
      }

      if (response.status === 403) {
        console.error('[TELECEL] ❌ 403 Forbidden:', response.data);
        return {
          success: false,
          error: 'Access forbidden - check account permissions',
          details: response.data,
          statusCode: 403
        };
      }

      // Any other non-success status
      console.error(`[TELECEL] ❌ Unexpected status ${response.status}:`, response.data);
      return {
        success: false,
        error: `Request failed with status ${response.status}`,
        details: response.data,
        statusCode: response.status
      };

    } catch (error) {
      console.error('[TELECEL] ❌ Critical error:', error.message);
      
      // Handle timeout
      if (error.code === 'ECONNABORTED') {
        console.error('[TELECEL] Request timeout after 30 seconds');
        return {
          success: false,
          error: 'Request timeout - Telecel API is not responding',
          statusCode: 408
        };
      }

      // Handle network errors
      if (error.code === 'ENOTFOUND') {
        console.error('[TELECEL] Network error - cannot find host');
        return {
          success: false,
          error: 'Cannot reach Telecel API - DNS resolution failed',
          statusCode: 503
        };
      }

      if (error.code === 'ECONNREFUSED') {
        console.error('[TELECEL] Connection refused by Telecel API');
        return {
          success: false,
          error: 'Connection refused by Telecel API',
          statusCode: 503
        };
      }

      // Handle validation errors
      if (error.message.includes('Validation failed')) {
        return {
          success: false,
          error: error.message,
          statusCode: 400
        };
      }

      // Handle token errors
      if (error.message.includes('token')) {
        return {
          success: false,
          error: error.message,
          requiresNewToken: true,
          statusCode: 401
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
      throw new Error(`Invalid phone number format: ${phoneNumber}`);
    }
    
    return cleaned;
  }

  // Get bundle plan name based on capacity
  getBundlePlan(capacity) {
    const capacityNum = parseFloat(capacity);
    
    // Map capacity to appropriate plan
    // You may need to adjust these based on actual Telecel plans
    if (capacityNum <= 100) {
      return 'Bundle Sharer 5500GB';
    } else if (capacityNum <= 1000) {
      return 'Bundle Sharer 5500GB';
    } else {
      return 'Bundle Sharer 5500GB';
    }
  }

  // Validate request before sending
  validateRequest(phoneNumber, capacity) {
    const errors = [];
    
    // Validate phone number
    try {
      const cleaned = phoneNumber.replace(/\D/g, '');
      if (!cleaned || cleaned.length < 9) {
        errors.push('Invalid phone number - too short');
      }
      
      // Format and validate
      const formatted = this.formatPhoneNumber(phoneNumber);
      if (!/^0[2-9]\d{8}$/.test(formatted)) {
        errors.push('Invalid Ghana phone number format');
      }
    } catch (error) {
      errors.push(error.message);
    }
    
    // Validate capacity
    const capacityNum = parseFloat(capacity);
    if (isNaN(capacityNum) || capacityNum <= 0) {
      errors.push('Invalid capacity - must be greater than 0');
    }
    if (capacityNum > 5500) {
      errors.push('Capacity exceeds maximum limit of 5500 GB');
    }
    
    return {
      valid: errors.length === 0,
      errors
    };
  }

  // Get service status - REAL STATUS ONLY
  async getServiceStatus() {
    try {
      const tokenStatus = await this.authService.checkTokenStatus();
      
      // Check if we can reach the API
      let apiReachable = false;
      try {
        await axios.get(`${this.baseURL}/enterprise-request/`, {
          timeout: 5000
        });
        apiReachable = true;
      } catch (error) {
        apiReachable = false;
      }
      
      return {
        service: 'TELECEL',
        mode: 'PRODUCTION',
        status: tokenStatus.status === 'active' && apiReachable ? 'operational' : 'degraded',
        apiReachable: apiReachable,
        tokenStatus: {
          active: tokenStatus.status === 'active',
          expiresIn: tokenStatus.expiresIn,
          message: tokenStatus.status === 'active' 
            ? 'Token is active' 
            : 'Token expired or missing - admin action required'
        },
        subscriberMsisdn: this.subscriberMsisdn,
        baseURL: this.baseURL,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        service: 'TELECEL',
        mode: 'PRODUCTION',
        status: 'error',
        error: error.message,
        message: 'Service status check failed - possible configuration issue',
        timestamp: new Date().toISOString()
      };
    }
  }

  // Check if bundle delivery is possible
  async canDeliverBundle() {
    try {
      const status = await this.getServiceStatus();
      return status.status === 'operational';
    } catch (error) {
      return false;
    }
  }

  // Get detailed error information for logging
  getErrorDetails(error) {
    return {
      message: error.message,
      code: error.code,
      statusCode: error.response?.status,
      statusText: error.response?.statusText,
      data: error.response?.data,
      headers: error.response?.headers,
      timestamp: new Date().toISOString()
    };
  }
}

// Export the class
module.exports = TelecelService;