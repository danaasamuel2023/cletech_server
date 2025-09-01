// ==================== services/telecelService.js ====================
// Simplified Telecel Ghana Bundle Sharer Integration

const axios = require('axios');

class TelecelService {
  constructor() {
    this.baseURL = 'https://play.telecel.com.gh';
    // Hardcoded token - in production, store this securely in environment variables
    this.authToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vcGxheS50ZWxlY2VsLmNvbS5naC9hcGkvbG9naW4iLCJpYXQiOjE3NTY3Mjg1MzEsImV4cCI6MTc1Njc3MTczMSwibmJmIjoxNzU2NzI4NTMxLCJqdGkiOiJTNnhRZ29aQ3lTYlFmU0RFIiwic3ViIjoiNTY2MyIsInBydiI6IjIzYmQ1Yzg5NDlmNjAwYWRiMzllNzAxYzQwMDg3MmRiN2E1OTc2ZjcifQ.Fv1Lfqkf449H2cBg-b3HaV1CpwemXhfG_ARrA9RBnug';
    this.subscriberMsisdn = '233509240147';
  }

  // Generate transaction ID
  generateTransactionId() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 7).toUpperCase();
    return `ERP${random}${timestamp}`;
  }

  // Format phone number for Telecel API
  formatPhoneNumber(phoneNumber) {
    // Remove any non-numeric characters
    let cleaned = phoneNumber.replace(/\D/g, '');
    
    // Handle Ghana phone numbers
    if (cleaned.startsWith('233')) {
      cleaned = '0' + cleaned.substring(3);
    } else if (!cleaned.startsWith('0')) {
      cleaned = '0' + cleaned;
    }
    
    return cleaned;
  }

  // Get bundle plan name based on capacity
  getBundlePlan(capacity) {
    // Always return 5500GB plan name regardless of capacity
    return 'Bundle Sharer 5500GB';
  }

  // Send data bundle to beneficiary
  async sendDataBundle(phoneNumber, capacity) {
    try {
      const formattedPhone = this.formatPhoneNumber(phoneNumber);
      const bundlePlan = 'Bundle Sharer 5500GB'; // Always use 5500GB plan
      const transactionId = this.generateTransactionId();

      console.log(`[TELECEL] Sending ${capacity}GB to ${formattedPhone}`);
      console.log(`[TELECEL] Bundle Plan: ${bundlePlan}`);
      console.log(`[TELECEL] Transaction ID: ${transactionId}`);

      const requestData = {
        beneficiaryMsisdn: formattedPhone,
        volume: capacity.toString(), // Send actual requested capacity
        plan: bundlePlan, // Always "Bundle Sharer 5500GB"
        transactionId: transactionId,
        subscriberMsisdn: this.subscriberMsisdn,
        beneficiaryName: formattedPhone
      };

      const response = await axios.post(
        `${this.baseURL}/enterprise-request/api/data-sharer/prepaid/add-beneficiary`,
        requestData,
        {
          headers: {
            'Authorization': `Bearer ${this.authToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
            'Origin': this.baseURL,
            'Referer': `${this.baseURL}/enterprise-request/app/bundle-sharer/beneficiaries/`
          },
          timeout: 30000 // 30 second timeout
        }
      );

      console.log('[TELECEL] Bundle sent successfully');

      return {
        success: true,
        transactionId: transactionId,
        data: response.data,
        message: `Successfully sent ${capacity}GB to ${formattedPhone}`
      };

    } catch (error) {
      console.error('[TELECEL] Error sending bundle:', error.response?.data || error.message);

      // Handle specific error cases
      if (error.response?.status === 401) {
        return {
          success: false,
          error: 'Authentication failed - token may be expired',
          requiresNewToken: true
        };
      }

      if (error.response?.status === 400) {
        return {
          success: false,
          error: 'Insufficient balance or invalid request',
          details: error.response.data
        };
      }

      return {
        success: false,
        error: error.message || 'Failed to send data bundle',
        details: error.response?.data
      };
    }
  }
}
 
// Create singleton instance
const telecelService = new TelecelService();

module.exports = telecelService;