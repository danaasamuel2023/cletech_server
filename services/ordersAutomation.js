// ==================== services/orderMonitoring.service.js ====================
// CORE SERVICE LOGIC FOR ORDER MONITORING

const cron = require('node-cron');
const axios = require('axios');
const XLSX = require('xlsx');
const fs = require('fs').promises;
const path = require('path');
const { 
  OrderAlert, 
  AutomationControl, 
  WhatsAppMessageLog 
} = require('../auomationSchema/schema');
const { DataPurchase } = require('../Schema/Schema');

// ==================== WHATSAPP CONFIGURATION ====================
const WhatsAppConfig = {
  // Twilio WhatsApp Configuration
  TWILIO_ACCOUNT_SID: process.env.TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN: process.env.TWILIO_AUTH_TOKEN,
  TWILIO_WHATSAPP_FROM: process.env.TWILIO_WHATSAPP_NUMBER || 'whatsapp:+14155238886',
  
  // Default admin numbers (can be overridden in database)
  ADMIN_NUMBERS: process.env.ADMIN_WHATSAPP_NUMBERS?.split(',') || ['233241234567'],
  
  // Default monitoring settings
  ORDER_COUNT_THRESHOLD: parseInt(process.env.ORDER_COUNT_THRESHOLD) || 40,
  CHECK_INTERVAL: process.env.CHECK_INTERVAL || '*/5 * * * *',
};

// Validate Twilio configuration on startup
const validateTwilioConfig = () => {
  if (!WhatsAppConfig.TWILIO_ACCOUNT_SID || !WhatsAppConfig.TWILIO_AUTH_TOKEN) {
    console.error('[MONITORING] ⚠️  WARNING: Twilio credentials not configured!');
    console.error('[MONITORING] Please set the following in your .env file:');
    console.error('  - TWILIO_ACCOUNT_SID');
    console.error('  - TWILIO_AUTH_TOKEN');
    console.error('  - TWILIO_WHATSAPP_NUMBER (optional, defaults to sandbox)');
    console.error('[MONITORING] WhatsApp alerts will NOT work without these credentials.');
    return false;
  }
  
  console.log('[MONITORING] ✅ Twilio configuration validated');
  console.log(`[MONITORING] Using WhatsApp number: ${WhatsAppConfig.TWILIO_WHATSAPP_FROM}`);
  console.log(`[MONITORING] Admin numbers configured: ${WhatsAppConfig.ADMIN_NUMBERS.join(', ')}`);
  return true;
};

// Store cron job reference
let monitoringJob = null;

// ==================== WHATSAPP MESSAGING WITH TWILIO ====================

const sendWhatsAppAlert = async (phoneNumber, message) => {
  try {
    // Check if Twilio is configured
    if (!WhatsAppConfig.TWILIO_ACCOUNT_SID || !WhatsAppConfig.TWILIO_AUTH_TOKEN) {
      throw new Error('Twilio credentials not configured');
    }
    
    // Initialize Twilio client
    const twilio = require('twilio');
    const client = twilio(
      WhatsAppConfig.TWILIO_ACCOUNT_SID,
      WhatsAppConfig.TWILIO_AUTH_TOKEN
    );
    
    // Format phone number for WhatsApp (Ghana format)
    let formattedNumber = phoneNumber.toString().trim();
    formattedNumber = formattedNumber.replace(/\D/g, '');
    
    // Ensure it's in international format (233...)
    if (formattedNumber.startsWith('0')) {
      formattedNumber = '233' + formattedNumber.substring(1);
    }
    
    // Add WhatsApp prefix
    const whatsappNumber = `whatsapp:+${formattedNumber}`;
    
    console.log(`[WHATSAPP] Sending message via Twilio to ${whatsappNumber}`);

    // Prepare message options
    const messageOptions = {
      from: WhatsAppConfig.TWILIO_WHATSAPP_FROM,
      to: whatsappNumber,
      body: message
    };

    // Send message via Twilio
    const twilioMessage = await client.messages.create(messageOptions);

    // Log message success
    await WhatsAppMessageLog.create({
      messageId: twilioMessage.sid,
      recipientNumber: formattedNumber,
      messageType: 'alert',
      content: message.substring(0, 500),
      status: 'sent'
    });
    
    console.log(`[WHATSAPP] Message sent successfully: ${twilioMessage.sid}`);
    
    return { 
      success: true, 
      messageId: twilioMessage.sid,
      status: twilioMessage.status
    };
    
  } catch (error) {
    console.error('[WHATSAPP] Twilio send error:', error.message);
    
    // Log failed message
    await WhatsAppMessageLog.create({
      recipientNumber: phoneNumber,
      messageType: 'alert',
      content: message.substring(0, 500),
      status: 'failed',
      error: error.message
    });
    
    return { 
      success: false, 
      error: error.message 
    };
  }
};

// ==================== MAIN MONITORING FUNCTION ====================

const checkHighVolumeOrders = async (forceAlert = false) => {
  try {
    // Get control settings
    const control = await AutomationControl.getControl();
    
    // Check if automation is paused
    if (control.isPaused && !forceAlert) {
      console.log('[MONITORING] Automation is paused by admin');
      return { message: 'Automation is paused', paused: true };
    }

    console.log('[MONITORING] Checking for processing orders that need manual delivery...');
    
    // Get ALL unalerted processing orders
    const recentOrders = await DataPurchase.find({
      status: 'processing',
      adminNotes: 'Requires manual processing',
      whatsappAlertSent: { $ne: true }
    })
    .select('_id phoneNumber network capacity price reference createdAt userId gateway')
    .populate('userId', 'name email')
    .sort({ createdAt: -1 });

    if (recentOrders.length === 0) {
      console.log('[MONITORING] No pending orders found');
      await AutomationControl.findOneAndUpdate(
        { serviceName: 'order_monitoring' },
        { lastCheck: new Date() }
      );
      return { message: 'No pending orders', ordersFound: 0 };
    }

    // Calculate totals
    const totalOrders = recentOrders.length;
    const totalCapacity = recentOrders.reduce((sum, order) => sum + order.capacity, 0);
    const totalAmount = recentOrders.reduce((sum, order) => sum + order.price, 0);

    console.log(`[MONITORING] Found ${totalOrders} processing orders needing manual delivery`);
    
    // Get threshold from settings or use default
    const orderThreshold = control.settings.orderCountThreshold || WhatsAppConfig.ORDER_COUNT_THRESHOLD || 40;
    
    // Determine if this is urgent (40+ orders)
    const isUrgent = totalOrders >= orderThreshold;
    
    console.log(`[MONITORING] Order count: ${totalOrders}, Urgent threshold: ${orderThreshold}, Is urgent: ${isUrgent}`);
    
    // Prepare order data
    const orderData = recentOrders.map(order => ({
      purchaseId: order._id,
      reference: order.reference,
      phoneNumber: order.phoneNumber,
      network: order.network,
      capacity: order.capacity,
      price: order.price,
      userId: order.userId?._id,
      userName: order.userId?.name,
      userEmail: order.userId?.email,
      purchaseTime: order.createdAt,
      paymentMethod: order.gateway
    }));

    // Generate alert ID
    const alertId = `ALERT-${Date.now()}`;

    // Create alert record
    const alert = await OrderAlert.create({
      alertId,
      orders: orderData,
      totalCapacity,
      totalAmount,
      totalOrders,
      alertSentAt: new Date(),
      status: 'sent',
      isUrgent
    });

    // Prepare WhatsApp message - ONLY phone numbers and capacity with tab spacing
    let alertMessage = '';
    
    // Just add the orders in the exact format requested
    orderData.forEach((order) => {
      alertMessage += `${order.phoneNumber}\t${order.capacity}\n`;
    });
    
    // Remove the last newline
    alertMessage = alertMessage.trim();

    // Get admin numbers
    const adminNumbers = control.settings.adminNumbers?.length > 0 
      ? control.settings.adminNumbers 
      : WhatsAppConfig.ADMIN_NUMBERS;

    // Send to all admin numbers
    const messageIds = [];
    for (const adminNumber of adminNumbers) {
      console.log(`[MONITORING] Sending alert to admin: ${adminNumber}`);
      
      const result = await sendWhatsAppAlert(adminNumber, alertMessage);
      
      if (result.success) {
        messageIds.push(result.messageId);
        console.log(`[MONITORING] Alert sent successfully to ${adminNumber}`);
      } else {
        console.error(`[MONITORING] Failed to send to ${adminNumber}:`, result.error);
      }
    }

    // Update alert with message IDs
    alert.whatsappMessageIds = messageIds;
    await alert.save();

    // Mark orders as alerted
    const orderIds = recentOrders.map(order => order._id);
    await DataPurchase.updateMany(
      { _id: { $in: orderIds } },
      { 
        $set: { 
          whatsappAlertSent: true,
          whatsappAlertAt: new Date(),
          whatsappAlertId: alertId
        }
      }
    );

    // Update statistics
    await AutomationControl.findOneAndUpdate(
      { serviceName: 'order_monitoring' },
      {
        $set: { 
          lastCheck: new Date(),
          'statistics.lastAlertAt': new Date()
        },
        $inc: {
          'statistics.totalAlerts': 1,
          'statistics.totalOrdersProcessed': totalOrders,
          'statistics.totalCapacityProcessed': totalCapacity
        }
      }
    );

    console.log(`[MONITORING] Alert ${alertId} sent to ${messageIds.length} admins for ${totalOrders} orders`);

    return {
      success: true,
      message: `Alert sent for ${totalOrders} orders`,
      alertId,
      ordersAlerted: totalOrders,
      totalCapacity,
      totalAmount,
      messagesSent: messageIds.length,
      isUrgent
    };

  } catch (error) {
    console.error('[MONITORING] Error in checkHighVolumeOrders:', error);
    
    // Send error alert to first admin
    const adminNumbers = WhatsAppConfig.ADMIN_NUMBERS;
    if (adminNumbers[0]) {
      await sendWhatsAppAlert(
        adminNumbers[0],
        `MONITORING ERROR: ${error.message}`
      );
    }
    
    throw error;
  }
};

// ==================== IMMEDIATE CHECK FUNCTION ====================
const checkOrdersImmediately = async () => {
  console.log('[MONITORING] Manual check triggered');
  return await checkHighVolumeOrders(true);
};

// ==================== NOTIFICATION HELPERS ====================

const notifyAdmins = async (type, message) => {
  try {
    const control = await AutomationControl.getControl();
    const adminNumbers = control.settings.adminNumbers?.length > 0 
      ? control.settings.adminNumbers 
      : WhatsAppConfig.ADMIN_NUMBERS;
    
    const results = [];
    for (const adminNumber of adminNumbers) {
      const result = await sendWhatsAppAlert(adminNumber, message);
      results.push({ number: adminNumber, ...result });
    }
    
    return results;
  } catch (error) {
    console.error('[MONITORING] Error notifying admins:', error);
    return [];
  }
};

// ==================== CRON JOB MANAGEMENT ====================

const startMonitoring = async () => {
  try {
    // Validate Twilio configuration first
    if (!validateTwilioConfig()) {
      console.warn('[MONITORING] Starting service WITHOUT WhatsApp capability due to missing Twilio credentials');
    }
    
    // Get or create control
    const control = await AutomationControl.getControl();
    
    const interval = control.settings.checkInterval || WhatsAppConfig.CHECK_INTERVAL;
    const orderThreshold = control.settings.orderCountThreshold || WhatsAppConfig.ORDER_COUNT_THRESHOLD || 40;
    
    console.log(`[MONITORING] Starting order monitoring service...`);
    console.log(`[MONITORING] Check interval: ${interval} (every 5 minutes)`);
    console.log(`[MONITORING] Order count threshold: ${orderThreshold} orders for urgent alert`);
    console.log(`[MONITORING] Will alert for ANY pending orders every check`);
    console.log(`[MONITORING] Admin numbers: ${control.settings.adminNumbers?.join(', ') || WhatsAppConfig.ADMIN_NUMBERS.join(', ')}`);

    // Stop existing job if any
    if (monitoringJob) {
      monitoringJob.stop();
    }

    // Schedule new cron job
    monitoringJob = cron.schedule(interval, async () => {
      await checkHighVolumeOrders();
    });

    // Run initial check
    checkHighVolumeOrders();

    // Update control
    await AutomationControl.findOneAndUpdate(
      { serviceName: 'order_monitoring' },
      { 
        isActive: true,
        lastCheck: new Date() 
      }
    );

    console.log('[MONITORING] Order monitoring service started successfully');
    
    // Send simple startup notification
    if (WhatsAppConfig.TWILIO_ACCOUNT_SID && WhatsAppConfig.TWILIO_AUTH_TOKEN) {
      await notifyAdmins('info', 'Monitoring started');
    }
    
    return { success: true, message: 'Monitoring started' };
  } catch (error) {
    console.error('[MONITORING] Failed to start monitoring:', error);
    throw error;
  }
};

const stopMonitoring = async () => {
  try {
    console.log('[MONITORING] Stopping order monitoring service...');
    
    if (monitoringJob) {
      monitoringJob.stop();
      monitoringJob = null;
    }
    
    await AutomationControl.findOneAndUpdate(
      { serviceName: 'order_monitoring' },
      { isActive: false }
    );
    
    console.log('[MONITORING] Order monitoring service stopped');
    
    return { success: true, message: 'Monitoring stopped' };
  } catch (error) {
    console.error('[MONITORING] Failed to stop monitoring:', error);
    throw error;
  }
};

const restartMonitoring = async () => {
  await stopMonitoring();
  await startMonitoring();
  return { success: true, message: 'Monitoring restarted' };
};

// ==================== WEBHOOK HANDLER ====================

const handleWhatsAppResponse = async (message) => {
  try {
    const text = message.text.body.toUpperCase();
    const from = message.from;

    // Check if sender is admin
    const control = await AutomationControl.getControl();
    const adminNumbers = control.settings.adminNumbers?.length > 0 
      ? control.settings.adminNumbers 
      : WhatsAppConfig.ADMIN_NUMBERS;
    
    if (!adminNumbers.includes(from)) {
      return;
    }

    // Parse acknowledgment
    if (text.startsWith('ACK ')) {
      const alertId = text.replace('ACK ', '').trim();
      
      const alert = await OrderAlert.findOne({ alertId });
      if (alert) {
        alert.adminResponses.push({
          adminPhone: from,
          response: 'acknowledged',
          receivedAt: new Date()
        });
        alert.status = 'acknowledged';
        await alert.save();

        await sendWhatsAppAlert(
          from,
          `Alert ${alertId} acknowledged`
        );
      }
    }
  } catch (error) {
    console.error('[MONITORING] Error handling WhatsApp response:', error);
  }
};

// ==================== EXPORTS ====================

module.exports = {
  startMonitoring,
  stopMonitoring,
  restartMonitoring,
  checkHighVolumeOrders,
  checkOrdersImmediately,
  handleWhatsAppResponse,
  sendWhatsAppAlert,
  notifyAdmins
};  