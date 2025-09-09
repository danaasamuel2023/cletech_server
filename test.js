// ==================== test-monitoring-complete.js ====================
// COMPLETE TEST FILE FOR WHATSAPP MONITORING SYSTEM

require('dotenv').config();
const twilio = require('twilio');
const mongoose = require('mongoose');
const XLSX = require('xlsx');
const fs = require('fs').promises;
const path = require('path');

// Your Twilio credentials
const ACCOUNT_SID = 'AC0705e31759f8522e3efcece09b184704';
const AUTH_TOKEN = '1b8425667157f1576491d04ee946bc9f';
const WHATSAPP_FROM = 'whatsapp:+14155238886';
const ADMIN_NUMBER = 'whatsapp:+233597760914';

// Initialize Twilio client
const client = twilio(ACCOUNT_SID, AUTH_TOKEN);

// Color codes for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m'
};

// ==================== TEST FUNCTIONS ====================

// Test 1: Basic WhatsApp Connection
async function testBasicConnection() {
  console.log(`\n${colors.blue}[TEST 1] Testing Basic WhatsApp Connection...${colors.reset}`);
  
  try {
    const message = await client.messages.create({
      from: WHATSAPP_FROM,
      to: ADMIN_NUMBER,
      body: '✅ *TEST 1 PASSED*\n\nWhatsApp connection successful!\n\nYour Twilio credentials are working correctly.'
    });
    
    console.log(`${colors.green}✅ Test 1 PASSED - Message sent successfully${colors.reset}`);
    console.log(`   Message SID: ${message.sid}`);
    console.log(`   Status: ${message.status}`);
    return true;
  } catch (error) {
    console.log(`${colors.red}❌ Test 1 FAILED${colors.reset}`);
    console.log(`   Error: ${error.message}`);
    
    if (error.code === 63007) {
      console.log(`${colors.yellow}   ⚠️  You need to join the sandbox first!${colors.reset}`);
      console.log(`   Send "join <your-code>" to +14155238886 on WhatsApp`);
    }
    return false;
  }
}

// Test 2: Send Sample Excel File
async function testExcelAttachment() {
  console.log(`\n${colors.blue}[TEST 2] Testing Excel File Attachment...${colors.reset}`);
  
  try {
    // Create sample Excel data
    const sampleOrders = [
      { 'No.': 1, 'Phone Number': '0241234567', 'Capacity (GB)': 5 },
      { 'No.': 2, 'Phone Number': '0551234567', 'Capacity (GB)': 10 },
      { 'No.': 3, 'Phone Number': '0261234567', 'Capacity (GB)': 15 },
      { 'No.': 4, 'Phone Number': '0501234567', 'Capacity (GB)': 20 },
      { 'No.': 'TOTAL', 'Phone Number': '4 Orders', 'Capacity (GB)': 50 }
    ];

    // Create Excel file
    const ws = XLSX.utils.json_to_sheet(sampleOrders);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Test Orders');
    
    // Save to temp file
    const fileName = `test_orders_${Date.now()}.xlsx`;
    const filePath = path.join(process.cwd(), 'temp', fileName);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    await fs.writeFile(filePath, buffer);
    
    console.log(`   Excel file created: ${fileName}`);
    
    // Use a public test Excel URL (since we can't upload in sandbox easily)
    const testExcelUrl = 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/xls/dummy.xls';
    
    const message = await client.messages.create({
      from: WHATSAPP_FROM,
      to: ADMIN_NUMBER,
      body: '📊 *TEST 2 - Excel Attachment*\n\n' +
            'This is how you will receive order reports:\n\n' +
            '• 4 test orders\n' +
            '• Total: 50GB\n' +
            '• Excel file attached\n\n' +
            'In production, this will contain real orders.',
      mediaUrl: [testExcelUrl]
    });
    
    console.log(`${colors.green}✅ Test 2 PASSED - Excel sent successfully${colors.reset}`);
    console.log(`   Message SID: ${message.sid}`);
    
    // Clean up
    await fs.unlink(filePath);
    return true;
  } catch (error) {
    console.log(`${colors.red}❌ Test 2 FAILED${colors.reset}`);
    console.log(`   Error: ${error.message}`);
    return false;
  }
}

// Test 3: Simulate Real Alert
async function testRealAlert() {
  console.log(`\n${colors.blue}[TEST 3] Simulating Real Alert Message...${colors.reset}`);
  
  try {
    const alertId = `TEST-ALERT-${Date.now()}`;
    const orderCount = 40;
    const totalCapacity = 185;
    
    const alertMessage = `🚨 *MANUAL DELIVERY REQUIRED* 🚨\n\n` +
      `📦 *Orders needing delivery:* ${orderCount}\n` +
      `💾 *Total Capacity:* ${totalCapacity}GB\n` +
      `⚠️ *Threshold reached:* ${orderCount} orders\n\n` +
      `📎 *Excel attached with phone numbers*\n\n` +
      `Please process these orders manually.\n` +
      `Alert ID: ${alertId}\n\n` +
      `_This is a test alert - no action needed_`;
    
    const message = await client.messages.create({
      from: WHATSAPP_FROM,
      to: ADMIN_NUMBER,
      body: alertMessage
    });
    
    console.log(`${colors.green}✅ Test 3 PASSED - Alert simulation sent${colors.reset}`);
    console.log(`   Alert ID: ${alertId}`);
    console.log(`   Message SID: ${message.sid}`);
    return true;
  } catch (error) {
    console.log(`${colors.red}❌ Test 3 FAILED${colors.reset}`);
    console.log(`   Error: ${error.message}`);
    return false;
  }
}

// Test 4: Database Connection
async function testDatabaseConnection() {
  console.log(`\n${colors.blue}[TEST 4] Testing Database Connection...${colors.reset}`);
  
  try {
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/your-database';
    
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    
    console.log(`${colors.green}✅ Test 4 PASSED - Database connected${colors.reset}`);
    console.log(`   MongoDB URI: ${mongoUri.replace(/\/\/.*@/, '//***@')}`);
    
    // Check for processing orders
    const DataPurchase = require('./Schema/Schema').DataPurchase;
    const processingCount = await DataPurchase.countDocuments({ 
      status: 'processing',
      whatsappAlertSent: { $ne: true }
    });
    
    console.log(`   Processing orders found: ${processingCount}`);
    console.log(`   Alert will trigger at: 40 orders`);
    
    await mongoose.disconnect();
    return true;
  } catch (error) {
    console.log(`${colors.red}❌ Test 4 FAILED${colors.reset}`);
    console.log(`   Error: ${error.message}`);
    console.log(`   Make sure MongoDB is running`);
    return false;
  }
}

// Test 5: Monitoring Service Check
async function testMonitoringService() {
  console.log(`\n${colors.blue}[TEST 5] Testing Monitoring Service...${colors.reset}`);
  
  try {
    const orderMonitoringService = require('./services/orderMonitoring.service');
    
    // Connect to database first
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/your-database';
    await mongoose.connect(mongoUri);
    
    console.log('   Triggering manual check...');
    
    // Force a check even with less than 40 orders
    const result = await orderMonitoringService.checkHighVolumeOrders(true);
    
    console.log(`${colors.green}✅ Test 5 PASSED - Monitoring service working${colors.reset}`);
    console.log(`   Result: ${result.message}`);
    if (result.ordersAlerted) {
      console.log(`   Orders alerted: ${result.ordersAlerted}`);
      console.log(`   Alert ID: ${result.alertId}`);
    }
    
    await mongoose.disconnect();
    return true;
  } catch (error) {
    console.log(`${colors.red}❌ Test 5 FAILED${colors.reset}`);
    console.log(`   Error: ${error.message}`);
    console.log(`   Make sure all monitoring files are in place`);
    return false;
  }
}

// ==================== MAIN TEST RUNNER ====================

async function runAllTests() {
  console.log('=====================================');
  console.log('  WHATSAPP MONITORING SYSTEM TESTS  ');
  console.log('=====================================');
  console.log(`Admin Number: ${ADMIN_NUMBER}`);
  console.log(`From Number: ${WHATSAPP_FROM}`);
  
  const tests = [
    { name: 'Basic Connection', fn: testBasicConnection },
    { name: 'Excel Attachment', fn: testExcelAttachment },
    { name: 'Real Alert', fn: testRealAlert },
    { name: 'Database', fn: testDatabaseConnection },
    { name: 'Monitoring Service', fn: testMonitoringService }
  ];
  
  const results = [];
  
  for (const test of tests) {
    try {
      const passed = await test.fn();
      results.push({ name: test.name, passed });
      
      // Wait 2 seconds between tests to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      results.push({ name: test.name, passed: false, error: error.message });
    }
  }
  
  // Final Summary
  console.log('\n=====================================');
  console.log('           TEST SUMMARY              ');
  console.log('=====================================');
  
  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;
  
  results.forEach(result => {
    const status = result.passed ? `${colors.green}✅ PASSED${colors.reset}` : `${colors.red}❌ FAILED${colors.reset}`;
    console.log(`${result.name}: ${status}`);
  });
  
  console.log('\n-------------------------------------');
  console.log(`Total: ${passed} passed, ${failed} failed`);
  
  if (passed === tests.length) {
    console.log(`\n${colors.green}🎉 ALL TESTS PASSED! Your monitoring system is ready!${colors.reset}`);
    
    // Send final success message
    await client.messages.create({
      from: WHATSAPP_FROM,
      to: ADMIN_NUMBER,
      body: '🎉 *SYSTEM READY!*\n\n' +
            '✅ All tests passed\n' +
            '✅ WhatsApp connected\n' +
            '✅ Monitoring active\n\n' +
            'Your system will now check every 5 minutes and alert you when 40+ orders need processing.\n\n' +
            'To pause: POST /api/monitoring/pause\n' +
            'To check: GET /api/monitoring/status'
    });
  } else {
    console.log(`\n${colors.yellow}⚠️  Some tests failed. Please fix the issues above.${colors.reset}`);
    
    if (!results[0].passed) {
      console.log(`\n${colors.yellow}IMPORTANT: Did you join the sandbox?${colors.reset}`);
      console.log('Send "join <your-code>" to +14155238886 on WhatsApp first!');
    }
  }
  
  process.exit(passed === tests.length ? 0 : 1);
}

// ==================== RUN TESTS ====================

// Check command line arguments
const args = process.argv.slice(2);

if (args.includes('--quick')) {
  // Quick test - just WhatsApp connection
  testBasicConnection().then(() => process.exit(0));
} else if (args.includes('--service')) {
  // Test monitoring service only
  testMonitoringService().then(() => process.exit(0));
} else {
  // Run all tests
  runAllTests().catch(error => {
    console.error(`${colors.red}Test runner failed:${colors.reset}`, error);
    process.exit(1);
  });
}

// ==================== USAGE ====================
/*
Run all tests:
  node test-monitoring-complete.js

Quick WhatsApp test only:
  node test-monitoring-complete.js --quick

Test monitoring service only:
  node test-monitoring-complete.js --service
*/