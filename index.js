const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const ConnectDB = require('./database/connection.js');
const authRoutes = require('./routes/Authroute/auth.js');
const dataOrderRoutes = require('./routes/Datapurchase/order.js');
const Depoite = require('./routes/deposite/deposite.js');
const adminManagement = require('./routes/admin_management/admin.js')
const SystemSettings = require('./routes/settings/setting.js')
const profile = require('./routes/User/User.js')
const Uaer_transactions = require('./routes/transaction/user_transactions.js')  
const agent_store = require('./routes/agent_store/agent_store.js')
const UserDeposite = require('./routes/deposite/deposite.js')  
const wallet = require('./routes/user_walllet/page.js')
const user_dashboard = require('./routes/user_dashboard/page.js')
const checkers = require('./routes/result_checkers/page.js')
const telecel_token = require('./routes/admin_telecel_auth/admin.js')
// const Profits = require('./routes/profits.js')
// const withdrawal = require('./withdrawal/withdrawal.js');
dotenv.config(); 

// Initialize Express app
const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Connect to Database
ConnectDB();

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/purchase', dataOrderRoutes);
// app.use('/api', Depoite);
app.use('/api/admin', adminManagement);
app.use('/api/admin/settings', SystemSettings);
app.use('/api/auth', profile);
app.use('/api', Uaer_transactions);
app.use('/api/store', agent_store);
app.use('/api/deposites', UserDeposite);
app.use('/api/users', wallet);
app.use('/api', user_dashboard);
app.use('/api/checkers', checkers);
app.use('/api/admin/telecel', telecel_token);
// app.use('/api', Profits);
// app.use('/api/admin-withdrawal', withdrawal);

// Default Route
app.get('/', (req, res) => {
  res.send('API is running...');
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
