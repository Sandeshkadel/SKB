require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const socketIo = require('socket.io');
const http = require('http');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key-2024';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/hcb-real-clone';

console.log('🔧 Environment Check:');
console.log('MONGODB_URI:', process.env.MONGODB_URI ? '✅ Set' : '❌ Not set');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? '✅ Set' : '❌ Not set');

// Configure Socket.IO with proper CORS
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware - CORS first
app.use(cors({
  origin: "*",
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// Simple OTP Generator
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Database Models
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  name: { type: String, required: true },
  hashed_password: { type: String, required: true },
  profile_picture: { type: String, default: null },
  phone: { type: String, default: null },
  status: { type: String, enum: ['pending', 'active', 'suspended'], default: 'pending' },
  email_verified: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

const AccountSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  account_number: { type: String, required: true, unique: true },
  balance_cents: { type: Number, default: 0 },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['active', 'frozen', 'closed'], default: 'active' },
  created_at: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  account_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Account', required: true },
  amount_cents: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer', 'payment'], required: true },
  description: { type: String },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  counterparty_name: { type: String },
  counterparty_account: { type: String },
  created_at: { type: Date, default: Date.now }
});

const CardSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  card_number: { type: String, required: true },
  last4: { type: String, required: true },
  expiry_month: { type: Number, required: true },
  expiry_year: { type: Number, required: true },
  cvv: { type: String, required: true },
  brand: { type: String, default: 'Visa' },
  status: { type: String, enum: ['active', 'blocked', 'expired'], default: 'active' },
  billing_address: {
    street: { type: String, default: '123 Main St' },
    city: { type: String, default: 'San Francisco' },
    state: { type: String, default: 'CA' },
    zip_code: { type: String, default: '94105' }
  },
  phone_number: { type: String, default: '+1-555-0123' },
  card_type: { type: String, default: 'virtual' },
  card_network: { type: String, default: 'visa' },
  created_at: { type: Date, default: Date.now }
});

const OTPSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  otp: { type: String, required: true },
  expires_at: { type: Date, required: true },
  used: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Account = mongoose.model('Account', AccountSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Card = mongoose.model('Card', CardSchema);
const OTP = mongoose.model('OTP', OTPSchema);

// Generate account number
const generateAccountNumber = () => {
  return 'HCB' + Math.floor(1000000000 + Math.random() * 9000000000).toString();
};

// Generate card number
const generateCardNumber = () => {
  return '4' + Math.floor(100000000000000 + Math.random() * 900000000000000).toString();
};

// Generate CVV
const generateCVV = () => {
  return Math.floor(100 + Math.random() * 900).toString();
};

// Auth middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Routes

// Health check
app.get('/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: dbStatus,
    environment: process.env.NODE_ENV || 'development'
  });
});

// Serve frontend for root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Auth Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    console.log('Signup request:', req.body);
    const { email, password, name, phone } = req.body;

    // Validate input
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = new User({
      email: email.toLowerCase(),
      name,
      hashed_password: hashedPassword,
      phone: phone || null
    });

    await user.save();

    // Create account for user
    const account = new Account({
      user_id: user._id,
      account_number: generateAccountNumber(),
      balance_cents: 100000, // Start with $1000 for demo
      currency: 'USD'
    });

    await account.save();

    // Generate OTP
    const otp = generateOTP();
    const otpRecord = new OTP({
      user_id: user._id,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });

    await otpRecord.save();

    console.log(`OTP for ${email}: ${otp}`);

    res.status(201).json({
      message: 'User created successfully. Please verify your email with OTP.',
      user_id: user._id,
      email: user.email
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('Login request:', req.body);
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.hashed_password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate OTP for 2FA
    const otp = generateOTP();
    
    // Delete any existing OTPs for this user
    await OTP.deleteMany({ user_id: user._id });
    
    const otpRecord = new OTP({
      user_id: user._id,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });

    await otpRecord.save();

    console.log(`OTP for ${email}: ${otp}`);

    res.json({
      message: 'OTP sent to your email',
      user_id: user._id,
      email: user.email
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    console.log('Verify OTP request:', req.body);
    const { user_id, otp } = req.body;

    if (!user_id || !otp) {
      return res.status(400).json({ error: 'User ID and OTP are required' });
    }

    // Find OTP record
    const otpRecord = await OTP.findOne({ 
      user_id, 
      otp, 
      used: false,
      expires_at: { $gt: new Date() }
    });

    if (!otpRecord) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Mark OTP as used
    otpRecord.used = true;
    await otpRecord.save();

    // Get user and account
    const user = await User.findById(user_id);
    const account = await Account.findOne({ user_id });

    if (!user || !account) {
      return res.status(404).json({ error: 'User or account not found' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'OTP verified successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        profile_picture: user.profile_picture,
        email_verified: user.email_verified
      },
      account: {
        id: account._id,
        account_number: account.account_number,
        balance_cents: account.balance_cents,
        currency: account.currency
      }
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const { user_id } = req.body;

    if (!user_id) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    const user = await User.findById(user_id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate new OTP
    const otp = generateOTP();
    
    // Delete any existing OTPs
    await OTP.deleteMany({ user_id });
    
    const otpRecord = new OTP({
      user_id,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000)
    });

    await otpRecord.save();

    console.log(`New OTP for ${user.email}: ${otp}`);

    res.json({
      message: 'New OTP sent to your email',
      user_id: user._id
    });

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

// Profile Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const account = await Account.findOne({ user_id: req.user._id });
    
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    res.json({
      user: {
        id: req.user._id,
        email: req.user.email,
        name: req.user.name,
        phone: req.user.phone,
        profile_picture: req.user.profile_picture,
        email_verified: req.user.email_verified,
        status: req.user.status
      },
      account: {
        id: account._id,
        account_number: account.account_number,
        balance_cents: account.balance_cents,
        currency: account.currency,
        status: account.status
      }
    });

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone } = req.body;

    const updates = {};
    if (name) updates.name = name;
    if (phone !== undefined) updates.phone = phone;
    updates.updated_at = new Date();

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true }
    );

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        profile_picture: user.profile_picture,
        email_verified: user.email_verified
      }
    });

  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

// Account Routes
app.get('/api/account/transactions', authenticateToken, async (req, res) => {
  try {
    const account = await Account.findOne({ user_id: req.user._id });
    
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    const transactions = await Transaction.find({ user_id: req.user._id })
      .sort({ created_at: -1 })
      .limit(20);

    res.json({
      transactions: transactions.map(t => ({
        id: t._id,
        amount_cents: t.amount_cents,
        currency: t.currency,
        type: t.type,
        description: t.description,
        status: t.status,
        counterparty_name: t.counterparty_name,
        counterparty_account: t.counterparty_account,
        created_at: t.created_at
      }))
    });

  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

app.post('/api/account/deposit', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, description } = req.body;

    if (!amount_cents || amount_cents <= 0) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }

    const account = await Account.findOne({ user_id: req.user._id });
    
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Update balance
    account.balance_cents += amount_cents;
    await account.save();

    // Create transaction record
    const transaction = new Transaction({
      user_id: req.user._id,
      account_id: account._id,
      amount_cents: amount_cents,
      type: 'deposit',
      description: description || 'Account deposit',
      status: 'completed'
    });

    await transaction.save();

    // Emit balance update via socket
    io.emit('balance_update', {
      user_id: req.user._id.toString(),
      balance_cents: account.balance_cents
    });

    res.json({
      message: 'Deposit successful',
      new_balance: account.balance_cents,
      transaction_id: transaction._id
    });

  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

app.post('/api/account/transfer', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, recipient_email, description } = req.body;

    if (!amount_cents || amount_cents <= 0 || !recipient_email) {
      return res.status(400).json({ error: 'Valid amount and recipient email are required' });
    }

    const senderAccount = await Account.findOne({ user_id: req.user._id });
    if (!senderAccount) {
      return res.status(404).json({ error: 'Sender account not found' });
    }

    if (senderAccount.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Find recipient
    const recipient = await User.findOne({ email: recipient_email.toLowerCase() });
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    const recipientAccount = await Account.findOne({ user_id: recipient._id });
    if (!recipientAccount) {
      return res.status(404).json({ error: 'Recipient account not found' });
    }

    // Update balances
    senderAccount.balance_cents -= amount_cents;
    recipientAccount.balance_cents += amount_cents;

    await senderAccount.save();
    await recipientAccount.save();

    // Create transactions for both parties
    const senderTransaction = new Transaction({
      user_id: req.user._id,
      account_id: senderAccount._id,
      amount_cents: -amount_cents,
      type: 'transfer',
      description: description || `Transfer to ${recipient_email}`,
      status: 'completed',
      counterparty_name: recipient.name,
      counterparty_account: recipientAccount.account_number
    });

    const recipientTransaction = new Transaction({
      user_id: recipient._id,
      account_id: recipientAccount._id,
      amount_cents: amount_cents,
      type: 'transfer',
      description: description || `Transfer from ${req.user.email}`,
      status: 'completed',
      counterparty_name: req.user.name,
      counterparty_account: senderAccount.account_number
    });

    await senderTransaction.save();
    await recipientTransaction.save();

    // Emit balance updates
    io.emit('balance_update', {
      user_id: req.user._id.toString(),
      balance_cents: senderAccount.balance_cents
    });

    io.emit('balance_update', {
      user_id: recipient._id.toString(),
      balance_cents: recipientAccount.balance_cents
    });

    res.json({
      message: 'Transfer successful',
      new_balance: senderAccount.balance_cents,
      transaction_id: senderTransaction._id
    });

  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

// Card Routes
app.get('/api/cards', authenticateToken, async (req, res) => {
  try {
    const cards = await Card.find({ user_id: req.user._id }).sort({ created_at: -1 });

    res.json({
      cards: cards.map(card => ({
        _id: card._id,
        card_number: card.card_number,
        last4: card.last4,
        expiry_month: card.expiry_month,
        expiry_year: card.expiry_year,
        brand: card.brand,
        status: card.status,
        billing_address: card.billing_address,
        phone_number: card.phone_number,
        card_type: card.card_type,
        card_network: card.card_network,
        created_at: card.created_at
      }))
    });

  } catch (error) {
    console.error('Get cards error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

app.post('/api/cards', authenticateToken, async (req, res) => {
  try {
    const account = await Account.findOne({ user_id: req.user._id });
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Generate card details
    const cardNumber = generateCardNumber();
    const currentYear = new Date().getFullYear();
    
    const card = new Card({
      user_id: req.user._id,
      card_number: cardNumber,
      last4: cardNumber.slice(-4),
      expiry_month: Math.floor(Math.random() * 12) + 1,
      expiry_year: currentYear + 3,
      cvv: generateCVV(),
      brand: 'Visa',
      status: 'active'
    });

    await card.save();

    res.json({
      message: 'Virtual card created successfully',
      card: {
        _id: card._id,
        card_number: card.card_number,
        last4: card.last4,
        expiry_month: card.expiry_month,
        expiry_year: card.expiry_year,
        cvv: card.cvv,
        brand: card.brand,
        status: card.status,
        billing_address: card.billing_address,
        phone_number: card.phone_number,
        card_type: card.card_type,
        card_network: card.card_network,
        created_at: card.created_at
      }
    });

  } catch (error) {
    console.error('Create card error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

app.get('/api/cards/:cardId', authenticateToken, async (req, res) => {
  try {
    const card = await Card.findOne({ 
      _id: req.params.cardId, 
      user_id: req.user._id 
    });

    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Get card transactions
    const transactions = await Transaction.find({ 
      user_id: req.user._id 
    }).sort({ created_at: -1 }).limit(10);

    res.json({
      card: {
        _id: card._id,
        card_number: card.card_number,
        last4: card.last4,
        expiry_month: card.expiry_month,
        expiry_year: card.expiry_year,
        brand: card.brand,
        status: card.status,
        billing_address: card.billing_address,
        phone_number: card.phone_number,
        card_type: card.card_type,
        card_network: card.card_network,
        created_at: card.created_at
      },
      transactions: transactions.map(t => ({
        _id: t._id,
        amount_cents: t.amount_cents,
        currency: t.currency,
        type: t.type,
        description: t.description,
        status: t.status,
        created_at: t.created_at
      }))
    });

  } catch (error) {
    console.error('Get card error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

app.post('/api/cards/:cardId/block', authenticateToken, async (req, res) => {
  try {
    const card = await Card.findOne({ 
      _id: req.params.cardId, 
      user_id: req.user._id 
    });

    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Toggle card status
    card.status = card.status === 'active' ? 'blocked' : 'active';
    await card.save();

    res.json({
      message: `Card ${card.status === 'active' ? 'unblocked' : 'blocked'} successfully`,
      card: {
        _id: card._id,
        status: card.status
      }
    });

  } catch (error) {
    console.error('Block card error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

// External Transfer Route
app.post('/api/transfers/external', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, recipient_name, recipient_account_number, routing_number, description } = req.body;

    if (!amount_cents || amount_cents <= 0 || !recipient_name || !recipient_account_number || !routing_number) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const account = await Account.findOne({ user_id: req.user._id });
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    if (account.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Update balance
    account.balance_cents -= amount_cents;
    await account.save();

    // Create transaction record
    const transaction = new Transaction({
      user_id: req.user._id,
      account_id: account._id,
      amount_cents: -amount_cents,
      type: 'transfer',
      description: description || `External transfer to ${recipient_name}`,
      status: 'completed',
      counterparty_name: recipient_name,
      counterparty_account: recipient_account_number
    });

    await transaction.save();

    // Emit balance update
    io.emit('balance_update', {
      user_id: req.user._id.toString(),
      balance_cents: account.balance_cents
    });

    res.json({
      message: 'External transfer initiated successfully',
      new_balance: account.balance_cents,
      transaction_id: transaction._id
    });

  } catch (error) {
    console.error('External transfer error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

// Handle all other routes - serve the frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Socket.IO authentication
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('authenticate', (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.userId = decoded.userId;
      console.log('User authenticated via socket:', decoded.userId);
    } catch (error) {
      console.log('Socket authentication failed');
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Connect to MongoDB
const connectToDatabase = async () => {
  try {
    console.log('🔗 Attempting to connect to MongoDB...');
    
    if (!process.env.MONGODB_URI) {
      console.log('❌ MONGODB_URI environment variable is not set');
      console.log('💡 Please set MONGODB_URI in your environment variables');
      return;
    }

    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Successfully connected to MongoDB!');
  } catch (error) {
    console.log('❌ MongoDB connection failed:', error.message);
  }
};

// Start server
const startServer = async () => {
  await connectToDatabase();
  
  server.listen(PORT, '0.0.0.0', () => {
    console.log('\n🚀 HCB Clone Server Started');
    console.log(`📍 Port: ${PORT}`);
    console.log(`📊 Database: ${mongoose.connection.readyState === 1 ? 'Connected ✅' : 'Not Connected ❌'}`);
    
    if (mongoose.connection.readyState === 1) {
      console.log('🎉 All systems ready! Your banking app is fully functional.');
    }
    
    console.log(`\n🔗 Health Check: http://localhost:${PORT}/health`);
  });
};

startServer().catch(console.error);
