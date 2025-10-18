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
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key-2024';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/hcb-real-clone';

console.log('🔧 Environment Check:');
console.log('MONGODB_URI:', process.env.MONGODB_URI ? '✅ Set' : '❌ Not set');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? '✅ Set' : '❌ Not set');
console.log('CLIENT_URL:', process.env.CLIENT_URL || 'Using default');

// Configure Socket.IO
const io = socketIo(server, {
  cors: {
    origin: CLIENT_URL,
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors({
  origin: CLIENT_URL,
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
  kyc_status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

const AccountSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  account_number: { type: String, required: true, unique: true },
  routing_number: { type: String, default: '021000021' },
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
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
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
    street: String,
    city: String,
    state: String,
    zip_code: String,
    country: { type: String, default: 'US' }
  },
  phone_number: String,
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
  return 'HCB' + Math.random().toString().slice(2, 11);
};

// Generate card number
const generateCardNumber = () => {
  const bin = '453245'; // Visa BIN
  const accountPart = Math.random().toString().slice(2, 11);
  const cardNumber = bin + accountPart.padEnd(10, '0').slice(0, 10);
  
  // Simple Luhn check digit
  let sum = 0;
  for (let i = 0; i < 15; i++) {
    let digit = parseInt(cardNumber[i]);
    if (i % 2 === 0) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  const checkDigit = (10 - (sum % 10)) % 10;
  
  return cardNumber + checkDigit;
};

// Generate CVV
const generateCVV = () => {
  return Math.floor(100 + Math.random() * 900).toString();
};

// Auth middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

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

// Auth Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;

    // Check if user exists
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
      phone,
      status: 'pending'
    });

    await user.save();

    // Create account
    const account = new Account({
      user_id: user._id,
      account_number: generateAccountNumber(),
      balance_cents: 0
    });

    await account.save();

    // Generate OTP (in real app, send via email)
    const otp = generateOTP();
    const otpRecord = new OTP({
      user_id: user._id,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });

    await otpRecord.save();

    console.log(`OTP for ${email}: ${otp}`); // In production, send via email

    res.status(201).json({
      message: 'User created successfully. Please check your email for OTP.',
      user_id: user._id,
      email: user.email
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.hashed_password);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Generate OTP
    const otp = generateOTP();
    
    // Invalidate previous OTPs
    await OTP.updateMany(
      { user_id: user._id, used: false },
      { used: true }
    );

    const otpRecord = new OTP({
      user_id: user._id,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000)
    });

    await otpRecord.save();

    console.log(`OTP for ${email}: ${otp}`); // In production, send via email

    res.json({
      message: 'OTP sent to your email',
      user_id: user._id,
      email: user.email
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { user_id, otp } = req.body;

    // Find valid OTP
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

    // Update user
    const user = await User.findById(user_id);
    user.email_verified = true;
    user.status = 'active';
    await user.save();

    // Get account
    const account = await Account.findOne({ user_id });

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
        _id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        email_verified: user.email_verified,
        kyc_status: user.kyc_status
      },
      account: {
        _id: account._id,
        account_number: account.account_number,
        balance_cents: account.balance_cents,
        currency: account.currency
      }
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const { user_id } = req.body;

    const user = await User.findById(user_id);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Generate new OTP
    const otp = generateOTP();
    
    // Invalidate previous OTPs
    await OTP.updateMany(
      { user_id: user._id, used: false },
      { used: true }
    );

    const otpRecord = new OTP({
      user_id: user._id,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000)
    });

    await otpRecord.save();

    console.log(`New OTP for ${user.email}: ${otp}`); // In production, send via email

    res.json({
      message: 'New OTP sent to your email',
      user_id: user._id
    });

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Profile Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const account = await Account.findOne({ user_id: req.user._id });
    
    res.json({
      user: {
        _id: req.user._id,
        email: req.user.email,
        name: req.user.name,
        phone: req.user.phone,
        profile_picture: req.user.profile_picture,
        email_verified: req.user.email_verified,
        kyc_status: req.user.kyc_status
      },
      account: {
        _id: account._id,
        account_number: account.account_number,
        balance_cents: account.balance_cents,
        currency: account.currency
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone } = req.body;

    const user = await User.findById(req.user._id);
    if (name) user.name = name;
    if (phone) user.phone = phone;
    
    await user.save();

    res.json({
      user: {
        _id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        profile_picture: user.profile_picture,
        email_verified: user.email_verified,
        kyc_status: user.kyc_status
      }
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Account Routes
app.get('/api/account/transactions', authenticateToken, async (req, res) => {
  try {
    const account = await Account.findOne({ user_id: req.user._id });
    const transactions = await Transaction.find({ user_id: req.user._id })
      .sort({ created_at: -1 })
      .limit(20);

    res.json({
      transactions: transactions.map(t => ({
        _id: t._id,
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
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/account/deposit', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, description } = req.body;
    const account = await Account.findOne({ user_id: req.user._id });

    // Update balance
    account.balance_cents += amount_cents;
    await account.save();

    // Create transaction
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
      transaction: {
        _id: transaction._id,
        amount_cents: transaction.amount_cents,
        description: transaction.description,
        status: transaction.status
      },
      new_balance: account.balance_cents
    });

  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/account/transfer', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, recipient_email, description } = req.body;
    const account = await Account.findOne({ user_id: req.user._id });

    // Check balance
    if (account.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Find recipient
    const recipient = await User.findOne({ email: recipient_email.toLowerCase() });
    if (!recipient) {
      return res.status(400).json({ error: 'Recipient not found' });
    }

    const recipientAccount = await Account.findOne({ user_id: recipient._id });

    // Update balances
    account.balance_cents -= amount_cents;
    recipientAccount.balance_cents += amount_cents;

    await account.save();
    await recipientAccount.save();

    // Create transactions for both users
    const senderTransaction = new Transaction({
      user_id: req.user._id,
      account_id: account._id,
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
      counterparty_account: account.account_number
    });

    await senderTransaction.save();
    await recipientTransaction.save();

    // Emit balance updates
    io.emit('balance_update', {
      user_id: req.user._id.toString(),
      balance_cents: account.balance_cents
    });

    io.emit('balance_update', {
      user_id: recipient._id.toString(),
      balance_cents: recipientAccount.balance_cents
    });

    res.json({
      message: 'Transfer successful',
      transaction: {
        _id: senderTransaction._id,
        amount_cents: senderTransaction.amount_cents,
        description: senderTransaction.description,
        status: senderTransaction.status
      },
      new_balance: account.balance_cents
    });

  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({ error: 'Internal server error' });
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
    console.error('Cards error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cards', authenticateToken, async (req, res) => {
  try {
    const account = await Account.findOne({ user_id: req.user._id });
    
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
      status: 'active',
      billing_address: {
        street: '123 Main St',
        city: 'New York',
        state: 'NY',
        zip_code: '10001',
        country: 'US'
      },
      phone_number: req.user.phone || '+1234567890',
      card_type: 'virtual',
      card_network: 'visa'
    });

    await card.save();

    res.json({
      message: 'Virtual card created successfully',
      card: {
        _id: card._id,
        card_number: card.card_number, // Return full number only on creation
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
    res.status(500).json({ error: 'Internal server error' });
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
      user_id: req.user._id,
      description: { $regex: card.last4, $options: 'i' }
    }).sort({ created_at: -1 }).limit(10);

    res.json({
      card: {
        _id: card._id,
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
        description: t.description,
        status: t.status,
        created_at: t.created_at
      }))
    });

  } catch (error) {
    console.error('Card details error:', error);
    res.status(500).json({ error: 'Internal server error' });
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
        status: card.status,
        last4: card.last4
      }
    });

  } catch (error) {
    console.error('Block card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// External Transfers
app.post('/api/transfers/external', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, recipient_name, recipient_account_number, routing_number, description } = req.body;
    const account = await Account.findOne({ user_id: req.user._id });

    // Check balance
    if (account.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Update balance
    account.balance_cents -= amount_cents;
    await account.save();

    // Create transaction
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
      transaction: {
        _id: transaction._id,
        amount_cents: transaction.amount_cents,
        description: transaction.description,
        status: transaction.status
      },
      new_balance: account.balance_cents
    });

  } catch (error) {
    console.error('External transfer error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Receipt upload (simplified)
app.post('/api/transactions/:transactionId/receipt', authenticateToken, async (req, res) => {
  try {
    // In a real app, you would handle file upload here
    // For now, we'll just return success
    res.json({
      message: 'Receipt added successfully',
      transaction_id: req.params.transactionId
    });
  } catch (error) {
    console.error('Receipt upload error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Socket.IO authentication and events
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
      console.log('💡 Please add MONGODB_URI to your Render environment variables');
      return;
    }

    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('✅ Successfully connected to MongoDB!');
  } catch (error) {
    console.log('❌ MongoDB connection failed:', error.message);
    console.log('💡 Please check your MONGODB_URI in Render environment variables');
  }
};

// Start server
const startServer = async () => {
  await connectToDatabase();
  
  server.listen(PORT, '0.0.0.0', () => {
    console.log('\n🚀 HCB Clone Server Started');
    console.log(`📍 Port: ${PORT}`);
    console.log(`🌐 URL: ${CLIENT_URL}`);
    console.log(`📊 Database: ${mongoose.connection.readyState === 1 ? 'Connected ✅' : 'Not Connected ❌'}`);
    
    if (mongoose.connection.readyState === 1) {
      console.log('🎉 All systems ready! Your banking app is fully functional.');
    } else {
      console.log('\n🔧 To fix database connection:');
      console.log('   1. Go to Render Dashboard → Your Service → Environment');
      console.log('   2. Add MONGODB_URI environment variable');
      console.log('   3. Value: mongodb+srv://your-username:your-password@your-cluster.mongodb.net/hcb-clone');
      console.log('   4. Wait for automatic redeploy');
    }
    
    console.log(`\n🔗 Health Check: ${CLIENT_URL}/health`);
  });
};

startServer().catch(console.error);
