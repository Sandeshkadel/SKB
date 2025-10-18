require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const socketIo = require('socket.io');
const http = require('http');
const cors = require('cors');
const axios = require('axios');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const server = http.createServer(app);

// Configuration
const PORT = process.env.PORT || 3000;
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key-2024';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/hcb-real-clone';
const COLUMN_API_KEY = process.env.COLUMN_API_KEY;
const COLUMN_BASE_URL = process.env.COLUMN_BASE_URL || 'https://sandbox.column.com';

// Configure Socket.IO
const io = socketIo(server, {
  cors: {
    origin: CLIENT_URL,
    methods: ["GET", "POST"]
  }
});

// Configure email transporter
let transporter;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  transporter = nodemailer.createTransporter({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
}

// Middleware
app.use(cors({
  origin: CLIENT_URL,
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// Database Models
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  name: { type: String, required: true },
  hashed_password: { type: String, required: true },
  profile_picture: { type: String, default: null },
  phone: { type: String, default: null },
  address: {
    street: String,
    city: String,
    state: String,
    zip_code: String,
    country: { type: String, default: 'US' }
  },
  status: { type: String, enum: ['pending', 'active', 'suspended'], default: 'pending' },
  kyc_status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  email_verified: { type: Boolean, default: false },
  two_factor_enabled: { type: Boolean, default: true },
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
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer', 'payment'], required: true },
  amount_cents: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  description: String,
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  counterparty_name: String,
  counterparty_email: String,
  column_transaction_id: String,
  metadata: mongoose.Schema.Types.Mixed,
  created_at: { type: Date, default: Date.now }
});

const VirtualCardSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  card_number: { type: String, required: true },
  last4: { type: String, required: true },
  expiry_month: { type: Number, required: true },
  expiry_year: { type: Number, required: true },
  cvv: { type: String, required: true },
  brand: { type: String, default: 'Visa' },
  type: { type: String, enum: ['virtual', 'physical'], default: 'virtual' },
  status: { type: String, enum: ['active', 'blocked', 'cancelled'], default: 'active' },
  billing_address: {
    street: { type: String, default: '8605 Santa Monica Blvd #86294' },
    city: { type: String, default: 'West Hollywood' },
    state: { type: String, default: 'CA' },
    zip_code: { type: String, default: '90069' },
    country: { type: String, default: 'US' }
  },
  phone_number: { type: String, default: '970-856-6136' },
  card_network: { type: String, default: 'Visa' },
  card_type: { type: String, default: 'Virtual' },
  spending_limit_cents: { type: Number, default: 1000000 },
  current_spend_cents: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now }
});

const CardTransactionSchema = new mongoose.Schema({
  card_id: { type: mongoose.Schema.Types.ObjectId, ref: 'VirtualCard', required: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount_cents: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  merchant_name: { type: String, required: true },
  merchant_category: String,
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'declined', 'cancelled'], 
    default: 'pending' 
  },
  description: String,
  location: {
    city: String,
    state: String,
    country: String
  },
  receipt_image: String,
  receipt_notes: String,
  transaction_date: { type: Date, default: Date.now },
  created_at: { type: Date, default: Date.now }
});

const OTPSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  otp: { type: String, required: true },
  type: { type: String, enum: ['login', 'verification', 'reset'], required: true },
  expires_at: { type: Date, required: true },
  used: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Account = mongoose.model('Account', AccountSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const VirtualCard = mongoose.model('VirtualCard', VirtualCardSchema);
const CardTransaction = mongoose.model('CardTransaction', CardTransactionSchema);
const OTP = mongoose.model('OTP', OTPSchema);

// Column API Configuration
const columnAPI = axios.create({
  baseURL: COLUMN_BASE_URL,
  headers: {
    'Authorization': `Bearer ${COLUMN_API_KEY}`,
    'Content-Type': 'application/json'
  }
});

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user || user.status !== 'active') {
      return res.status(401).json({ error: 'Invalid token or user inactive' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// WebSocket for Real-time Updates
const userSockets = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId);
      
      if (user) {
        userSockets.set(user._id.toString(), socket.id);
        socket.userId = user._id.toString();
        
        const account = await Account.findOne({ user_id: user._id });
        if (account) {
          socket.emit('balance_update', {
            balance_cents: account.balance_cents,
            currency: account.currency
          });
        }
      }
    } catch (error) {
      socket.emit('error', 'Authentication failed');
    }
  });

  socket.on('disconnect', () => {
    if (socket.userId) {
      userSockets.delete(socket.userId);
    }
    console.log('User disconnected:', socket.id);
  });
});

// Helper Functions
const emitBalanceUpdate = async (userId) => {
  const account = await Account.findOne({ user_id: userId });
  const socketId = userSockets.get(userId.toString());
  
  if (socketId && account) {
    io.to(socketId).emit('balance_update', {
      balance_cents: account.balance_cents,
      currency: account.currency
    });
  }
};

const generateAccountNumber = () => {
  return 'HCB' + Date.now() + Math.floor(Math.random() * 1000);
};

const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const sendOTPEmail = async (user, otp) => {
  if (!transporter) {
    console.log('Email not configured. OTP would be:', otp);
    return;
  }

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: 'Your HCB Clone Login OTP',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #7C3AED;">HCB Clone Security Code</h2>
        <p>Hello ${user.name},</p>
        <p>Your One-Time Password (OTP) for login is:</p>
        <div style="background-color: #f3f4f6; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; margin: 20px 0;">
          ${otp}
        </div>
        <p>This OTP will expire in 10 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
        <p>Stay secure,<br>The HCB Clone Team</p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Failed to send OTP email:', error);
  }
};

const createSampleCardTransactions = async (cardId, userId) => {
  const sampleTransactions = [
    {
      merchant_name: 'SINCH MAILGUN',
      amount_cents: -2702,
      status: 'declined',
      description: 'Email service subscription',
      location: { city: 'San Francisco', state: 'CA', country: 'US' },
      transaction_date: new Date('2025-10-08')
    },
    {
      merchant_name: 'FOODMANDU PVT. LTD.',
      amount_cents: -702,
      status: 'declined',
      description: 'Food delivery',
      location: { city: 'Kathmandu', state: '', country: 'NP' },
      transaction_date: new Date('2025-08-27')
    },
    {
      merchant_name: 'FOODMANDU PVT. LTD.',
      amount_cents: -853,
      status: 'declined',
      description: 'Food delivery',
      location: { city: 'Kathmandu', state: '', country: 'NP' },
      transaction_date: new Date('2025-08-27')
    },
    {
      merchant_name: 'FOODMANDU PVT. LTD.',
      amount_cents: -794,
      status: 'completed',
      description: 'Food delivery',
      location: { city: 'Kathmandu', state: '', country: 'NP' },
      transaction_date: new Date('2025-08-28')
    },
    {
      merchant_name: 'AMAZON WEB SERVICES',
      amount_cents: -2945,
      status: 'completed',
      description: 'Cloud services',
      location: { city: 'Seattle', state: 'WA', country: 'US' },
      transaction_date: new Date('2025-09-15')
    }
  ];

  for (const transaction of sampleTransactions) {
    const cardTransaction = new CardTransaction({
      card_id: cardId,
      user_id: userId,
      ...transaction
    });
    await cardTransaction.save();
  }
};

// Input validation helper
const validateInput = (fields) => {
  const errors = [];
  
  if (fields.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields.email)) {
    errors.push({ field: 'email', message: 'Invalid email format' });
  }
  
  if (fields.password && fields.password.length < 6) {
    errors.push({ field: 'password', message: 'Password must be at least 6 characters' });
  }
  
  if (fields.name && !fields.name.trim()) {
    errors.push({ field: 'name', message: 'Name is required' });
  }
  
  return errors;
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Auth Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;

    const errors = validateInput({ email, password, name });
    if (errors.length > 0) {
      return res.status(400).json({ errors });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = new User({
      email,
      name,
      phone,
      hashed_password: hashedPassword
    });

    await user.save();

    const account = new Account({
      user_id: user._id,
      account_number: generateAccountNumber()
    });
    await account.save();

    res.status(201).json({
      message: 'Account created successfully.',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error during signup' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const errors = validateInput({ email, password });
    if (errors.length > 0) {
      return res.status(400).json({ errors });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isValidPassword = await bcrypt.compare(password, user.hashed_password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (user.status !== 'active') {
      return res.status(401).json({ error: 'Account is not active' });
    }

    const otp = generateOTP();

    const otpRecord = new OTP({
      user_id: user._id,
      otp,
      type: 'login',
      expires_at: new Date(Date.now() + 10 * 60 * 1000)
    });
    await otpRecord.save();

    await sendOTPEmail(user, otp);

    res.json({
      message: 'OTP sent to your email',
      user_id: user._id,
      email: user.email,
      otp: otp // Remove in production
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { user_id, otp } = req.body;

    if (!user_id || !otp || otp.length !== 6) {
      return res.status(400).json({ error: 'User ID and 6-digit OTP are required' });
    }

    const otpRecord = await OTP.findOne({
      user_id,
      otp,
      type: 'login',
      used: false,
      expires_at: { $gt: new Date() }
    });

    if (!otpRecord) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    otpRecord.used = true;
    await otpRecord.save();

    const user = await User.findById(user_id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    const account = await Account.findOne({ user_id: user._id });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        profile_picture: user.profile_picture
      },
      account: account ? {
        account_number: account.account_number,
        balance_cents: account.balance_cents,
        currency: account.currency
      } : null
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
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

    const otp = generateOTP();

    const otpRecord = new OTP({
      user_id: user._id,
      otp,
      type: 'login',
      expires_at: new Date(Date.now() + 10 * 60 * 1000)
    });
    await otpRecord.save();

    await sendOTPEmail(user, otp);

    res.json({
      message: 'New OTP sent to your email',
      user_id: user._id
    });

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Failed to resend OTP' });
  }
});

// Profile Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-hashed_password');
    const account = await Account.findOne({ user_id: req.user._id });
    
    res.json({
      user,
      account: account ? {
        account_number: account.account_number,
        balance_cents: account.balance_cents,
        currency: account.currency
      } : null
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone, address } = req.body;
    const updates = {};

    if (name && name.trim()) updates.name = name.trim();
    if (phone) updates.phone = phone;
    if (address) updates.address = address;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true }
    ).select('-hashed_password');

    res.json({ message: 'Profile updated successfully', user });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Account Routes
app.get('/api/account/balance', authenticateToken, async (req, res) => {
  try {
    const account = await Account.findOne({ user_id: req.user._id });
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    res.json({
      balance_cents: account.balance_cents,
      currency: account.currency,
      account_number: account.account_number
    });
  } catch (error) {
    console.error('Balance fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/account/transactions', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const transactions = await Transaction.find({ user_id: req.user._id })
      .sort({ created_at: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Transaction.countDocuments({ user_id: req.user._id });

    res.json({
      transactions,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Transactions fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Deposit Route
app.post('/api/account/deposit', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, description } = req.body;

    if (!amount_cents || amount_cents < 100) {
      return res.status(400).json({ error: 'Amount must be at least 100 cents ($1.00)' });
    }

    const account = await Account.findOne({ user_id: req.user._id });
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    account.balance_cents += amount_cents;
    await account.save();

    const transaction = new Transaction({
      user_id: req.user._id,
      account_id: account._id,
      type: 'deposit',
      amount_cents,
      description: description || 'Account deposit',
      status: 'completed'
    });
    await transaction.save();

    await emitBalanceUpdate(req.user._id);

    res.json({
      message: 'Deposit completed successfully',
      new_balance: account.balance_cents,
      transaction_id: transaction._id
    });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ error: 'Deposit failed' });
  }
});

// Transfer Route
app.post('/api/account/transfer', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, recipient_email, description } = req.body;

    if (!amount_cents || amount_cents < 1) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }

    if (!recipient_email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient_email)) {
      return res.status(400).json({ error: 'Valid recipient email is required' });
    }

    const senderAccount = await Account.findOne({ user_id: req.user._id });
    if (!senderAccount) {
      return res.status(404).json({ error: 'Account not found' });
    }

    if (senderAccount.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    const recipient = await User.findOne({ email: recipient_email });
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    const recipientAccount = await Account.findOne({ user_id: recipient._id });
    if (!recipientAccount) {
      return res.status(404).json({ error: 'Recipient account not found' });
    }

    senderAccount.balance_cents -= amount_cents;
    recipientAccount.balance_cents += amount_cents;

    await senderAccount.save();
    await recipientAccount.save();

    const senderTransaction = new Transaction({
      user_id: req.user._id,
      account_id: senderAccount._id,
      type: 'transfer',
      amount_cents: -amount_cents,
      description: description || `Transfer to ${recipient_email}`,
      status: 'completed',
      counterparty_name: recipient.name,
      counterparty_email: recipient_email
    });

    const recipientTransaction = new Transaction({
      user_id: recipient._id,
      account_id: recipientAccount._id,
      type: 'transfer',
      amount_cents: amount_cents,
      description: description || `Transfer from ${req.user.email}`,
      status: 'completed',
      counterparty_name: req.user.name,
      counterparty_email: req.user.email
    });

    await senderTransaction.save();
    await recipientTransaction.save();

    await emitBalanceUpdate(req.user._id);
    await emitBalanceUpdate(recipient._id);

    res.json({
      message: 'Transfer completed successfully',
      new_balance: senderAccount.balance_cents,
      transaction_id: senderTransaction._id
    });
  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({ error: 'Transfer failed' });
  }
});

// Card Routes
app.post('/api/cards', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const account = await Account.findOne({ user_id: user._id });

    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    const generateCardNumber = () => {
      const bin = '4532';
      const random = Array.from({ length: 12 }, () => 
        Math.floor(Math.random() * 10)
      ).join('');
      return bin + random;
    };

    const cardNumber = generateCardNumber();
    const currentYear = new Date().getFullYear();

    const virtualCard = new VirtualCard({
      user_id: user._id,
      card_number: cardNumber,
      last4: cardNumber.slice(-4),
      expiry_month: Math.floor(Math.random() * 12) + 1,
      expiry_year: currentYear + 3,
      cvv: Array.from({ length: 3 }, () => Math.floor(Math.random() * 10)).join(''),
      brand: 'Visa'
    });

    await virtualCard.save();

    await createSampleCardTransactions(virtualCard._id, user._id);

    res.status(201).json({
      message: 'Virtual card created successfully',
      card: {
        id: virtualCard._id,
        card_number: virtualCard.card_number,
        last4: virtualCard.last4,
        expiry_month: virtualCard.expiry_month,
        expiry_year: virtualCard.expiry_year,
        cvv: virtualCard.cvv,
        brand: virtualCard.brand,
        status: virtualCard.status,
        billing_address: virtualCard.billing_address,
        phone_number: virtualCard.phone_number,
        card_network: virtualCard.card_network,
        card_type: virtualCard.card_type,
        created_at: virtualCard.created_at
      }
    });
  } catch (error) {
    console.error('Card creation error:', error);
    res.status(500).json({ error: 'Failed to create virtual card' });
  }
});

app.get('/api/cards', authenticateToken, async (req, res) => {
  try {
    const cards = await VirtualCard.find({ user_id: req.user._id })
      .sort({ created_at: -1 });

    res.json({ cards });
  } catch (error) {
    console.error('Get cards error:', error);
    res.status(500).json({ error: 'Failed to fetch cards' });
  }
});

app.get('/api/cards/:cardId', authenticateToken, async (req, res) => {
  try {
    const card = await VirtualCard.findOne({
      _id: req.params.cardId,
      user_id: req.user._id
    });

    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    const transactions = await CardTransaction.find({
      card_id: card._id
    }).sort({ transaction_date: -1 });

    res.json({
      card,
      transactions
    });
  } catch (error) {
    console.error('Get card details error:', error);
    res.status(500).json({ error: 'Failed to fetch card details' });
  }
});

app.post('/api/cards/:id/block', authenticateToken, async (req, res) => {
  try {
    const card = await VirtualCard.findOne({
      _id: req.params.id,
      user_id: req.user._id
    });

    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    card.status = card.status === 'active' ? 'blocked' : 'active';
    await card.save();

    res.json({
      message: `Card ${card.status === 'active' ? 'unblocked' : 'blocked'} successfully`,
      card
    });
  } catch (error) {
    console.error('Block card error:', error);
    res.status(500).json({ error: 'Failed to update card status' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: dbStatus,
    environment: process.env.NODE_ENV || 'development',
    message: dbStatus === 'connected' ? 
      'Database connected successfully!' : 
      'Database not connected.'
  });
});

// Connect to MongoDB
const connectToDatabase = async () => {
  try {
    console.log('🔗 Connecting to MongoDB...');
    
    if (!MONGODB_URI) {
      console.log('❌ MONGODB_URI not set');
      return;
    }

    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('✅ MongoDB connected successfully!');
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
    console.log(`🌐 URL: ${CLIENT_URL}`);
    console.log(`📊 Database: ${mongoose.connection.readyState === 1 ? 'Connected ✅' : 'Not Connected ❌'}`);
    console.log('🎉 All features available: OTP Auth, Money Transfers, Virtual Cards, Real-time Updates');
    console.log(`\n🔗 Health Check: ${CLIENT_URL}/health`);
  });
};

startServer().catch(console.error);

module.exports = app;
