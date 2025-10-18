require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const socketIo = require('socket.io');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const otpGenerator = require('otp-generator');
const { body, validationResult } = require('express-validator');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Email transporter
const transporter = nodemailer.createTransporter({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// File upload configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  }
});

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
  date_of_birth: Date,
  status: { type: String, enum: ['pending', 'active', 'suspended'], default: 'pending' },
  kyc_status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  column_customer_id: String,
  column_account_id: String,
  verification_token: String,
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
  column_payment_id: String,
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
  column_card_id: String,
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
  column_transaction_id: String,
  metadata: mongoose.Schema.Types.Mixed,
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

const VerificationTokenSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token: { type: String, required: true },
  type: { type: String, enum: ['email_verification', 'password_reset'], required: true },
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
const VerificationToken = mongoose.model('VerificationToken', VerificationTokenSchema);

// Column API Configuration
const COLUMN_API_KEY = process.env.COLUMN_API_KEY;
const COLUMN_BASE_URL = process.env.COLUMN_BASE_URL;

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

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
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
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId);
      
      if (user) {
        userSockets.set(user._id.toString(), socket.id);
        socket.userId = user._id.toString();
        
        // Send initial balance
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

const sendOTPEmail = async (user, otp) => {
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

  await transporter.sendMail(mailOptions);
};

const sendVerificationEmail = async (user, token) => {
  const verificationUrl = `${process.env.CLIENT_URL}/verify-email?token=${token}`;
  
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: 'Verify Your HCB Clone Account',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #7C3AED;">Welcome to HCB Clone!</h2>
        <p>Hello ${user.name},</p>
        <p>Please verify your email address by clicking the button below:</p>
        <a href="${verificationUrl}" 
           style="background-color: #7C3AED; color: white; padding: 12px 24px; 
                  text-decoration: none; border-radius: 6px; display: inline-block;">
          Verify Email
        </a>
        <p>Or copy this link: ${verificationUrl}</p>
        <p>This link will expire in 24 hours.</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
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
      merchant_name: 'DARAZ KAYMU PVT LTD',
      amount_cents: -946,
      status: 'declined',
      description: 'Online shopping',
      location: { city: 'Kathmandu', state: '', country: 'NP' },
      transaction_date: new Date('2025-08-27')
    },
    {
      merchant_name: 'AMAZON WEB SERVICES',
      amount_cents: -2945,
      status: 'completed',
      description: 'Cloud services',
      location: { city: 'Seattle', state: 'WA', country: 'US' },
      transaction_date: new Date('2025-09-15')
    },
    {
      merchant_name: 'SPOTIFY',
      amount_cents: -1299,
      status: 'completed',
      description: 'Music subscription',
      location: { city: 'New York', state: 'NY', country: 'US' },
      transaction_date: new Date('2025-09-10')
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

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Auth Routes
app.post('/api/auth/signup', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('name').notEmpty().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, name, phone } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create Column customer
    let columnCustomerId;
    try {
      const customerResponse = await columnAPI.post('/customers', {
        name,
        email,
        type: 'individual'
      });
      columnCustomerId = customerResponse.data.id;
    } catch (error) {
      console.error('Column customer creation failed:', error.response?.data);
      return res.status(500).json({ error: 'Failed to create financial account' });
    }

    // Create user
    const user = new User({
      email,
      name,
      phone,
      hashed_password: hashedPassword,
      column_customer_id: columnCustomerId,
      verification_token: uuidv4()
    });

    await user.save();

    // Create account
    const account = new Account({
      user_id: user._id,
      account_number: generateAccountNumber()
    });
    await account.save();

    // Create verification token
    const verificationToken = new VerificationToken({
      user_id: user._id,
      token: uuidv4(),
      type: 'email_verification',
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
    });
    await verificationToken.save();

    // Send verification email
    await sendVerificationEmail(user, verificationToken.token);

    res.status(201).json({
      message: 'Account created successfully. Please check your email for verification.',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        email_verified: user.email_verified,
        kyc_status: user.kyc_status
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error during signup' });
  }
});

app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

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

    // Generate OTP
    const otp = otpGenerator.generate(6, {
      digits: true,
      alphabets: false,
      upperCase: false,
      specialChars: false
    });

    // Save OTP to database
    const otpRecord = new OTP({
      user_id: user._id,
      otp,
      type: 'login',
      expires_at: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });
    await otpRecord.save();

    // Send OTP via email
    await sendOTPEmail(user, otp);

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

app.post('/api/auth/verify-otp', [
  body('user_id').notEmpty(),
  body('otp').isLength({ min: 6, max: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { user_id, otp } = req.body;

    // Find valid OTP
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

    // Mark OTP as used
    otpRecord.used = true;
    await otpRecord.save();

    // Get user
    const user = await User.findById(user_id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    // Get account info
    const account = await Account.findOne({ user_id: user._id });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        profile_picture: user.profile_picture,
        email_verified: user.email_verified,
        kyc_status: user.kyc_status
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

app.post('/api/auth/resend-otp', [
  body('user_id').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { user_id } = req.body;

    const user = await User.findById(user_id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate new OTP
    const otp = otpGenerator.generate(6, {
      digits: true,
      alphabets: false,
      upperCase: false,
      specialChars: false
    });

    // Save OTP to database
    const otpRecord = new OTP({
      user_id: user._id,
      otp,
      type: 'login',
      expires_at: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });
    await otpRecord.save();

    // Send OTP via email
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

app.post('/api/auth/verify-email', async (req, res) => {
  try {
    const { token } = req.body;

    const verificationToken = await VerificationToken.findOne({ 
      token, 
      type: 'email_verification',
      used: false,
      expires_at: { $gt: new Date() }
    }).populate('user_id');

    if (!verificationToken) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }

    const user = verificationToken.user_id;
    user.email_verified = true;
    user.status = 'active';
    await user.save();

    verificationToken.used = true;
    await verificationToken.save();

    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
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

app.put('/api/profile', authenticateToken, [
  body('name').optional().trim(),
  body('phone').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, phone, address, date_of_birth } = req.body;
    const updates = {};

    if (name) updates.name = name;
    if (phone) updates.phone = phone;
    if (address) updates.address = address;
    if (date_of_birth) updates.date_of_birth = new Date(date_of_birth);

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true, runValidators: true }
    ).select('-hashed_password');

    res.json({ message: 'Profile updated successfully', user });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/profile/picture', authenticateToken, upload.single('profile_picture'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Upload to Cloudinary
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: 'hcb-clone/profiles' },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );
      stream.end(req.file.buffer);
    });

    // Update user profile picture
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { profile_picture: result.secure_url },
      { new: true }
    ).select('-hashed_password');

    res.json({ 
      message: 'Profile picture updated successfully', 
      user,
      profile_picture: result.secure_url 
    });
  } catch (error) {
    console.error('Profile picture upload error:', error);
    res.status(500).json({ error: 'Failed to upload profile picture' });
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
app.post('/api/account/deposit', authenticateToken, [
  body('amount_cents').isInt({ min: 100 }),
  body('currency').isLength({ min: 3, max: 3 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount_cents, currency, description } = req.body;

    const account = await Account.findOne({ user_id: req.user._id });
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Create Column payment for deposit
    let columnPaymentId;
    try {
      const paymentResponse = await columnAPI.post('/payments', {
        amount: amount_cents,
        currency: currency.toLowerCase(),
        description: description || 'Account deposit',
        status: 'completed'
      });
      columnPaymentId = paymentResponse.data.id;
    } catch (error) {
      console.error('Column deposit failed:', error.response?.data);
      return res.status(500).json({ error: 'Deposit processing failed' });
    }

    // Update account balance
    account.balance_cents += amount_cents;
    await account.save();

    // Create transaction record
    const transaction = new Transaction({
      user_id: req.user._id,
      account_id: account._id,
      type: 'deposit',
      amount_cents,
      currency,
      description: description || 'Account deposit',
      status: 'completed',
      column_payment_id: columnPaymentId
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
app.post('/api/account/transfer', authenticateToken, [
  body('amount_cents').isInt({ min: 1 }),
  body('recipient_email').isEmail(),
  body('description').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount_cents, recipient_email, description } = req.body;

    const senderAccount = await Account.findOne({ user_id: req.user._id });
    if (!senderAccount) {
      return res.status(404).json({ error: 'Account not found' });
    }

    if (senderAccount.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Check if recipient exists
    const recipient = await User.findOne({ email: recipient_email });
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    const recipientAccount = await Account.findOne({ user_id: recipient._id });
    if (!recipientAccount) {
      return res.status(404).json({ error: 'Recipient account not found' });
    }

    // Process transfer
    senderAccount.balance_cents -= amount_cents;
    recipientAccount.balance_cents += amount_cents;

    await senderAccount.save();
    await recipientAccount.save();

    // Create transactions for both users
    const senderTransaction = new Transaction({
      user_id: req.user._id,
      account_id: senderAccount._id,
      type: 'transfer',
      amount_cents: -amount_cents,
      currency: 'USD',
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
      currency: 'USD',
      description: description || `Transfer from ${req.user.email}`,
      status: 'completed',
      counterparty_name: req.user.name,
      counterparty_email: req.user.email
    });

    await senderTransaction.save();
    await recipientTransaction.save();

    // Emit balance updates to both users
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

// External Transfer Route
app.post('/api/transfers/external', authenticateToken, [
  body('amount_cents').isInt({ min: 100 }),
  body('recipient_name').notEmpty(),
  body('recipient_account_number').notEmpty(),
  body('routing_number').notEmpty(),
  body('description').optional()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount_cents, recipient_name, recipient_account_number, routing_number, description } = req.body;

    const account = await Account.findOne({ user_id: req.user._id });
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    if (account.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Process external transfer via Column API
    let columnTransactionId;
    try {
      const transferResponse = await columnAPI.post('/payments', {
        amount: amount_cents,
        currency: 'usd',
        description: description || `Transfer to ${recipient_name}`,
        to: {
          type: 'account',
          account_number: recipient_account_number,
          routing_number: routing_number
        },
        metadata: {
          recipient_name,
          user_id: req.user._id.toString()
        }
      });
      columnTransactionId = transferResponse.data.id;
    } catch (error) {
      console.error('Column transfer failed:', error.response?.data);
      return res.status(500).json({ error: 'External transfer failed' });
    }

    // Update account balance
    account.balance_cents -= amount_cents;
    await account.save();

    // Create transaction record
    const transaction = new Transaction({
      user_id: req.user._id,
      account_id: account._id,
      type: 'transfer',
      amount_cents: -amount_cents,
      currency: 'USD',
      description: description || `External transfer to ${recipient_name}`,
      status: 'completed',
      counterparty_name: recipient_name,
      column_transaction_id: columnTransactionId,
      metadata: {
        recipient_account_number: recipient_account_number.slice(-4),
        routing_number: routing_number.slice(-4),
        transfer_type: 'external'
      }
    });
    await transaction.save();

    await emitBalanceUpdate(req.user._id);

    res.json({
      message: 'External transfer initiated successfully',
      transaction_id: transaction._id,
      column_transaction_id: columnTransactionId,
      new_balance: account.balance_cents
    });
  } catch (error) {
    console.error('External transfer error:', error);
    res.status(500).json({ error: 'Transfer failed' });
  }
});

// Card Routes
app.post('/api/cards', authenticateToken, [
  body('billing_address').optional(),
  body('phone_number').optional()
], async (req, res) => {
  try {
    const user = req.user;
    const { billing_address, phone_number } = req.body;
    const account = await Account.findOne({ user_id: user._id });

    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Generate realistic card details
    const generateCardNumber = () => {
      const bin = '4532'; // Visa bin
      const random = Array.from({ length: 12 }, () => 
        Math.floor(Math.random() * 10)
      ).join('');
      return bin + random;
    };

    const cardNumber = generateCardNumber();
    const currentYear = new Date().getFullYear();
    
    // Create virtual card via Column API
    let columnCardId;
    try {
      const cardResponse = await columnAPI.post('/cards', {
        account_id: account._id.toString(),
        type: 'virtual'
      });
      columnCardId = cardResponse.data.id;
    } catch (error) {
      console.error('Column card creation failed:', error.response?.data);
    }

    // Create virtual card in database
    const virtualCard = new VirtualCard({
      user_id: user._id,
      card_number: cardNumber,
      last4: cardNumber.slice(-4),
      expiry_month: Math.floor(Math.random() * 12) + 1,
      expiry_year: currentYear + 3,
      cvv: Array.from({ length: 3 }, () => Math.floor(Math.random() * 10)).join(''),
      brand: 'Visa',
      type: 'virtual',
      column_card_id: columnCardId,
      billing_address: billing_address || {
        street: '8605 Santa Monica Blvd #86294',
        city: 'West Hollywood',
        state: 'CA',
        zip_code: '90069',
        country: 'US'
      },
      phone_number: phone_number || '970-856-6136'
    });

    await virtualCard.save();

    // Create sample transactions for the new card
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

    // Get card transactions
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

    // Update via Column API if we have a column_card_id
    if (card.column_card_id) {
      try {
        await columnAPI.post(`/cards/${card.column_card_id}/block`);
      } catch (error) {
        console.error('Column card block failed:', error.response?.data);
      }
    }

    res.json({
      message: `Card ${card.status === 'active' ? 'unblocked' : 'blocked'} successfully`,
      card
    });
  } catch (error) {
    console.error('Block card error:', error);
    res.status(500).json({ error: 'Failed to update card status' });
  }
});

// Receipt Management
app.post('/api/transactions/:transactionId/receipt', authenticateToken, upload.single('receipt_image'), async (req, res) => {
  try {
    const { notes } = req.body;
    const transaction = await CardTransaction.findOne({
      _id: req.params.transactionId,
      user_id: req.user._id
    });

    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    let receiptImageUrl = null;
    if (req.file) {
      // Upload to Cloudinary
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'hcb-clone/receipts' },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        stream.end(req.file.buffer);
      });
      receiptImageUrl = result.secure_url;
    }

    transaction.receipt_image = receiptImageUrl;
    transaction.receipt_notes = notes;
    await transaction.save();

    res.json({
      message: 'Receipt added successfully',
      transaction
    });
  } catch (error) {
    console.error('Add receipt error:', error);
    res.status(500).json({ error: 'Failed to add receipt' });
  }
});

// Webhook endpoint for Column
app.post('/webhooks/column', async (req, res) => {
  try {
    const event = req.body;
    console.log('Received Column webhook:', event.type, event);

    // Handle different webhook events
    switch (event.type) {
      case 'payment.completed':
        // Handle completed payments
        break;
      case 'payment.failed':
        // Handle failed payments
        break;
      case 'card.updated':
        // Handle card updates
        break;
      default:
        console.log('Unhandled webhook type:', event.type);
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Connect to MongoDB and start server
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/hcb-real-clone';

mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    server.listen(PORT, () => {
      console.log(`HCB Clone Server running on port ${PORT}`);
      console.log(`Frontend: http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

module.exports = app;
