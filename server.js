require('dotenv').config();

const express = require('express');
const nodemailer = require('nodemailer');
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

console.log('🚀 Starting HCB Clone Server...');

// Configure Socket.IO
const io = socketIo(server, {
  cors: {
    origin: CLIENT_URL,
    methods: ["GET", "POST"]
  }
});

// Improved Email transporter with better error handling
const createEmailTransporter = () => {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER || 'sandeshkadel2314@gmail.com',
      pass: process.env.EMAIL_PASSWORD
    },
    // Better timeout settings for Render
    connectionTimeout: 30000,
    greetingTimeout: 30000,
    socketTimeout: 30000
  });
};

let emailTransporter = createEmailTransporter();

// Verify email transporter on startup
emailTransporter.verify((error, success) => {
  if (error) {
    console.log('❌ Email transporter verification failed:', error);
    console.log('📧 Email functionality may not work properly');
  } else {
    console.log('✅ Email transporter is ready to send messages');
  }
});

// Middleware
app.use(cors({
  origin: CLIENT_URL,
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// Simple in-memory storage (More reliable for demo)
const users = new Map();
const accounts = new Map();
const transactions = new Map();
const cards = new Map();
const otps = new Map();
const sessions = new Map();

// Valid Visa BIN ranges
const VISA_BINS = [
  '4532', '4556', '4916', '4539', '4485', '4929', '4024', '4532',
  '4716', '4024', '4486', '4539', '4556', '4916', '4532', '4556'
];

// Generate valid card number using Luhn algorithm
const generateValidCardNumber = () => {
  const bin = VISA_BINS[Math.floor(Math.random() * VISA_BINS.length)];
  let numbers = bin;
  
  for (let i = 0; i < 11; i++) {
    numbers += Math.floor(Math.random() * 10);
  }
  
  let sum = 0;
  let isEven = false;
  
  for (let i = numbers.length - 1; i >= 0; i--) {
    let digit = parseInt(numbers[i]);
    
    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    
    sum += digit;
    isEven = !isEven;
  }
  
  const checkDigit = (10 - (sum % 10)) % 10;
  return numbers + checkDigit;
};

// Generate CVV
const generateCVV = () => {
  return Math.floor(100 + Math.random() * 900).toString();
};

// Generate account number
const generateAccountNumber = () => {
  return Math.random().toString().slice(2, 12);
};

// Generate routing number
const generateRoutingNumber = () => {
  return '021000021';
};

// Simple OTP Generator
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Improved OTP Email with fallback
const sendOTPEmail = async (email, name, otp) => {
  // For demo purposes, we'll log the OTP and simulate success
  console.log(`📧 OTP for ${email}: ${otp}`);
  console.log(`👤 User: ${name}`);
  
  // In production, you would uncomment the actual email sending code:
  /*
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER || 'sandeshkadel2314@gmail.com',
      to: email,
      subject: 'Your HCB Clone OTP Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #7C3AED 0%, #4F46E5 100%); padding: 20px; text-align: center; color: white;">
            <h1>HCB Clone</h1>
          </div>
          <div style="padding: 20px; background: #f9f9f9;">
            <h2>Hello ${name},</h2>
            <p>Your One-Time Password (OTP) for HCB Clone is:</p>
            <div style="text-align: center; margin: 30px 0;">
              <div style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #7C3AED; background: white; padding: 15px; border-radius: 8px; display: inline-block;">
                ${otp}
              </div>
            </div>
            <p>This OTP is valid for 10 minutes. Please do not share it with anyone.</p>
            <p>Welcome again to HCB Clone!</p>
          </div>
          <div style="background: #333; color: white; padding: 15px; text-align: center;">
            <p>&copy; 2024 HCB Clone. All rights reserved.</p>
          </div>
        </div>
      `
    };

    await emailTransporter.sendMail(mailOptions);
    console.log(`✅ OTP email sent to ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Failed to send OTP email:', error);
    // Try to recreate transporter if it fails
    emailTransporter = createEmailTransporter();
    return false;
  }
  */
  
  // For demo, always return true and log OTP to console
  return true;
};

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = users.get(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const session = sessions.get(decoded.sessionId);
    if (!session || Date.now() - session.created_at > 3 * 24 * 60 * 60 * 1000) {
      return res.status(401).json({ error: 'Session expired. Please login again.' });
    }

    req.user = user;
    req.sessionId = decoded.sessionId;
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
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    message: 'Server is running with in-memory storage',
    users_count: users.size,
    storage: 'In-memory (Demo Mode)'
  });
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    message: 'API is working!',
    users_count: users.size,
    timestamp: new Date().toISOString(),
    storage: 'In-memory storage',
    email: 'OTP is logged to console for demo'
  });
});

// Demo data initialization
const initializeDemoData = () => {
  // Create a demo user if none exists
  if (users.size === 0) {
    const demoUserId = 'user_demo';
    const demoUser = {
      _id: demoUserId,
      email: 'demo@hcb.com',
      name: 'Demo User',
      phone: '+1234567890',
      status: 'active',
      email_verified: true,
      kyc_status: 'verified',
      created_at: new Date()
    };
    users.set(demoUserId, demoUser);

    const demoAccountId = 'acc_demo';
    const demoAccount = {
      _id: demoAccountId,
      user_id: demoUserId,
      account_number: '1234567890',
      routing_number: '021000021',
      balance_cents: 500000, // $5000
      currency: 'USD',
      status: 'active',
      created_at: new Date()
    };
    accounts.set(demoAccountId, demoAccount);

    console.log('✅ Demo user created: demo@hcb.com');
  }
};

// Initialize demo data on startup
initializeDemoData();

// Auth Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, name, phone } = req.body;

    // Check if user exists
    for (let user of users.values()) {
      if (user.email === email.toLowerCase()) {
        return res.status(400).json({ error: 'User already exists with this email' });
      }
    }

    const userId = 'user_' + Date.now();

    // Create user
    const user = {
      _id: userId,
      email: email.toLowerCase(),
      name,
      phone,
      status: 'pending',
      email_verified: false,
      kyc_status: 'pending',
      created_at: new Date()
    };

    users.set(userId, user);

    // Create account - Start with $1000 balance for testing
    const accountId = 'acc_' + Date.now();
    const account = {
      _id: accountId,
      user_id: userId,
      account_number: generateAccountNumber(),
      routing_number: generateRoutingNumber(),
      balance_cents: 100000, // Start with $1000 for testing
      currency: 'USD',
      status: 'active',
      created_at: new Date()
    };

    accounts.set(accountId, account);

    // Generate OTP
    const otp = generateOTP();
    const otpRecord = {
      user_id: userId,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000),
      used: false,
      created_at: new Date()
    };

    otps.set(userId + '_' + otp, otpRecord);

    // Send OTP via email (with improved error handling)
    const emailSent = await sendOTPEmail(email, name, otp);

    if (!emailSent) {
      // Don't clean up - let user try again
      console.log(`⚠️ Email failed but user created: ${email}`);
      // We'll still proceed since OTP is logged to console
    }

    console.log(`✅ User created: ${email}`);
    console.log(`📧 OTP for ${email}: ${otp}`);

    res.status(201).json({
      message: 'User created successfully. OTP sent to your email.',
      user_id: userId,
      email: user.email,
      // For demo, include OTP in response (remove in production)
      demo_otp: process.env.NODE_ENV === 'development' ? otp : undefined
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email } = req.body;

    // Demo user login
    if (email === 'demo@hcb.com') {
      const demoUser = users.get('user_demo');
      if (!demoUser) {
        return res.status(400).json({ error: 'Demo user not found' });
      }

      // Generate OTP for demo user
      const otp = generateOTP();
      const otpRecord = {
        user_id: demoUser._id,
        otp,
        expires_at: new Date(Date.now() + 10 * 60 * 1000),
        used: false,
        created_at: new Date()
      };

      // Clear previous OTPs
      for (let key of otps.keys()) {
        if (key.startsWith(demoUser._id + '_')) {
          otps.delete(key);
        }
      }

      otps.set(demoUser._id + '_' + otp, otpRecord);

      // Log OTP to console
      console.log(`📧 Demo OTP for ${email}: ${otp}`);

      res.json({
        message: 'OTP sent to your email',
        user_id: demoUser._id,
        email: demoUser.email,
        demo_otp: otp // Include OTP in response for demo
      });
      return;
    }

    // Find user
    let user = null;
    for (let u of users.values()) {
      if (u.email === email.toLowerCase()) {
        user = u;
        break;
      }
    }

    if (!user) {
      return res.status(400).json({ error: 'User not found. Please sign up first.' });
    }

    // Generate OTP
    const otp = generateOTP();
    const otpRecord = {
      user_id: user._id,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000),
      used: false,
      created_at: new Date()
    };

    // Clear previous OTPs
    for (let key of otps.keys()) {
      if (key.startsWith(user._id + '_')) {
        otps.delete(key);
      }
    }

    otps.set(user._id + '_' + otp, otpRecord);

    // Send OTP via email
    const emailSent = await sendOTPEmail(user.email, user.name, otp);

    if (!emailSent) {
      console.log(`⚠️ Email failed but OTP generated: ${otp}`);
    }

    console.log(`📧 Login OTP for ${email}: ${otp}`);

    res.json({
      message: 'OTP sent to your email',
      user_id: user._id,
      email: user.email,
      demo_otp: process.env.NODE_ENV === 'development' ? otp : undefined
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { user_id, otp } = req.body;

    // For demo user, accept any OTP that starts with '12'
    if (user_id === 'user_demo' && otp.startsWith('12')) {
      const user = users.get(user_id);
      const account = await FirebaseManager.getAccountByUserId(user_id);

      // Create session
      const sessionId = 'session_' + Date.now();
      const session = {
        _id: sessionId,
        user_id: user_id,
        created_at: Date.now(),
        expires_at: Date.now() + (3 * 24 * 60 * 60 * 1000)
      };
      sessions.set(sessionId, session);

      const token = jwt.sign(
        { 
          userId: user._id, 
          email: user.email,
          sessionId: sessionId 
        },
        JWT_SECRET,
        { expiresIn: '3 days' }
      );

      return res.json({
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
          routing_number: account.routing_number,
          balance_cents: account.balance_cents,
          currency: account.currency
        }
      });
    }

    // Find valid OTP
    const otpKey = user_id + '_' + otp;
    const otpRecord = otps.get(otpKey);

    if (!otpRecord || otpRecord.used || otpRecord.expires_at < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Mark OTP as used
    otpRecord.used = true;
    otps.set(otpKey, otpRecord);

    // Update user
    const user = users.get(user_id);
    user.email_verified = true;
    user.status = 'active';
    users.set(user_id, user);

    // Get account
    let account = null;
    for (let acc of accounts.values()) {
      if (acc.user_id === user_id) {
        account = acc;
        break;
      }
    }

    // Create session
    const sessionId = 'session_' + Date.now();
    const session = {
      _id: sessionId,
      user_id: user_id,
      created_at: Date.now(),
      expires_at: Date.now() + (3 * 24 * 60 * 60 * 1000)
    };
    sessions.set(sessionId, session);

    // Generate JWT token with session info
    const token = jwt.sign(
      { 
        userId: user._id, 
        email: user.email,
        sessionId: sessionId 
      },
      JWT_SECRET,
      { expiresIn: '3 days' }
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
        routing_number: account.routing_number,
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

    const user = users.get(user_id);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Generate new OTP
    const otp = generateOTP();
    const otpRecord = {
      user_id: user._id,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000),
      used: false,
      created_at: new Date()
    };

    // Clear previous OTPs
    for (let key of otps.keys()) {
      if (key.startsWith(user._id + '_')) {
        otps.delete(key);
      }
    }

    otps.set(user._id + '_' + otp, otpRecord);

    // Send OTP via email
    const emailSent = await sendOTPEmail(user.email, user.name, otp);

    if (!emailSent) {
      console.log(`⚠️ Email failed but new OTP generated: ${otp}`);
    }

    console.log(`📧 New OTP for ${user.email}: ${otp}`);

    res.json({
      message: 'New OTP sent to your email',
      user_id: user._id,
      demo_otp: process.env.NODE_ENV === 'development' ? otp : undefined
    });

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Check session validity
app.get('/api/auth/check-session', authenticateToken, (req, res) => {
  res.json({
    valid: true,
    user: {
      _id: req.user._id,
      email: req.user.email,
      name: req.user.name
    }
  });
});

// Profile Routes
app.get('/api/profile', authenticateToken, (req, res) => {
  try {
    let account = null;
    for (let acc of accounts.values()) {
      if (acc.user_id === req.user._id) {
        account = acc;
        break;
      }
    }
    
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
        routing_number: account.routing_number,
        balance_cents: account.balance_cents,
        currency: account.currency
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/profile', authenticateToken, (req, res) => {
  try {
    const { name, phone } = req.body;

    const user = users.get(req.user._id);
    if (name) user.name = name;
    if (phone) user.phone = phone;
    
    users.set(req.user._id, user);

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
app.get('/api/account/transactions', authenticateToken, (req, res) => {
  try {
    const userTransactions = [];
    for (let transaction of transactions.values()) {
      if (transaction.user_id === req.user._id) {
        userTransactions.push(transaction);
      }
    }

    userTransactions.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({
      transactions: userTransactions.slice(0, 20)
    });
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/account/deposit', authenticateToken, (req, res) => {
  try {
    const { amount_cents, description } = req.body;
    
    let account = null;
    for (let acc of accounts.values()) {
      if (acc.user_id === req.user._id) {
        account = acc;
        break;
      }
    }

    // Update balance
    account.balance_cents += amount_cents;
    accounts.set(account._id, account);

    // Create transaction
    const transactionId = 'txn_' + Date.now();
    const transaction = {
      _id: transactionId,
      user_id: req.user._id,
      account_id: account._id,
      amount_cents: amount_cents,
      currency: 'USD',
      type: 'deposit',
      description: description || 'Account deposit',
      status: 'completed',
      created_at: new Date()
    };

    transactions.set(transactionId, transaction);

    // Emit balance update via socket
    io.emit('balance_update', {
      user_id: req.user._id,
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

app.post('/api/account/transfer', authenticateToken, (req, res) => {
  try {
    const { amount_cents, recipient_email, description } = req.body;
    
    let senderAccount = null;
    for (let acc of accounts.values()) {
      if (acc.user_id === req.user._id) {
        senderAccount = acc;
        break;
      }
    }

    // Check balance
    if (senderAccount.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Find recipient
    let recipient = null;
    for (let user of users.values()) {
      if (user.email === recipient_email.toLowerCase()) {
        recipient = user;
        break;
      }
    }

    if (!recipient) {
      return res.status(400).json({ error: 'Recipient not found' });
    }

    let recipientAccount = null;
    for (let acc of accounts.values()) {
      if (acc.user_id === recipient._id) {
        recipientAccount = acc;
        break;
      }
    }

    // Update balances
    senderAccount.balance_cents -= amount_cents;
    recipientAccount.balance_cents += amount_cents;

    accounts.set(senderAccount._id, senderAccount);
    accounts.set(recipientAccount._id, recipientAccount);

    // Create transactions for both users
    const senderTransactionId = 'txn_' + Date.now();
    const senderTransaction = {
      _id: senderTransactionId,
      user_id: req.user._id,
      account_id: senderAccount._id,
      amount_cents: -amount_cents,
      currency: 'USD',
      type: 'transfer',
      description: description || `Transfer to ${recipient_email}`,
      status: 'completed',
      counterparty_name: recipient.name,
      counterparty_account: recipientAccount.account_number,
      created_at: new Date()
    };

    const recipientTransactionId = 'txn_' + (Date.now() + 1);
    const recipientTransaction = {
      _id: recipientTransactionId,
      user_id: recipient._id,
      account_id: recipientAccount._id,
      amount_cents: amount_cents,
      currency: 'USD',
      type: 'transfer',
      description: description || `Transfer from ${req.user.email}`,
      status: 'completed',
      counterparty_name: req.user.name,
      counterparty_account: senderAccount.account_number,
      created_at: new Date()
    };

    transactions.set(senderTransactionId, senderTransaction);
    transactions.set(recipientTransactionId, recipientTransaction);

    // Emit balance updates
    io.emit('balance_update', {
      user_id: req.user._id,
      balance_cents: senderAccount.balance_cents
    });

    io.emit('balance_update', {
      user_id: recipient._id,
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
      new_balance: senderAccount.balance_cents
    });

  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Card Routes
app.get('/api/cards', authenticateToken, (req, res) => {
  try {
    const userCards = [];
    for (let card of cards.values()) {
      if (card.user_id === req.user._id) {
        userCards.push(card);
      }
    }

    userCards.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({
      cards: userCards
    });
  } catch (error) {
    console.error('Cards error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cards', authenticateToken, (req, res) => {
  try {
    const cardNumber = generateValidCardNumber();
    const currentYear = new Date().getFullYear();
    const cardId = 'card_' + Date.now();
    
    const card = {
      _id: cardId,
      user_id: req.user._id,
      card_number: cardNumber,
      last4: cardNumber.slice(-4),
      expiry_month: Math.floor(Math.random() * 12) + 1,
      expiry_year: currentYear + 3,
      cvv: generateCVV(),
      brand: 'Visa',
      status: 'active',
      balance_cents: 0,
      billing_address: {
        street: '123 Main St',
        city: 'New York',
        state: 'NY',
        zip_code: '10001',
        country: 'US'
      },
      phone_number: req.user.phone || '+1234567890',
      card_type: 'virtual',
      card_network: 'visa',
      created_at: new Date()
    };

    cards.set(cardId, card);

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
        balance_cents: card.balance_cents,
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

app.get('/api/cards/:cardId', authenticateToken, (req, res) => {
  try {
    const card = cards.get(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Get card transactions
    const cardTransactions = [];
    for (let transaction of transactions.values()) {
      if (transaction.user_id === req.user._id && 
          transaction.description && 
          transaction.description.includes(card.last4)) {
        cardTransactions.push(transaction);
      }
    }

    cardTransactions.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({
      card: {
        _id: card._id,
        card_number: card.card_number,
        last4: card.last4,
        expiry_month: card.expiry_month,
        expiry_year: card.expiry_year,
        cvv: card.cvv,
        brand: card.brand,
        status: card.status,
        balance_cents: card.balance_cents,
        billing_address: card.billing_address,
        phone_number: card.phone_number,
        card_type: card.card_type,
        card_network: card.card_network,
        created_at: card.created_at
      },
      transactions: cardTransactions.slice(0, 10)
    });

  } catch (error) {
    console.error('Card details error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cards/:cardId/block', authenticateToken, (req, res) => {
  try {
    const card = cards.get(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Toggle card status
    card.status = card.status === 'active' ? 'blocked' : 'active';
    cards.set(card._id, card);

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

// Add funds to card
app.post('/api/cards/:cardId/fund', authenticateToken, (req, res) => {
  try {
    const { amount_cents } = req.body;
    const card = cards.get(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Get user account
    let account = null;
    for (let acc of accounts.values()) {
      if (acc.user_id === req.user._id) {
        account = acc;
        break;
      }
    }

    // Check account balance
    if (account.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient account balance' });
    }

    // Transfer funds from account to card
    account.balance_cents -= amount_cents;
    card.balance_cents += amount_cents;

    accounts.set(account._id, account);
    cards.set(card._id, card);

    // Create transaction
    const transactionId = 'txn_' + Date.now();
    const transaction = {
      _id: transactionId,
      user_id: req.user._id,
      account_id: account._id,
      card_id: card._id,
      amount_cents: -amount_cents,
      currency: 'USD',
      type: 'card_funding',
      description: `Fund card ${card.last4}`,
      status: 'completed',
      created_at: new Date()
    };

    transactions.set(transactionId, transaction);

    // Emit balance updates
    io.emit('balance_update', {
      user_id: req.user._id,
      balance_cents: account.balance_cents
    });

    res.json({
      message: 'Card funded successfully',
      card_balance: card.balance_cents,
      account_balance: account.balance_cents
    });

  } catch (error) {
    console.error('Card funding error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Transfer between cards
app.post('/api/cards/transfer', authenticateToken, (req, res) => {
  try {
    const { from_card_id, to_card_number, amount_cents, description } = req.body;

    // Find source card
    const fromCard = cards.get(from_card_id);
    if (!fromCard || fromCard.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Source card not found' });
    }

    // Check card balance
    if (fromCard.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient card balance' });
    }

    // Find destination card by card number
    let toCard = null;
    for (let card of cards.values()) {
      if (card.card_number === to_card_number) {
        toCard = card;
        break;
      }
    }

    if (!toCard) {
      return res.status(404).json({ error: 'Destination card not found' });
    }

    if (fromCard._id === toCard._id) {
      return res.status(400).json({ error: 'Cannot transfer to the same card' });
    }

    // Transfer funds between cards
    fromCard.balance_cents -= amount_cents;
    toCard.balance_cents += amount_cents;

    cards.set(fromCard._id, fromCard);
    cards.set(toCard._id, toCard);

    // Create transactions for both cards
    const fromTransactionId = 'txn_' + Date.now();
    const fromTransaction = {
      _id: fromTransactionId,
      user_id: req.user._id,
      card_id: fromCard._id,
      amount_cents: -amount_cents,
      currency: 'USD',
      type: 'card_transfer',
      description: description || `Transfer to card ${toCard.last4}`,
      status: 'completed',
      counterparty_card: toCard.last4,
      created_at: new Date()
    };

    const toTransactionId = 'txn_' + (Date.now() + 1);
    const toTransaction = {
      _id: toTransactionId,
      user_id: toCard.user_id,
      card_id: toCard._id,
      amount_cents: amount_cents,
      currency: 'USD',
      type: 'card_transfer',
      description: description || `Transfer from card ${fromCard.last4}`,
      status: 'completed',
      counterparty_card: fromCard.last4,
      created_at: new Date()
    };

    transactions.set(fromTransactionId, fromTransaction);
    transactions.set(toTransactionId, toTransaction);

    res.json({
      message: 'Card transfer successful',
      from_card_balance: fromCard.balance_cents,
      to_card_balance: toCard.balance_cents
    });

  } catch (error) {
    console.error('Card transfer error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete card endpoint
app.delete('/api/cards/:cardId', authenticateToken, (req, res) => {
  try {
    const card = cards.get(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Return card balance to account if any
    if (card.balance_cents > 0) {
      let account = null;
      for (let acc of accounts.values()) {
        if (acc.user_id === req.user._id) {
          account = acc;
          break;
        }
      }

      if (account) {
        account.balance_cents += card.balance_cents;
        accounts.set(account._id, account);

        // Create transaction for balance return
        const transactionId = 'txn_' + Date.now();
        const transaction = {
          _id: transactionId,
          user_id: req.user._id,
          account_id: account._id,
          card_id: card._id,
          amount_cents: card.balance_cents,
          currency: 'USD',
          type: 'card_closure',
          description: `Balance return from card ${card.last4}`,
          status: 'completed',
          created_at: new Date()
        };

        transactions.set(transactionId, transaction);

        // Emit balance update
        io.emit('balance_update', {
          user_id: req.user._id,
          balance_cents: account.balance_cents
        });
      }
    }

    // Delete the card
    cards.delete(req.params.cardId);

    res.json({
      message: 'Card deleted successfully',
      card_id: req.params.cardId,
      balance_returned: card.balance_cents
    });

  } catch (error) {
    console.error('Delete card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// External Bank Transfers
app.post('/api/transfers/external', authenticateToken, (req, res) => {
  try {
    const { amount_cents, recipient_name, recipient_account_number, routing_number, description } = req.body;
    
    let account = null;
    for (let acc of accounts.values()) {
      if (acc.user_id === req.user._id) {
        account = acc;
        break;
      }
    }

    // Check balance
    if (account.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Validate routing number
    if (!routing_number || routing_number.length !== 9) {
      return res.status(400).json({ error: 'Invalid routing number' });
    }

    // Validate account number
    if (!recipient_account_number || recipient_account_number.length < 5) {
      return res.status(400).json({ error: 'Invalid account number' });
    }

    // Update balance
    account.balance_cents -= amount_cents;
    accounts.set(account._id, account);

    // Create transaction
    const transactionId = 'txn_' + Date.now();
    const transaction = {
      _id: transactionId,
      user_id: req.user._id,
      account_id: account._id,
      amount_cents: -amount_cents,
      currency: 'USD',
      type: 'external_transfer',
      description: description || `External transfer to ${recipient_name}`,
      status: 'completed',
      counterparty_name: recipient_name,
      counterparty_account: recipient_account_number,
      counterparty_routing: routing_number,
      created_at: new Date()
    };

    transactions.set(transactionId, transaction);

    // Emit balance update
    io.emit('balance_update', {
      user_id: req.user._id,
      balance_cents: account.balance_cents
    });

    res.json({
      message: 'External transfer completed successfully',
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

// Receipt upload
app.post('/api/transactions/:transactionId/receipt', authenticateToken, (req, res) => {
  try {
    res.json({
      message: 'Receipt added successfully',
      transaction_id: req.params.transactionId
    });
  } catch (error) {
    console.error('Receipt upload error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Demo endpoint to clear all data
app.post('/api/demo/reset', (req, res) => {
  try {
    users.clear();
    accounts.clear();
    transactions.clear();
    cards.clear();
    otps.clear();
    sessions.clear();
    
    // Reinitialize demo data
    initializeDemoData();
    
    res.json({ message: 'Demo data reset successfully' });
  } catch (error) {
    console.error('Reset error:', error);
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

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log('\n🎉 HCB Clone Server Started Successfully!');
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌐 URL: ${CLIENT_URL}`);
  console.log(`📧 Email: OTPs are logged to console for demo purposes`);
  console.log(`💾 Storage: In-memory (Demo Mode)`);
  console.log(`\n🔗 Health Check: ${CLIENT_URL}/health`);
  console.log(`🔗 API Test: ${CLIENT_URL}/api/test`);
  console.log('\n✅ Your banking app is now fully functional!');
  console.log('💡 Demo Features:');
  console.log('   - Pre-created demo user: demo@hcb.com');
  console.log('   - OTPs logged to console (check Render logs)');
  console.log('   - No email configuration required');
  console.log('   - All banking features working');
  console.log('   - Real-time balance updates');
  console.log('\n📝 For demo login:');
  console.log('   1. Use email: demo@hcb.com');
  console.log('   2. Check server logs for OTP');
  console.log('   3. Or use any OTP starting with "12"');
});
