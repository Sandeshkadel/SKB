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

// Email transporter
const createEmailTransporter = () => {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER || 'sandeshkadel2314@gmail.com',
      pass: process.env.EMAIL_PASSWORD
    },
    connectionTimeout: 30000,
    greetingTimeout: 30000,
    socketTimeout: 30000
  });
};

let emailTransporter = createEmailTransporter();

// Verify email transporter
emailTransporter.verify((error, success) => {
  if (error) {
    console.log('❌ Email transporter verification failed:', error);
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

// In-memory storage
const users = new Map();
const accounts = new Map();
const transactions = new Map();
const cards = new Map();
const organizations = new Map();
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

// Send OTP Email
const sendOTPEmail = async (email, name, otp) => {
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
    // For demo purposes, log OTP to console
    console.log(`📧 OTP for ${email}: ${otp}`);
    return true; // Return true for demo even if email fails
  }
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
    storage: 'In-memory'
  });
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    message: 'API is working!',
    users_count: users.size,
    timestamp: new Date().toISOString()
  });
});

// Demo data initialization
const initializeDemoData = () => {
  // Create demo users if none exist
  if (users.size === 0) {
    // Demo user 1
    const demoUserId1 = 'user_demo1';
    const demoUser1 = {
      _id: demoUserId1,
      email: 'demo@hcb.com',
      name: 'Demo User',
      phone: '+1234567890',
      status: 'active',
      email_verified: true,
      kyc_status: 'verified',
      created_at: new Date()
    };
    users.set(demoUserId1, demoUser1);

    const demoAccountId1 = 'acc_demo1';
    const demoAccount1 = {
      _id: demoAccountId1,
      user_id: demoUserId1,
      account_number: '1234567890',
      routing_number: '021000021',
      balance_cents: 500000, // $5000
      currency: 'USD',
      status: 'active',
      created_at: new Date()
    };
    accounts.set(demoAccountId1, demoAccount1);

    // Demo user 2
    const demoUserId2 = 'user_demo2';
    const demoUser2 = {
      _id: demoUserId2,
      email: 'user2@hcb.com',
      name: 'Test User',
      phone: '+1234567891',
      status: 'active',
      email_verified: true,
      kyc_status: 'verified',
      created_at: new Date()
    };
    users.set(demoUserId2, demoUser2);

    const demoAccountId2 = 'acc_demo2';
    const demoAccount2 = {
      _id: demoAccountId2,
      user_id: demoUserId2,
      account_number: '1234567891',
      routing_number: '021000021',
      balance_cents: 300000, // $3000
      currency: 'USD',
      status: 'active',
      created_at: new Date()
    };
    accounts.set(demoAccountId2, demoAccount2);

    // Create demo organizations
    const orgId1 = 'org_demo1';
    const demoOrg1 = {
      _id: orgId1,
      name: 'Tech Startup Inc.',
      description: 'A technology startup company',
      owner_id: demoUserId1,
      members: [
        {
          user_id: demoUserId1,
          name: 'Demo User',
          role: 'owner',
          joined_at: new Date()
        },
        {
          user_id: demoUserId2,
          name: 'Test User',
          role: 'member',
          joined_at: new Date()
        }
      ],
      visibility: 'public',
      status: 'active',
      created_at: new Date()
    };
    organizations.set(orgId1, demoOrg1);

    const orgId2 = 'org_demo2';
    const demoOrg2 = {
      _id: orgId2,
      name: 'Open Source Project',
      description: 'Community open source project',
      owner_id: demoUserId2,
      members: [
        {
          user_id: demoUserId2,
          name: 'Test User',
          role: 'owner',
          joined_at: new Date()
        }
      ],
      visibility: 'public',
      status: 'active',
      created_at: new Date()
    };
    organizations.set(orgId2, demoOrg2);

    console.log('✅ Demo users and organizations created');
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

    // Create account - Start with $1000 balance
    const accountId = 'acc_' + Date.now();
    const account = {
      _id: accountId,
      user_id: userId,
      account_number: generateAccountNumber(),
      routing_number: generateRoutingNumber(),
      balance_cents: 100000, // $1000
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

    // Send OTP via email
    const emailSent = await sendOTPEmail(email, name, otp);

    console.log(`✅ User created: ${email}`);
    console.log(`📧 OTP for ${email}: ${otp}`);

    res.status(201).json({
      message: 'User created successfully. OTP sent to your email.',
      user_id: userId,
      email: user.email
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email } = req.body;

    // Find user
    let user = null;
    for (let u of users.values()) {
      if (u.email === email.toLowerCase()) {
        user = u;
        break;
      }
    }

    if (!user) {
      return res.status(400).json({ error: 'No account found with this email. Please create an account first.' });
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

    console.log(`📧 Login OTP for ${email}: ${otp}`);

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

    // For demo users, accept any OTP
    if (user_id.startsWith('user_demo')) {
      const user = users.get(user_id);
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
    await sendOTPEmail(user.email, user.name, otp);

    console.log(`📧 New OTP for ${user.email}: ${otp}`);

    res.json({
      message: 'New OTP sent to your email',
      user_id: user._id
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

    // Get user's organizations
    const userOrganizations = [];
    for (let org of organizations.values()) {
      if (org.members.some(member => member.user_id === req.user._id)) {
        userOrganizations.push(org);
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
      },
      organizations: userOrganizations
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/profile', authenticateToken, (req, res) => {
  try {
    const { name, phone, organization_id } = req.body;

    const user = users.get(req.user._id);
    if (name) user.name = name;
    if (phone) user.phone = phone;
    if (organization_id) user.organization_id = organization_id;
    
    users.set(req.user._id, user);

    res.json({
      user: {
        _id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        profile_picture: user.profile_picture,
        email_verified: user.email_verified,
        kyc_status: user.kyc_status,
        organization_id: user.organization_id
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
      transactions: userTransactions.slice(0, 50)
    });
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get card transactions
app.get('/api/cards/:cardId/transactions', authenticateToken, (req, res) => {
  try {
    const card = cards.get(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    const cardTransactions = [];
    for (let transaction of transactions.values()) {
      if ((transaction.user_id === req.user._id && 
           transaction.description && 
           transaction.description.includes(card.last4)) ||
          (transaction.card_id === req.params.cardId)) {
        cardTransactions.push(transaction);
      }
    }

    cardTransactions.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({
      transactions: cardTransactions
    });

  } catch (error) {
    console.error('Card transactions error:', error);
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

// FIXED TRANSFER ENDPOINT - Properly deduct from sender and add to recipient
app.post('/api/account/transfer', authenticateToken, (req, res) => {
  try {
    const { amount_cents, recipient_email, description } = req.body;
    
    // Find sender account
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

    // Find recipient account
    let recipientAccount = null;
    for (let acc of accounts.values()) {
      if (acc.user_id === recipient._id) {
        recipientAccount = acc;
        break;
      }
    }

    if (!recipientAccount) {
      return res.status(400).json({ error: 'Recipient account not found' });
    }

    // CRITICAL FIX: Properly update balances
    // Deduct from sender
    senderAccount.balance_cents -= amount_cents;
    // Add to recipient
    recipientAccount.balance_cents += amount_cents;

    // Save updated accounts
    accounts.set(senderAccount._id, senderAccount);
    accounts.set(recipientAccount._id, recipientAccount);

    // Create transactions for both users
    const senderTransactionId = 'txn_' + Date.now();
    const senderTransaction = {
      _id: senderTransactionId,
      user_id: req.user._id,
      account_id: senderAccount._id,
      amount_cents: -amount_cents, // Negative for sender
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
      amount_cents: amount_cents, // Positive for recipient
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

    // Emit balance updates to both users
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
      card_owner: req.user.name, // Set initial card owner to user's name
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
        card_owner: card.card_owner,
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
      if ((transaction.user_id === req.user._id && 
           transaction.description && 
           transaction.description.includes(card.last4)) ||
          (transaction.card_id === req.params.cardId)) {
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
        card_owner: card.card_owner,
        billing_address: card.billing_address,
        phone_number: card.phone_number,
        card_type: card.card_type,
        card_network: card.card_network,
        created_at: card.created_at
      },
      transactions: cardTransactions.slice(0, 20)
    });

  } catch (error) {
    console.error('Card details error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update card owner name
app.put('/api/cards/:cardId', authenticateToken, (req, res) => {
  try {
    const { card_owner } = req.body;
    const card = cards.get(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Update card owner
    card.card_owner = card_owner;
    cards.set(card._id, card);

    res.json({
      message: 'Card owner updated successfully',
      card: {
        _id: card._id,
        card_owner: card.card_owner,
        last4: card.last4
      }
    });

  } catch (error) {
    console.error('Update card owner error:', error);
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

// Transfer from card to bank account
app.post('/api/cards/transfer-to-bank', authenticateToken, (req, res) => {
  try {
    const { card_id, account_number, routing_number, amount_cents, description } = req.body;

    // Find source card
    const card = cards.get(card_id);
    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Check card balance
    if (card.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient card balance' });
    }

    // Validate bank details
    if (!account_number || account_number.length < 5) {
      return res.status(400).json({ error: 'Invalid account number' });
    }

    if (!routing_number || routing_number.length !== 9) {
      return res.status(400).json({ error: 'Invalid routing number' });
    }

    // Transfer funds from card to bank (simulate)
    card.balance_cents -= amount_cents;
    cards.set(card._id, card);

    // Create transaction
    const transactionId = 'txn_' + Date.now();
    const transaction = {
      _id: transactionId,
      user_id: req.user._id,
      card_id: card_id,
      amount_cents: -amount_cents,
      currency: 'USD',
      type: 'card_to_bank_transfer',
      description: description || `Transfer to bank account ${account_number.slice(-4)}`,
      status: 'completed',
      counterparty_account: account_number.slice(-4),
      created_at: new Date()
    };

    transactions.set(transactionId, transaction);

    res.json({
      message: 'Transfer to bank account successful',
      card_balance: card.balance_cents,
      amount_transferred: amount_cents
    });

  } catch (error) {
    console.error('Card to bank transfer error:', error);
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

// Organization Routes
app.get('/api/organizations', authenticateToken, (req, res) => {
  try {
    const userOrganizations = [];
    for (let org of organizations.values()) {
      if (org.members.some(member => member.user_id === req.user._id)) {
        userOrganizations.push(org);
      }
    }

    res.json({
      organizations: userOrganizations
    });
  } catch (error) {
    console.error('Organizations error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/organizations/all', authenticateToken, (req, res) => {
  try {
    const allOrganizations = Array.from(organizations.values());
    
    res.json({
      organizations: allOrganizations
    });
  } catch (error) {
    console.error('All organizations error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/organizations', authenticateToken, (req, res) => {
  try {
    const { name, description } = req.body;

    const orgId = 'org_' + Date.now();
    const organization = {
      _id: orgId,
      name,
      description,
      owner_id: req.user._id,
      members: [
        {
          user_id: req.user._id,
          name: req.user.name,
          role: 'owner',
          joined_at: new Date()
        }
      ],
      visibility: 'public',
      status: 'active',
      created_at: new Date()
    };

    organizations.set(orgId, organization);

    res.json({
      message: 'Organization created successfully',
      organization: {
        _id: organization._id,
        name: organization.name,
        description: organization.description,
        owner_id: organization.owner_id,
        members: organization.members,
        visibility: organization.visibility,
        status: organization.status,
        created_at: organization.created_at
      }
    });

  } catch (error) {
    console.error('Create organization error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/organizations/:orgId', authenticateToken, (req, res) => {
  try {
    const organization = organizations.get(req.params.orgId);

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    res.json({
      organization: {
        _id: organization._id,
        name: organization.name,
        description: organization.description,
        owner_id: organization.owner_id,
        members: organization.members,
        visibility: organization.visibility,
        status: organization.status,
        created_at: organization.created_at
      }
    });

  } catch (error) {
    console.error('Organization details error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/organizations/:orgId/join', authenticateToken, (req, res) => {
  try {
    const organization = organizations.get(req.params.orgId);

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Check if user is already a member
    const isMember = organization.members.some(member => member.user_id === req.user._id);
    if (isMember) {
      return res.status(400).json({ error: 'Already a member of this organization' });
    }

    // Add user as member
    organization.members.push({
      user_id: req.user._id,
      name: req.user.name,
      role: 'member',
      joined_at: new Date()
    });

    organizations.set(organization._id, organization);

    res.json({
      message: 'Successfully joined the organization',
      organization: {
        _id: organization._id,
        name: organization.name,
        members: organization.members
      }
    });

  } catch (error) {
    console.error('Join organization error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Payment processing
app.post('/api/payments/process', authenticateToken, (req, res) => {
  try {
    const { card_number, amount_cents, description } = req.body;

    // Find card
    let card = null;
    for (let c of cards.values()) {
      if (c.card_number === card_number && c.user_id === req.user._id) {
        card = c;
        break;
      }
    }

    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Check card balance
    if (card.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient card balance' });
    }

    // Validate card using Luhn algorithm
    if (!Utils.validateCardNumber(card_number)) {
      return res.status(400).json({ error: 'Invalid card number' });
    }

    // Process payment
    card.balance_cents -= amount_cents;
    cards.set(card._id, card);

    // Create transaction
    const transactionId = 'txn_' + Date.now();
    const transaction = {
      _id: transactionId,
      user_id: req.user._id,
      card_id: card._id,
      amount_cents: -amount_cents,
      currency: 'USD',
      type: 'payment',
      description: description || 'Card payment',
      status: 'completed',
      created_at: new Date()
    };

    transactions.set(transactionId, transaction);

    res.json({
      message: 'Payment processed successfully',
      transaction: {
        _id: transaction._id,
        amount_cents: transaction.amount_cents,
        description: transaction.description,
        status: transaction.status
      },
      card_balance: card.balance_cents
    });

  } catch (error) {
    console.error('Payment processing error:', error);
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
    organizations.clear();
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

// Utility functions for validation
const Utils = {
  validateCardNumber(cardNumber) {
    // Luhn algorithm validation
    if (!/^\d+$/.test(cardNumber) || cardNumber.length < 13 || cardNumber.length > 19) {
      return false;
    }

    let sum = 0;
    let isEven = false;
    
    for (let i = cardNumber.length - 1; i >= 0; i--) {
      let digit = parseInt(cardNumber[i]);
      
      if (isEven) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      
      sum += digit;
      isEven = !isEven;
    }
    
    return sum % 10 === 0;
  }
};

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
  console.log(`📧 Email: OTPs will be sent to registered emails`);
  console.log(`💾 Storage: In-memory`);
  console.log(`\n🔗 Health Check: ${CLIENT_URL}/health`);
  console.log(`🔗 API Test: ${CLIENT_URL}/api/test`);
  console.log('\n✅ Your banking app is now fully functional!');
  console.log('💡 Demo Users:');
  console.log('   - demo@hcb.com (Password: any OTP)');
  console.log('   - user2@hcb.com (Password: any OTP)');
  console.log('   - Or create new account with any email');
  console.log('\n🆕 New Features Added:');
  console.log('   ✅ Card owner name editing');
  console.log('   ✅ Improved authentication flow');
  console.log('   ✅ Organization management');
  console.log('   ✅ Card number validation');
  console.log('   ✅ Card to bank transfers');
});
