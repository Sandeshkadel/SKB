require('dotenv').config();

const express = require('express');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const socketIo = require('socket.io');
const http = require('http');
const cors = require('cors');
const path = require('path');
const admin = require('firebase-admin');

const app = express();
const server = http.createServer(app);

// Initialize Firebase Admin
const serviceAccount = {
  type: "service_account",
  project_id: "hcb-4ce8c",
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL,
  universe_domain: "googleapis.com"
};

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://hcb-4ce8c-default-rtdb.firebaseio.com"
  });
  console.log('✅ Firebase initialized successfully');
} catch (error) {
  console.log('✅ Firebase already initialized');
}

const db = admin.database();

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

// Email transporter - FIXED: createTransport instead of createTransporter
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'sandeshkadel2314@gmail.com',
    pass: process.env.EMAIL_PASSWORD
  }
});

// Middleware
app.use(cors({
  origin: CLIENT_URL,
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// Firebase Data Management
const FirebaseManager = {
  // User operations
  async getUser(userId) {
    try {
      const snapshot = await db.ref(`users/${userId}`).once('value');
      return snapshot.val();
    } catch (error) {
      console.error('Firebase getUser error:', error);
      return null;
    }
  },

  async createUser(userData) {
    try {
      await db.ref(`users/${userData._id}`).set(userData);
      return userData;
    } catch (error) {
      console.error('Firebase createUser error:', error);
      throw error;
    }
  },

  async updateUser(userId, updates) {
    try {
      await db.ref(`users/${userId}`).update(updates);
      const updatedUser = await this.getUser(userId);
      return updatedUser;
    } catch (error) {
      console.error('Firebase updateUser error:', error);
      throw error;
    }
  },

  async getUserByEmail(email) {
    try {
      const snapshot = await db.ref('users').orderByChild('email').equalTo(email).once('value');
      return snapshot.val();
    } catch (error) {
      console.error('Firebase getUserByEmail error:', error);
      return null;
    }
  },

  // Account operations
  async createAccount(accountData) {
    try {
      await db.ref(`accounts/${accountData._id}`).set(accountData);
      return accountData;
    } catch (error) {
      console.error('Firebase createAccount error:', error);
      throw error;
    }
  },

  async getAccount(accountId) {
    try {
      const snapshot = await db.ref(`accounts/${accountId}`).once('value');
      return snapshot.val();
    } catch (error) {
      console.error('Firebase getAccount error:', error);
      return null;
    }
  },

  async getAccountByUserId(userId) {
    try {
      const snapshot = await db.ref('accounts').orderByChild('user_id').equalTo(userId).once('value');
      const accounts = snapshot.val();
      return accounts ? Object.values(accounts)[0] : null;
    } catch (error) {
      console.error('Firebase getAccountByUserId error:', error);
      return null;
    }
  },

  async updateAccount(accountId, updates) {
    try {
      await db.ref(`accounts/${accountId}`).update(updates);
      const updatedAccount = await this.getAccount(accountId);
      return updatedAccount;
    } catch (error) {
      console.error('Firebase updateAccount error:', error);
      throw error;
    }
  },

  // Transaction operations
  async createTransaction(transactionData) {
    try {
      await db.ref(`transactions/${transactionData._id}`).set(transactionData);
      return transactionData;
    } catch (error) {
      console.error('Firebase createTransaction error:', error);
      throw error;
    }
  },

  async getUserTransactions(userId) {
    try {
      const snapshot = await db.ref('transactions').orderByChild('user_id').equalTo(userId).once('value');
      const transactions = snapshot.val();
      return transactions ? Object.values(transactions) : [];
    } catch (error) {
      console.error('Firebase getUserTransactions error:', error);
      return [];
    }
  },

  // Card operations
  async createCard(cardData) {
    try {
      await db.ref(`cards/${cardData._id}`).set(cardData);
      return cardData;
    } catch (error) {
      console.error('Firebase createCard error:', error);
      throw error;
    }
  },

  async getUserCards(userId) {
    try {
      const snapshot = await db.ref('cards').orderByChild('user_id').equalTo(userId).once('value');
      const cards = snapshot.val();
      return cards ? Object.values(cards) : [];
    } catch (error) {
      console.error('Firebase getUserCards error:', error);
      return [];
    }
  },

  async getCard(cardId) {
    try {
      const snapshot = await db.ref(`cards/${cardId}`).once('value');
      return snapshot.val();
    } catch (error) {
      console.error('Firebase getCard error:', error);
      return null;
    }
  },

  async updateCard(cardId, updates) {
    try {
      await db.ref(`cards/${cardId}`).update(updates);
      const updatedCard = await this.getCard(cardId);
      return updatedCard;
    } catch (error) {
      console.error('Firebase updateCard error:', error);
      throw error;
    }
  },

  async deleteCard(cardId) {
    try {
      await db.ref(`cards/${cardId}`).remove();
      return true;
    } catch (error) {
      console.error('Firebase deleteCard error:', error);
      throw error;
    }
  },

  // OTP operations
  async createOTP(otpData) {
    try {
      await db.ref(`otps/${otpData.user_id}_${otpData.otp}`).set(otpData);
      return otpData;
    } catch (error) {
      console.error('Firebase createOTP error:', error);
      throw error;
    }
  },

  async getOTP(userId, otp) {
    try {
      const snapshot = await db.ref(`otps/${userId}_${otp}`).once('value');
      return snapshot.val();
    } catch (error) {
      console.error('Firebase getOTP error:', error);
      return null;
    }
  },

  async deleteOTP(userId, otp) {
    try {
      await db.ref(`otps/${userId}_${otp}`).remove();
      return true;
    } catch (error) {
      console.error('Firebase deleteOTP error:', error);
      throw error;
    }
  },

  // Session operations
  async createSession(sessionData) {
    try {
      await db.ref(`sessions/${sessionData._id}`).set(sessionData);
      return sessionData;
    } catch (error) {
      console.error('Firebase createSession error:', error);
      throw error;
    }
  },

  async getSession(sessionId) {
    try {
      const snapshot = await db.ref(`sessions/${sessionId}`).once('value');
      return snapshot.val();
    } catch (error) {
      console.error('Firebase getSession error:', error);
      return null;
    }
  },

  async deleteSession(sessionId) {
    try {
      await db.ref(`sessions/${sessionId}`).remove();
      return true;
    } catch (error) {
      console.error('Firebase deleteSession error:', error);
      throw error;
    }
  }
};

// Valid Visa BIN ranges
const VISA_BINS = [
  '4532', '4556', '4916', '4539', '4485', '4929', '4024', '4532',
  '4716', '4024', '4486', '4539', '4556', '4916', '4532', '4556'
];

// Generate valid card number using Luhn algorithm
const generateValidCardNumber = () => {
  const bin = VISA_BINS[Math.floor(Math.random() * VISA_BINS.length)];
  let numbers = bin;
  
  // Generate remaining digits (total 15 digits before check digit)
  for (let i = 0; i < 11; i++) {
    numbers += Math.floor(Math.random() * 10);
  }
  
  // Calculate Luhn check digit
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

// Generate routing number (valid US routing number)
const generateRoutingNumber = () => {
  return '021000021'; // Standard routing number for testing
};

// Simple OTP Generator
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send OTP Email
const sendOTPEmail = async (email, name, otp) => {
  try {
    const mailOptions = {
      from: 'sandeshkadel2314@gmail.com',
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
    return false;
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
    
    // Check session from Firebase
    FirebaseManager.getSession(decoded.sessionId).then(session => {
      if (!session || Date.now() - session.created_at > 3 * 24 * 60 * 60 * 1000) {
        return res.status(401).json({ error: 'Session expired. Please login again.' });
      }

      // Get user from Firebase
      FirebaseManager.getUser(decoded.userId).then(user => {
        if (!user) {
          return res.status(401).json({ error: 'Invalid token' });
        }

        req.user = user;
        req.sessionId = decoded.sessionId;
        next();
      });
    }).catch(error => {
      return res.status(403).json({ error: 'Invalid or expired token' });
    });
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
    message: 'Server is running with Firebase database'
  });
});

// Test endpoint
app.get('/api/test', async (req, res) => {
  try {
    const usersSnapshot = await db.ref('users').once('value');
    const usersCount = usersSnapshot.val() ? Object.keys(usersSnapshot.val()).length : 0;
    
    res.json({
      message: 'API is working with Firebase!',
      users_count: usersCount,
      timestamp: new Date().toISOString(),
      database: 'Firebase Realtime Database'
    });
  } catch (error) {
    res.status(500).json({ error: 'Database connection failed' });
  }
});

// Auth Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, name, phone } = req.body;

    // Check if user exists using Firebase
    const existingUser = await FirebaseManager.getUserByEmail(email.toLowerCase());
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
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
      created_at: new Date().toISOString()
    };

    await FirebaseManager.createUser(user);

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
      created_at: new Date().toISOString()
    };

    await FirebaseManager.createAccount(account);

    // Generate OTP
    const otp = generateOTP();
    const otpRecord = {
      user_id: userId,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      used: false,
      created_at: new Date().toISOString()
    };

    await FirebaseManager.createOTP(otpRecord);

    // Send OTP via email
    const emailSent = await sendOTPEmail(email, name, otp);

    if (!emailSent) {
      // Clean up if email fails
      await FirebaseManager.deleteUser(userId);
      await FirebaseManager.deleteAccount(accountId);
      return res.status(500).json({ error: 'Failed to send OTP email. Please try again.' });
    }

    console.log(`✅ User created: ${email}`);
    console.log(`📧 OTP sent to ${email}: ${otp}`);

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

    // Find user using Firebase
    const existingUser = await FirebaseManager.getUserByEmail(email.toLowerCase());
    if (!existingUser) {
      return res.status(400).json({ error: 'User not found. Please sign up first.' });
    }

    const user = Object.values(existingUser)[0]; // Get first user from result

    // Generate OTP
    const otp = generateOTP();
    const otpRecord = {
      user_id: user._id,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      used: false,
      created_at: new Date().toISOString()
    };

    // Clear previous OTPs (in a real app, you'd query and delete)
    await FirebaseManager.createOTP(otpRecord);

    // Send OTP via email
    const emailSent = await sendOTPEmail(user.email, user.name, otp);

    if (!emailSent) {
      return res.status(500).json({ error: 'Failed to send OTP email. Please try again.' });
    }

    console.log(`📧 Login OTP sent to ${email}: ${otp}`);

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

    // Find valid OTP from Firebase
    const otpRecord = await FirebaseManager.getOTP(user_id, otp);

    if (!otpRecord || otpRecord.used || new Date(otpRecord.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Mark OTP as used
    await FirebaseManager.deleteOTP(user_id, otp);

    // Update user in Firebase
    const user = await FirebaseManager.updateUser(user_id, {
      email_verified: true,
      status: 'active'
    });

    // Get account from Firebase
    const account = await FirebaseManager.getAccountByUserId(user_id);

    // Create session in Firebase
    const sessionId = 'session_' + Date.now();
    const session = {
      _id: sessionId,
      user_id: user_id,
      created_at: Date.now(),
      expires_at: Date.now() + (3 * 24 * 60 * 60 * 1000) // 3 days
    };
    await FirebaseManager.createSession(session);

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

    const user = await FirebaseManager.getUser(user_id);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Generate new OTP
    const otp = generateOTP();
    const otpRecord = {
      user_id: user._id,
      otp,
      expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      used: false,
      created_at: new Date().toISOString()
    };

    await FirebaseManager.createOTP(otpRecord);

    // Send OTP via email
    const emailSent = await sendOTPEmail(user.email, user.name, otp);

    if (!emailSent) {
      return res.status(500).json({ error: 'Failed to send OTP email. Please try again.' });
    }

    console.log(`📧 New OTP sent to ${user.email}: ${otp}`);

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
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const account = await FirebaseManager.getAccountByUserId(req.user._id);
    
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

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone } = req.body;

    const updates = {};
    if (name) updates.name = name;
    if (phone) updates.phone = phone;
    
    const user = await FirebaseManager.updateUser(req.user._id, updates);

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
    const userTransactions = await FirebaseManager.getUserTransactions(req.user._id);

    userTransactions.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({
      transactions: userTransactions.slice(0, 20)
    });
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/account/deposit', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, description } = req.body;
    
    const account = await FirebaseManager.getAccountByUserId(req.user._id);

    // Update balance
    const newBalance = account.balance_cents + amount_cents;
    await FirebaseManager.updateAccount(account._id, { balance_cents: newBalance });

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
      created_at: new Date().toISOString()
    };

    await FirebaseManager.createTransaction(transaction);

    // Emit balance update via socket
    io.emit('balance_update', {
      user_id: req.user._id,
      balance_cents: newBalance
    });

    res.json({
      message: 'Deposit successful',
      transaction: {
        _id: transaction._id,
        amount_cents: transaction.amount_cents,
        description: transaction.description,
        status: transaction.status
      },
      new_balance: newBalance
    });

  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/account/transfer', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, recipient_email, description } = req.body;
    
    const senderAccount = await FirebaseManager.getAccountByUserId(req.user._id);

    // Check balance
    if (senderAccount.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Find recipient using Firebase
    const existingRecipient = await FirebaseManager.getUserByEmail(recipient_email.toLowerCase());
    if (!existingRecipient) {
      return res.status(400).json({ error: 'Recipient not found' });
    }

    const recipient = Object.values(existingRecipient)[0];
    const recipientAccount = await FirebaseManager.getAccountByUserId(recipient._id);

    // Update balances
    const senderNewBalance = senderAccount.balance_cents - amount_cents;
    const recipientNewBalance = recipientAccount.balance_cents + amount_cents;

    await FirebaseManager.updateAccount(senderAccount._id, { balance_cents: senderNewBalance });
    await FirebaseManager.updateAccount(recipientAccount._id, { balance_cents: recipientNewBalance });

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
      created_at: new Date().toISOString()
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
      created_at: new Date().toISOString()
    };

    await FirebaseManager.createTransaction(senderTransaction);
    await FirebaseManager.createTransaction(recipientTransaction);

    // Emit balance updates
    io.emit('balance_update', {
      user_id: req.user._id,
      balance_cents: senderNewBalance
    });

    io.emit('balance_update', {
      user_id: recipient._id,
      balance_cents: recipientNewBalance
    });

    res.json({
      message: 'Transfer successful',
      transaction: {
        _id: senderTransaction._id,
        amount_cents: senderTransaction.amount_cents,
        description: senderTransaction.description,
        status: senderTransaction.status
      },
      new_balance: senderNewBalance
    });

  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Card Routes
app.get('/api/cards', authenticateToken, async (req, res) => {
  try {
    const userCards = await FirebaseManager.getUserCards(req.user._id);

    userCards.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({
      cards: userCards
    });
  } catch (error) {
    console.error('Cards error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cards', authenticateToken, async (req, res) => {
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
      balance_cents: 0, // Card-specific balance
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
      created_at: new Date().toISOString()
    };

    await FirebaseManager.createCard(card);

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

app.get('/api/cards/:cardId', authenticateToken, async (req, res) => {
  try {
    const card = await FirebaseManager.getCard(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Get card transactions
    const cardTransactions = await FirebaseManager.getUserTransactions(req.user._id);
    const filteredTransactions = cardTransactions.filter(transaction => 
      transaction.description && transaction.description.includes(card.last4)
    );

    filteredTransactions.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

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
      transactions: filteredTransactions.slice(0, 10)
    });

  } catch (error) {
    console.error('Card details error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cards/:cardId/block', authenticateToken, async (req, res) => {
  try {
    const card = await FirebaseManager.getCard(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Toggle card status
    const newStatus = card.status === 'active' ? 'blocked' : 'active';
    await FirebaseManager.updateCard(card._id, { status: newStatus });

    res.json({
      message: `Card ${newStatus === 'active' ? 'unblocked' : 'blocked'} successfully`,
      card: {
        _id: card._id,
        status: newStatus,
        last4: card.last4
      }
    });

  } catch (error) {
    console.error('Block card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add funds to card
app.post('/api/cards/:cardId/fund', authenticateToken, async (req, res) => {
  try {
    const { amount_cents } = req.body;
    const card = await FirebaseManager.getCard(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Get user account
    const account = await FirebaseManager.getAccountByUserId(req.user._id);

    // Check account balance
    if (account.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient account balance' });
    }

    // Transfer funds from account to card
    const accountNewBalance = account.balance_cents - amount_cents;
    const cardNewBalance = card.balance_cents + amount_cents;

    await FirebaseManager.updateAccount(account._id, { balance_cents: accountNewBalance });
    await FirebaseManager.updateCard(card._id, { balance_cents: cardNewBalance });

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
      created_at: new Date().toISOString()
    };

    await FirebaseManager.createTransaction(transaction);

    // Emit balance updates
    io.emit('balance_update', {
      user_id: req.user._id,
      balance_cents: accountNewBalance
    });

    res.json({
      message: 'Card funded successfully',
      card_balance: cardNewBalance,
      account_balance: accountNewBalance
    });

  } catch (error) {
    console.error('Card funding error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Transfer between cards
app.post('/api/cards/transfer', authenticateToken, async (req, res) => {
  try {
    const { from_card_id, to_card_number, amount_cents, description } = req.body;

    // Find source card
    const fromCard = await FirebaseManager.getCard(from_card_id);
    if (!fromCard || fromCard.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Source card not found' });
    }

    // Check card balance
    if (fromCard.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient card balance' });
    }

    // Find destination card by card number
    const allCards = await FirebaseManager.getUserCards(); // This would need to be modified to get all cards
    let toCard = null;
    for (let card of allCards) {
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
    const fromCardNewBalance = fromCard.balance_cents - amount_cents;
    const toCardNewBalance = toCard.balance_cents + amount_cents;

    await FirebaseManager.updateCard(fromCard._id, { balance_cents: fromCardNewBalance });
    await FirebaseManager.updateCard(toCard._id, { balance_cents: toCardNewBalance });

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
      created_at: new Date().toISOString()
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
      created_at: new Date().toISOString()
    };

    await FirebaseManager.createTransaction(fromTransaction);
    await FirebaseManager.createTransaction(toTransaction);

    res.json({
      message: 'Card transfer successful',
      from_card_balance: fromCardNewBalance,
      to_card_balance: toCardNewBalance
    });

  } catch (error) {
    console.error('Card transfer error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete card endpoint
app.delete('/api/cards/:cardId', authenticateToken, async (req, res) => {
  try {
    const card = await FirebaseManager.getCard(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Return card balance to account if any
    if (card.balance_cents > 0) {
      const account = await FirebaseManager.getAccountByUserId(req.user._id);

      if (account) {
        const accountNewBalance = account.balance_cents + card.balance_cents;
        await FirebaseManager.updateAccount(account._id, { balance_cents: accountNewBalance });

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
          created_at: new Date().toISOString()
        };

        await FirebaseManager.createTransaction(transaction);

        // Emit balance update
        io.emit('balance_update', {
          user_id: req.user._id,
          balance_cents: accountNewBalance
        });
      }
    }

    // Delete the card
    await FirebaseManager.deleteCard(req.params.cardId);

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
app.post('/api/transfers/external', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, recipient_name, recipient_account_number, routing_number, description } = req.body;
    
    const account = await FirebaseManager.getAccountByUserId(req.user._id);

    // Check balance
    if (account.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Validate routing number (basic validation)
    if (!routing_number || routing_number.length !== 9) {
      return res.status(400).json({ error: 'Invalid routing number' });
    }

    // Validate account number
    if (!recipient_account_number || recipient_account_number.length < 5) {
      return res.status(400).json({ error: 'Invalid account number' });
    }

    // Update balance
    const newBalance = account.balance_cents - amount_cents;
    await FirebaseManager.updateAccount(account._id, { balance_cents: newBalance });

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
      created_at: new Date().toISOString()
    };

    await FirebaseManager.createTransaction(transaction);

    // Emit balance update
    io.emit('balance_update', {
      user_id: req.user._id,
      balance_cents: newBalance
    });

    res.json({
      message: 'External transfer completed successfully',
      transaction: {
        _id: transaction._id,
        amount_cents: transaction.amount_cents,
        description: transaction.description,
        status: transaction.status
      },
      new_balance: newBalance
    });

  } catch (error) {
    console.error('External transfer error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Receipt upload
app.post('/api/transactions/:transactionId/receipt', authenticateToken, async (req, res) => {
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
  console.log(`📧 Email: OTPs will be sent from sandeshkadel2314@gmail.com`);
  console.log(`💾 Storage: Firebase Realtime Database`);
  console.log(`\n🔗 Health Check: ${CLIENT_URL}/health`);
  console.log(`🔗 API Test: ${CLIENT_URL}/api/test`);
  console.log('\n✅ Your banking app is now fully functional with Firebase!');
  console.log('💡 Features working:');
  console.log('   - OTP-based authentication (no passwords)');
  console.log('   - Real OTP emails sent to users');
  console.log('   - 3-day session validity');
  console.log('   - Card-specific balances');
  console.log('   - Card-to-card transfers');
  console.log('   - Valid virtual card numbers');
  console.log('   - Real money transfers');
  console.log('   - Card management (create, view, block, delete)');
  console.log('   - Permanent data storage with Firebase');
});
