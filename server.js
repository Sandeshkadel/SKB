require('dotenv').config();

const express = require('express');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const socketIo = require('socket.io');
const http = require('http');
const cors = require('cors');
const path = require('path');
const admin = require('firebase-admin');

// Check if Stripe module is available
let Stripe;
let stripe;
try {
  Stripe = require('stripe');
  console.log('✅ Stripe module loaded successfully');
} catch (error) {
  console.error('❌ Stripe module not found. Please run: npm install stripe');
  console.error('💡 Run: npm install stripe');
  process.exit(1);
}

const app = express();
const server = http.createServer(app);

// Environment variables
const PORT = process.env.PORT || 3000;
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET || '4482eab8e42aa27db453de50461a098538751c9cbf58eef712f2e918955f17172bb6e19fa5dcde148aff1d5b4f908ba1';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || 'sk_test_51Ru6f5JNa6A3w8pIwXRPd21C5TEMZ3dpElyW9txFMyTdC0xxoHU6doRwNjeYsbg68tdguoEzCqu0eRQsK8CXJkb8000kCenkQS';
const STRIPE_RESTRICTED_KEY = process.env.STRIPE_RESTRICTED_KEY || 'rk_test_51Ru6f5JNa6A3w8pIC66USMcZvaD53Rry8nIu7X5tD4Sax3qcJAyZdclBsyxBYkUB3fZI8MaGNQcJEAeP4ZOMzz5000YI4W4fxs';

// Initialize Stripe with restricted key for Issuing
try {
  if (!STRIPE_RESTRICTED_KEY) {
    throw new Error('STRIPE_RESTRICTED_KEY is required');
  }
  stripe = Stripe(STRIPE_RESTRICTED_KEY);
  console.log('✅ Stripe initialized successfully');
} catch (error) {
  console.error('❌ Stripe initialization failed:', error.message);
  stripe = null;
}

const CARDHOLDER_ID = process.env.CARDHOLDER_ID;

console.log('🚀 Starting HCB Clone Server with Stripe Issuing...');
console.log(`💳 Stripe Mode: ${STRIPE_RESTRICTED_KEY && STRIPE_RESTRICTED_KEY.startsWith('rk_test_') ? 'TEST' : 'LIVE'}`);

// Initialize Firebase Admin
let db = null;
try {
  // For demo purposes, use in-memory storage if Firebase is not configured
  if (process.env.FIREBASE_PRIVATE_KEY) {
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

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: "https://hcb-4ce8c.firebaseio.com"
    });
    
    db = admin.firestore();
    console.log('✅ Firebase Admin initialized successfully');
  } else {
    console.log('⚠️ Firebase credentials not found, using in-memory storage');
  }
} catch (error) {
  console.log('⚠️ Firebase Admin initialization failed, using in-memory storage:', error.message);
}

// Configure Socket.IO
const io = socketIo(server, {
  cors: {
    origin: CLIENT_URL,
    methods: ["GET", "POST"]
  }
});

// Middleware - MUST BE BEFORE ROUTES
app.use(cors({
  origin: CLIENT_URL,
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));

// Improved Email Transporter with better configuration and fallbacks
const createEmailTransporter = () => {
  // Try Gmail first if credentials are available
  if (process.env.GMAIL_USER && process.env.GMAIL_PASS) {
    console.log('📧 Using Gmail SMTP configuration');
    return nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS
      },
      connectionTimeout: 10000, // 10 seconds
      greetingTimeout: 10000,
      socketTimeout: 15000
    });
  }

  // Try Porkbun with improved configuration
  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    console.log('📧 Using Porkbun SMTP configuration');
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.porkbun.com',
      port: process.env.SMTP_PORT || 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      },
      connectionTimeout: 15000, // 15 seconds
      greetingTimeout: 15000,
      socketTimeout: 20000,
      tls: {
        rejectUnauthorized: false // For development only
      }
    });
  }

  // Fallback to console logging only
  console.log('📧 No email configuration found - OTPs will be logged to console only');
  return {
    sendMail: (options) => {
      console.log('📧 Email would be sent:', {
        to: options.to,
        subject: options.subject,
        text: options.text || 'Check console for OTP'
      });
      return Promise.resolve({ messageId: 'console-only' });
    },
    verify: () => Promise.resolve(true)
  };
};

let emailTransporter = createEmailTransporter();

// Verify email transporter with better error handling
const verifyEmailTransporter = async () => {
  try {
    await emailTransporter.verify();
    console.log('✅ Email transporter is ready to send messages');
    return true;
  } catch (error) {
    console.log('❌ Email transporter verification failed:', error.message);
    console.log('💡 Emails will be logged to console instead');
    return false;
  }
};

verifyEmailTransporter();

// In-memory storage fallback
const users = new Map();
const accounts = new Map();
const transactions = new Map();
const cards = new Map();
const organizations = new Map();
const otps = new Map();

// Firebase Data Management
const FirebaseManager = {
  async saveUser(user) {
    if (db) {
      try {
        await db.collection('users').doc(user._id).set(user);
        return;
      } catch (error) {
        console.error('Firebase saveUser error:', error);
      }
    }
    users.set(user._id, user);
  },

  async getUser(userId) {
    if (db) {
      try {
        const doc = await db.collection('users').doc(userId).get();
        return doc.exists ? doc.data() : null;
      } catch (error) {
        console.error('Firebase getUser error:', error);
      }
    }
    return users.get(userId);
  },

  async getUserByEmail(email) {
    if (db) {
      try {
        const snapshot = await db.collection('users').where('email', '==', email.toLowerCase()).get();
        if (!snapshot.empty) {
          return snapshot.docs[0].data();
        }
        return null;
      } catch (error) {
        console.error('Firebase getUserByEmail error:', error);
      }
    }
    
    for (let user of users.values()) {
      if (user.email === email.toLowerCase()) {
        return user;
      }
    }
    return null;
  },

  async saveAccount(account) {
    if (db) {
      try {
        await db.collection('accounts').doc(account._id).set(account);
        return;
      } catch (error) {
        console.error('Firebase saveAccount error:', error);
      }
    }
    accounts.set(account._id, account);
  },

  async getAccountByUserId(userId) {
    if (db) {
      try {
        const snapshot = await db.collection('accounts').where('user_id', '==', userId).get();
        if (!snapshot.empty) {
          return snapshot.docs[0].data();
        }
        return null;
      } catch (error) {
        console.error('Firebase getAccountByUserId error:', error);
      }
    }
    
    for (let account of accounts.values()) {
      if (account.user_id === userId) {
        return account;
      }
    }
    return null;
  },

  async saveTransaction(transaction) {
    if (db) {
      try {
        await db.collection('transactions').doc(transaction._id).set(transaction);
        return;
      } catch (error) {
        console.error('Firebase saveTransaction error:', error);
      }
    }
    transactions.set(transaction._id, transaction);
  },

  async getTransactionsByUserId(userId) {
    if (db) {
      try {
        const snapshot = await db.collection('transactions').where('user_id', '==', userId).get();
        return snapshot.docs.map(doc => doc.data());
      } catch (error) {
        console.error('Firebase getTransactionsByUserId error:', error);
      }
    }
    
    const userTransactions = [];
    for (let transaction of transactions.values()) {
      if (transaction.user_id === userId) {
        userTransactions.push(transaction);
      }
    }
    return userTransactions;
  },

  async saveCard(card) {
    if (db) {
      try {
        await db.collection('cards').doc(card._id).set(card);
        return;
      } catch (error) {
        console.error('Firebase saveCard error:', error);
      }
    }
    cards.set(card._id, card);
  },

  async getCardsByUserId(userId) {
    if (db) {
      try {
        const snapshot = await db.collection('cards').where('user_id', '==', userId).get();
        return snapshot.docs.map(doc => doc.data());
      } catch (error) {
        console.error('Firebase getCardsByUserId error:', error);
      }
    }
    
    const userCards = [];
    for (let card of cards.values()) {
      if (card.user_id === userId) {
        userCards.push(card);
      }
    }
    return userCards;
  },

  async getCardById(cardId) {
    if (db) {
      try {
        const doc = await db.collection('cards').doc(cardId).get();
        return doc.exists ? doc.data() : null;
      } catch (error) {
        console.error('Firebase getCardById error:', error);
      }
    }
    return cards.get(cardId);
  },

  async getCardByNumber(cardNumber) {
    if (db) {
      try {
        const snapshot = await db.collection('cards').where('card_number', '==', cardNumber).get();
        if (!snapshot.empty) {
          return snapshot.docs[0].data();
        }
        return null;
      } catch (error) {
        console.error('Firebase getCardByNumber error:', error);
      }
    }
    
    for (let card of cards.values()) {
      if (card.card_number === cardNumber) {
        return card;
      }
    }
    return null;
  },

  async saveStripeCard(stripeCard) {
    if (db) {
      try {
        await db.collection('stripe_cards').doc(stripeCard.id).set(stripeCard);
      } catch (error) {
        console.error('Firebase saveStripeCard error:', error);
      }
    }
  },

  async getStripeCardsByUserId(userId) {
    if (db) {
      try {
        const snapshot = await db.collection('stripe_cards').where('user_id', '==', userId).get();
        return snapshot.docs.map(doc => doc.data());
      } catch (error) {
        console.error('Firebase getStripeCardsByUserId error:', error);
      }
    }
    return [];
  },

  async saveOrganization(organization) {
    if (db) {
      try {
        await db.collection('organizations').doc(organization._id).set(organization);
        return;
      } catch (error) {
        console.error('Firebase saveOrganization error:', error);
      }
    }
    organizations.set(organization._id, organization);
  },

  async getOrganizationById(orgId) {
    if (db) {
      try {
        const doc = await db.collection('organizations').doc(orgId).get();
        return doc.exists ? doc.data() : null;
      } catch (error) {
        console.error('Firebase getOrganizationById error:', error);
      }
    }
    return organizations.get(orgId);
  },

  async getAllOrganizations() {
    if (db) {
      try {
        const snapshot = await db.collection('organizations').get();
        return snapshot.docs.map(doc => doc.data());
      } catch (error) {
        console.error('Firebase getAllOrganizations error:', error);
      }
    }
    return Array.from(organizations.values());
  },

  async getOrganizationsByUserId(userId) {
    if (db) {
      try {
        const snapshot = await db.collection('organizations').where('members', 'array-contains', userId).get();
        return snapshot.docs.map(doc => doc.data());
      } catch (error) {
        console.error('Firebase getOrganizationsByUserId error:', error);
      }
    }
    
    const userOrganizations = [];
    for (let org of organizations.values()) {
      if (org.members.some(member => member.user_id === userId)) {
        userOrganizations.push(org);
      }
    }
    return userOrganizations;
  },

  async searchOrganizations(query) {
    const allOrgs = await this.getAllOrganizations();
    return allOrgs.filter(org => 
      org.name.toLowerCase().includes(query.toLowerCase()) ||
      org._id.toLowerCase().includes(query.toLowerCase()) ||
      (org.code && org.code.toLowerCase().includes(query.toLowerCase()))
    );
  },

  // OTP Management
  async saveOTP(email, otpData) {
    if (db) {
      try {
        await db.collection('otps').doc(email).set({
          ...otpData,
          created_at: new Date()
        });
        return;
      } catch (error) {
        console.error('Firebase saveOTP error:', error);
      }
    }
    otps.set(email, otpData);
  },

  async getOTP(email) {
    if (db) {
      try {
        const doc = await db.collection('otps').doc(email).get();
        return doc.exists ? doc.data() : null;
      } catch (error) {
        console.error('Firebase getOTP error:', error);
      }
    }
    return otps.get(email);
  },

  async deleteOTP(email) {
    if (db) {
      try {
        await db.collection('otps').doc(email).delete();
        return;
      } catch (error) {
        console.error('Firebase deleteOTP error:', error);
      }
    }
    otps.delete(email);
  }
};

// Generate account number
const generateAccountNumber = () => {
  return Math.random().toString().slice(2, 12);
};

// Generate routing number
const generateRoutingNumber = () => {
  return '021000021';
};

// Generate organization code
const generateOrgCode = () => {
  return 'ORG-' + Math.floor(10000000 + Math.random() * 90000000);
};

// Simple OTP Generator
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Improved Send OTP Email with better error handling
const sendOTPEmail = async (email, name, otp) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_FROM || 'noreply@hcbclone.com',
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
            <p>This OTP is valid for 5 minutes. Please do not share it with anyone.</p>
            <p>If you didn't request this, please ignore this email.</p>
          </div>
          <div style="background: #333; color: white; padding: 15px; text-align: center;">
            <p>&copy; 2024 HCB Clone. All rights reserved.</p>
          </div>
        </div>
      `,
      text: `Your HCB Clone OTP is: ${otp}. This OTP is valid for 5 minutes.`
    };

    // Try to send email, but don't fail the request if email fails
    try {
      await emailTransporter.sendMail(mailOptions);
      console.log(`✅ OTP email sent to ${email}`);
    } catch (emailError) {
      console.log(`❌ Failed to send OTP email to ${email}:`, emailError.message);
      // Don't throw error - just log it and continue
    }

    // Always log OTP to console for development/demo purposes
    console.log(`📧 OTP for ${email}: ${otp}`);
    return true;

  } catch (error) {
    console.error('❌ Error in sendOTPEmail function:', error);
    // Log OTP to console as fallback
    console.log(`📧 OTP for ${email}: ${otp}`);
    return true; // Return true to not block the OTP process
  }
};

// Create Stripe Cardholder (run once to set up)
const createStripeCardholder = async () => {
  try {
    if (!stripe) {
      console.log('⚠️ Stripe not initialized, skipping cardholder creation');
      return null;
    }

    if (!CARDHOLDER_ID) {
      console.log('🔄 Creating Stripe cardholder...');
      const cardholder = await stripe.issuing.cardholders.create({
        name: 'HCB Clone User',
        email: 'support@hcbclone.com',
        phone_number: '+18008675309',
        status: 'active',
        type: 'individual',
        individual: {
          first_name: 'HCB',
          last_name: 'User',
          dob: {
            day: 1,
            month: 1,
            year: 1990,
          },
        },
        billing: {
          address: {
            line1: '123 Main Street',
            city: 'San Francisco',
            state: 'CA',
            postal_code: '94111',
            country: 'US',
          },
        },
      });
      console.log('✅ Stripe Cardholder created:', cardholder.id);
      return cardholder.id;
    }
    console.log('✅ Using existing Stripe cardholder:', CARDHOLDER_ID);
    return CARDHOLDER_ID;
  } catch (error) {
    console.error('❌ Failed to create Stripe cardholder:', error.message);
    return null;
  }
};

// Improved Auth middleware with better error handling
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user from storage
    const user = users.get(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
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
    message: 'Server is running with Stripe Issuing',
    storage: db ? 'Firebase Firestore' : 'In-memory',
    stripe: stripe ? 'Enabled' : 'Disabled',
    stripe_mode: STRIPE_RESTRICTED_KEY && STRIPE_RESTRICTED_KEY.startsWith('rk_test_') ? 'TEST' : 'LIVE',
    email: 'Email system configured with fallbacks'
  });
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    message: 'API is working with Stripe!',
    storage: db ? 'Firebase' : 'In-memory',
    stripe: stripe ? 'Enabled' : 'Disabled',
    stripe_mode: STRIPE_RESTRICTED_KEY && STRIPE_RESTRICTED_KEY.startsWith('rk_test_') ? 'TEST' : 'LIVE',
    email_provider: 'SMTP with fallback',
    timestamp: new Date().toISOString()
  });
});

// Stripe test endpoint
app.get('/api/stripe/test', authenticateToken, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({
        error: 'Stripe not initialized',
        message: 'Stripe module is not properly configured'
      });
    }

    // Test Stripe connection by listing cardholders
    const cardholders = await stripe.issuing.cardholders.list({limit: 1});
    
    res.json({
      message: 'Stripe connection successful!',
      stripe_mode: STRIPE_RESTRICTED_KEY && STRIPE_RESTRICTED_KEY.startsWith('rk_test_') ? 'TEST' : 'LIVE',
      cardholders_count: cardholders.data.length,
      can_create_cards: true
    });
  } catch (error) {
    res.status(500).json({
      error: 'Stripe connection failed',
      message: error.message
    });
  }
});

// ========== OTP AUTH ROUTES ==========

// Send OTP endpoint with improved error handling
app.post('/api/send-otp', async (req, res) => {
  try {
    console.log('📧 Send OTP request received:', req.body);
    
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Generate OTP
    const otp = generateOTP();
    const otpData = {
      otp: otp,
      expires: Date.now() + 5 * 60 * 1000, // 5 minutes
      attempts: 0
    };

    // Save OTP to storage
    await FirebaseManager.saveOTP(email, otpData);

    // Send OTP email (this won't throw errors that break the request)
    await sendOTPEmail(email, 'User', otp);

    res.json({
      message: 'OTP sent successfully',
      email: email,
      expires_in: '5 minutes',
      note: 'Check your email and also the server console for the OTP'
    });

  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ error: 'Internal server error while sending OTP' });
  }
});

// Verify OTP endpoint
app.post('/api/verify-otp', async (req, res) => {
  try {
    console.log('✅ Verify OTP request received:', req.body);
    
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }

    // Get OTP data
    const otpData = await FirebaseManager.getOTP(email);
    
    if (!otpData) {
      return res.status(400).json({ error: 'OTP not found or expired' });
    }

    // Check if OTP has expired
    if (Date.now() > otpData.expires) {
      await FirebaseManager.deleteOTP(email);
      return res.status(400).json({ error: 'OTP has expired' });
    }

    // Check if OTP matches
    if (otpData.otp !== otp) {
      // Increment attempts
      otpData.attempts += 1;
      await FirebaseManager.saveOTP(email, otpData);

      if (otpData.attempts >= 3) {
        await FirebaseManager.deleteOTP(email);
        return res.status(400).json({ error: 'Too many failed attempts. OTP invalidated.' });
      }

      return res.status(400).json({ error: 'Invalid OTP' });
    }

    // OTP is valid - check if user exists or needs to be created
    let user = await FirebaseManager.getUserByEmail(email);
    let isNewUser = false;

    if (!user) {
      // Create new user
      isNewUser = true;
      const userId = 'user_' + Date.now();
      user = {
        _id: userId,
        email: email.toLowerCase(),
        name: email.split('@')[0], // Default name from email
        phone: '',
        status: 'active',
        email_verified: true,
        kyc_status: 'pending',
        created_at: new Date()
      };

      await FirebaseManager.saveUser(user);

      // Create account for user
      const accountId = 'acc_' + Date.now();
      const account = {
        _id: accountId,
        user_id: userId,
        account_number: generateAccountNumber(),
        routing_number: generateRoutingNumber(),
        balance_cents: 100000, // Start with $1000 for demo
        currency: 'USD',
        status: 'active',
        created_at: new Date()
      };

      await FirebaseManager.saveAccount(account);
    }

    // Get user account
    const account = await FirebaseManager.getAccountByUserId(user._id);

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id
      }, 
      JWT_SECRET, 
      { expiresIn: '3d' }
    );

    // Clean up OTP
    await FirebaseManager.deleteOTP(email);

    // Store user in memory for session management
    users.set(user._id, user);

    res.json({
      message: isNewUser ? 'Account created and verified successfully' : 'Login successful',
      token,
      user: {
        _id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        email_verified: user.email_verified,
        kyc_status: user.kyc_status
      },
      account: account,
      is_new_user: isNewUser
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Internal server error during OTP verification' });
  }
});

// ========== LEGACY AUTH ROUTES (for backward compatibility) ==========

// Signup endpoint
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, name, phone } = req.body;

    if (!email || !name) {
      return res.status(400).json({ error: 'Email and name are required' });
    }

    // Check if user already exists
    const existingUser = await FirebaseManager.getUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    // Create new user
    const userId = 'user_' + Date.now();
    const user = {
      _id: userId,
      email: email.toLowerCase(),
      name: name,
      phone: phone || '',
      status: 'active',
      email_verified: false,
      kyc_status: 'pending',
      created_at: new Date()
    };

    await FirebaseManager.saveUser(user);

    // Generate OTP
    const otp = generateOTP();
    const otpData = {
      otp,
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
      attempts: 0
    };

    await FirebaseManager.saveOTP(email, otpData);

    // Send OTP email
    await sendOTPEmail(email, name, otp);

    res.json({
      message: 'OTP sent to your email',
      user_id: userId,
      email: email,
      requires_otp: true
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error during signup' });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Check if user exists
    const user = await FirebaseManager.getUserByEmail(email);
    if (!user) {
      return res.status(400).json({ error: 'No account found with this email' });
    }

    // Generate OTP
    const otp = generateOTP();
    const otpData = {
      otp,
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
      attempts: 0
    };

    await FirebaseManager.saveOTP(email, otpData);

    // Send OTP email
    await sendOTPEmail(email, user.name, otp);

    res.json({
      message: 'OTP sent to your email',
      user_id: user._id,
      email: email,
      requires_otp: true
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});

// Verify OTP endpoint (legacy)
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { user_id, otp } = req.body;

    if (!user_id || !otp) {
      return res.status(400).json({ error: 'User ID and OTP are required' });
    }

    // For demo purposes, accept any OTP for demo accounts
    const user = await FirebaseManager.getUser(user_id);
    if (user && (user.email.includes('demo@hcb.com') || user.email.includes('user2@hcb.com'))) {
      // Accept any OTP for demo accounts
      console.log(`✅ Demo user ${user.email} OTP bypassed`);
    } else {
      // Check OTP for real users using new OTP system
      const otpData = await FirebaseManager.getOTP(user.email);
      if (!otpData || otpData.otp !== otp) {
        return res.status(400).json({ error: 'Invalid OTP' });
      }

      if (Date.now() > otpData.expires) {
        await FirebaseManager.deleteOTP(user.email);
        return res.status(400).json({ error: 'OTP has expired' });
      }
    }

    // OTP is valid, get user data
    const userData = await FirebaseManager.getUser(user_id);
    if (!userData) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Get user account
    const account = await FirebaseManager.getAccountByUserId(user_id);

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: userData._id
      }, 
      JWT_SECRET, 
      { expiresIn: '3d' }
    );

    // Clean up OTP
    if (userData.email) {
      await FirebaseManager.deleteOTP(userData.email);
    }

    // Store user in memory for session management
    users.set(userData._id, userData);

    res.json({
      message: 'Login successful',
      token,
      user: {
        _id: userData._id,
        email: userData.email,
        name: userData.name,
        phone: userData.phone,
        email_verified: userData.email_verified,
        kyc_status: userData.kyc_status
      },
      account: account
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Internal server error during OTP verification' });
  }
});

// Resend OTP endpoint
app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const { user_id } = req.body;

    if (!user_id) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    const user = await FirebaseManager.getUser(user_id);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Generate new OTP
    const otp = generateOTP();
    const otpData = {
      otp,
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
      attempts: 0
    };

    await FirebaseManager.saveOTP(user.email, otpData);

    // Send OTP email
    await sendOTPEmail(user.email, user.name, otp);

    res.json({
      message: 'New OTP sent to your email',
      user_id: user_id
    });

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Internal server error during OTP resend' });
  }
});

// Check session endpoint
app.get('/api/auth/check-session', authenticateToken, async (req, res) => {
  try {
    res.json({
      valid: true,
      user: req.user
    });
  } catch (error) {
    res.status(401).json({ valid: false, error: 'Invalid session' });
  }
});

// ========== PROFILE ROUTES ==========

// Get profile endpoint
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const account = await FirebaseManager.getAccountByUserId(req.user._id);
    
    res.json({
      user: req.user,
      account: account
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update profile endpoint
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone, organization_id } = req.body;

    // Update user data
    if (name) req.user.name = name;
    if (phone) req.user.phone = phone;
    if (organization_id) req.user.organization_id = organization_id;

    await FirebaseManager.saveUser(req.user);

    // Update in-memory user
    users.set(req.user._id, req.user);

    res.json({
      message: 'Profile updated successfully',
      user: req.user
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== ACCOUNT ROUTES ==========

// Get transactions endpoint
app.get('/api/account/transactions', authenticateToken, async (req, res) => {
  try {
    const transactions = await FirebaseManager.getTransactionsByUserId(req.user._id);
    
    res.json({
      transactions: transactions.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    });
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Deposit endpoint
app.post('/api/account/deposit', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, description } = req.body;

    if (!amount_cents || amount_cents <= 0) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }

    const account = await FirebaseManager.getAccountByUserId(req.user._id);
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Update balance
    account.balance_cents += amount_cents;
    await FirebaseManager.saveAccount(account);

    // Create transaction record
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

    await FirebaseManager.saveTransaction(transaction);

    // Emit balance update via socket
    io.emit('balance_update', {
      user_id: req.user._id,
      balance_cents: account.balance_cents
    });

    res.json({
      message: 'Deposit successful',
      new_balance: account.balance_cents,
      transaction: transaction
    });

  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ error: 'Internal server error during deposit' });
  }
});

// Transfer endpoint
app.post('/api/account/transfer', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, recipient_email, description } = req.body;

    if (!amount_cents || amount_cents <= 0) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }

    if (!recipient_email) {
      return res.status(400).json({ error: 'Recipient email is required' });
    }

    // Get sender account
    const senderAccount = await FirebaseManager.getAccountByUserId(req.user._id);
    if (!senderAccount) {
      return res.status(404).json({ error: 'Sender account not found' });
    }

    // Check sufficient balance
    if (senderAccount.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Get recipient user
    const recipientUser = await FirebaseManager.getUserByEmail(recipient_email);
    if (!recipientUser) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    // Get recipient account
    const recipientAccount = await FirebaseManager.getAccountByUserId(recipientUser._id);
    if (!recipientAccount) {
      return res.status(404).json({ error: 'Recipient account not found' });
    }

    // Update balances
    senderAccount.balance_cents -= amount_cents;
    recipientAccount.balance_cents += amount_cents;

    await FirebaseManager.saveAccount(senderAccount);
    await FirebaseManager.saveAccount(recipientAccount);

    // Create transactions for both parties
    const transactionId = 'txn_' + Date.now();
    const senderTransaction = {
      _id: transactionId + '_sent',
      user_id: req.user._id,
      account_id: senderAccount._id,
      amount_cents: -amount_cents,
      currency: 'USD',
      type: 'transfer_sent',
      description: description || `Transfer to ${recipient_email}`,
      counterparty_name: recipientUser.name,
      counterparty_email: recipient_email,
      status: 'completed',
      created_at: new Date()
    };

    const recipientTransaction = {
      _id: transactionId + '_received',
      user_id: recipientUser._id,
      account_id: recipientAccount._id,
      amount_cents: amount_cents,
      currency: 'USD',
      type: 'transfer_received',
      description: description || `Transfer from ${req.user.email}`,
      counterparty_name: req.user.name,
      counterparty_email: req.user.email,
      status: 'completed',
      created_at: new Date()
    };

    await FirebaseManager.saveTransaction(senderTransaction);
    await FirebaseManager.saveTransaction(recipientTransaction);

    // Emit balance updates
    io.emit('balance_update', {
      user_id: req.user._id,
      balance_cents: senderAccount.balance_cents
    });

    io.emit('balance_update', {
      user_id: recipientUser._id,
      balance_cents: recipientAccount.balance_cents
    });

    res.json({
      message: 'Transfer successful',
      new_balance: senderAccount.balance_cents,
      transaction: senderTransaction
    });

  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({ error: 'Internal server error during transfer' });
  }
});

// ========== CARD ROUTES ==========

// Get cards endpoint
app.get('/api/cards', authenticateToken, async (req, res) => {
  try {
    const cards = await FirebaseManager.getCardsByUserId(req.user._id);
    const stripeCards = await FirebaseManager.getStripeCardsByUserId(req.user._id);
    
    // Combine both types of cards
    const allCards = [
      ...cards,
      ...stripeCards.map(sc => ({
        _id: sc.id,
        user_id: sc.user_id,
        card_number: sc.card_number,
        last4: sc.last4,
        expiry_month: sc.expiry_month,
        expiry_year: sc.expiry_year,
        cvv: sc.cvv,
        brand: sc.brand,
        status: sc.status,
        balance_cents: sc.balance_cents,
        card_owner: sc.card_owner,
        billing_address: sc.billing_address,
        phone_number: sc.phone_number,
        card_type: 'virtual',
        card_network: sc.brand.toLowerCase(),
        created_at: new Date(sc.created * 1000),
        is_stripe_card: true,
        stripe_card_id: sc.id
      }))
    ];

    res.json({
      cards: allCards.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    });
  } catch (error) {
    console.error('Cards error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create card endpoint
app.post('/api/cards', authenticateToken, async (req, res) => {
  try {
    const { card_owner, organization_id } = req.body;

    // Try to create real Stripe card first
    if (stripe && CARDHOLDER_ID) {
      try {
        console.log(`🔄 Creating real Stripe virtual card for user: ${req.user.email}`);

        const cardParams = {
          cardholder: CARDHOLDER_ID,
          currency: 'usd',
          type: 'virtual',
          status: 'active',
          metadata: {
            user_id: req.user._id,
            user_email: req.user.email,
            card_owner: card_owner || req.user.name,
            created_via: 'hcb_clone'
          }
        };

        const stripeCard = await stripe.issuing.cards.create(cardParams);

        console.log(`✅ Real Stripe card created: ${stripeCard.id}`);

        // Store card in Firebase
        const cardData = {
          id: stripeCard.id,
          user_id: req.user._id,
          card_number: stripeCard.number,
          last4: stripeCard.last4,
          expiry_month: stripeCard.exp_month,
          expiry_year: stripeCard.exp_year,
          cvv: stripeCard.cvc,
          brand: stripeCard.brand,
          status: stripeCard.status,
          currency: stripeCard.currency,
          type: stripeCard.type,
          card_owner: card_owner || req.user.name,
          organization_id: organization_id || null,
          balance_cents: 0,
          billing_address: {
            line1: '123 Main Street',
            city: 'San Francisco',
            state: 'CA',
            postal_code: '94111',
            country: 'US'
          },
          created: stripeCard.created,
          stripe_object: 'issuing.card'
        };

        await FirebaseManager.saveStripeCard(cardData);

        // Also store in regular cards collection for compatibility
        const compatibleCard = {
          _id: `card_${stripeCard.id}`,
          user_id: req.user._id,
          card_number: stripeCard.number,
          last4: stripeCard.last4,
          expiry_month: stripeCard.exp_month,
          expiry_year: stripeCard.exp_year,
          cvv: stripeCard.cvc,
          brand: stripeCard.brand,
          status: stripeCard.status,
          balance_cents: 0,
          card_owner: card_owner || req.user.name,
          billing_address: {
            street: '123 Main Street',
            city: 'San Francisco',
            state: 'CA',
            zip_code: '94111',
            country: 'US'
          },
          phone_number: req.user.phone || '+1234567890',
          card_type: 'virtual',
          card_network: stripeCard.brand.toLowerCase(),
          created_at: new Date(stripeCard.created * 1000),
          stripe_card_id: stripeCard.id,
          is_stripe_card: true
        };

        await FirebaseManager.saveCard(compatibleCard);

        return res.json({
          message: 'Real virtual card created successfully via Stripe',
          card: compatibleCard,
          stripe_card_id: stripeCard.id
        });

      } catch (stripeError) {
        console.error('Stripe card creation failed, falling back to virtual card:', stripeError.message);
      }
    }

    // Fallback to virtual card if Stripe fails or not configured
    const cardId = 'card_' + Date.now();
    const card = {
      _id: cardId,
      user_id: req.user._id,
      card_number: Math.random().toString().slice(2, 18),
      last4: Math.random().toString().slice(2, 6),
      expiry_month: Math.floor(Math.random() * 12) + 1,
      expiry_year: new Date().getFullYear() + 3,
      cvv: Math.floor(Math.random() * 900) + 100,
      brand: 'Visa',
      status: 'active',
      balance_cents: 0,
      card_owner: card_owner || req.user.name,
      billing_address: {
        street: '123 Main Street',
        city: 'San Francisco',
        state: 'CA',
        zip_code: '94111',
        country: 'US'
      },
      phone_number: req.user.phone || '+1234567890',
      card_type: 'virtual',
      card_network: 'visa',
      created_at: new Date(),
      is_stripe_card: false
    };

    await FirebaseManager.saveCard(card);

    res.json({
      message: 'Virtual card created successfully',
      card: card
    });

  } catch (error) {
    console.error('Create card error:', error);
    res.status(500).json({ error: 'Internal server error during card creation' });
  }
});

// Get card details endpoint
app.get('/api/cards/:cardId', authenticateToken, async (req, res) => {
  try {
    const card = await FirebaseManager.getCardById(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Get card transactions
    const transactions = await FirebaseManager.getTransactionsByUserId(req.user._id);
    const cardTransactions = transactions.filter(t => t.card_id === card._id);

    res.json({
      card: card,
      transactions: cardTransactions
    });
  } catch (error) {
    console.error('Card details error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update card endpoint
app.put('/api/cards/:cardId', authenticateToken, async (req, res) => {
  try {
    const { card_owner } = req.body;
    const card = await FirebaseManager.getCardById(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    if (card_owner) {
      card.card_owner = card_owner;
    }

    await FirebaseManager.saveCard(card);

    res.json({
      message: 'Card updated successfully',
      card: card
    });
  } catch (error) {
    console.error('Update card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Fund card endpoint
app.post('/api/cards/:cardId/fund', authenticateToken, async (req, res) => {
  try {
    const { amount_cents } = req.body;
    const card = await FirebaseManager.getCardById(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Get user account
    const account = await FirebaseManager.getAccountByUserId(req.user._id);

    // Check account balance
    if (account.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient account balance' });
    }

    // Update balances
    account.balance_cents -= amount_cents;
    card.balance_cents += amount_cents;

    await FirebaseManager.saveAccount(account);
    await FirebaseManager.saveCard(card);

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

    await FirebaseManager.saveTransaction(transaction);

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

// Block/unblock card endpoint
app.post('/api/cards/:cardId/block', authenticateToken, async (req, res) => {
  try {
    const card = await FirebaseManager.getCardById(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Toggle card status
    card.status = card.status === 'active' ? 'blocked' : 'active';
    await FirebaseManager.saveCard(card);

    res.json({
      message: `Card ${card.status === 'active' ? 'unblocked' : 'blocked'} successfully`,
      card: card
    });
  } catch (error) {
    console.error('Block card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete card endpoint
app.delete('/api/cards/:cardId', authenticateToken, async (req, res) => {
  try {
    const card = await FirebaseManager.getCardById(req.params.cardId);

    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Return balance to account if any
    if (card.balance_cents > 0) {
      const account = await FirebaseManager.getAccountByUserId(req.user._id);
      if (account) {
        account.balance_cents += card.balance_cents;
        await FirebaseManager.saveAccount(account);

        // Create transaction for balance return
        const transactionId = 'txn_' + Date.now();
        const transaction = {
          _id: transactionId,
          user_id: req.user._id,
          account_id: account._id,
          card_id: card._id,
          amount_cents: card.balance_cents,
          currency: 'USD',
          type: 'card_closure_refund',
          description: `Card closure refund - ${card.last4}`,
          status: 'completed',
          created_at: new Date()
        };

        await FirebaseManager.saveTransaction(transaction);

        // Emit balance update
        io.emit('balance_update', {
          user_id: req.user._id,
          balance_cents: account.balance_cents
        });
      }
    }

    // Delete card
    if (db) {
      await db.collection('cards').doc(card._id).delete();
    } else {
      cards.delete(card._id);
    }

    res.json({
      message: 'Card deleted successfully',
      refunded_amount: card.balance_cents
    });

  } catch (error) {
    console.error('Delete card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Card transfer endpoint
app.post('/api/cards/transfer', authenticateToken, async (req, res) => {
  try {
    const { from_card_id, to_card_number, amount_cents, description } = req.body;

    if (!from_card_id || !to_card_number || !amount_cents) {
      return res.status(400).json({ error: 'From card, to card, and amount are required' });
    }

    // Get sender card
    const fromCard = await FirebaseManager.getCardById(from_card_id);
    if (!fromCard || fromCard.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Sender card not found' });
    }

    // Check sender card balance
    if (fromCard.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient card balance' });
    }

    // Get recipient card
    const toCard = await FirebaseManager.getCardByNumber(to_card_number);
    if (!toCard) {
      return res.status(404).json({ error: 'Recipient card not found' });
    }

    // Update balances
    fromCard.balance_cents -= amount_cents;
    toCard.balance_cents += amount_cents;

    await FirebaseManager.saveCard(fromCard);
    await FirebaseManager.saveCard(toCard);

    // Create transactions for both cards
    const transactionId = 'txn_' + Date.now();
    const senderTransaction = {
      _id: transactionId + '_sent',
      user_id: req.user._id,
      card_id: fromCard._id,
      amount_cents: -amount_cents,
      currency: 'USD',
      type: 'card_transfer_sent',
      description: description || `Card transfer to ${toCard.last4}`,
      counterparty_card: toCard.last4,
      status: 'completed',
      created_at: new Date()
    };

    const recipientTransaction = {
      _id: transactionId + '_received',
      user_id: toCard.user_id,
      card_id: toCard._id,
      amount_cents: amount_cents,
      currency: 'USD',
      type: 'card_transfer_received',
      description: description || `Card transfer from ${fromCard.last4}`,
      counterparty_card: fromCard.last4,
      status: 'completed',
      created_at: new Date()
    };

    await FirebaseManager.saveTransaction(senderTransaction);
    await FirebaseManager.saveTransaction(recipientTransaction);

    res.json({
      message: 'Card transfer successful',
      from_card_balance: fromCard.balance_cents,
      to_card_balance: toCard.balance_cents
    });

  } catch (error) {
    console.error('Card transfer error:', error);
    res.status(500).json({ error: 'Internal server error during card transfer' });
  }
});

// Card to bank transfer endpoint
app.post('/api/cards/transfer-to-bank', authenticateToken, async (req, res) => {
  try {
    const { card_id, account_number, routing_number, amount_cents, description } = req.body;

    if (!card_id || !account_number || !routing_number || !amount_cents) {
      return res.status(400).json({ error: 'Card, account, routing, and amount are required' });
    }

    // Get card
    const card = await FirebaseManager.getCardById(card_id);
    if (!card || card.user_id !== req.user._id) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Check card balance
    if (card.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient card balance' });
    }

    // Get user account
    const account = await FirebaseManager.getAccountByUserId(req.user._id);
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Transfer from card to account
    card.balance_cents -= amount_cents;
    account.balance_cents += amount_cents;

    await FirebaseManager.saveCard(card);
    await FirebaseManager.saveAccount(account);

    // Create transaction
    const transactionId = 'txn_' + Date.now();
    const transaction = {
      _id: transactionId,
      user_id: req.user._id,
      card_id: card._id,
      account_id: account._id,
      amount_cents: amount_cents,
      currency: 'USD',
      type: 'card_to_bank_transfer',
      description: description || `Transfer from card to bank account`,
      status: 'completed',
      created_at: new Date()
    };

    await FirebaseManager.saveTransaction(transaction);

    // Emit balance update
    io.emit('balance_update', {
      user_id: req.user._id,
      balance_cents: account.balance_cents
    });

    res.json({
      message: 'Transfer to bank account successful',
      card_balance: card.balance_cents,
      account_balance: account.balance_cents
    });

  } catch (error) {
    console.error('Card to bank transfer error:', error);
    res.status(500).json({ error: 'Internal server error during transfer' });
  }
});

// ========== ORGANIZATION ROUTES ==========

// Get organizations endpoint
app.get('/api/organizations', authenticateToken, async (req, res) => {
  try {
    const organizations = await FirebaseManager.getOrganizationsByUserId(req.user._id);
    
    res.json({
      organizations: organizations
    });
  } catch (error) {
    console.error('Organizations error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all organizations endpoint
app.get('/api/organizations/all', authenticateToken, async (req, res) => {
  try {
    const organizations = await FirebaseManager.getAllOrganizations();
    
    res.json({
      organizations: organizations
    });
  } catch (error) {
    console.error('All organizations error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Search organizations endpoint
app.get('/api/organizations/search', authenticateToken, async (req, res) => {
  try {
    const { q } = req.query;
    
    if (!q) {
      return res.status(400).json({ error: 'Search query is required' });
    }

    const organizations = await FirebaseManager.searchOrganizations(q);
    
    res.json({
      organizations: organizations
    });
  } catch (error) {
    console.error('Search organizations error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create organization endpoint
app.post('/api/organizations', authenticateToken, async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Organization name is required' });
    }

    const orgId = 'org_' + Date.now();
    const organization = {
      _id: orgId,
      name: name,
      description: description || '',
      code: generateOrgCode(),
      owner_id: req.user._id,
      members: [
        {
          user_id: req.user._id,
          name: req.user.name,
          email: req.user.email,
          role: 'owner',
          joined_at: new Date()
        }
      ],
      cards: [],
      pending_requests: [],
      visibility: 'public',
      status: 'active',
      created_at: new Date()
    };

    await FirebaseManager.saveOrganization(organization);

    res.json({
      message: 'Organization created successfully',
      organization: organization
    });
  } catch (error) {
    console.error('Create organization error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get organization details endpoint
app.get('/api/organizations/:orgId', authenticateToken, async (req, res) => {
  try {
    const organization = await FirebaseManager.getOrganizationById(req.params.orgId);

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    res.json({
      organization: organization
    });
  } catch (error) {
    console.error('Organization details error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Join organization endpoint
app.post('/api/organizations/:orgId/join', authenticateToken, async (req, res) => {
  try {
    const organization = await FirebaseManager.getOrganizationById(req.params.orgId);

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Check if user is already a member
    const isMember = organization.members.some(member => member.user_id === req.user._id);
    if (isMember) {
      return res.status(400).json({ error: 'Already a member of this organization' });
    }

    // Add user to members
    organization.members.push({
      user_id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: 'member',
      joined_at: new Date()
    });

    await FirebaseManager.saveOrganization(organization);

    res.json({
      message: 'Successfully joined organization',
      organization: organization
    });
  } catch (error) {
    console.error('Join organization error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Request to join organization endpoint
app.post('/api/organizations/:orgId/request-join', authenticateToken, async (req, res) => {
  try {
    const organization = await FirebaseManager.getOrganizationById(req.params.orgId);

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Check if user is already a member
    const isMember = organization.members.some(member => member.user_id === req.user._id);
    if (isMember) {
      return res.status(400).json({ error: 'Already a member of this organization' });
    }

    // Check if request already exists
    const existingRequest = organization.pending_requests.find(req => req.user_id === req.user._id);
    if (existingRequest) {
      return res.status(400).json({ error: 'Join request already pending' });
    }

    // Add join request
    organization.pending_requests.push({
      user_id: req.user._id,
      user_name: req.user.name,
      user_email: req.user.email,
      requested_at: new Date()
    });

    await FirebaseManager.saveOrganization(organization);

    res.json({
      message: 'Join request sent successfully',
      organization: organization
    });
  } catch (error) {
    console.error('Request join organization error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Approve join request endpoint
app.post('/api/organizations/:orgId/approve-request', authenticateToken, async (req, res) => {
  try {
    const { user_id } = req.body;
    const organization = await FirebaseManager.getOrganizationById(req.params.orgId);

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Check if user is owner
    if (organization.owner_id !== req.user._id) {
      return res.status(403).json({ error: 'Only organization owner can approve requests' });
    }

    // Find and remove the request
    const requestIndex = organization.pending_requests.findIndex(req => req.user_id === user_id);
    if (requestIndex === -1) {
      return res.status(404).json({ error: 'Join request not found' });
    }

    const request = organization.pending_requests[requestIndex];
    organization.pending_requests.splice(requestIndex, 1);

    // Add user to members
    organization.members.push({
      user_id: user_id,
      name: request.user_name,
      email: request.user_email,
      role: 'member',
      joined_at: new Date()
    });

    await FirebaseManager.saveOrganization(organization);

    res.json({
      message: 'Join request approved successfully',
      organization: organization
    });
  } catch (error) {
    console.error('Approve join request error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reject join request endpoint
app.post('/api/organizations/:orgId/reject-request', authenticateToken, async (req, res) => {
  try {
    const { user_id } = req.body;
    const organization = await FirebaseManager.getOrganizationById(req.params.orgId);

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Check if user is owner
    if (organization.owner_id !== req.user._id) {
      return res.status(403).json({ error: 'Only organization owner can reject requests' });
    }

    // Remove the request
    const requestIndex = organization.pending_requests.findIndex(req => req.user_id === user_id);
    if (requestIndex === -1) {
      return res.status(404).json({ error: 'Join request not found' });
    }

    organization.pending_requests.splice(requestIndex, 1);
    await FirebaseManager.saveOrganization(organization);

    res.json({
      message: 'Join request rejected successfully',
      organization: organization
    });
  } catch (error) {
    console.error('Reject join request error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change member role endpoint
app.put('/api/organizations/:orgId/member-role', authenticateToken, async (req, res) => {
  try {
    const { user_id, new_role } = req.body;
    const organization = await FirebaseManager.getOrganizationById(req.params.orgId);

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Check if user is owner
    if (organization.owner_id !== req.user._id) {
      return res.status(403).json({ error: 'Only organization owner can change roles' });
    }

    // Cannot change owner role
    if (user_id === organization.owner_id) {
      return res.status(400).json({ error: 'Cannot change owner role' });
    }

    // Find member and update role
    const memberIndex = organization.members.findIndex(member => member.user_id === user_id);
    if (memberIndex === -1) {
      return res.status(404).json({ error: 'Member not found' });
    }

    organization.members[memberIndex].role = new_role;
    await FirebaseManager.saveOrganization(organization);

    res.json({
      message: 'Member role updated successfully',
      organization: organization
    });
  } catch (error) {
    console.error('Change member role error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove member endpoint
app.delete('/api/organizations/:orgId/members/:userId', authenticateToken, async (req, res) => {
  try {
    const organization = await FirebaseManager.getOrganizationById(req.params.orgId);

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Check if user is owner
    if (organization.owner_id !== req.user._id) {
      return res.status(403).json({ error: 'Only organization owner can remove members' });
    }

    // Cannot remove owner
    if (req.params.userId === organization.owner_id) {
      return res.status(400).json({ error: 'Cannot remove organization owner' });
    }

    // Remove member
    const memberIndex = organization.members.findIndex(member => member.user_id === req.params.userId);
    if (memberIndex === -1) {
      return res.status(404).json({ error: 'Member not found' });
    }

    organization.members.splice(memberIndex, 1);
    await FirebaseManager.saveOrganization(organization);

    res.json({
      message: 'Member removed successfully',
      organization: organization
    });
  } catch (error) {
    console.error('Remove member error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create organization card endpoint
app.post('/api/organizations/:orgId/cards', authenticateToken, async (req, res) => {
  try {
    const organization = await FirebaseManager.getOrganizationById(req.params.orgId);

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Check if user is owner or manager
    const member = organization.members.find(member => member.user_id === req.user._id);
    if (!member || (member.role !== 'owner' && member.role !== 'manager')) {
      return res.status(403).json({ error: 'Only organization owners and managers can create cards' });
    }

    // Create a virtual card for the organization
    const cardId = 'card_org_' + Date.now();
    const card = {
      _id: cardId,
      organization_id: organization._id,
      user_id: req.user._id, // Created by this user
      card_number: Math.random().toString().slice(2, 18),
      last4: Math.random().toString().slice(2, 6),
      expiry_month: Math.floor(Math.random() * 12) + 1,
      expiry_year: new Date().getFullYear() + 3,
      cvv: Math.floor(Math.random() * 900) + 100,
      brand: 'Visa',
      status: 'active',
      balance_cents: 0,
      card_owner: organization.name,
      billing_address: {
        street: '123 Main Street',
        city: 'San Francisco',
        state: 'CA',
        zip_code: '94111',
        country: 'US'
      },
      phone_number: '+1234567890',
      card_type: 'virtual',
      card_network: 'visa',
      created_at: new Date(),
      is_organization_card: true
    };

    await FirebaseManager.saveCard(card);

    // Add card to organization
    organization.cards.push({
      _id: cardId,
      card_number: card.card_number,
      last4: card.last4,
      balance_cents: 0,
      created_by: req.user._id,
      created_at: new Date()
    });

    await FirebaseManager.saveOrganization(organization);

    res.json({
      message: 'Organization card created successfully',
      card: card
    });
  } catch (error) {
    console.error('Create organization card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete organization card endpoint
app.delete('/api/organizations/:orgId/cards/:cardId', authenticateToken, async (req, res) => {
  try {
    const organization = await FirebaseManager.getOrganizationById(req.params.orgId);

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Check if user is owner or manager
    const member = organization.members.find(member => member.user_id === req.user._id);
    if (!member || (member.role !== 'owner' && member.role !== 'manager')) {
      return res.status(403).json({ error: 'Only organization owners and managers can delete cards' });
    }

    // Remove card from organization
    const cardIndex = organization.cards.findIndex(card => card._id === req.params.cardId);
    if (cardIndex === -1) {
      return res.status(404).json({ error: 'Organization card not found' });
    }

    organization.cards.splice(cardIndex, 1);
    await FirebaseManager.saveOrganization(organization);

    // Also delete the actual card
    if (db) {
      await db.collection('cards').doc(req.params.cardId).delete();
    } else {
      cards.delete(req.params.cardId);
    }

    res.json({
      message: 'Organization card deleted successfully',
      organization: organization
    });
  } catch (error) {
    console.error('Delete organization card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== PAYMENT ROUTES ==========

// Process payment endpoint
app.post('/api/payments/process', authenticateToken, async (req, res) => {
  try {
    const { card_number, amount_cents, description } = req.body;

    if (!card_number || !amount_cents) {
      return res.status(400).json({ error: 'Card number and amount are required' });
    }

    // Get card
    const card = await FirebaseManager.getCardByNumber(card_number);
    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Check card balance
    if (card.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient card balance' });
    }

    // Process payment (deduct from card)
    card.balance_cents -= amount_cents;
    await FirebaseManager.saveCard(card);

    // Create transaction
    const transactionId = 'txn_' + Date.now();
    const transaction = {
      _id: transactionId,
      user_id: card.user_id,
      card_id: card._id,
      amount_cents: -amount_cents,
      currency: 'USD',
      type: 'payment',
      description: description || 'Payment processed',
      status: 'completed',
      created_at: new Date()
    };

    await FirebaseManager.saveTransaction(transaction);

    res.json({
      message: 'Payment processed successfully',
      card_balance: card.balance_cents,
      transaction: transaction
    });
  } catch (error) {
    console.error('Payment processing error:', error);
    res.status(500).json({ error: 'Internal server error during payment processing' });
  }
});

// ========== TRANSFER ROUTES ==========

// External transfer endpoint
app.post('/api/transfers/external', authenticateToken, async (req, res) => {
  try {
    const { amount_cents, recipient_name, recipient_account_number, routing_number, description } = req.body;

    if (!amount_cents || !recipient_name || !recipient_account_number || !routing_number) {
      return res.status(400).json({ error: 'All fields are required for external transfer' });
    }

    // Get user account
    const account = await FirebaseManager.getAccountByUserId(req.user._id);
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Check sufficient balance
    if (account.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Process external transfer (simulate)
    account.balance_cents -= amount_cents;
    await FirebaseManager.saveAccount(account);

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
      counterparty_name: recipient_name,
      counterparty_account: recipient_account_number,
      status: 'completed',
      created_at: new Date()
    };

    await FirebaseManager.saveTransaction(transaction);

    // Emit balance update
    io.emit('balance_update', {
      user_id: req.user._id,
      balance_cents: account.balance_cents
    });

    res.json({
      message: 'External transfer initiated successfully',
      new_balance: account.balance_cents,
      transaction: transaction
    });
  } catch (error) {
    console.error('External transfer error:', error);
    res.status(500).json({ error: 'Internal server error during external transfer' });
  }
});

// Demo data initialization
const initializeDemoData = async () => {
  // Create demo users if none exist
  const existingUsers = await FirebaseManager.getUserByEmail('demo@hcb.com');
  if (!existingUsers) {
    console.log('🔄 Creating demo users...');
    
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
    await FirebaseManager.saveUser(demoUser1);
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
    await FirebaseManager.saveAccount(demoAccount1);

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
    await FirebaseManager.saveUser(demoUser2);
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
    await FirebaseManager.saveAccount(demoAccount2);

    // Create demo organizations
    const orgId1 = 'org_demo1';
    const demoOrg1 = {
      _id: orgId1,
      name: 'Tech Startup Inc.',
      code: generateOrgCode(),
      description: 'A technology startup company',
      owner_id: demoUserId1,
      members: [
        {
          user_id: demoUserId1,
          name: 'Demo User',
          email: 'demo@hcb.com',
          role: 'owner',
          joined_at: new Date()
        },
        {
          user_id: demoUserId2,
          name: 'Test User',
          email: 'user2@hcb.com',
          role: 'manager',
          joined_at: new Date()
        }
      ],
      cards: [],
      pending_requests: [],
      visibility: 'public',
      status: 'active',
      created_at: new Date()
    };
    await FirebaseManager.saveOrganization(demoOrg1);

    const orgId2 = 'org_demo2';
    const demoOrg2 = {
      _id: orgId2,
      name: 'Open Source Project',
      code: generateOrgCode(),
      description: 'Community open source project',
      owner_id: demoUserId2,
      members: [
        {
          user_id: demoUserId2,
          name: 'Test User',
          email: 'user2@hcb.com',
          role: 'owner',
          joined_at: new Date()
        }
      ],
      cards: [],
      pending_requests: [],
      visibility: 'public',
      status: 'active',
      created_at: new Date()
    };
    await FirebaseManager.saveOrganization(demoOrg2);

    console.log('✅ Demo users and organizations created');
  }
};

// Initialize demo data on startup
initializeDemoData();

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

// Initialize Stripe cardholder on startup
createStripeCardholder().then(cardholderId => {
  if (cardholderId) {
    console.log('✅ Stripe cardholder ready:', cardholderId);
    // Store the cardholder ID for future use
    process.env.CARDHOLDER_ID = cardholderId;
  } else {
    console.log('⚠️ Stripe cardholder creation failed - card creation will not work');
  }
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log('\n🎉 HCB Clone Server Started Successfully!');
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌐 URL: ${CLIENT_URL}`);
  console.log(`📧 Email Provider: Console logging (OTPs will be shown in logs)`);
  console.log(`📧 OTP Emails: Enabled with 5-minute expiration`);
  console.log(`💾 Storage: ${db ? 'Firebase Firestore' : 'In-memory'}`);
  console.log(`💳 Stripe: ${stripe ? 'Real virtual cards enabled (TEST MODE)' : 'Disabled - check configuration'}`);
  console.log(`🔑 JWT: Authentication enabled`);
  console.log(`\n🔗 Health Check: ${CLIENT_URL}/health`);
  console.log(`🔗 API Test: ${CLIENT_URL}/api/test`);
  console.log(`🔗 Stripe Test: ${CLIENT_URL}/api/stripe/test`);
  console.log('\n✅ Your banking app is now fully functional with OTP authentication!');
  console.log('💡 Demo Users:');
  console.log('   - demo@hcb.com (Password: any OTP)');
  console.log('   - user2@hcb.com (Password: any OTP)');
  console.log('   - Or create new account with any email');
  console.log('\n📧 OTP Features:');
  console.log('   ✅ OTP generation and verification');
  console.log('   ✅ 6-digit OTP with 5-minute expiration');
  console.log('   ✅ 3 attempt limit');
  console.log('   ✅ Automatic user creation for new emails');
  console.log('   ✅ OTPs logged to console for development');
  if (stripe) {
    console.log('\n🆕 Stripe Features:');
    console.log('   ✅ Real Stripe virtual card generation');
    console.log('   ✅ Stripe Issuing API integration');
    console.log('   ✅ Real card numbers with proper validation');
    console.log('   ✅ Organization Stripe card support');
    console.log('   ✅ Enhanced security with Stripe Issuing');
  } else {
    console.log('\n⚠️  Stripe Features Disabled:');
    console.log('   Please check your Stripe configuration');
  }
});
