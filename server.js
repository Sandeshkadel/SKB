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
const { body, validationResult } = require('express-validator');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Database models
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  hashed_password: { type: String, required: true },
  status: { type: String, enum: ['pending', 'active', 'suspended'], default: 'pending' },
  kyc_status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  column_customer_id: String,
  created_at: { type: Date, default: Date.now }
});

const AccountSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  balance_cents: { type: Number, default: 0 },
  currency: { type: String, default: 'USD' },
  created_at: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
  sender_user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiver_user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiver_email: String,
  amount_cents: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['pending', 'posted', 'failed'], default: 'pending' },
  description: String,
  column_transaction_id: String,
  timestamp: { type: Date, default: Date.now }
});

const VirtualCardSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  column_card_token: { type: String, required: true },
  last4: { type: String, required: true },
  brand: String,
  expiry_month: Number,
  expiry_year: Number,
  status: { type: String, enum: ['active', 'blocked'], default: 'active' },
  created_at: { type: Date, default: Date.now }
});

const IdempotencyKeySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  created_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  created_at: { type: Date, default: Date.now, expires: 86400 } // 24 hours TTL
});

const User = mongoose.model('User', UserSchema);
const Account = mongoose.model('Account', AccountSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const VirtualCard = mongoose.model('VirtualCard', VirtualCardSchema);
const IdempotencyKey = mongoose.model('IdempotencyKey', IdempotencyKeySchema);

// Column API configuration
const COLUMN_API_KEY = process.env.COLUMN_API_KEY;
const COLUMN_BASE_URL = 'https://sandbox.column.com';

const columnAPI = axios.create({
  baseURL: COLUMN_BASE_URL,
  headers: {
    'Authorization': `Bearer ${COLUMN_API_KEY}`,
    'Content-Type': 'application/json'
  }
});

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
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

// WebSocket connections for real-time updates
const userSockets = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('authenticate', (token) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      userSockets.set(decoded.userId, socket.id);
      socket.userId = decoded.userId;
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

// Helper function to emit balance updates
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

    const { email, password, name } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create Column customer
    const customerResponse = await columnAPI.post('/customers', {
      name,
      email,
      type: 'individual'
    });

    // Create user
    const user = new User({
      email,
      name,
      hashed_password: hashedPassword,
      column_customer_id: customerResponse.data.id
    });

    await user.save();

    // Create account
    const account = new Account({
      user_id: user._id
    });
    await account.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        kyc_status: user.kyc_status
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
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

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.hashed_password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        kyc_status: user.kyc_status
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Account Routes
app.get('/api/accounts/balance', authenticateToken, async (req, res) => {
  try {
    const account = await Account.findOne({ user_id: req.user._id });
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    res.json({
      balance_cents: account.balance_cents,
      currency: account.currency
    });
  } catch (error) {
    console.error('Balance error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/accounts/transactions', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const transactions = await Transaction.find({
      $or: [
        { sender_user_id: req.user._id },
        { receiver_user_id: req.user._id }
      ]
    })
    .sort({ timestamp: -1 })
    .skip(skip)
    .limit(limit)
    .populate('sender_user_id', 'name email')
    .populate('receiver_user_id', 'name email');

    const total = await Transaction.countDocuments({
      $or: [
        { sender_user_id: req.user._id },
        { receiver_user_id: req.user._id }
      ]
    });

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
    console.error('Transactions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Payment Routes
app.post('/api/payments', [
  authenticateToken,
  body('to_identifier').notEmpty(),
  body('amount_cents').isInt({ min: 1 }),
  body('currency').isLength({ min: 3, max: 3 }),
  body('idempotency_key').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { to_identifier, amount_cents, currency, idempotency_key, description } = req.body;

    // Check idempotency key
    const existingKey = await IdempotencyKey.findOne({ key: idempotency_key });
    if (existingKey) {
      const existingTransaction = await Transaction.findOne({
        $or: [
          { sender_user_id: req.user._id },
          { receiver_user_id: req.user._id }
        ]
      }).sort({ timestamp: -1 });

      if (existingTransaction) {
        return res.json({
          transaction: existingTransaction,
          message: 'Duplicate request - transaction already processed'
        });
      }
    }

    // Store idempotency key
    await IdempotencyKey.create({
      key: idempotency_key,
      created_by: req.user._id
    });

    const senderAccount = await Account.findOne({ user_id: req.user._id });
    if (!senderAccount) {
      return res.status(404).json({ error: 'Sender account not found' });
    }

    // Check balance
    if (senderAccount.balance_cents < amount_cents) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Check if receiver is internal (email) or external
    let receiverUser = await User.findOne({ email: to_identifier });
    let receiverAccount = null;

    if (receiverUser) {
      receiverAccount = await Account.findOne({ user_id: receiverUser._id });
    }

    // Create pending transaction
    const transaction = new Transaction({
      sender_user_id: req.user._id,
      receiver_user_id: receiverUser ? receiverUser._id : null,
      receiver_email: receiverUser ? null : to_identifier,
      amount_cents,
      currency,
      description,
      status: 'pending'
    });

    await transaction.save();

    if (receiverUser && receiverAccount) {
      // Internal transfer
      senderAccount.balance_cents -= amount_cents;
      receiverAccount.balance_cents += amount_cents;

      await senderAccount.save();
      await receiverAccount.save();

      transaction.status = 'posted';
      await transaction.save();

      // Emit balance updates
      await emitBalanceUpdate(req.user._id);
      await emitBalanceUpdate(receiverUser._id);

      res.json({
        transaction,
        message: 'Transfer completed successfully'
      });
    } else {
      // External transfer via Column API
      try {
        const paymentResponse = await columnAPI.post('/payments', {
          from: senderAccount._id.toString(), // Using account ID as source
          to: to_identifier,
          amount: amount_cents,
          currency: currency.toLowerCase(),
          description: description || 'Payment'
        });

        transaction.column_transaction_id = paymentResponse.data.id;
        transaction.status = 'posted';
        await transaction.save();

        senderAccount.balance_cents -= amount_cents;
        await senderAccount.save();

        await emitBalanceUpdate(req.user._id);

        res.json({
          transaction,
          message: 'External payment processed successfully'
        });
      } catch (columnError) {
        transaction.status = 'failed';
        await transaction.save();

        console.error('Column API error:', columnError);
        res.status(500).json({ error: 'External payment failed' });
      }
    }
  } catch (error) {
    console.error('Payment error:', error);
    res.status(500).json({ error: 'Internal server error' });
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

    // Create virtual card via Column API
    const cardResponse = await columnAPI.post('/cards', {
      account_id: account._id.toString(),
      type: 'virtual'
    });

    const cardData = cardResponse.data;

    // Store only necessary card details
    const virtualCard = new VirtualCard({
      user_id: user._id,
      column_card_token: cardData.id,
      last4: cardData.last4,
      brand: cardData.brand,
      expiry_month: cardData.exp_month,
      expiry_year: cardData.exp_year
    });

    await virtualCard.save();

    res.status(201).json({
      card: {
        id: virtualCard._id,
        last4: virtualCard.last4,
        brand: virtualCard.brand,
        expiry_month: virtualCard.expiry_month,
        expiry_year: virtualCard.expiry_year,
        status: virtualCard.status
      },
      message: 'Virtual card created successfully'
    });
  } catch (error) {
    console.error('Card creation error:', error);
    res.status(500).json({ error: 'Failed to create virtual card' });
  }
});

app.get('/api/cards', authenticateToken, async (req, res) => {
  try {
    const cards = await VirtualCard.find({ user_id: req.user._id });
    res.json({ cards });
  } catch (error) {
    console.error('Get cards error:', error);
    res.status(500).json({ error: 'Failed to fetch cards' });
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

    // Also block via Column API
    await columnAPI.post(`/cards/${card.column_card_token}/block`);

    res.json({
      card,
      message: `Card ${card.status === 'active' ? 'unblocked' : 'blocked'} successfully`
    });
  } catch (error) {
    console.error('Block card error:', error);
    res.status(500).json({ error: 'Failed to update card status' });
  }
});

// Webhook endpoint for Column
app.post('/webhooks/column', async (req, res) => {
  try {
    const event = req.body;

    console.log('Received webhook:', event.type);

    // Handle different webhook events
    switch (event.type) {
      case 'payment.posted':
        // Handle completed payments
        break;
      case 'card.updated':
        // Handle card status changes
        break;
      default:
        console.log('Unhandled webhook type:', event.type);
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Deposit endpoint
app.post('/api/deposit', [
  authenticateToken,
  body('amount_cents').isInt({ min: 1 }),
  body('currency').isLength({ min: 3, max: 3 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount_cents, currency } = req.body;

    const account = await Account.findOne({ user_id: req.user._id });
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Simulate deposit - in real scenario, this would involve bank transfer
    account.balance_cents += amount_cents;
    await account.save();

    // Create transaction record
    const transaction = new Transaction({
      receiver_user_id: req.user._id,
      amount_cents,
      currency,
      description: 'Deposit',
      status: 'posted'
    });
    await transaction.save();

    await emitBalanceUpdate(req.user._id);

    res.json({
      new_balance: account.balance_cents,
      message: 'Deposit completed successfully'
    });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ error: 'Deposit failed' });
  }
});

// Connect to MongoDB and start server
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/hcb-clone';

mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    server.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

module.exports = app;
