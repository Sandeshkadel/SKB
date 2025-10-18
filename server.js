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

const User = mongoose.model('User', UserSchema);
const Account = mongoose.model('Account', AccountSchema);

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Health check with detailed info
app.get('/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: dbStatus,
    environment: process.env.NODE_ENV || 'development',
    mongodb_uri_set: !!process.env.MONGODB_URI,
    message: dbStatus === 'connected' ? 
      'Database connected successfully!' : 
      'Database not connected. Please check MONGODB_URI environment variable.'
  });
});

// Demo signup endpoint to test database
app.post('/api/test-db', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ 
        error: 'Database not connected',
        message: 'MONGODB_URI environment variable is not set or invalid'
      });
    }

    // Test database connection by creating a test user
    const testUser = new User({
      email: 'test@example.com',
      name: 'Test User',
      hashed_password: await bcrypt.hash('password123', 12)
    });

    await testUser.save();
    
    res.json({
      message: 'Database connection successful!',
      user_created: true,
      user_id: testUser._id
    });
  } catch (error) {
    res.status(500).json({
      error: 'Database test failed',
      message: error.message
    });
  }
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

    if (!process.env.MONGODB_URI.startsWith('mongodb://') && !process.env.MONGODB_URI.startsWith('mongodb+srv://')) {
      console.log('❌ Invalid MongoDB connection string format');
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
      console.log('   3. Value: mongodb+srv://sandeshkadel:Sandesh@123@sandesh.2u8wyot.mongodb.net/hcb-clone?retryWrites=true&w=majority&appName=sandesh');
      console.log('   4. Wait for automatic redeploy');
    }
    
    console.log(`\n🔗 Health Check: ${CLIENT_URL}/health`);
    console.log(`🔗 Test Database: ${CLIENT_URL}/api/test-db`);
  });
};

startServer().catch(console.error);
