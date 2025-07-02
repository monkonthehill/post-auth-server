import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import ImageKit from 'imagekit';

// Initialize environment variables
dotenv.config();

// Validate required environment variables
const requiredEnvVars = [
  'IMAGEKIT_PUBLIC_KEY',
  'IMAGEKIT_PRIVATE_KEY',
  'IMAGEKIT_URL_ENDPOINT',
  'PORT',
  'ALLOWED_ORIGINS'  // Fixed typo from ALLOWED_ORIGINS
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// Initialize Express
const app = express();

// Security Middleware
app.use(helmet());

// Enhanced CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.error(`🚫 CORS blocked for origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Enable preflight for all routes

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, please try again later.'
});

// Initialize ImageKit
const imagekit = new ImageKit({
  publicKey: process.env.IMAGEKIT_PUBLIC_KEY,
  privateKey: process.env.IMAGEKIT_PRIVATE_KEY,
  urlEndpoint: process.env.IMAGEKIT_URL_ENDPOINT
});

// Routes
app.get('/', (req, res) => {
  res.json({
    status: 'healthy',
    message: 'ImageKit Authentication Service',
    timestamp: new Date().toISOString()
  });
});

app.post('/auth', apiLimiter, express.json(), (req, res) => {
  try {
    const authParams = imagekit.getAuthenticationParameters();
    
    // Manually set CORS headers as additional safeguard
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    res.json({
      success: true,
      ...authParams,
      timestamp: new Date().getTime()
    });
  } catch (error) {
    console.error('Authentication Error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate authentication parameters',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Error handlers
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({ 
    success: false, 
    error: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Start Server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔑 ImageKit Public Key: ${process.env.IMAGEKIT_PUBLIC_KEY}`);
  console.log(`🌐 URL Endpoint: ${process.env.IMAGEKIT_URL_ENDPOINT}`);
  console.log(`🌍 Allowed Origins: ${process.env.ALLOWED_ORIGINS}`);
});