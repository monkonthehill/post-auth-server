import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import ImageKit from 'imagekit';

// Initialize environment variables
dotenv.config();

// Enhanced environment validation
const validateEnvironment = () => {
  const requiredEnvVars = {
    'IMAGEKIT_PUBLIC_KEY': 'Your ImageKit public key',
    'IMAGEKIT_PRIVATE_KEY': 'Your ImageKit private key',
    'IMAGEKIT_URL_ENDPOINT': 'Your ImageKit URL endpoint',
    'PORT': 'Server port',
    'ALLOWED_ORIGINS': 'Comma-separated list of allowed origins',
    'NODE_ENV': 'Node environment (development/production)'
  };

  let valid = true;
  for (const [envVar, description] of Object.entries(requiredEnvVars)) {
    if (!process.env[envVar]) {
      console.error(`❌ Missing required environment variable: ${envVar} (${description})`);
      valid = false;
    }
  }

  if (!valid) process.exit(1);

  // Validate ALLOWED_ORIGINS format
  try {
    const origins = process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
    if (origins.length === 0) throw new Error('No origins specified');
  } catch (error) {
    console.error('❌ Invalid ALLOWED_ORIGINS format:', error.message);
    process.exit(1);
  }
};

validateEnvironment();

// Initialize Express
const app = express();

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", process.env.IMAGEKIT_URL_ENDPOINT],
      connectSrc: ["'self'", process.env.IMAGEKIT_URL_ENDPOINT]
    }
  }
}));

// Enhanced CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin && process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    
    const allowedOrigins = process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
    
    if (allowedOrigins.some(allowed => {
      return origin === allowed || 
             (allowed.startsWith('*.') && 
              origin.endsWith(allowed.substring(1)));
    })) {
      callback(null, true);
    } else {
      console.error(`🚫 CORS blocked for origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
  optionsSuccessStatus: 204,
  maxAge: 86400
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.ip}-${req.headers['user-agent']}`,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: 'Too many requests',
      message: 'Please try again later'
    });
  }
});

// Initialize ImageKit with error handling
let imagekit;
try {
  imagekit = new ImageKit({
    publicKey: process.env.IMAGEKIT_PUBLIC_KEY,
    privateKey: process.env.IMAGEKIT_PRIVATE_KEY,
    urlEndpoint: process.env.IMAGEKIT_URL_ENDPOINT
  });
  
  // Test connection
  imagekit.listFiles({}, (error) => {
    if (error) {
      console.error('❌ ImageKit connection failed:', error);
      process.exit(1);
    }
    console.log('✅ ImageKit connected successfully');
  });
} catch (error) {
  console.error('❌ ImageKit initialization failed:', error);
  process.exit(1);
}

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Routes
app.get('/', (req, res) => {
  res.json({
    status: 'healthy',
    message: 'ImageKit Authentication Service',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV
  });
});

app.post('/auth', apiLimiter, express.json(), (req, res) => {
  try {
    if (req.body && Object.keys(req.body).length > 0) {
      console.log('Auth request body:', req.body);
    }

    const authParams = imagekit.getAuthenticationParameters();
    
    // Security headers
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'DENY');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('Cache-Control', 'no-store, max-age=0');
    
    res.json({
      success: true,
      ...authParams,
      timestamp: new Date().getTime(),
      expiresIn: 3600
    });
  } catch (error) {
    console.error('Authentication Error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate authentication parameters',
      ...(process.env.NODE_ENV === 'development' && { 
        details: error.message,
        stack: error.stack 
      })
    });
  }
});

// Error handlers
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    error: 'Endpoint not found',
    path: req.path
  });
});

app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({ 
    success: false, 
    error: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { 
      message: err.message,
      stack: err.stack 
    })
  });
});

// Start Server
const PORT = process.env.PORT || 3001;
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔑 ImageKit Public Key: ${process.env.IMAGEKIT_PUBLIC_KEY}`);
  console.log(`🌐 URL Endpoint: ${process.env.IMAGEKIT_URL_ENDPOINT}`);
  console.log(`🌍 Allowed Origins: ${process.env.ALLOWED_ORIGINS}`);
  console.log(`⚙️  Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
