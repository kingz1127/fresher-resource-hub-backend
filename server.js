

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, existsSync } from 'fs';
import nodemailer from 'nodemailer';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();


const otpStore = new Map(); 


const OTP_EXPIRY_MINUTES = 10;


app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:5174','https://fresher-resource-hub.onrender.com','https://fresher-resource-hub-backend.onrender.com',], 
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}));

const distExists = existsSync(join(__dirname, 'dist'));
console.log('📁 dist exists:', distExists);

app.use(express.json());

if (distExists) {
  app.use(express.static(join(__dirname, 'dist')));
  console.log('✅ Serving static files from dist/');
}


// Replace your transporter setup with this:
let transporter = null;

if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  try {
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      // Gmail specific settings:
      secure: true, // Use SSL
      port: 465, // SSL port
      tls: {
        rejectUnauthorized: false // Allow self-signed certificates
      },
      // Timeout settings for Render free tier:
      connectionTimeout: 10000, // 10 seconds
      greetingTimeout: 10000,
      socketTimeout: 10000
    });
    
    console.log('✅ Email transporter configured');
    
    // Test connection on startup
    transporter.verify(function(error, success) {
      if (error) {
        console.log('❌ Email transporter verification failed:', error.message);
      } else {
        console.log('✅ Email transporter is ready to send messages');
      }
    });
    
  } catch (error) {
    console.log('❌ Failed to create email transporter:', error.message);
    transporter = null;
  }
} else {
  console.log('⚠️ Email not configured (missing EMAIL_USER or EMAIL_PASS)');
}

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'Fresher Hub',
    timestamp: new Date().toISOString(),
    email: !!transporter,
    otpsStored: otpStore.size
  });
});


app.post('/api/send-otp', async (req, res) => {
  
  
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false,
        error: 'Email required' 
      });
    }

    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    
    const expiresAt = Date.now() + (OTP_EXPIRY_MINUTES * 60 * 1000);
    otpStore.set(email.toLowerCase(), { otp, expiresAt });
    
    
    
    
    if (transporter) {
      console.log('📤 Attempting to send email to:', email);
      
      try {
        const mailOptions = {
          from: `"Fresher Hub" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: 'Password Reset OTP - Fresher Hub',
          html: `
            <!DOCTYPE html>
            <html>
            <head>
              <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                .otp-box { background: white; border: 2px dashed #667eea; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
                .otp-code { font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 5px; }
                .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
              </style>
            </head>
            <body>
              <div class="container">
                <div class="header">
                  <h1>🔐 Password Reset</h1>
                </div>
                <div class="content">
                  <p>Hello,</p>
                  <p>You requested to reset your password. Use the OTP code below to continue:</p>
                  <div class="otp-box">
                    <div class="otp-code">${otp}</div>
                  </div>
                  <p><strong>⏱️ This code expires in ${OTP_EXPIRY_MINUTES} minutes.</strong></p>
                  <p>If you didn't request this, please ignore this email.</p>
                  <div class="footer">
                    <p>This is an automated email from Fresher Hub</p>
                  </div>
                </div>
              </div>
            </body>
            </html>
          `,
          text: `Your OTP is: ${otp}. It expires in ${OTP_EXPIRY_MINUTES} minutes.`
        };
        
        await transporter.sendMail(mailOptions);
        console.log('✅ Email sent successfully');
        
        return res.json({
          success: true,
          message: 'OTP sent to your email',
          service: 'Email',
          expiresIn: `${OTP_EXPIRY_MINUTES} minutes`
        });
        
      } catch (emailError) {
        console.error('❌ Email failed:', emailError.message);
        
      }
    }
    
    
    console.log('⚠️ Running in MOCK mode - OTP in response');
    res.json({
      success: true,
      message: 'OTP generated (mock mode)',
      otp: otp,
      service: 'Mock',
      expiresIn: `${OTP_EXPIRY_MINUTES} minutes`,
      note: 'Email not configured - check this response for your OTP'
    });
    
  } catch (error) {
    console.error('❌ Server error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      details: error.message 
    });
  }
});


app.post('/api/verify-otp', async (req, res) => {
  console.log('🔍 OTP verification request:', req.body?.email);
  
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and OTP are required' 
      });
    }

    const normalizedEmail = email.toLowerCase();
    const storedData = otpStore.get(normalizedEmail);

    if (!storedData) {
      console.log('❌ No OTP found for:', email);
      return res.status(400).json({ 
        success: false,
        error: 'No OTP found. Please request a new one.' 
      });
    }

    
    if (Date.now() > storedData.expiresAt) {
      console.log('❌ OTP expired for:', email);
      otpStore.delete(normalizedEmail);
      return res.status(400).json({ 
        success: false,
        error: 'OTP has expired. Please request a new one.' 
      });
    }

    
    if (storedData.otp !== otp.toString()) {
      console.log('❌ Invalid OTP for:', email);
      return res.status(400).json({ 
        success: false,
        error: 'Invalid OTP. Please try again.' 
      });
    }

    
    console.log('✅ OTP verified for:', email);
    otpStore.delete(normalizedEmail); 
    
    res.json({
      success: true,
      message: 'OTP verified successfully'
    });

  } catch (error) {
    console.error('❌ Verification error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      details: error.message 
    });
  }
});


setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  
  for (const [email, data] of otpStore.entries()) {
    if (now > data.expiresAt) {
      otpStore.delete(email);
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    console.log(`🧹 Cleaned ${cleaned} expired OTP(s)`);
  }
}, 60000); 

let indexHtml = null;
if (distExists) {
  try {
    const indexPath = join(__dirname, 'dist', 'index.html');
    if (existsSync(indexPath)) {
      indexHtml = readFileSync(indexPath, 'utf8');
      console.log('✅ Loaded index.html for SPA routing');
    }
  } catch (err) {
    console.error('Error loading index.html:', err.message);
  }
}

const handleSPA = (req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return next();
  }
  
  if (req.path.match(/\.[a-zA-Z0-9]{2,}$/)) {
    return next();
  }
  
  if (indexHtml) {
    return res.send(indexHtml);
  }
  
  next();
};

app.use(handleSPA);

app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ 
      success: false,
      error: 'API endpoint not found',
      path: req.path 
    });
  }
  
  if (indexHtml) {
    return res.send(indexHtml);
  }
  
  res.status(404).send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Fresher Hub - Not Found</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 40px; text-align: center; }
        h1 { color: #667eea; }
        code { background: #f5f5f5; padding: 10px; border-radius: 5px; }
      </style>
    </head>
    <body>
      <h1>404 - Page Not Found</h1>
      <p>The requested URL <code>${req.path}</code> was not found.</p>
      <p><a href="/">Go to Homepage</a></p>
    </body>
    </html>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/api/health`);
  console.log(`📧 Email configured: ${transporter ? '✅ Yes' : '❌ No (using mock)'}`);
  console.log(`📁 SPA routing: ${indexHtml ? '✅ Enabled' : '❌ Disabled'}`);
});