
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, existsSync } from 'fs';
import nodemailer from 'nodemailer';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();


const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);


const otpStore = new Map(); 

const sessions = new Map(); 


const OTP_EXPIRY_MINUTES = 10;
const SALT_ROUNDS = 12;
const SESSION_EXPIRY_HOURS = 24;


app.use(cors({
  origin: ['http://localhost:5173', 
    'http://localhost:5174',
    'https://fresher-resource-hub.onrender.com' ], 
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


let transporter = null; 

if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    secure: false,
  });
  console.log('✅ Email configured with:', process.env.EMAIL_USER);
} else {
  console.log('⚠️ Email not configured (missing EMAIL_USER or EMAIL_PASS)');
}

console.log('✅ Supabase connected as database');


const generateSessionId = () => {
  return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
};


app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'Fresher Hub',
    timestamp: new Date().toISOString(),
    email: !!transporter,
    otpsStored: otpStore.size,
    sessionsCount: sessions.size,
    database: 'Supabase'
  });
});


app.post('/api/register', async (req, res) => {
  console.log('📝 Register request:', req.body?.email);
  
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Full name, email, and password are required' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 6 characters' 
      });
    }

    const normalizedEmail = email.toLowerCase();

    
    const { data: existingUser, error: checkError } = await supabase
      .from('Registered')
      .select('*')
      .eq('Email', normalizedEmail)
      .single();

    if (checkError && checkError.code !== 'PGRST116') { 
      console.error('❌ Check error:', checkError);
    }

    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        error: 'Email already registered' 
      });
    }

    
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    
    
    const { data: newUser, error: insertError } = await supabase
      .from('Registered')
      .insert([
        {
          FullName: fullName,
          Email: normalizedEmail,
          Password: hashedPassword,
          role: 'user',
          created_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (insertError) {
      console.error('❌ Supabase insert error:', insertError);
      return res.status(500).json({ 
        success: false,
        error: 'Failed to create user in database',
        details: insertError.message
      });
    }

    console.log('✅ User registered in Supabase:', normalizedEmail);

    res.status(201).json({
      success: true,
      message: 'Registration successful',
      user: {
        id: newUser.id,
        FullName: newUser.FullName,
        Email: newUser.Email,
        role: newUser.role,
        createdAt: newUser.created_at
      }
    });

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Registration failed',
      details: error.message 
    });
  }
});


app.post('/api/login', async (req, res) => {
  console.log('🔐 Login request:', req.body?.email);
  
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and password are required' 
      });
    }

    const normalizedEmail = email.toLowerCase();

    
    const { data: user, error: fetchError } = await supabase
      .from('Registered')
      .select('*')
      .eq('Email', normalizedEmail)
      .single();

    if (fetchError || !user) {
      console.log('❌ User not found:', fetchError?.message);
      return res.status(401).json({ 
        success: false,
        error: 'Invalid email or password' 
      });
    }

    
    const isValid = await bcrypt.compare(password, user.Password);
    
    if (!isValid) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid email or password' 
      });
    }

    
    const sessionId = generateSessionId();
    const expiresAt = Date.now() + (SESSION_EXPIRY_HOURS * 60 * 60 * 1000);
    
    sessions.set(sessionId, {
      userId: user.id,
      email: normalizedEmail,
      expires: expiresAt,
      role: user.role
    });
    
    console.log('✅ User logged in:', normalizedEmail);

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        FullName: user.FullName,
        Email: user.Email,
        role: user.role
      },
      sessionId: sessionId,
      expiresAt: expiresAt
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Login failed',
      details: error.message 
    });
  }
});


app.post('/api/validate-session', (req, res) => {
  try {
    const { sessionId } = req.body;

    if (!sessionId) {
      return res.status(400).json({ 
        success: false,
        error: 'Session ID required' 
      });
    }

    const session = sessions.get(sessionId);

    if (!session) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid session' 
      });
    }

    
    if (Date.now() > session.expires) {
      sessions.delete(sessionId);
      return res.status(401).json({ 
        success: false,
        error: 'Session expired' 
      });
    }

    res.json({
      success: true,
      user: {
        userId: session.userId,
        email: session.email,
        role: session.role
      },
      sessionId: sessionId,
      expiresAt: session.expires
    });

  } catch (error) {
    console.error('❌ Session validation error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Session validation failed',
      details: error.message 
    });
  }
});


app.post('/api/logout', (req, res) => {
  try {
    const { sessionId } = req.body;

    if (sessionId) {
      sessions.delete(sessionId);
    }

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    console.error('❌ Logout error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Logout failed',
      details: error.message 
    });
  }
});


app.post('/api/send-otp', async (req, res) => {
  console.log('📧 OTP request:', req.body?.email);
  
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false,
        error: 'Email required' 
      });
    }

    const normalizedEmail = email.toLowerCase();

    
    const { data: user, error: userError } = await supabase
      .from('Registered')
      .select('*')
      .eq('Email', normalizedEmail)
      .single();

    if (userError || !user) {
      return res.status(404).json({ 
        success: false,
        error: 'No account found with this email' 
      });
    }

    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    
    const expiresAt = Date.now() + (OTP_EXPIRY_MINUTES * 60 * 1000);
    otpStore.set(normalizedEmail, { otp, expiresAt });
    
    console.log(`✅ OTP stored for ${email}: ${otp} (expires in ${OTP_EXPIRY_MINUTES}min)`);
    
    
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


app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ 
        success: false,
        error: 'Email, OTP, and new password are required' 
      });
    }

    const normalizedEmail = email.toLowerCase();
    const storedData = otpStore.get(normalizedEmail);

    
    if (!storedData || storedData.otp !== otp.toString()) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid OTP' 
      });
    }
    
    
    if (Date.now() > storedData.expiresAt) {
      otpStore.delete(normalizedEmail);
      return res.status(400).json({ 
        success: false,
        error: 'OTP has expired' 
      });
    }

    
    const { data: user, error: userError } = await supabase
      .from('Registered')
      .select('*')
      .eq('Email', normalizedEmail)
      .single();

    if (userError || !user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }

    
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

    
    const { error: updateError } = await supabase
      .from('Registered')
      .update({ Password: hashedPassword })
      .eq('Email', normalizedEmail);

    if (updateError) {
      console.error('❌ Password update error:', updateError);
      return res.status(500).json({ 
        success: false,
        error: 'Failed to update password in database',
        details: updateError.message
      });
    }

    
    otpStore.delete(normalizedEmail);

    console.log('✅ Password reset for:', email);

    res.json({
      success: true,
      message: 'Password reset successful'
    });

  } catch (error) {
    console.error('❌ Password reset error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to reset password',
      details: error.message 
    });
  }
});


setInterval(() => {
  const now = Date.now();
  let cleanedOTPs = 0;
  let cleanedSessions = 0;
  
  
  for (const [email, data] of otpStore.entries()) {
    if (now > data.expiresAt) {
      otpStore.delete(email);
      cleanedOTPs++;
    }
  }
  
  
  for (const [sessionId, session] of sessions.entries()) {
    if (now > session.expires) {
      sessions.delete(sessionId);
      cleanedSessions++;
    }
  }
  
  if (cleanedOTPs > 0 || cleanedSessions > 0) {
    console.log(`🧹 Cleaned ${cleanedOTPs} expired OTP(s) and ${cleanedSessions} expired session(s)`);
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
  console.log(`💾 Database: Supabase`);
  console.log(`📁 SPA routing: ${indexHtml ? '✅ Enabled' : '❌ Disabled'}`);
});