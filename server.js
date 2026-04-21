import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import { GoogleGenAI } from '@google/genai';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, existsSync } from 'fs';
import sgMail from '@sendgrid/mail';
import { PROJECT_KNOWLEDGE } from './projectKnowledge.js';

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
const CHATBOT_MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5174',
  process.env.FRONTEND_URL,
  process.env.BACKEND_PUBLIC_URL,
  'https://resource-hub-as2o.onrender.com',
  'https://resource-hub-backend-hpq8.onrender.com'
].filter(Boolean);
const chatbotClient = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY
  ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY })
  : null;
const CHATBOT_SYSTEM_PROMPT = `You are the Fresher Resource Hub assistant.
Help students quickly find and use academic resources on the platform.
Keep answers practical, clear, and supportive.
Prefer short answers with action steps.
If asked about resources, suggest using filters like department, level, file type, and search.
Use the project knowledge provided to answer questions about how this app works.
If a question is covered by the project knowledge, answer it directly instead of saying you do not know.
If a detail is truly not available, say that politely and offer the closest helpful guidance without inventing features.
Format answers cleanly for chat:
- Do not use markdown asterisks for emphasis.
- If you need emphasis, keep the wording simple and natural.
- Use short paragraphs or numbered points when helpful.`;
const getChatbotErrorResponse = (error) => {
  const errorCode = error?.code || error?.error?.code || 'chatbot_error';
  const statusCode = error?.status || 500;

  if (errorCode === 'RESOURCE_EXHAUSTED' || errorCode === 'insufficient_quota') {
    return {
      statusCode: 429,
      payload: {
        success: false,
        code: errorCode,
        message: 'The chatbot is connected, but this Gemini project has hit its quota or free-tier limit right now.'
      }
    };
  }

  if (errorCode === 'API_KEY_INVALID' || errorCode === 'invalid_api_key') {
    return {
      statusCode: 401,
      payload: {
        success: false,
        code: errorCode,
        message: 'The backend Gemini API key is invalid. Update GEMINI_API_KEY and restart the backend.'
      }
    };
  }

  if (errorCode === 'NOT_FOUND' || errorCode === 'model_not_found') {
    return {
      statusCode: 400,
      payload: {
        success: false,
        code: errorCode,
        message: `The configured model "${CHATBOT_MODEL}" is unavailable for this Gemini API key.`
      }
    };
  }

  return {
    statusCode,
    payload: {
      success: false,
      code: errorCode,
      message: error?.error?.message || error?.message || 'Unable to get a chatbot response right now.'
    }
  };
};

// ✅ FIXED: UPDATED CORS FOR BOTH FRONTEND AND BACKEND DOMAINS
app.use(cors({
  origin: allowedOrigins,
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

// ==================== ENHANCED EMAIL CONFIGURATION ====================

console.log('\n🔧 ========== EMAIL CONFIGURATION CHECK ==========');
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

let emailService = {
  name: 'Gmail',
  isAvailable: !!(process.env.EMAIL_USER && process.env.EMAIL_PASS),
  sendEmail: async (toEmail, subject, htmlContent, textContent) => {
    console.log(`\n📧 === GMAIL SENDING PROCESS STARTED ===`);
    console.log(`📧 To: ${toEmail}`);
    
    const mailOptions = {
      from: `"Fresher Hub" <${process.env.EMAIL_USER}>`,
      to: toEmail,
      subject: subject,
      text: textContent,
      html: htmlContent,
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      console.log(`✅ EMAIL SENT SUCCESSFULLY!`);
      console.log(`📬 Message ID: ${info.messageId}`);
      return { success: true, messageId: info.messageId };
    } catch (error) {
      console.error('❌ GMAIL SENDING ERROR:', error.message);
      throw error;
    }
  }
};

// Verify connection on startup
if (emailService.isAvailable) {
  transporter.verify((error) => {
    if (error) console.log('❌ Gmail Transporter Error:', error);
    else console.log('✅ Gmail is ready to send messages');
  });
}



console.log('✅ Supabase connected as database');

const generateSessionId = () => {
  return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
};

// ==================== DEBUG ENDPOINTS ====================

app.get('/api/health', (req, res) => {
  const healthData = {
    status: 'OK',
    service: 'Resource Hub Backend',
    timestamp: new Date().toISOString(),
    server: process.env.BACKEND_PUBLIC_URL || 'https://resource-hub-backend-hpq8.onrender.com',
    email: {
      available: emailService.isAvailable,
      service: emailService.name,
      error: emailService.error,
      sendGridConfigured: !!process.env.SENDGRID_API_KEY,
      fromAddress: process.env.EMAIL_FROM || 'Not configured'
    },
    cors: {
      allowedOrigins
    },
    endpoints: {
      sendOtp: '/api/send-otp (POST)',
      debugEmail: '/api/debug-email (GET)',
      testEmail: '/api/test-email (GET)'
    }
  };
  
  console.log('🏥 Health check requested from:', req.headers.origin);
  res.json(healthData);
});

app.post('/api/chatbot', async (req, res) => {
  try {
    if (!chatbotClient) {
      return res.status(503).json({
        success: false,
        message: 'Chatbot is not configured yet.',
        error: 'GEMINI_API_KEY is missing on the backend.'
      });
    }

    const incomingMessages = Array.isArray(req.body?.messages) ? req.body.messages : [];
    const sanitizedMessages = incomingMessages
      .filter((message) => {
        return (
          message &&
          (message.role === 'user' || message.role === 'assistant') &&
          typeof message.content === 'string' &&
          message.content.trim()
        );
      })
      .slice(-8);

    if (!sanitizedMessages.length) {
      return res.status(400).json({
        success: false,
        message: 'At least one chat message is required.'
      });
    }

    const conversationTranscript = sanitizedMessages
      .map((message) => {
        const speaker = message.role === 'assistant' ? 'Assistant' : 'User';
        return `${speaker}: ${message.content.trim()}`;
      })
      .join('\n');

    const groundedPrompt = `Project knowledge:
${PROJECT_KNOWLEDGE}

Conversation:
${conversationTranscript}`;

    const response = await chatbotClient.models.generateContent({
      model: CHATBOT_MODEL,
      contents: groundedPrompt,
      config: {
        systemInstruction: CHATBOT_SYSTEM_PROMPT,
        maxOutputTokens: 350,
        temperature: 0.7
      }
    });

    const reply = response.text?.trim();

    if (!reply) {
      return res.status(502).json({
        success: false,
        message: 'The chatbot did not return a reply.'
      });
    }

    return res.json({
      success: true,
      reply
    });
  } catch (error) {
    const { statusCode, payload } = getChatbotErrorResponse(error);
    console.error('Chatbot error:', {
      status: error?.status,
      code: error?.code || error?.error?.code,
      message: error?.error?.message || error?.message
    });

    return res.status(statusCode).json(payload);
  }
});

app.get('/api/debug-email', (req, res) => {
  const debugInfo = {
    timestamp: new Date().toISOString(),
    requestOrigin: req.headers.origin || 'Unknown',
    
    emailService: {
      name: emailService.name,
      isAvailable: emailService.isAvailable,
      error: emailService.error
    },
    
    environmentCheck: {
      SENDGRID_API_KEY: {
        exists: !!process.env.SENDGRID_API_KEY,
        length: process.env.SENDGRID_API_KEY?.length || 0,
        formatValid: process.env.SENDGRID_API_KEY?.startsWith?.('SG.') || false
      },
      EMAIL_FROM: process.env.EMAIL_FROM || 'Not set',
      NODE_ENV: process.env.NODE_ENV || 'development'
    },
    
    commonIssues: [
      '1. SENDGRID_API_KEY not set in Render.com Environment',
      '2. Sender email not verified in SendGrid dashboard',
      '3. EMAIL_FROM not set or format incorrect'
    ]
  };
  
  console.log('🔍 Debug email requested from:', req.headers.origin);
  res.json(debugInfo);
});

app.get('/api/test-email', async (req, res) => {
  console.log('\n🧪 Test email requested from:', req.headers.origin);
  
  const testEmail = req.query.email || process.env.EMAIL_USER || 'osunyingboadedeji1@gmail.com';
  
  if (!emailService.isAvailable) {
    const response = {
      success: false,
      message: 'Email service not available',
      error: emailService.error,
      requiredSteps: [
        '1. Go to Render.com → Backend service → Environment',
        '2. Add: SENDGRID_API_KEY=sg.your_api_key_here',
        '3. Add: EMAIL_FROM="Fresher Hub <osunyingboadedeji1@gmail.com>"',
        '4. Click "Save Changes" and "Manual Deploy"'
      ]
    };
    
    return res.json(response);
  }
  
  try {
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; padding: 20px; }
          .container { max-width: 600px; margin: 0 auto; }
          .header { background: #667eea; color: white; padding: 20px; text-align: center; }
          .content { background: #f9f9f9; padding: 20px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>✅ Fresher Hub Test Email</h1>
          </div>
          <div class="content">
            <p>This is a test email sent from your Fresher Hub backend.</p>
            <p><strong>Backend:</strong> fresher-resource-hub-backend.onrender.com</p>
            <p><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
            <p>If you're receiving this, your email configuration is working correctly!</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    const textContent = `Test email from Fresher Hub Backend - Sent at: ${new Date().toISOString()}`;
    
    const result = await emailService.sendEmail(
      testEmail,
      '✅ Fresher Hub Backend - Test Email',
      htmlContent,
      textContent
    );
    
    res.json({
      success: true,
      message: 'Test email sent successfully',
      to: testEmail,
      result: result
    });
    
  } catch (error) {
    console.error('Test email error:', error);
    res.json({
      success: false,
      message: 'Test email failed',
      error: error.message
    });
  }
});

// ==================== YOUR EXISTING ROUTES ====================

app.post('/api/register', async (req, res) => {
  console.log('📝 Register request from:', req.headers.origin);
  
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
  console.log('🔐 Login request from:', req.headers.origin);
  
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

// ==================== SEND-OTP ENDPOINT ====================
app.post('/api/send-otp', async (req, res) => {
  console.log('📧 OTP request from:', req.headers.origin);
  console.log('📧 Request body:', { email: req.body?.email });
  
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
      .select('FullName, Email')
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
    
    // Try to send email via SendGrid
    if (emailService.isAvailable) {
      console.log(`📤 Attempting to send email via ${emailService.name} to:`, email);
      
      try {
        const htmlContent = `
          <!DOCTYPE html>
          <html>
          <head>
            <style>
              body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
              .container { max-width: 600px; margin: 0 auto; padding: 20px; }
              .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
              .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
              .otp-box { background: white; border: 2px dashed #667eea; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
              .otp-code { font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 5px; font-family: monospace; }
              .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>🔐 Password Reset</h1>
              </div>
              <div class="content">
                <p>Hello ${user.FullName || 'User'},</p>
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
        `;
        
        const textContent = `Your OTP is: ${otp}. It expires in ${OTP_EXPIRY_MINUTES} minutes.`;
        
        await emailService.sendEmail(
          email, 
          'Password Reset OTP - Fresher Hub', 
          htmlContent, 
          textContent
        );
        
        console.log('✅ Email sent successfully!');
        
        return res.json({
          success: true,
          message: 'OTP sent to your email',
          service: emailService.name,
          expiresIn: `${OTP_EXPIRY_MINUTES} minutes`
        });
        
      } catch (emailError) {
        console.error('❌ Email sending failed!');
        console.error('Error message:', emailError.message);
        
        // Fallback: return OTP in response if email fails
        return res.json({
          success: true,
          message: 'OTP generated (email delivery failed)',
          otp: otp,
          service: 'Fallback',
          expiresIn: `${OTP_EXPIRY_MINUTES} minutes`,
          note: 'Email service temporary issue - use OTP above',
          debug: emailError.message
        });
      }
    } else {
      // Email service not available - return OTP in response
      console.log('⚠️ Email service not available - returning OTP in response');
      return res.json({
        success: true,
        message: 'OTP generated (email service unavailable)',
        otp: otp,
        service: 'Direct',
        expiresIn: `${OTP_EXPIRY_MINUTES} minutes`,
        note: 'Use this OTP to reset your password'
      });
    }
    
  } catch (error) {
    console.error('❌ Server error in send-otp:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      details: error.message 
    });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  console.log('🔍 OTP verification request from:', req.headers.origin);
  
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

// ==================== CLEANUP INTERVAL ====================
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

// ==================== SPA ROUTING ====================
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

// ==================== 404 HANDLER ====================
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ 
      success: false,
      error: 'API endpoint not found',
      path: req.path,
      method: req.method,
      availableEndpoints: [
        'POST /api/register',
        'POST /api/login', 
        'POST /api/send-otp',
        'POST /api/verify-otp',
        'POST /api/reset-password',
        'GET /api/health',
        'GET /api/debug-email',
        'GET /api/test-email'
      ]
    });
  }
  
  if (indexHtml) {
    return res.send(indexHtml);
  }
  
  res.status(404).send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Fresher Hub Backend - Not Found</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 40px; text-align: center; }
        h1 { color: #667eea; }
        code { background: #f5f5f5; padding: 10px; border-radius: 5px; }
      </style>
    </head>
    <body>
      <h1>404 - Page Not Found</h1>
      <p>The requested URL <code>${req.path}</code> was not found.</p>
      <p>This is the Fresher Hub Backend API server.</p>
      <p>Try <a href="/api/health">/api/health</a> to check server status.</p>
    </body>
    </html>
  `);
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 ========== FRESHER HUB BACKEND STARTED ==========`);
  console.log(`🌐 Server URL: https://resource-hub-backend-hpq8.onrender.com`);
  console.log(`🔗 Local: http://localhost:${PORT}`);
  console.log(`\n📊 ========== API ENDPOINTS ==========`);
  console.log(`🏥 Health: /api/health`);
  console.log(`🔍 Debug: /api/debug-email`);
  console.log(`🧪 Test Email: /api/test-email`);
  console.log(`📧 Send OTP: POST /api/send-otp`);
  console.log(`🔐 Register: POST /api/register`);
  console.log(`🔑 Login: POST /api/login`);
  console.log(`\n🌍 ========== CORS ALLOWED ORIGINS ==========`);
  console.log(`✅ https://resource-hub-as2o.onrender.com (Frontend)`);
  console.log(`✅ https://resource-hub-backend-hpq8.onrender.com (Backend)`);
  console.log(`✅ http://localhost:5173`);
  console.log(`✅ http://localhost:5174`);
  console.log(`\n📧 ========== EMAIL STATUS ==========`);
  console.log(`Service: ${emailService.name}`);
  console.log(`Available: ${emailService.isAvailable ? '✅ Yes' : '❌ No'}`);
  if (emailService.error) console.log(`Error: ${emailService.error}`);
  console.log(`\n💾 Database: Supabase ✅`);
  console.log(`========================================\n`);
});
