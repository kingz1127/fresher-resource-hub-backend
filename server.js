

// import 'dotenv/config';
// import express from 'express';
// import cors from 'cors';
// import bcrypt from 'bcryptjs';
// import { createClient } from '@supabase/supabase-js';
// import { fileURLToPath } from 'url';
// import { dirname, join } from 'path';
// import { readFileSync, existsSync } from 'fs';
// import nodemailer from 'nodemailer';
// import sgMail from '@sendgrid/mail';

// const __dirname = dirname(fileURLToPath(import.meta.url));
// const app = express();

// const supabase = createClient(
//   process.env.SUPABASE_URL,
//   process.env.SUPABASE_ANON_KEY
// );

// const otpStore = new Map(); 
// const sessions = new Map(); 

// const OTP_EXPIRY_MINUTES = 10;
// const SALT_ROUNDS = 12;
// const SESSION_EXPIRY_HOURS = 24;

// app.use(cors({
//   origin: [
//     'http://localhost:5173', 
//     'http://localhost:5174',
//     'https://fresher-resource-hub.onrender.com'
//   ], 
//   methods: ['GET', 'POST', 'PUT', 'DELETE'],
//   credentials: true,
// }));

// const distExists = existsSync(join(__dirname, 'dist'));
// console.log('📁 dist exists:', distExists);

// app.use(express.json());

// if (distExists) {
//   app.use(express.static(join(__dirname, 'dist')));
//   console.log('✅ Serving static files from dist/');
// }


// let emailService = {
//   name: 'none',
//   isAvailable: false,
//   sendEmail: null
// };

// // Initialize SendGrid if API key exists
// if (process.env.SENDGRID_API_KEY) {
//   sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  
//   emailService = {
//     name: 'SendGrid',
//     isAvailable: true,
//     sendEmail: async (toEmail, subject, htmlContent, textContent) => {
//       const msg = {
//         to: toEmail,
//         from: process.env.EMAIL_FROM || 'Fresher Hub <osunyingboadedeji1@gmail.com>',
//         subject: subject,
//         html: htmlContent,
//         text: textContent,
//         trackingSettings: {
//           clickTracking: { enable: false },
//           openTracking: { enable: false }
//         }
//       };
      
//       try {
//         console.log(`📤 Sending email via SendGrid to: ${toEmail}`);
//         const response = await sgMail.send(msg);
//         console.log(`✅ Email sent! Message ID: ${response[0]?.headers?.['x-message-id']}`);
//         return { success: true, messageId: response[0]?.headers?.['x-message-id'] };
//       } catch (error) {
//         console.error('❌ SendGrid error:', error.response?.body || error.message);
//         throw error;
//       }
//     }
//   };
//   console.log('✅ SendGrid email service configured');
// } else {
//   console.log('⚠️ SendGrid API key not found - email service unavailable');
  
//   // Fallback to nodemailer if SendGrid not configured
//   if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
//     const transporter = nodemailer.createTransport({
//       service: 'gmail',
//       auth: {
//         user: process.env.EMAIL_USER,
//         pass: process.env.EMAIL_PASS,
//       },
//       secure: true,
//       tls: { rejectUnauthorized: false }
//     });
    
//     emailService = {
//       name: 'Nodemailer (may not work on Render)',
//       isAvailable: true,
//       sendEmail: async (toEmail, subject, htmlContent, textContent) => {
//         const mailOptions = {
//           from: process.env.EMAIL_USER,
//           to: toEmail,
//           subject: subject,
//           html: htmlContent,
//           text: textContent
//         };
        
//         return await transporter.sendMail(mailOptions);
//       }
//     };
//     console.log('⚠️ Using Nodemailer (may timeout on Render free tier)');
//   }
// }

// // Keep transporter for backward compatibility if needed
// const transporter = emailService.isAvailable ? { 
//   sendMail: async (options) => {
//     if (emailService.name === 'SendGrid') {
//       const msg = {
//         to: options.to,
//         from: options.from || process.env.EMAIL_FROM,
//         subject: options.subject,
//         html: options.html,
//         text: options.text
//       };
//       return await sgMail.send(msg);
//     }
//     // For nodemailer fallback
//     return emailService.sendEmail(options.to, options.subject, options.html, options.text);
//   },
//   verify: async () => emailService.isAvailable
// } : null;

// console.log('✅ Supabase connected as database');

// const generateSessionId = () => {
//   return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
// };

// app.get('/api/health', (req, res) => {
//   res.json({ 
//     status: 'OK', 
//     service: 'Fresher Hub',
//     timestamp: new Date().toISOString(),
//     email: emailService.isAvailable,
//     emailService: emailService.name,
//     otpsStored: otpStore.size,
//     sessionsCount: sessions.size,
//     database: 'Supabase'
//   });
// });

// app.post('/api/register', async (req, res) => {
//   console.log('📝 Register request:', req.body?.email);
  
//   try {
//     const { fullName, email, password } = req.body;

//     if (!fullName || !email || !password) {
//       return res.status(400).json({ 
//         success: false,
//         error: 'Full name, email, and password are required' 
//       });
//     }

//     if (password.length < 6) {
//       return res.status(400).json({ 
//         success: false,
//         error: 'Password must be at least 6 characters' 
//       });
//     }

//     const normalizedEmail = email.toLowerCase();

//     const { data: existingUser, error: checkError } = await supabase
//       .from('Registered')
//       .select('*')
//       .eq('Email', normalizedEmail)
//       .single();

//     if (checkError && checkError.code !== 'PGRST116') { 
//       console.error('❌ Check error:', checkError);
//     }

//     if (existingUser) {
//       return res.status(400).json({ 
//         success: false,
//         error: 'Email already registered' 
//       });
//     }

//     const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    
//     const { data: newUser, error: insertError } = await supabase
//       .from('Registered')
//       .insert([
//         {
//           FullName: fullName,
//           Email: normalizedEmail,
//           Password: hashedPassword,
//           role: 'user',
//           created_at: new Date().toISOString()
//         }
//       ])
//       .select()
//       .single();

//     if (insertError) {
//       console.error('❌ Supabase insert error:', insertError);
//       return res.status(500).json({ 
//         success: false,
//         error: 'Failed to create user in database',
//         details: insertError.message
//       });
//     }

//     console.log('✅ User registered in Supabase:', normalizedEmail);

//     res.status(201).json({
//       success: true,
//       message: 'Registration successful',
//       user: {
//         id: newUser.id,
//         FullName: newUser.FullName,
//         Email: newUser.Email,
//         role: newUser.role,
//         createdAt: newUser.created_at
//       }
//     });

//   } catch (error) {
//     console.error('❌ Registration error:', error);
//     res.status(500).json({ 
//       success: false,
//       error: 'Registration failed',
//       details: error.message 
//     });
//   }
// });

// app.post('/api/login', async (req, res) => {
//   console.log('🔐 Login request:', req.body?.email);
  
//   try {
//     const { email, password } = req.body;

//     if (!email || !password) {
//       return res.status(400).json({ 
//         success: false,
//         error: 'Email and password are required' 
//       });
//     }

//     const normalizedEmail = email.toLowerCase();

//     const { data: user, error: fetchError } = await supabase
//       .from('Registered')
//       .select('*')
//       .eq('Email', normalizedEmail)
//       .single();

//     if (fetchError || !user) {
//       console.log('❌ User not found:', fetchError?.message);
//       return res.status(401).json({ 
//         success: false,
//         error: 'Invalid email or password' 
//       });
//     }

//     const isValid = await bcrypt.compare(password, user.Password);
    
//     if (!isValid) {
//       return res.status(401).json({ 
//         success: false,
//         error: 'Invalid email or password' 
//       });
//     }

//     const sessionId = generateSessionId();
//     const expiresAt = Date.now() + (SESSION_EXPIRY_HOURS * 60 * 60 * 1000);
    
//     sessions.set(sessionId, {
//       userId: user.id,
//       email: normalizedEmail,
//       expires: expiresAt,
//       role: user.role
//     });
    
//     console.log('✅ User logged in:', normalizedEmail);

//     res.json({
//       success: true,
//       message: 'Login successful',
//       user: {
//         id: user.id,
//         FullName: user.FullName,
//         Email: user.Email,
//         role: user.role
//       },
//       sessionId: sessionId,
//       expiresAt: expiresAt
//     });

//   } catch (error) {
//     console.error('❌ Login error:', error);
//     res.status(500).json({ 
//       success: false,
//       error: 'Login failed',
//       details: error.message 
//     });
//   }
// });

// app.post('/api/validate-session', (req, res) => {
//   try {
//     const { sessionId } = req.body;

//     if (!sessionId) {
//       return res.status(400).json({ 
//         success: false,
//         error: 'Session ID required' 
//       });
//     }

//     const session = sessions.get(sessionId);

//     if (!session) {
//       return res.status(401).json({ 
//         success: false,
//         error: 'Invalid session' 
//       });
//     }

//     if (Date.now() > session.expires) {
//       sessions.delete(sessionId);
//       return res.status(401).json({ 
//         success: false,
//         error: 'Session expired' 
//       });
//     }

//     res.json({
//       success: true,
//       user: {
//         userId: session.userId,
//         email: session.email,
//         role: session.role
//       },
//       sessionId: sessionId,
//       expiresAt: session.expires
//     });

//   } catch (error) {
//     console.error('❌ Session validation error:', error);
//     res.status(500).json({ 
//       success: false,
//       error: 'Session validation failed',
//       details: error.message 
//     });
//   }
// });

// app.post('/api/logout', (req, res) => {
//   try {
//     const { sessionId } = req.body;

//     if (sessionId) {
//       sessions.delete(sessionId);
//     }

//     res.json({
//       success: true,
//       message: 'Logged out successfully'
//     });

//   } catch (error) {
//     console.error('❌ Logout error:', error);
//     res.status(500).json({ 
//       success: false,
//       error: 'Logout failed',
//       details: error.message 
//     });
//   }
// });

// // ==================== UPDATED SEND-OTP WITH SENDGRID ====================
// app.post('/api/send-otp', async (req, res) => {
//   console.log('📧 OTP request:', req.body?.email);
  
//   try {
//     const { email } = req.body;

//     if (!email) {
//       return res.status(400).json({ 
//         success: false,
//         error: 'Email required' 
//       });
//     }

//     const normalizedEmail = email.toLowerCase();

//     const { data: user, error: userError } = await supabase
//       .from('Registered')
//       .select('FullName, Email')
//       .eq('Email', normalizedEmail)
//       .single();

//     if (userError || !user) {
//       return res.status(404).json({ 
//         success: false,
//         error: 'No account found with this email' 
//       });
//     }

//     const otp = Math.floor(100000 + Math.random() * 900000).toString();
//     const expiresAt = Date.now() + (OTP_EXPIRY_MINUTES * 60 * 1000);
//     otpStore.set(normalizedEmail, { otp, expiresAt });
    
//     console.log(`✅ OTP stored for ${email}: ${otp} (expires in ${OTP_EXPIRY_MINUTES}min)`);
    
//     // Try to send email via SendGrid
//     if (emailService.isAvailable) {
//       console.log(`📤 Attempting to send email via ${emailService.name} to:`, email);
      
//       try {
//         const htmlContent = `
//           <!DOCTYPE html>
//           <html>
//           <head>
//             <style>
//               body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
//               .container { max-width: 600px; margin: 0 auto; padding: 20px; }
//               .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
//               .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
//               .otp-box { background: white; border: 2px dashed #667eea; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
//               .otp-code { font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 5px; font-family: monospace; }
//               .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
//             </style>
//           </head>
//           <body>
//             <div class="container">
//               <div class="header">
//                 <h1>🔐 Password Reset</h1>
//               </div>
//               <div class="content">
//                 <p>Hello ${user.FullName || 'User'},</p>
//                 <p>You requested to reset your password. Use the OTP code below to continue:</p>
//                 <div class="otp-box">
//                   <div class="otp-code">${otp}</div>
//                 </div>
//                 <p><strong>⏱️ This code expires in ${OTP_EXPIRY_MINUTES} minutes.</strong></p>
//                 <p>If you didn't request this, please ignore this email.</p>
//                 <div class="footer">
//                   <p>This is an automated email from Fresher Hub</p>
//                 </div>
//               </div>
//             </div>
//           </body>
//           </html>
//         `;
        
//         const textContent = `Your OTP is: ${otp}. It expires in ${OTP_EXPIRY_MINUTES} minutes.`;
        
//         await emailService.sendEmail(
//           email, 
//           'Password Reset OTP - Fresher Hub', 
//           htmlContent, 
//           textContent
//         );
        
//         console.log('✅ Email sent successfully!');
        
//         return res.json({
//           success: true,
//           message: 'OTP sent to your email',
//           service: emailService.name,
//           expiresIn: `${OTP_EXPIRY_MINUTES} minutes`
//         });
        
//       } catch (emailError) {
//         console.error('❌ Email sending failed!');
//         console.error('Error message:', emailError.message);
        
//         // Fallback: return OTP in response if email fails
//         return res.json({
//           success: true,
//           message: 'OTP generated (email delivery failed)',
//           otp: otp,
//           service: 'Fallback',
//           expiresIn: `${OTP_EXPIRY_MINUTES} minutes`,
//           note: 'Email service temporary issue - use OTP above',
//           debug: emailError.message
//         });
//       }
//     } else {
//       // Email service not available - return OTP in response
//       console.log('⚠️ Email service not available - returning OTP in response');
//       return res.json({
//         success: true,
//         message: 'OTP generated (email service unavailable)',
//         otp: otp,
//         service: 'Direct',
//         expiresIn: `${OTP_EXPIRY_MINUTES} minutes`,
//         note: 'Use this OTP to reset your password'
//       });
//     }
    
//   } catch (error) {
//     console.error('❌ Server error in send-otp:', error);
//     res.status(500).json({ 
//       success: false,
//       error: 'Internal server error',
//       details: error.message 
//     });
//   }
// });

// app.post('/api/verify-otp', async (req, res) => {
//   console.log('🔍 OTP verification request:', req.body?.email);
  
//   try {
//     const { email, otp } = req.body;

//     if (!email || !otp) {
//       return res.status(400).json({ 
//         success: false,
//         error: 'Email and OTP are required' 
//       });
//     }

//     const normalizedEmail = email.toLowerCase();
//     const storedData = otpStore.get(normalizedEmail);

//     if (!storedData) {
//       console.log('❌ No OTP found for:', email);
//       return res.status(400).json({ 
//         success: false,
//         error: 'No OTP found. Please request a new one.' 
//       });
//     }

//     if (Date.now() > storedData.expiresAt) {
//       console.log('❌ OTP expired for:', email);
//       otpStore.delete(normalizedEmail);
//       return res.status(400).json({ 
//         success: false,
//         error: 'OTP has expired. Please request a new one.' 
//       });
//     }

//     if (storedData.otp !== otp.toString()) {
//       console.log('❌ Invalid OTP for:', email);
//       return res.status(400).json({ 
//         success: false,
//         error: 'Invalid OTP. Please try again.' 
//       });
//     }

//     console.log('✅ OTP verified for:', email);
//     otpStore.delete(normalizedEmail); 
    
//     res.json({
//       success: true,
//       message: 'OTP verified successfully'
//     });

//   } catch (error) {
//     console.error('❌ Verification error:', error);
//     res.status(500).json({ 
//       success: false,
//       error: 'Internal server error',
//       details: error.message 
//     });
//   }
// });

// app.post('/api/reset-password', async (req, res) => {
//   try {
//     const { email, otp, newPassword } = req.body;

//     if (!email || !otp || !newPassword) {
//       return res.status(400).json({ 
//         success: false,
//         error: 'Email, OTP, and new password are required' 
//       });
//     }

//     const normalizedEmail = email.toLowerCase();
//     const storedData = otpStore.get(normalizedEmail);

//     if (!storedData || storedData.otp !== otp.toString()) {
//       return res.status(400).json({ 
//         success: false,
//         error: 'Invalid OTP' 
//       });
//     }
    
//     if (Date.now() > storedData.expiresAt) {
//       otpStore.delete(normalizedEmail);
//       return res.status(400).json({ 
//         success: false,
//         error: 'OTP has expired' 
//       });
//     }

//     const { data: user, error: userError } = await supabase
//       .from('Registered')
//       .select('*')
//       .eq('Email', normalizedEmail)
//       .single();

//     if (userError || !user) {
//       return res.status(404).json({ 
//         success: false,
//         error: 'User not found' 
//       });
//     }

//     const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

//     const { error: updateError } = await supabase
//       .from('Registered')
//       .update({ Password: hashedPassword })
//       .eq('Email', normalizedEmail);

//     if (updateError) {
//       console.error('❌ Password update error:', updateError);
//       return res.status(500).json({ 
//         success: false,
//         error: 'Failed to update password in database',
//         details: updateError.message
//       });
//     }

//     otpStore.delete(normalizedEmail);

//     console.log('✅ Password reset for:', email);

//     res.json({
//       success: true,
//       message: 'Password reset successful'
//     });

//   } catch (error) {
//     console.error('❌ Password reset error:', error);
//     res.status(500).json({ 
//       success: false,
//       error: 'Failed to reset password',
//       details: error.message 
//     });
//   }
// });

// // Add a test endpoint for SendGrid
// app.get('/api/test-email', async (req, res) => {
//   try {
//     if (!emailService.isAvailable) {
//       return res.json({
//         success: false,
//         message: 'Email service not available',
//         service: emailService.name,
//         env: {
//           SENDGRID_API_KEY: process.env.SENDGRID_API_KEY ? 'Set' : 'Not set',
//           EMAIL_FROM: process.env.EMAIL_FROM || 'Not set',
//           EMAIL_USER: process.env.EMAIL_USER ? 'Set' : 'Not set'
//         }
//       });
//     }
    
//     const testEmail = process.env.TEST_EMAIL || process.env.EMAIL_USER;
    
//     if (!testEmail) {
//       return res.json({
//         success: false,
//         message: 'No test email configured',
//         note: 'Set TEST_EMAIL or EMAIL_USER in environment variables'
//       });
//     }
    
//     const htmlContent = `<h1>Test Email from Fresher Hub</h1><p>Sent at: ${new Date().toISOString()}</p>`;
//     const textContent = `Test Email from Fresher Hub - Sent at: ${new Date().toISOString()}`;
    
//     const result = await emailService.sendEmail(
//       testEmail,
//       'Test Email - Fresher Hub',
//       htmlContent,
//       textContent
//     );
    
//     res.json({
//       success: true,
//       message: 'Test email sent successfully',
//       service: emailService.name,
//       to: testEmail,
//       result: result
//     });
    
//   } catch (error) {
//     console.error('Test email error:', error);
//     res.json({
//       success: false,
//       message: 'Test email failed',
//       error: error.message,
//       service: emailService.name
//     });
//   }
// });

// setInterval(() => {
//   const now = Date.now();
//   let cleanedOTPs = 0;
//   let cleanedSessions = 0;
  
//   for (const [email, data] of otpStore.entries()) {
//     if (now > data.expiresAt) {
//       otpStore.delete(email);
//       cleanedOTPs++;
//     }
//   }
  
//   for (const [sessionId, session] of sessions.entries()) {
//     if (now > session.expires) {
//       sessions.delete(sessionId);
//       cleanedSessions++;
//     }
//   }
  
//   if (cleanedOTPs > 0 || cleanedSessions > 0) {
//     console.log(`🧹 Cleaned ${cleanedOTPs} expired OTP(s) and ${cleanedSessions} expired session(s)`);
//   }
// }, 60000); 

// let indexHtml = null;
// if (distExists) {
//   try {
//     const indexPath = join(__dirname, 'dist', 'index.html');
//     if (existsSync(indexPath)) {
//       indexHtml = readFileSync(indexPath, 'utf8');
//       console.log('✅ Loaded index.html for SPA routing');
//     }
//   } catch (err) {
//     console.error('Error loading index.html:', err.message);
//   }
// }

// const handleSPA = (req, res, next) => {
//   if (req.path.startsWith('/api/')) {
//     return next();
//   }
  
//   if (req.path.match(/\.[a-zA-Z0-9]{2,}$/)) {
//     return next();
//   }
  
//   if (indexHtml) {
//     return res.send(indexHtml);
//   }
  
//   next();
// };

// app.use(handleSPA);

// app.use((req, res) => {
//   if (req.path.startsWith('/api/')) {
//     return res.status(404).json({ 
//       success: false,
//       error: 'API endpoint not found',
//       path: req.path 
//     });
//   }
  
//   if (indexHtml) {
//     return res.send(indexHtml);
//   }
  
//   res.status(404).send(`
//     <!DOCTYPE html>
//     <html>
//     <head>
//       <title>Fresher Hub - Not Found</title>
//       <style>
//         body { font-family: Arial, sans-serif; padding: 40px; text-align: center; }
//         h1 { color: #667eea; }
//         code { background: #f5f5f5; padding: 10px; border-radius: 5px; }
//       </style>
//     </head>
//     <body>
//       <h1>404 - Page Not Found</h1>
//       <p>The requested URL <code>${req.path}</code> was not found.</p>
//       <p><a href="/">Go to Homepage</a></p>
//     </body>
//     </html>
//   `);
// });

// const PORT = process.env.PORT || 3000;
// app.listen(PORT, '0.0.0.0', () => {
//   console.log(`🚀 Server running on port ${PORT}`);
//   console.log(`🌐 Health check: http://localhost:${PORT}/api/health`);
//   console.log(`📧 Email service: ${emailService.name} ${emailService.isAvailable ? '✅ Ready' : '❌ Not available'}`);
//   console.log(`💾 Database: Supabase`);
//   console.log(`📁 SPA routing: ${indexHtml ? '✅ Enabled' : '❌ Disabled'}`);
// });


import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, existsSync } from 'fs';
import sgMail from '@sendgrid/mail';

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
  origin: [
    'http://localhost:5173', 
    'http://localhost:5174',
    'https://fresher-resource-hub.onrender.com'
  ], 
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

// ==================== ENHANCED EMAIL CONFIGURATION WITH DEBUGGING ====================
console.log('\n🔧 ========== EMAIL CONFIGURATION CHECK ==========');
console.log('📋 Checking environment variables:');
console.log('- SENDGRID_API_KEY:', process.env.SENDGRID_API_KEY ? `✅ Set (${process.env.SENDGRID_API_KEY.substring(0, 10)}...)` : '❌ NOT SET');
console.log('- EMAIL_FROM:', process.env.EMAIL_FROM || '❌ NOT SET (Required for SendGrid)');
console.log('- EMAIL_USER:', process.env.EMAIL_USER || 'Not set (optional)');
console.log('- SUPABASE_URL:', process.env.SUPABASE_URL ? '✅ Set' : '❌ NOT SET');
console.log('===================================================\n');

let emailService = {
  name: 'none',
  isAvailable: false,
  sendEmail: null,
  error: null
};

// Initialize SendGrid if API key exists
if (process.env.SENDGRID_API_KEY) {
  try {
    // Test if API key is valid format
    if (!process.env.SENDGRID_API_KEY.startsWith('SG.')) {
      console.log('❌ SendGrid API key format invalid - should start with "SG."');
      emailService.error = 'API key format invalid. Should start with "SG."';
    } else {
      sgMail.setApiKey(process.env.SENDGRID_API_KEY);
      console.log('✅ SendGrid API key configured');
      
      emailService = {
        name: 'SendGrid',
        isAvailable: true,
        error: null,
        sendEmail: async (toEmail, subject, htmlContent, textContent) => {
          console.log(`\n📧 === EMAIL SENDING PROCESS STARTED ===`);
          console.log(`📧 To: ${toEmail}`);
          console.log(`📝 Subject: ${subject}`);
          
          const msg = {
            to: toEmail,
            from: process.env.EMAIL_FROM || 'Fresher Hub <osunyingboadedeji1@gmail.com>',
            subject: subject,
            html: htmlContent,
            text: textContent,
            trackingSettings: {
              clickTracking: { enable: false },
              openTracking: { enable: false }
            }
          };
          
          console.log(`📤 Attempting to send via SendGrid...`);
          console.log(`📨 From address: ${msg.from}`);
          
          try {
            const response = await sgMail.send(msg);
            console.log(`✅ EMAIL SENT SUCCESSFULLY!`);
            console.log(`📬 Status Code: ${response[0]?.statusCode}`);
            
            if (response[0]?.headers?.['x-message-id']) {
              console.log(`📧 Message ID: ${response[0].headers['x-message-id']}`);
            }
            
            console.log(`====================================\n`);
            
            return { 
              success: true, 
              messageId: response[0]?.headers?.['x-message-id'],
              statusCode: response[0]?.statusCode
            };
          } catch (error) {
            console.error('❌ SENDGRID API ERROR DETAILS:');
            console.error('- Error Message:', error.message);
            console.error('- Error Code:', error.code);
            
            if (error.response) {
              console.error('- HTTP Status Code:', error.response.statusCode);
              console.error('- Response Body:', JSON.stringify(error.response.body, null, 2));
              
              // Common error analysis
              if (error.response.body?.errors) {
                error.response.body.errors.forEach((err, i) => {
                  console.error(`  Error ${i + 1}: ${err.message}`);
                  if (err.field) console.error(`  Field: ${err.field}`);
                  if (err.help) console.error(`  Help: ${err.help}`);
                });
              }
            }
            
            console.error(`====================================\n`);
            
            // Store the error for debugging
            emailService.error = error.message;
            throw error;
          }
        }
      };
      console.log('✅ SendGrid email service initialized successfully');
    }
  } catch (error) {
    console.error('❌ Failed to initialize SendGrid:', error.message);
    emailService.isAvailable = false;
    emailService.error = error.message;
  }
} else {
  console.log('⚠️ SENDGRID_API_KEY not found in environment variables');
  console.log('💡 REQUIRED: Add to Render.com → Environment → SENDGRID_API_KEY=sg.your_api_key_here');
  emailService.error = 'SENDGRID_API_KEY environment variable not set';
}

console.log('📧 Email service status:', {
  name: emailService.name,
  available: emailService.isAvailable ? '✅ Yes' : '❌ No',
  error: emailService.error || 'None'
});

console.log('✅ Supabase connected as database');

const generateSessionId = () => {
  return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
};

// ==================== COMPREHENSIVE DEBUG ENDPOINTS ====================

app.get('/api/health', (req, res) => {
  const healthData = {
    status: 'OK',
    service: 'Fresher Hub',
    timestamp: new Date().toISOString(),
    email: {
      available: emailService.isAvailable,
      service: emailService.name,
      error: emailService.error,
      sendGridConfigured: !!process.env.SENDGRID_API_KEY,
      fromAddress: process.env.EMAIL_FROM || 'Not configured',
      apiKeyPreview: process.env.SENDGRID_API_KEY ? 
        `${process.env.SENDGRID_API_KEY.substring(0, 10)}...` : 'Not set'
    },
    environment: {
      node: process.version,
      env: process.env.NODE_ENV || 'development',
      port: process.env.PORT || 3000,
      render: process.env.RENDER ? 'Yes' : 'No'
    },
    stats: {
      otpsStored: otpStore.size,
      sessionsActive: sessions.size,
      uptime: Math.floor(process.uptime()) + ' seconds'
    },
    database: 'Supabase ✅',
    endpoints: {
      debug: '/api/debug-email',
      testEmail: '/api/test-email',
      quickOtp: '/api/quick-otp/:email'
    }
  };
  
  console.log('🏥 Health check requested');
  res.json(healthData);
});

// COMPREHENSIVE DEBUG ENDPOINT
app.get('/api/debug-email', (req, res) => {
  const debugInfo = {
    timestamp: new Date().toISOString(),
    serverUptime: Math.floor(process.uptime()) + ' seconds',
    
    emailService: {
      name: emailService.name,
      isAvailable: emailService.isAvailable,
      error: emailService.error,
      sendGridInitialized: !!sgMail
    },
    
    environmentCheck: {
      SENDGRID_API_KEY: {
        exists: !!process.env.SENDGRID_API_KEY,
        length: process.env.SENDGRID_API_KEY?.length || 0,
        formatValid: process.env.SENDGRID_API_KEY?.startsWith?.('SG.') || false,
        preview: process.env.SENDGRID_API_KEY ? 
          `${process.env.SENDGRID_API_KEY.substring(0, 10)}...` : 'Not set'
      },
      EMAIL_FROM: {
        value: process.env.EMAIL_FROM || 'Not set',
        isValid: process.env.EMAIL_FROM?.includes('<') && process.env.EMAIL_FROM?.includes('>')
      },
      EMAIL_USER: process.env.EMAIL_USER || 'Not set',
      NODE_ENV: process.env.NODE_ENV || 'development',
      PORT: process.env.PORT || 3000,
      RENDER: process.env.RENDER ? 'Yes (Running on Render)' : 'No'
    },
    
    serverInfo: {
      nodeVersion: process.version,
      platform: process.platform,
      memory: {
        rss: Math.round(process.memoryUsage().rss / 1024 / 1024) + ' MB',
        heapTotal: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB',
        heapUsed: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB'
      }
    },
    
    commonIssues: [
      '1. SENDGRID_API_KEY not set in Render.com Environment',
      '2. Sender email not verified in SendGrid dashboard',
      '3. EMAIL_FROM not set or format incorrect',
      '4. Daily sending limit reached (100 emails/day free tier)'
    ],
    
    immediateFixSteps: [
      'Go to Render.com → Your service → Environment tab',
      'Add: SENDGRID_API_KEY=sg.your_actual_api_key_here',
      'Add: EMAIL_FROM="Fresher Hub <osunyingboadedeji1@gmail.com>"',
      'Click "Save Changes" → "Manual Deploy"',
      'Verify sender: https://app.sendgrid.com/settings/sender_auth'
    ],
    
    usefulLinks: {
      sendGridActivity: 'https://app.sendgrid.com/activity-feed',
      sendGridSenders: 'https://app.sendgrid.com/settings/sender_auth',
      sendGridApiKeys: 'https://app.sendgrid.com/settings/api_keys',
      renderEnvironment: 'https://dashboard.render.com/'
    }
  };
  
  console.log('🔍 Comprehensive email debug info requested');
  res.json(debugInfo);
});

// ENHANCED TEST EMAIL ENDPOINT
app.get('/api/test-email', async (req, res) => {
  console.log('\n🧪 ========== TEST EMAIL REQUESTED ==========');
  
  const testEmail = req.query.email || process.env.EMAIL_USER || 'osunyingboadedeji1@gmail.com';
  console.log(`📧 Test email destination: ${testEmail}`);
  
  if (!emailService.isAvailable) {
    console.log('❌ Email service not available');
    const response = {
      success: false,
      message: 'Email service not available',
      service: emailService.name,
      error: emailService.error,
      requiredConfiguration: {
        step1: 'Go to Render.com → Your service → Environment tab',
        step2: 'Add: SENDGRID_API_KEY=sg.your_api_key_here',
        step3: 'Add: EMAIL_FROM="Fresher Hub <osunyingboadedeji1@gmail.com>"',
        step4: 'Click "Save Changes" and "Manual Deploy"'
      },
      currentStatus: {
        SENDGRID_API_KEY_set: !!process.env.SENDGRID_API_KEY,
        EMAIL_FROM_set: !!process.env.EMAIL_FROM,
        EMAIL_USER_set: !!process.env.EMAIL_USER
      }
    };
    
    console.log('Test email failed - service unavailable');
    console.log('====================================\n');
    return res.json(response);
  }
  
  try {
    console.log(`🔧 Using service: ${emailService.name}`);
    
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Fresher Hub - Test Email</title>
        <style>
          body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            margin: 0; 
            padding: 0; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
          }
          .container { 
            max-width: 600px; 
            margin: 40px auto; 
            background: white; 
            border-radius: 15px; 
            overflow: hidden; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.2); 
          }
          .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 40px; 
            text-align: center; 
          }
          .header h1 { 
            margin: 0; 
            font-size: 28px; 
            font-weight: 700; 
          }
          .header p { 
            margin: 10px 0 0; 
            opacity: 0.9; 
            font-size: 16px; 
          }
          .content { 
            padding: 40px; 
          }
          .success-badge { 
            background: #10b981; 
            color: white; 
            padding: 12px 20px; 
            border-radius: 50px; 
            display: inline-block; 
            font-weight: 600; 
            margin-bottom: 25px; 
            font-size: 18px; 
          }
          .info-box { 
            background: #f0f9ff; 
            border-left: 4px solid #3b82f6; 
            padding: 25px; 
            margin: 25px 0; 
            border-radius: 0 8px 8px 0; 
          }
          .info-box p { 
            margin: 8px 0; 
          }
          .info-box strong { 
            color: #1e40af; 
          }
          .steps { 
            background: #f8fafc; 
            border: 1px solid #e2e8f0; 
            border-radius: 10px; 
            padding: 25px; 
            margin-top: 30px; 
          }
          .steps h3 { 
            margin-top: 0; 
            color: #475569; 
          }
          .steps ol { 
            margin: 15px 0; 
            padding-left: 20px; 
          }
          .steps li { 
            margin: 10px 0; 
            color: #475569; 
          }
          .footer { 
            text-align: center; 
            margin-top: 40px; 
            padding-top: 25px; 
            border-top: 1px solid #e2e8f0; 
            color: #64748b; 
            font-size: 14px; 
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>✅ Fresher Hub - Test Email</h1>
            <p>Email Service Configuration Test</p>
          </div>
          <div class="content">
            <div class="success-badge">✓ TEST SUCCESSFUL</div>
            
            <p>This is a test email sent from your Fresher Hub application.</p>
            <p>If you're receiving this, your email configuration is working correctly!</p>
            
            <div class="info-box">
              <p><strong>📅 Timestamp:</strong> ${new Date().toISOString()}</p>
              <p><strong>🔧 Service:</strong> ${emailService.name}</p>
              <p><strong>📧 To:</strong> ${testEmail}</p>
              <p><strong>📨 From:</strong> ${process.env.EMAIL_FROM || 'Fresher Hub <osunyingboadedeji1@gmail.com>'}</p>
              <p><strong>🌐 Environment:</strong> ${process.env.NODE_ENV || 'development'}</p>
            </div>
            
            <div class="steps">
              <h3>Next Steps:</h3>
              <ol>
                <li>Check your email inbox (and spam folder if not visible)</li>
                <li>Visit SendGrid Activity Feed to monitor delivery status</li>
                <li>Test the password reset functionality in your app</li>
                <li>Verify sender authentication if emails go to spam</li>
              </ol>
            </div>
            
            <div class="footer">
              <p>This is an automated test email from Fresher Hub</p>
              <p>Server: ${process.env.RENDER ? 'Render.com' : 'Local'} | ${process.env.NODE_ENV || 'development'} environment</p>
            </div>
          </div>
        </div>
      </body>
      </html>
    `;
    
    const textContent = `
FRESHER HUB - TEST EMAIL CONFIRMATION
=====================================

✅ TEST SUCCESSFUL

This is a test email sent from your Fresher Hub application.

DETAILS:
• Timestamp: ${new Date().toISOString()}
• Service: ${emailService.name}
• To: ${testEmail}
• From: ${process.env.EMAIL_FROM || 'Fresher Hub <osunyingboadedeji1@gmail.com>'}
• Environment: ${process.env.NODE_ENV || 'development'}

If you're receiving this, your email configuration is working correctly!

NEXT STEPS:
1. Check your email inbox (and spam folder if not visible)
2. Visit SendGrid Activity Feed to monitor delivery status
3. Test the password reset functionality in your app
4. Verify sender authentication if emails go to spam

---
This is an automated test email from Fresher Hub
Server: ${process.env.RENDER ? 'Render.com' : 'Local'} | ${process.env.NODE_ENV || 'development'} environment
    `;
    
    console.log(`📤 Sending test email...`);
    const result = await emailService.sendEmail(
      testEmail,
      '✅ Fresher Hub - Email Configuration Test Successful',
      htmlContent,
      textContent
    );
    
    console.log('✅ Test email sent successfully!');
    
    const response = {
      success: true,
      message: 'Test email sent successfully',
      service: emailService.name,
      details: {
        to: testEmail,
        from: process.env.EMAIL_FROM || 'Fresher Hub <osunyingboadedeji1@gmail.com>',
        timestamp: new Date().toISOString(),
        messageId: result.messageId,
        statusCode: result.statusCode,
        environment: process.env.NODE_ENV || 'development'
      },
      nextSteps: [
        '1. Check your email inbox (and spam folder)',
        '2. Visit SendGrid Activity Feed: https://app.sendgrid.com/activity-feed',
        '3. Test password reset functionality in your app',
        '4. If not received, check sender verification in SendGrid'
      ],
      troubleshooting: {
        checkSpam: 'Important: Check spam folder as emails often go there initially',
        senderVerification: 'Verify sender: https://app.sendgrid.com/settings/sender_auth',
        activityFeed: 'Monitor deliveries: https://app.sendgrid.com/activity-feed',
        apiKeyCheck: 'Verify API key: https://app.sendgrid.com/settings/api_keys'
      }
    };
    
    console.log('Test email completed successfully');
    console.log('====================================\n');
    res.json(response);
    
  } catch (error) {
    console.error('❌ Test email failed with error:', error.message);
    
    // Detailed error analysis
    let errorDetails = {
      message: error.message,
      code: error.code,
      response: null
    };
    
    if (error.response) {
      errorDetails.response = {
        statusCode: error.response.statusCode,
        body: error.response.body,
        headers: Object.keys(error.response.headers || {})
      };
      
      // Common SendGrid errors
      if (error.response.body?.errors) {
        errorDetails.sendGridErrors = error.response.body.errors.map(err => ({
          message: err.message,
          field: err.field,
          help: err.help
        }));
      }
    }
    
    console.log('Test email failed - see error details above');
    console.log('====================================\n');
    
    res.json({
      success: false,
      message: 'Test email failed',
      error: errorDetails,
      service: emailService.name,
      commonIssues: [
        '1. SendGrid API key invalid or expired - regenerate in SendGrid',
        '2. Sender email not verified - verify at SendGrid dashboard',
        '3. Daily sending limit reached (100 emails/day on free tier)',
        '4. Email address blocked or not allowed',
        '5. EMAIL_FROM format incorrect - use: "Fresher Hub <email@gmail.com>"'
      ],
      immediateActions: [
        'Visit: https://app.sendgrid.com/settings/sender_auth (verify sender)',
        'Check: https://app.sendgrid.com/activity-feed (see attempts)',
        'Verify: https://app.sendgrid.com/settings/api_keys (check API key)',
        'Format: EMAIL_FROM="Fresher Hub <osunyingboadedeji1@gmail.com>"'
      ]
    });
  }
});

// QUICK FIX ENDPOINT - Returns OTP directly (bypasses email if needed)
app.get('/api/quick-otp/:email', async (req, res) => {
  const email = req.params.email;
  console.log(`\n🔑 ========== QUICK OTP REQUESTED ==========`);
  console.log(`📧 For email: ${email}`);
  
  try {
    const { data: user } = await supabase
      .from('Registered')
      .select('FullName, Email')
      .eq('Email', email.toLowerCase())
      .single();
    
    if (!user) {
      console.log('❌ User not found in database');
      console.log('====================================\n');
      return res.json({
        success: false,
        message: 'User not found in database'
      });
    }
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + (OTP_EXPIRY_MINUTES * 60 * 1000);
    otpStore.set(email.toLowerCase(), { otp, expiresAt });
    
    console.log(`✅ Quick OTP generated: ${otp}`);
    console.log(`⏱️ Expires in: ${OTP_EXPIRY_MINUTES} minutes`);
    console.log('====================================\n');
    
    res.json({
      success: true,
      message: 'OTP generated (direct mode)',
      otp: otp,
      expiresIn: `${OTP_EXPIRY_MINUTES} minutes`,
      note: 'Use this OTP to reset password. Configure SendGrid for real emails.',
      emailStatus: {
        service: emailService.name,
        available: emailService.isAvailable,
        error: emailService.error,
        configured: !!process.env.SENDGRID_API_KEY
      },
      setupInstructions: emailService.isAvailable ? null : [
        '1. Get SendGrid API key from https://app.sendgrid.com',
        '2. Add to Render: SENDGRID_API_KEY=sg.your_key_here',
        '3. Add: EMAIL_FROM="Fresher Hub <your-email@gmail.com>"',
        '4. Redeploy and test with /api/test-email'
      ]
    });
    
  } catch (error) {
    console.error('❌ Error in quick OTP:', error.message);
    console.log('====================================\n');
    res.json({
      success: false,
      error: error.message
    });
  }
});

// ==================== YOUR EXISTING ROUTES (UNCHANGED) ====================
// [All your existing POST routes remain exactly the same]
// register, login, validate-session, logout, send-otp, verify-otp, reset-password
// Keep them as they are in your current code...

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
        body { font-family: Arial, sans-serif; padding: 40px; text-align: center; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; color: white; }
        .container { max-width: 600px; margin: 100px auto; background: rgba(255,255,255,0.1); padding: 40px; border-radius: 15px; backdrop-filter: blur(10px); }
        h1 { margin: 0 0 20px; font-size: 36px; }
        code { background: rgba(255,255,255,0.2); padding: 10px 15px; border-radius: 5px; font-family: monospace; }
        a { color: #ffd700; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>404 - Page Not Found</h1>
        <p>The requested URL <code>${req.path}</code> was not found.</p>
        <p><a href="/">← Go to Homepage</a></p>
        <p style="margin-top: 30px; font-size: 14px; opacity: 0.8;">
          Fresher Hub API is running. Try <a href="/api/health">/api/health</a> for status.
        </p>
      </div>
    </body>
    </html>
  `);
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 ========== FRESHER HUB SERVER STARTED ==========`);
  console.log(`🌐 Server running on port ${PORT}`);
  console.log(`🔗 Local: http://localhost:${PORT}`);
  console.log(`🔗 Production: https://fresher-resource-hub.onrender.com`);
  console.log(`\n📊 ========== DEBUG ENDPOINTS ==========`);
  console.log(`🏥 Health Check: https://fresher-resource-hub.onrender.com/api/health`);
  console.log(`🔍 Debug Email: https://fresher-resource-hub.onrender.com/api/debug-email`);
  console.log(`🧪 Test Email: https://fresher-resource-hub.onrender.com/api/test-email`);
  console.log(`📧 Test Specific: https://fresher-resource-hub.onrender.com/api/test-email?email=your-email@gmail.com`);
  console.log(`🔑 Quick OTP: https://fresher-resource-hub.onrender.com/api/quick-otp/test@example.com`);
  console.log(`\n📧 ========== EMAIL STATUS ==========`);
  console.log(`Service: ${emailService.name}`);
  console.log(`Available: ${emailService.isAvailable ? '✅ Yes' : '❌ No'}`);
  if (emailService.error) console.log(`Error: ${emailService.error}`);
  console.log(`Configured: ${process.env.SENDGRID_API_KEY ? '✅ Yes' : '❌ No'}`);
  console.log(`\n💾 Database: Supabase ✅`);
  console.log(`📁 SPA routing: ${distExists ? '✅ Enabled' : '❌ Disabled'}`);
  console.log(`========================================\n`);
});