import express from 'express';
import bcrypt from 'bcryptjs';
import { supabase } from './supabase.js'; // Your supabase config

const router = express.Router();

// Register endpoint
router.post('/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    const { data, error } = await supabase
      .from('Registered')
      .insert([{ 
        FullName: fullName, 
        Email: email, 
        Password: hashedPassword,
        role: 'user' 
      }]);
      
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login endpoint
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const { data: user, error } = await supabase
      .from('Registered')
      .select('*')
      .eq('Email', email)
      .single();
      
    if (error || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isValid = await bcrypt.compare(password, user.Password);
    
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    res.json({ 
      success: true, 
      user: {
        id: user.id,
        FullName: user.FullName,
        Email: user.Email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;