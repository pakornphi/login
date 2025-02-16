const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const pool = require('./db');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(bodyParser.json());

// API สำหรับการลงทะเบียน
app.post('/register', async (req, res) => {
  const { email, username, password, confirmPassword } = req.body;

  try {
      
      if (password !== confirmPassword) {
          console.log('Error: Passwords do not match'); 
          return res.status(400).json({ error: 'Passwords do not match' });
      }

     
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;
      if (!passwordRegex.test(password)) {
          console.log('Error: Password does not meet the requirements'); 
          return res.status(400).json({ 
              error: 'Password must include at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 6 characters long.' 
          });
      }

      
      const emailExists = await pool.query('SELECT * FROM register WHERE email = $1', [email]);
      const usernameExists = await pool.query('SELECT * FROM register WHERE username = $1', [username]);

      if (emailExists.rows.length > 0) {
          console.log(`Error: Email '${email}' already exists`); 
          return res.status(400).json({ error: 'Email already exists' });
      }

      if (usernameExists.rows.length > 0) {
          console.log(`Error: Username '${username}' already exists`); 
          return res.status(400).json({ error: 'Username already exists' });
      }

     
      const hashedPassword = await bcrypt.hash(password, 10);

      
      const result = await pool.query(
          'INSERT INTO register (email, username, password) VALUES ($1, $2, $3) RETURNING *',
          [email, username, hashedPassword]
      );

      console.log('User registered successfully:', result.rows[0]); 
      res.status(201).json({ message: 'User registered successfully!', user: result.rows[0] });
  } catch (err) {
      console.error('Error:', err.message); 
      res.status(500).json({ error: 'Internal server error' });
  }
});


// API สำหรับการเข้้าใช่้งาน
app.post('/login', async (req, res) => {
    console.log(`POST /login - Data received:`, req.body);

    const { username, password } = req.body;

    if (!username || !password) {
        console.log('Login failed: Missing username or password.');
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const result = await pool.query('SELECT * FROM register WHERE username = $1', [username]);

        if (result.rows.length === 0) {
            console.log(`Login failed: Username "${username}" not found.`);
            return res.status(400).json({ error: 'Username not found' });
        }

        const user = result.rows[0];

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            console.log(`Login failed: Invalid password for username "${username}".`);
            return res.status(400).json({ error: 'Invalid password' });
        }

        console.log(`Login successful for username: "${username}".`);
        res.status(200).json({ user: user });
    } catch (err) {
        console.error(`Error during login:`, err.message);
        res.status(500).json({ error: err.message });
    }
});

// เปิดใช้งานเซิร์ฟเวอร์
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
