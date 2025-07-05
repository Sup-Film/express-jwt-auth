require('dotenv').config(); // โหลด .env เข้าสู่ process.env
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/authRoutes');

const app = express();
const port = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: 'http://localhost:3000', // Frontend URL
  credentials: true, // Allow cookies to be sent
}));
app.use(express.json()); // สำหรับ Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // สำหรับ Parse URL-encoded bodies
app.use(cookieParser()); // สำหรับ Parse Cookies

app.get('/', (req, res) => {
  res.send('<h1>Welcome to Express JWT Auth API</h1>');
});

// Routes
app.use('/api/auth', authRoutes);

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`)
  console.log(`Press Ctrl+C to stop the server.`);
})