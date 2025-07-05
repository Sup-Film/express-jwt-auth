const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ฐานข้อมูลจำลอง
const users = [
  {
    id: 1,
    username: 'user1',
    password: '$2b$10$EIX/5Z7z5Q8e3f9j6F4uUO0m5k5h5k5h5k5h5k5h5k5h5k5h5k5h', // hashed password for 'password123'
  },
]

// @desc    Register a new user
// @route   POST /api/auth/signup
exports.signup = async (req, res) => {
  try {
    // ใช้การ Destructuring เพื่อดึงข้อมูล username และ password จาก req.body
    const { username, password } = req.body;

    // 1. ตรวจสอบ Input
    if (!username || !password) {
      return res.status(400).json({ message: 'กรุณากรอก Username และ Password' });
    }

    // 2. เช็คว่ามี username นี้ในระบบหรือยัง
    const existingUser = users.find(user => user.username === username);
    if (existingUser) {
      return res.status(409).json({ message: 'Username นี้มีผู้ใช้งานแล้ว' })
    }

    // 3. เข้ารหัสรหัสผ่าน (Hashing)
    const hashedPassword = await bcrypt.hash(password, 10)

    // 4. สร้างผู้ใช้ใหม่
    const newUser = { id: users.length + 1, username: username, password: hashedPassword };
    users.push(newUser);

    console.log('Users in DB:', users);
    res.status(201).json({ message: 'ลงทะเบียนสำเร็จ' });
  } catch (error) {
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในระบบ', error: error.message });
  }
}

exports.signin = async (req, res) => {
  try {
    const { username, password } = req.body

    // 1. ตรวจสอบ Input
    if (!username || !password) {
      return res.status(400).json({ message: 'กรุณากรอก Username และ Password' });
    }

    // 2. ค้นหาผู้ใช้ในระบบ
    const user = users.find(u => u.username === username)
    if (!user) {
      return res.status(401).json({ message: "ไม่พบผู้ใช้ในระบบ" })
    }

    // 3. เปรียบเทียบรหัสผ่านที่ส่งมากับรหัสผ่านที่ถูกเข้ารหัสไว้
    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.status(401).json({ message: "รหัสผ่านไม่ถูกต้องกรุณาลองใหม่" })
    }

    // 4. สร้าง JWT Payload
    const payload = {
      id: user.id,
      username: user.username
    };

    // 5. สร้าง Access Token (อายุสั้น)
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: '15m' // Token หมดอายุใน 15 นาที
    })

    // 5.1 สร้าง Refresh Token (อายุยาว)
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
      expiresIn: '7d' // Token หมดอายุใน 7 วัน
    })

    // 5.2 เก็บ Refresh Token ในฐานข้อมูล (ในที่นี้ใช้ตัวแปร users จำลอง)
    user.refreshToken = refreshToken; // เก็บ Refresh Token ในผู้ใช้

    // 6. ส่ง Token กลับไปในรูปแบบ httpOnly Cookie (Best Practice)
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 วัน
    })

    res.status(200).json({
      message: 'เข้าสู่ระบบสำเร็จ',
      user: payload,
      accessToken: accessToken // ส่ง Access Token กลับไปด้วย
    });
  } catch (error) {
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในระบบ', error: error.message });
  }
}

exports.refreshToken = (req, res) => {
  // 1. ดึง Refresh Token จาก Cookie
  const refreshToken = req.cookies.refreshToken;

  // 2. เช็คว่ามี Refresh Token หรือไม่
  if (!refreshToken) return res.status(401).json({ message: 'Unauthorized: No refresh token provided' });

  // 3. ค้นหาผู้ใช้จาก Refresh Token ที่มีในฐานข้อมูล
  const user = user.find(u => u.refreshToken === refreshToken);
  if (!user) return res.status(403).json({ message: 'Forbidden: Invalid refresh token' });

  // 4. ตรวจสอบความถูกต้องของ Refresh Token
  jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
    if (err || user.id !== decoded.id) {
      return res.status(403).json({ message: 'Forbidden: Invalid refresh token' });
    }

    // 5. ถ้าทุกอย่างถูกต้อง, สร้าง Access Token ใหม่
    const accessToken = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '15m' } // Token หมดอายุใน 15 นาที
    );

    res.status(200).json({ accessToken })
  })
}

// @desc    Get user profile
// @route   GET /api/auth/profile
exports.getProfile = (req, res) => {
  // ข้อมูล user จะถูกแนบมาจาก authMiddleware
  res.status(200).json({
    message: "เข้าถึงข้อมูลส่วนตัวสำเร็จ",
    user: req.user
  })
};

// @desc    Log user out
// @route   POST /api/auth/signout
exports.signout = (req, res) => {
  // 1. ดึง Refresh Token จาก Cookie
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.sendStatus(204); // No content, ไม่มีอะไรให้ทำ

  // 2. ลบ RefreshToken ออกจากฐานข้อมูลของผู้ใช้
  const user = users.find(u => u.refreshToken === refreshToken)
  if (user) {
    user.refreshToken = null;
  }

  // 3. ลบ Cookie ที่ฝั่ง Client
  res.clearCookies('refreshToken', { httpOnly: true, sameSite: 'strict', secure: true });

  res.status(200).json({ message: 'ออกจากระบบสำเร็จ' });
};