const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
  // 1. ดึง Token จาก Cookie
  const authHeader = req.headers.authorization || req.headers.Authorization;

  // 2.
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'ไม่ได้รับอนุญาต, รูปแบบ Token ไม่ถูกต้อง' });
  }

  // 2. ตรวจสอบว่า Header ถูกต้องหรือไม่ (ต้องมีและขึ้นต้นด้วย 'Bearer ')
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'ไม่ได้รับอนุญาต หรือรูปแบบ Token ไม่ถูกต้อง' });
  }

  // 3. แยกเอาเฉพาะส่วนของ Token ออกมา
  const token = authHeader.split(' ')[1];

  // 4. ตรวจสอบความถูกต้องของ Token
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    // หากมี Error (Token ไม่ถูกต้อง, หมดอายุ) ให้ส่ง 403 Forbidden
    if (err) {
      return res.status(403).json({ message: 'สิทธิ์การเข้าถึงถูกปฏิเสธ' });
    }

    // 5. หาก Token ถูกต้อง, แนบข้อมูลผู้ใช้ (payload) ไปกับ request แล้วไปขั้นตอนถัดไป
    req.user = decoded;
    next();
  });
}

module.exports = authMiddleware;