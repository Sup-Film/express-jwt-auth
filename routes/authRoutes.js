const express = require("express");
const router = express.Router();
const { signup, signin, getProfile, signout } = require("../controller/authController");
const authMiddleware = require("../middleware/authMiddleware");

// Public routes
router.post('/signup', signup);
router.post('/signin', signin);
router.post('/signout', signout);

// Protected route
// ใช้ authMiddleware เพื่อตรวจสอบ Token ก่อนเข้าถึง route นี้
router.get('/profile', authMiddleware, getProfile);

module.exports = router;