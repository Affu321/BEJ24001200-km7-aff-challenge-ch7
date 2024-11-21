const express = require('express');
const AuthController = require('../controller/auth');

const router = express.Router();

router.post('/register', AuthController.register); 
router.post('/login', AuthController.login); 
router.get('/dashboard', AuthController.isAuthenticated, AuthController.dashboard); 
router.post('/forgot-password', AuthController.forgotPassword); 
router.post('/reset-password', AuthController.resetPassword); 

module.exports = router;
