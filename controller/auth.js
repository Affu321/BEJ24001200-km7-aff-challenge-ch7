const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const sendMail = require('../utils/mailer');
const cookie = require('cookie');

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    throw new Error('Missing environment variables: JWT_SECRET');
}

class AuthController {
    async register(req, res) {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        try {
            const existingUser = await prisma.user.findUnique({ where: { email } });

            if (existingUser) {
                // Kirim notifikasi menggunakan WebSocket
                const io = req.app.get('io'); // Ambil instance `io` dari app
                if (io) {
                    io.emit('notification', { message: 'Email already registered' });
                }

                return res.status(409).json({ message: 'Email already registered' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            await prisma.user.create({
                data: { email, password: hashedPassword },
            });

            res.redirect('/login');
        } catch (error) {
            console.error('Error during registration:', error.message);
            res.status(500).json({ message: 'An error occurred during registration' });
        }
    }
    // Login user
    async login(req, res) {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        try {
            const user = await prisma.user.findUnique({ where: { email } });

            if (!user || !(await bcrypt.compare(password, user.password))) {
                return res.status(401).json({ message: 'Email or password is incorrect' });
            }

            const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });

            // Set token in cookie
            res.setHeader(
                'Set-Cookie',
                cookie.serialize('token', token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    maxAge: 60 * 60, // 1 hour
                    path: '/',
                })
            );

            res.redirect('/dashboard'); // Redirect to dashboard after login
        } catch (error) {
            console.error('Error during login:', error.message);
            res.status(500).json({ message: 'An error occurred during login' });
        }
    }

    // Middleware: Protect dashboard
    isAuthenticated(req, res, next) {
        const token = req.cookies.token;

        if (!token) {
            return res.redirect('/login'); // Redirect to login if no token
        }

        try {
            jwt.verify(token, JWT_SECRET); // Verify token
            next(); // Proceed to dashboard
        } catch (error) {
            console.error('Invalid token:', error.message);
            return res.redirect('/login'); // Redirect to login if token is invalid
        }
    }

    // Dashboard
    async dashboard(req, res) {
        res.render('dashboard'); // Render the dashboard page
    }

    // Forgot Password
    async forgotPassword(req, res) {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }

        try {
            const user = await prisma.user.findUnique({ where: { email } });

            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '15m' });
            const resetUrl = `http://localhost:3000/reset-password?token=${token}`;

            try {
                await sendMail(
                    email,
                    'Reset Password',
                    `<p>Click <a href="${resetUrl}">here</a> to reset your password</p>`
                );
            } catch (emailError) {
                console.error('Error sending email:', emailError.message);
            }

            res.status(200).json({ message: 'Password reset link sent to your email' });
        } catch (error) {
            console.error('Error during forgot password:', error.message);
            res.status(500).json({ message: 'An error occurred during forgot password' });
        }
    }

    // Reset Password
    async resetPassword(req, res) {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ message: 'Token and new password are required' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ message: 'Password must be at least 8 characters' });
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET);

            const hashedPassword = await bcrypt.hash(newPassword, 10);

            await prisma.user.update({
                where: { id: decoded.id },
                data: { password: hashedPassword },
            });

            res.status(200).json({ message: 'Password updated successfully' });
        } catch (error) {
            console.error('Error during reset password:', error.message);
            res.status(400).json({ message: 'Invalid or expired token' });
        }
    }
}

module.exports = new AuthController();
