require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'secretcoder_secret_key';

// ─── Middleware ───────────────────────────────────────────────
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB Error:', err.message);
    process.exit(1);
  });

// ─── File Helpers ─────────────────────────────────────────────
const FILES = {
  users: path.join(__dirname, 'users.json'),
  enrollments: path.join(__dirname, 'enrollments.json'),
  contacts: path.join(__dirname, 'contacts.json'),
};

function readFile(file) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, '[]');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeFile(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ─── Auth Middleware ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied. No token.' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ message: 'Invalid or expired token.' });
  }
}

// ─── Routes ───────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({ message: 'SecretCoder Backend Running ✓', status: 'ok' });
});

// ── SIGNUP ────────────────────────────────────────────────────
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ message: 'All fields are required.' });

    if (password.length < 6)
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });

    const users = readFile(FILES.users);
    const exists = users.find(u => u.email === email.toLowerCase());
    if (exists)
      return res.status(400).json({ message: 'Email already registered.' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: Date.now().toString(),
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    writeFile(FILES.users, users);

    const token = jwt.sign({ id: newUser.id, email: newUser.email, name: newUser.name }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'Signup successful! Welcome to SecretCoder.',
      token,
      user: { id: newUser.id, name: newUser.name, email: newUser.email }
    });

  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── LOGIN ─────────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: 'Email and password are required.' });

    const users = readFile(FILES.users);
    const user = users.find(u => u.email === email.toLowerCase());
    if (!user)
      return res.status(400).json({ message: 'No account found with this email.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ message: 'Incorrect password.' });

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful! Welcome back.',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── GET PROFILE (protected) ───────────────────────────────────
app.get('/profile', authMiddleware, (req, res) => {
  const users = readFile(FILES.users);
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found.' });
  res.json({ user: { id: user.id, name: user.name, email: user.email, createdAt: user.createdAt } });
});

// ── ENROLL ────────────────────────────────────────────────────
app.post('/enroll', authMiddleware, (req, res) => {
  try {
    const { course } = req.body;
    if (!course)
      return res.status(400).json({ message: 'Course name is required.' });

    const enrollments = readFile(FILES.enrollments);

    const alreadyEnrolled = enrollments.find(
      e => e.userId === req.user.id && e.course === course
    );
    if (alreadyEnrolled)
      return res.status(400).json({ message: `You are already enrolled in "${course}".` });

    const enrollment = {
      id: Date.now().toString(),
      userId: req.user.id,
      userName: req.user.name,
      userEmail: req.user.email,
      course,
      enrolledAt: new Date().toISOString()
    };

    enrollments.push(enrollment);
    writeFile(FILES.enrollments, enrollments);

    res.json({
      success: true,
      message: `Successfully enrolled in "${course}"!`,
      enrollment
    });

  } catch (err) {
    console.error('Enroll error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── GET MY ENROLLMENTS (protected) ───────────────────────────
app.get('/my-enrollments', authMiddleware, (req, res) => {
  const enrollments = readFile(FILES.enrollments);
  const myEnrollments = enrollments.filter(e => e.userId === req.user.id);
  res.json({ enrollments: myEnrollments });
});

// ── CONTACT FORM ──────────────────────────────────────────────
app.post('/contact', (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !subject || !message)
      return res.status(400).json({ message: 'All fields are required.' });

    const contacts = readFile(FILES.contacts);

    const contact = {
      id: Date.now().toString(),
      name: name.trim(),
      email: email.toLowerCase().trim(),
      subject: subject.trim(),
      message: message.trim(),
      receivedAt: new Date().toISOString()
    };

    contacts.push(contact);
    writeFile(FILES.contacts, contacts);

    res.json({ success: true, message: 'Message received! We will get back to you soon.' });

  } catch (err) {
    console.error('Contact error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── ALL USERS (admin debug) ───────────────────────────────────
app.get('/users', (req, res) => {
  const users = readFile(FILES.users);
  const safe = users.map(({ password, ...rest }) => rest);
  res.json({ count: safe.length, users: safe });
});

// ── ALL ENROLLMENTS (admin debug) ────────────────────────────
app.get('/enrollments', (req, res) => {
  const enrollments = readFile(FILES.enrollments);
  res.json({ count: enrollments.length, enrollments });
});

// ── ALL CONTACTS (admin debug) ────────────────────────────────
app.get('/contacts', (req, res) => {
  const contacts = readFile(FILES.contacts);
  res.json({ count: contacts.length, contacts });
});

// ─── Start Server ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ SecretCoder Backend running on http://localhost:${PORT}`);
  console.log(`   Routes ready:`);
  console.log(`   GET  /              → Health check`);
  console.log(`   POST /signup        → Register new user`);
  console.log(`   POST /login         → Login user`);
  console.log(`   GET  /profile       → Get profile (auth required)`);
  console.log(`   POST /enroll        → Enroll in course (auth required)`);
  console.log(`   GET  /my-enrollments→ My courses (auth required)`);
  console.log(`   POST /contact       → Send contact message`);
  console.log(`   GET  /users         → All users (admin)`);
  console.log(`   GET  /enrollments   → All enrollments (admin)`);
  console.log(`   GET  /contacts      → All messages (admin)\n`);
});
