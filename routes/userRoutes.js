const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('C:/Users/madks/Documents/FullStack/Project 2/models/User.js');
const bcrypt = require('bcryptjs');
const authenticateToken = require('C:/Users/madks/Documents/FullStack/Project 2/utils/authMiddleware.js'); 
const router = express.Router();

const Joi = require('joi');

const registerSchema = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});



// 1. (POST /register)
router.post('/register', async (req, res, next) => {
  const { error } = registerSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists.' });
    }

    const newUser = new User({ username, email, password });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    next(error); 
  }
});

// 2. (POST /login)
router.post('/login', async (req, res, next) => {
  const { error } = loginSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: 'Invalid password.' });
    }

    // Generating accessToken and refreshToken
    const accessToken = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ _id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

    // Saving refreshToken in database
    user.refreshToken = refreshToken;
    await user.save();

    // Ответ с токенами
    res.status(200).json({
      accessToken,        // sending accessToken
      refreshToken,       // sending refreshToken
      message: 'Successful login!'
    });
  } catch (error) {
    next(error); 
  }
});

// 3. (GET /profile)
router.get('/profile', authenticateToken, async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('username email');
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json({
      username: user.username,
      email: user.email,
    });
  } catch (error) {
    next(error);
  }
});


// 4. (PUT /profile)
router.put('/profile', authenticateToken, async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (username) user.username = username;
    if (email) user.email = email;
    if (password) user.password = await bcrypt.hash(password, 10);

    await user.save();

    res.status(200).json({ message: 'Profile updated successfully!' });
  }  catch (error) {
    next(error); // Passing an error to a centralized handler
  }
});

// 5. (DELETE /profile)
router.delete('/profile', authenticateToken, async (req, res) => {
  try {
    // Удаляем пользователя по ID из токена
    const user = await User.findByIdAndDelete(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json({ message: 'User deleted successfully!' });
  } catch (error) {
    next(error); // Passing an error to a centralized handler
  }
});

// 6. (POST /logout)
router.post('/logout', async (req, res, next) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).json({ message: 'No Refresh token.' });
  }

  try {
    const user = await User.findOneAndUpdate({ refreshToken }, { refreshToken: null });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json({ message: 'You have successfully logged out.' });
  } catch (error) {
    next(error); 
  }
});

router.post('/refresh-token', async (req, res, next) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).json({ message: 'No Refresh token.' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded._id);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ message: 'Incorrect refresh token.' });
    }

    // Generating new access token
    const accessToken = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    res.status(200).json({ accessToken });
  } catch (error) {
    next(error);
  }
});


router.get('/debug/users', async (req, res) => {
  try {
    const users = await User.find(); // getting all users
    // console.log('User List from database:', users); 
    res.status(200).json(users); // sending to client
  }  catch (error) {
      // console.error('Error getting users:', error.message);
      next(error); // Passing an error to a centralized handler
  }
});

module.exports = router;
