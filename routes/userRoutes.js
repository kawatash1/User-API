const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('C:/Users/madks/Documents/FullStack/Project 2/models/User.js');
const bcrypt = require('bcryptjs');
const authenticateToken = require('C:/Users/madks/Documents/FullStack/Project 2/utils/authMiddleware.js'); // Подключаем middleware для аутентификации
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



// 1. Регистрация пользователя (POST /register)
router.post('/register', async (req, res, next) => {
  const { error } = registerSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Пользователь уже существует.' });
    }

    const newUser = new User({ username, email, password });
    await newUser.save();

    res.status(201).json({ message: 'Пользователь зарегистрирован успешно!' });
  } catch (error) {
    next(error); // Передача ошибки в централизованный обработчик
  }
});

// 2. Вход пользователя (POST /login)
router.post('/login', async (req, res, next) => {
  const { error } = loginSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден.' });
    }

    // Проверка пароля
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: 'Неверный пароль.' });
    }

    // Генерация accessToken и refreshToken
    const accessToken = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ _id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

    // Сохраняем refreshToken в базе данных
    user.refreshToken = refreshToken;
    await user.save();

    // Ответ с токенами
    res.status(200).json({
      accessToken,        // Отправляем accessToken
      refreshToken,       // Отправляем refreshToken
      message: 'Успешный вход в систему!'
    });
  } catch (error) {
    next(error); // Перехват ошибки и передача в централизованный обработчик
  }
});

// 3. Получение профиля пользователя (GET /profile)
router.get('/profile', authenticateToken, async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('username email');
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден.' });
    }

    res.status(200).json({
      username: user.username,
      email: user.email,
    });
  } catch (error) {
    next(error);
  }
});


// 4. Обновление пользователя (PUT /profile)
router.put('/profile', authenticateToken, async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Ищем пользователя по ID из токена
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден.' });
    }

    // Обновляем данные
    if (username) user.username = username;
    if (email) user.email = email;
    if (password) user.password = await bcrypt.hash(password, 10);

    await user.save();

    res.status(200).json({ message: 'Профиль обновлён успешно!' });
  }  catch (error) {
    next(error); // Passing an error to a centralized handler
  }
});

// 5. Удаление пользователя (DELETE /profile)
router.delete('/profile', authenticateToken, async (req, res) => {
  try {
    // Удаляем пользователя по ID из токена
    const user = await User.findByIdAndDelete(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден.' });
    }

    res.status(200).json({ message: 'Пользователь удалён успешно!' });
  } catch (error) {
    next(error); // Passing an error to a centralized handler
  }
});

// 6. Выход пользователя (POST /logout)
router.post('/logout', async (req, res, next) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token отсутствует.' });
  }

  try {
    // Находим пользователя по refresh token и обновляем его значение на null
    const user = await User.findOneAndUpdate({ refreshToken }, { refreshToken: null });
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден.' });
    }

    res.status(200).json({ message: 'Вы успешно вышли из системы.' });
  } catch (error) {
    next(error); // Перехват ошибки и передача в централизованный обработчик
  }
});

router.post('/refresh-token', async (req, res, next) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token отсутствует.' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded._id);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ message: 'Неверный refresh token.' });
    }

    // Генерация нового access token
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
