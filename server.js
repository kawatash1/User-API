const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv'); // Для работы с переменными окружения


require('dotenv').config(); // Загружаем переменные окружения из .env файла
const jwtSecret = process.env.JWT_SECRET; // Считываем JWT_SECRET из переменной окружения

// Загружаем переменные окружения
dotenv.config();

const app = express();

// Middleware
app.use(express.json()); // Для парсинга JSON в теле запросов
app.use(cors()); // Для разрешения кросс-доменных запросов
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 })); // 100 запросов за 15 минут

// Подключение маршрутов
const userRoutes = require('c:/Users/madks/Documents/FullStack/Project 2/routes/userRoutes');
app.use('/api/users', userRoutes); // Подключаем маршруты пользователей

// Подключение к базе данных MongoDB
const DB_URL = process.env.MONGO_URI; // Строка подключения к базе из переменной окружения
mongoose.connect(DB_URL)
  .then(() => console.log('MongoDB подключен'))
  .catch(err => console.error('Ошибка подключения к MongoDB:', err));


app.use((err, req, res, next) => {
  console.error('Ошибка:', err.message);
  res.status(err.status || 500).json({ message: err.message || 'Произошла ошибка сервера.' });
});

// Запуск сервера
const PORT = process.env.PORT || 5000; // Используем порт из переменной окружения или 5000 по умолчанию
app.get('/', (req, res) => {
  res.send('Сервер работает! 🚀');
});

app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});