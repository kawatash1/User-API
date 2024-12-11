const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Определяем схему пользователя
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,  // Имя пользователя должно быть уникальным
    trim: true,
    minlength: [3, 'Имя пользователя должно быть не менее 3 символов'],
  },
  email: {
    type: String,
    required: true,
    unique: true,  // Электронная почта должна быть уникальной
    match: [/\S+@\S+\.\S+/, 'Введите правильный адрес электронной почты'], // Проверка формата почты
  },
  password: {
    type: String,
    required: true,
    minlength: [6, 'Пароль должен содержать не менее 6 символов'],
  },
  refreshToken: {
    type: String,
    default: null,  // Значение по умолчанию, если refreshToken не установлен
  },
}, { timestamps: true });  // timestamps добавляет поля createdAt и updatedAt

// Хэширование пароля перед сохранением пользователя
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next(); // Если пароль не изменился, продолжаем
  }

  // console.log('Password before hashing:', this.password); 
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  // console.log('Hashed password:', this.password); 
  next();
});

// Метод для проверки пароля
userSchema.methods.isPasswordValid = async function(password) {
  try {
    // Сравниваем введенный пароль с хэшированным в базе данных
    return await bcrypt.compare(password, this.password);
  } catch (err) {
    throw new Error('Ошибка при проверке пароля');
  }
};

// Экспортируем модель
module.exports = mongoose.model('User', userSchema);