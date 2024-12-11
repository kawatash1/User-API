const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true, 
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
  },
  email: {
    type: String,
    required: true,
    unique: true,  
    match: [/\S+@\S+\.\S+/, 'Please enter a valid email address'],
  },
  password: {
    type: String,
    required: true,
    minlength: [6, 'The password must contain at least 6 characters'],
  },
  refreshToken: {
    type: String,
    default: null,  // Значение по умолчанию, если refreshToken не установлен
  },
}, { timestamps: true });  // timestamps добавляет поля createdAt и updatedAt

// Хэширование пароля перед сохранением пользователя
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
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
    throw new Error('Error checking password');
  }
};

// Экспортируем модель
module.exports = mongoose.model('User', userSchema);
