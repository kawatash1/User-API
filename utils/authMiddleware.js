const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Извлекаем токен из заголовка

  if (!token) {
    return res.status(401).json({ message: 'No token' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user; // Делаем данные пользователя доступными для последующих маршрутов
    next();
  });
};

module.exports = authenticateToken;
