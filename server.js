const express = require('express');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;
const USERS_FILE = 'users.json';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'user-management-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 1800000 } // 30 минут
}));

// Статические файлы
app.use(express.static(path.join(__dirname, 'public')));

// Загрузка пользователей из файла
function loadUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      // Создаем файл с администратором по умолчанию
      const defaultUsers = {
        "ADMIN": {
          "password": "",
          "isBlocked": false,
          "passwordRestrictions": true
        }
      };
      fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
      return defaultUsers;
    }
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Ошибка загрузки пользователей:', error);
    return {};
  }
}

// Сохранение пользователей в файл
function saveUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    return true;
  } catch (error) {
    console.error('Ошибка сохранения пользователей:', error);
    return false;
  }
}

// Проверка ограничений пароля
function validatePassword(username, password) {
  // Ограничение 5: Наличие цифр и знаков препинания
  const hasDigit = /\d/.test(password);
  const hasPunctuation = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
  
  if (!hasDigit || !hasPunctuation) {
    return {
      valid: false,
      message: 'Пароль должен содержать хотя бы 1 цифру и 1 знак препинания'
    };
  }
  
  return { valid: true };
}

// Хеширование пароля
async function hashPassword(password) {
  if (password === '') return '';
  return await bcrypt.hash(password, 10);
}

// Проверка пароля
async function verifyPassword(password, hashedPassword) {
  if (hashedPassword === '' && password === '') return true;
  if (hashedPassword === '') return false;
  return await bcrypt.compare(password, hashedPassword);
}

// Главная страница
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Вход в систему
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();

  if (!users[username]) {
    return res.json({ 
      success: false, 
      message: 'Пользователь не найден в системе' 
    });
  }

  const user = users[username];
  
  if (user.isBlocked) {
    return res.json({ 
      success: false, 
      message: 'Учетная запись заблокирована' 
    });
  }

  // Инициализация счетчика попыток
  if (!req.session.loginAttempts) {
    req.session.loginAttempts = {};
  }
  if (!req.session.loginAttempts[username]) {
    req.session.loginAttempts[username] = 0;
  }

  const passwordMatch = await verifyPassword(password, user.password);
  
  if (!passwordMatch) {
    req.session.loginAttempts[username]++;
    
    if (req.session.loginAttempts[username] >= 3) {
      return res.json({ 
        success: false, 
        message: 'Превышено количество попыток ввода пароля. Работа завершена.',
        terminate: true
      });
    }
    
    return res.json({ 
      success: false, 
      message: `Неверный пароль. Осталось попыток: ${3 - req.session.loginAttempts[username]}` 
    });
  }

  // Успешный вход
  req.session.loginAttempts[username] = 0;
  req.session.user = username;
  req.session.isAdmin = username === 'ADMIN';
  req.session.needPasswordChange = user.password === '';

  res.json({ 
    success: true, 
    isAdmin: req.session.isAdmin,
    needPasswordChange: req.session.needPasswordChange
  });
});

// Смена пароля
app.post('/api/change-password', async (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, message: 'Не авторизован' });
  }

  const { oldPassword, newPassword, confirmPassword } = req.body;
  const users = loadUsers();
  const user = users[req.session.user];

  if (!req.session.needPasswordChange) {
    const oldPasswordMatch = await verifyPassword(oldPassword, user.password);
    if (!oldPasswordMatch) {
      return res.json({ success: false, message: 'Неверный старый пароль' });
    }
  }

  if (newPassword !== confirmPassword) {
    return res.json({ success: false, message: 'Пароли не совпадают' });
  }

  if (user.passwordRestrictions) {
    const validation = validatePassword(req.session.user, newPassword);
    if (!validation.valid) {
      return res.json({ success: false, message: validation.message });
    }
  }

  user.password = await hashPassword(newPassword);
  
  if (saveUsers(users)) {
    req.session.needPasswordChange = false;
    res.json({ success: true, message: 'Пароль успешно изменен' });
  } else {
    res.json({ success: false, message: 'Ошибка сохранения пароля' });
  }
});

// Получение списка пользователей (только для админа)
app.get('/api/users', (req, res) => {
  if (!req.session.isAdmin) {
    return res.json({ success: false, message: 'Доступ запрещен' });
  }

  const users = loadUsers();
  const userList = Object.keys(users).map(username => ({
    username,
    isBlocked: users[username].isBlocked,
    passwordRestrictions: users[username].passwordRestrictions,
    hasPassword: users[username].password !== ''
  }));

  res.json({ success: true, users: userList });
});

// Добавление пользователя (только для админа)
app.post('/api/add-user', (req, res) => {
  if (!req.session.isAdmin) {
    return res.json({ success: false, message: 'Доступ запрещен' });
  }

  const { username } = req.body;
  const users = loadUsers();

  if (users[username]) {
    return res.json({ success: false, message: 'Пользователь уже существует' });
  }

  users[username] = {
    password: '',
    isBlocked: false,
    passwordRestrictions: true
  };

  if (saveUsers(users)) {
    res.json({ success: true, message: 'Пользователь добавлен' });
  } else {
    res.json({ success: false, message: 'Ошибка сохранения' });
  }
});

// Управление блокировкой пользователя (только для админа)
app.post('/api/toggle-block', (req, res) => {
  if (!req.session.isAdmin) {
    return res.json({ success: false, message: 'Доступ запрещен' });
  }

  const { username } = req.body;
  const users = loadUsers();

  if (!users[username]) {
    return res.json({ success: false, message: 'Пользователь не найден' });
  }

  if (username === 'ADMIN') {
    return res.json({ success: false, message: 'Нельзя заблокировать администратора' });
  }

  users[username].isBlocked = !users[username].isBlocked;

  if (saveUsers(users)) {
    const status = users[username].isBlocked ? 'заблокирован' : 'разблокирован';
    res.json({ success: true, message: `Пользователь ${status}` });
  } else {
    res.json({ success: false, message: 'Ошибка сохранения' });
  }
});

// Управление ограничениями пароля (только для админа)
app.post('/api/toggle-restrictions', (req, res) => {
  if (!req.session.isAdmin) {
    return res.json({ success: false, message: 'Доступ запрещен' });
  }

  const { username } = req.body;
  const users = loadUsers();

  if (!users[username]) {
    return res.json({ success: false, message: 'Пользователь не найден' });
  }

  users[username].passwordRestrictions = !users[username].passwordRestrictions;

  if (saveUsers(users)) {
    const status = users[username].passwordRestrictions ? 'включены' : 'отключены';
    res.json({ success: true, message: `Ограничения пароля ${status}` });
  } else {
    res.json({ success: false, message: 'Ошибка сохранения' });
  }
});

// Выход из системы
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Проверка статуса сессии
app.get('/api/status', (req, res) => {
  res.json({
    authenticated: !!req.session.user,
    username: req.session.user,
    isAdmin: req.session.isAdmin,
    needPasswordChange: req.session.needPasswordChange
  });
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
  console.log('Для входа используйте: ADMIN с пустым паролем');
});