// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const session = require('express-session');

const {
  TEMP_USERS_FILE,
  ensureDecryptedOnStart,
  saveAndReencrypt,
  md4Hex,
  wipeFileSafe
} = require('./cryptoStore');

const app = express();
const PORT = 3000;

// ==== Парольная фраза (сеансовый ключ) ====
const MASTER_PASSPHRASE = process.env.MASTER_PASSPHRASE || '';
if (!MASTER_PASSPHRASE) {
  console.error('Ошибка: не задана переменная окружения MASTER_PASSPHRASE.');
  process.exit(1);
}

// При старте: расшифровываем в temp, валидируем ADMIN
let TEMP_FILE_PATH;
try {
  TEMP_FILE_PATH = ensureDecryptedOnStart(MASTER_PASSPHRASE);
  console.log('Файл пользователей расшифрован во временный:', TEMP_FILE_PATH);
} catch (e) {
  console.error(String(e));
  process.exit(1);
}

// ==== Middleware ====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'user-management-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 1800000 } // 30 мин
}));

// Статика
app.use(express.static(path.join(__dirname, 'public')));

// ==== Работа с временным открытым файлом ====
function loadUsers() {
  try {
    const data = fs.readFileSync(TEMP_FILE_PATH, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    console.error('Ошибка чтения временного файла:', e);
    return {};
  }
}

function saveUsers(users) {
  try {
    fs.writeFileSync(TEMP_FILE_PATH, JSON.stringify(users, null, 2));
    return true;
  } catch (e) {
    console.error('Ошибка записи временного файла:', e);
    return false;
  }
}

// Проверка ограничений пароля (как было)
function validatePassword(username, password) {
  const hasDigit = /\d/.test(password);
  const hasPunctuation = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
  if (!hasDigit || !hasPunctuation) {
    return { valid: false, message: 'Пароль должен содержать хотя бы 1 цифру и 1 знак препинания' };
  }
  return { valid: true };
}

// === MD4-хеширование пароля пользователя (по варианту) ===
function hashPasswordMD4(password) {
  if (password === '') return ''; // пустой (только для первичной ADMIN)
  return md4Hex(password);        // hex-строка длиной 32
}

function verifyPasswordMD4(password, stored) {
  if (stored === '' && password === '') return true;
  if (stored === '') return false;
  return md4Hex(password) === stored;
}

// ==== Маршруты ====
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Вход
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();

  if (!users[username]) {
    return res.json({ success: false, message: 'Пользователь не найден в системе' });
  }

  const user = users[username];
  if (user.isBlocked) {
    return res.json({ success: false, message: 'Учетная запись заблокирована' });
  }

  // счётчик попыток на сессию/пользователя
  if (!req.session.loginAttempts) req.session.loginAttempts = {};
  if (!req.session.loginAttempts[username]) req.session.loginAttempts[username] = 0;

  const ok = verifyPasswordMD4(password, user.password);
  if (!ok) {
    req.session.loginAttempts[username]++;
    if (req.session.loginAttempts[username] >= 3) {
      return res.json({ success: false, message: 'Превышено количество попыток ввода пароля. Работа завершена.', terminate: true });
    }
    return res.json({ success: false, message: `Неверный пароль. Осталось попыток: ${3 - req.session.loginAttempts[username]}` });
  }

  // успех
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
  if (!req.session.user) return res.json({ success: false, message: 'Не авторизован' });

  const { oldPassword, newPassword, confirmPassword } = req.body;
  const users = loadUsers();
  const user = users[req.session.user];

  if (!req.session.needPasswordChange) {
    if (!verifyPasswordMD4(oldPassword, user.password)) {
      return res.json({ success: false, message: 'Неверный старый пароль' });
    }
  }

  if (newPassword !== confirmPassword) {
    return res.json({ success: false, message: 'Пароли не совпадают' });
  }

  if (user.passwordRestrictions) {
    const validation = validatePassword(req.session.user, newPassword);
    if (!validation.valid) return res.json({ success: false, message: validation.message });
  }

  user.password = hashPasswordMD4(newPassword);

  if (saveUsers(users)) {
    req.session.needPasswordChange = false;
    res.json({ success: true, message: 'Пароль успешно изменен' });
  } else {
    res.json({ success: false, message: 'Ошибка сохранения пароля' });
  }
});

// Список пользователей (админ)
app.get('/api/users', (req, res) => {
  if (!req.session.isAdmin) return res.json({ success: false, message: 'Доступ запрещен' });

  const users = loadUsers();
  const userList = Object.keys(users).map(username => ({
    username,
    isBlocked: users[username].isBlocked,
    passwordRestrictions: users[username].passwordRestrictions,
    hasPassword: users[username].password !== ''
  }));

  res.json({ success: true, users: userList });
});

// Добавление (админ)
app.post('/api/add-user', (req, res) => {
  if (!req.session.isAdmin) return res.json({ success: false, message: 'Доступ запрещен' });

  const { username } = req.body;
  const users = loadUsers();

  if (users[username]) return res.json({ success: false, message: 'Пользователь уже существует' });

  users[username] = { password: '', isBlocked: false, passwordRestrictions: true };

  if (saveUsers(users)) res.json({ success: true, message: 'Пользователь добавлен' });
  else res.json({ success: false, message: 'Ошибка сохранения' });
});

// Блокировка (админ)
app.post('/api/toggle-block', (req, res) => {
  if (!req.session.isAdmin) return res.json({ success: false, message: 'Доступ запрещен' });

  const { username } = req.body;
  const users = loadUsers();
  if (!users[username]) return res.json({ success: false, message: 'Пользователь не найден' });
  if (username === 'ADMIN') return res.json({ success: false, message: 'Нельзя заблокировать администратора' });

  users[username].isBlocked = !users[username].isBlocked;

  if (saveUsers(users)) {
    const status = users[username].isBlocked ? 'заблокирован' : 'разблокирован';
    res.json({ success: true, message: `Пользователь ${status}` });
  } else res.json({ success: false, message: 'Ошибка сохранения' });
});

// Ограничения пароля (админ)
app.post('/api/toggle-restrictions', (req, res) => {
  if (!req.session.isAdmin) return res.json({ success: false, message: 'Доступ запрещен' });

  const { username } = req.body;
  const users = loadUsers();
  if (!users[username]) return res.json({ success: false, message: 'Пользователь не найден' });

  users[username].passwordRestrictions = !users[username].passwordRestrictions;

  if (saveUsers(users)) {
    const status = users[username].passwordRestrictions ? 'включены' : 'отключены';
    res.json({ success: true, message: `Ограничения пароля ${status}` });
  } else res.json({ success: false, message: 'Ошибка сохранения' });
});

// Logout / статус
app.post('/api/logout', (req, res) => { req.session.destroy(()=>{}); res.json({ success: true }); });
app.get('/api/status', (req, res) => {
  res.json({
    authenticated: !!req.session.user,
    username: req.session.user,
    isAdmin: req.session.isAdmin,
    needPasswordChange: req.session.needPasswordChange
  });
});

// ==== Корректное завершение: перешифровка и удаление временного ====
function shutdown() {
  try {
    saveAndReencrypt(MASTER_PASSPHRASE);
  } finally {
    wipeFileSafe(TEMP_USERS_FILE);
    process.exit(0);
  }
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('exit', () => {
  try { saveAndReencrypt(MASTER_PASSPHRASE); } catch (_) {}
  try { wipeFileSafe(TEMP_USERS_FILE); } catch (_) {}
});

// ==== Запуск ====
app.listen(PORT, () => {
  console.log(`Сервер: http://localhost:${PORT}`);
  console.log('Вход по умолчанию: ADMIN с пустым паролем (после первого запуска установите пароль).');
});
