// cryptoStore.js
// Хранилище пользователей с шифрованием AES-CBC, солью и MD4 KDF/хешем паролей
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

// ====== Чистая JS реализация MD4 (короткая, достаточная для учебной задачи) ======
function md4(buffer) {
  // принимает Buffer, возвращает Buffer(16)
  // Реализация компактная, ориентирована на совместимость; не для продакшена.
  function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
  function F(x, y, z) { return ((x & y) | (~x & z)) >>> 0; }
  function G(x, y, z) { return ((x & y) | (x & z) | (y & z)) >>> 0; }
  function H(x, y, z) { return (x ^ y ^ z) >>> 0; }
  function toWordsLE(buf) {
    const words = [];
    for (let i = 0; i < buf.length; i += 4) {
      words.push(buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16) | (buf[i+3] << 24));
    }
    return words;
  }
  function fromWordsLE(words) {
    const out = Buffer.allocUnsafe(words.length * 4);
    for (let i = 0; i < words.length; i++) {
      out[i*4] =  words[i]        & 0xff;
      out[i*4+1] = (words[i]>>>8) & 0xff;
      out[i*4+2] = (words[i]>>>16)& 0xff;
      out[i*4+3] = (words[i]>>>24)& 0xff;
    }
    return out;
  }

  const origLen = buffer.length;
  const bitLen = origLen * 8;

  // padding: 0x80 + zeros + length(64-bit LE)
  const padLen = (((56 - (origLen + 1)) % 64) + 64) % 64;
  const padded = Buffer.concat([
    buffer,
    Buffer.from([0x80]),
    Buffer.alloc(padLen, 0),
    Buffer.alloc(8, 0)
  ]);
  padded.writeUInt32LE(bitLen & 0xffffffff, padded.length - 8);
  padded.writeUInt32LE(Math.floor(bitLen / 0x100000000), padded.length - 4);

  let a = 0x67452301 >>> 0;
  let b = 0xefcdab89 >>> 0;
  let c = 0x98badcfe >>> 0;
  let d = 0x10325476 >>> 0;

  for (let i = 0; i < padded.length; i += 64) {
    const block = padded.subarray(i, i + 64);
    const X = toWordsLE(block);
    let aa = a, bb = b, cc = c, dd = d;

    // round 1
    const r1 = (k, s) => { a = rotl((a + F(b, c, d) + X[k]) >>> 0, s); [a,b,c,d] = [d,a,b,c]; };
    r1( 0, 3); r1( 1, 7); r1( 2,11); r1( 3,19);
    r1( 4, 3); r1( 5, 7); r1( 6,11); r1( 7,19);
    r1( 8, 3); r1( 9, 7); r1(10,11); r1(11,19);
    r1(12, 3); r1(13, 7); r1(14,11); r1(15,19);

    // round 2
    const r2 = (k, s) => { a = rotl((a + G(b, c, d) + X[k] + 0x5a827999) >>> 0, s); [a,b,c,d] = [d,a,b,c]; };
    r2( 0, 3); r2( 4, 5); r2( 8, 9); r2(12,13);
    r2( 1, 3); r2( 5, 5); r2( 9, 9); r2(13,13);
    r2( 2, 3); r2( 6, 5); r2(10, 9); r2(14,13);
    r2( 3, 3); r2( 7, 5); r2(11, 9); r2(15,13);

    // round 3
    const r3 = (k, s) => { a = rotl((a + H(b, c, d) + X[k] + 0x6ed9eba1) >>> 0, s); [a,b,c,d] = [d,a,b,c]; };
    r3( 0, 3); r3( 8, 9); r3( 4,11); r3(12,15);
    r3( 2, 3); r3(10, 9); r3( 6,11); r3(14,15);
    r3( 1, 3); r3( 9, 9); r3( 5,11); r3(13,15);
    r3( 3, 3); r3(11, 9); r3( 7,11); r3(15,15);

    a = (a + aa) >>> 0;
    b = (b + bb) >>> 0;
    c = (c + cc) >>> 0;
    d = (d + dd) >>> 0;
  }

  return fromWordsLE([a,b,c,d]);
}

function md4Hex(str) {
  return md4(Buffer.from(str, 'utf8')).toString('hex');
}

// ====== Формат файла и KDF ======
/*
Формат users.json.enc:
[5 байт "USRV1"][16 байт salt][16 байт IV][ciphertext...]
KDF: key = MD4(passphrase + salt) -> 16 байт (AES-128-CBC)
*/
const MAGIC = Buffer.from('USRV1');

function deriveKey(passphrase, salt) {
  const joined = Buffer.concat([Buffer.from(passphrase, 'utf8'), salt]);
  return md4(joined); // 16 bytes -> AES-128 key
}

function encryptUsers(passphrase, plainBuf) {
  const salt = crypto.randomBytes(16);
  const iv   = crypto.randomBytes(16);
  const key  = deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  const enc = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  return Buffer.concat([MAGIC, salt, iv, enc]);
}

function decryptUsers(passphrase, encBuf) {
  if (encBuf.length < MAGIC.length + 32) throw new Error('Encrypted file too short');
  if (!encBuf.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('Bad header');
  const salt = encBuf.subarray(MAGIC.length, MAGIC.length + 16);
  const iv   = encBuf.subarray(MAGIC.length + 16, MAGIC.length + 32);
  const data = encBuf.subarray(MAGIC.length + 32);
  const key  = deriveKey(passphrase, salt);
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ====== Путь временного файла ======
const TEMP_USERS_FILE = path.join(os.tmpdir(), `users_${process.pid}.json`);
const ENC_USERS_FILE  = path.join(process.cwd(), 'users.json.enc');

function wipeFileSafe(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      const size = fs.statSync(filePath).size;
      // простая перезапись нулями (для учебной задачи)
      const zeros = Buffer.alloc(size, 0);
      fs.writeFileSync(filePath, zeros);
      fs.unlinkSync(filePath);
    }
  } catch (_) { /* ignore */ }
}

function ensureDecryptedOnStart(passphrase) {
  // Если зашифрованного нет — создаём с ADMIN и пустым паролем
  if (!fs.existsSync(ENC_USERS_FILE)) {
    const initial = {
      "ADMIN": { password: "", isBlocked: false, passwordRestrictions: true }
    };
    const enc = encryptUsers(passphrase, Buffer.from(JSON.stringify(initial, null, 2), 'utf8'));
    fs.writeFileSync(ENC_USERS_FILE, enc);
  }

  // Расшифровка → во временный
  const encBuf = fs.readFileSync(ENC_USERS_FILE);
  let plain;
  try {
    plain = decryptUsers(passphrase, encBuf);
  } catch (e) {
    throw new Error('Неверная парольная фраза или повреждён файл (расшифровка не удалась).');
  }

  // Проверка: JSON и наличие ADMIN
  let obj;
  try {
    obj = JSON.parse(plain.toString('utf8'));
  } catch {
    throw new Error('Расшифрованные данные не являются корректным JSON.');
  }
  if (!obj.ADMIN) {
    throw new Error('В расшифрованном файле отсутствует учетная запись ADMIN. Парольная фраза неверна.');
  }

  // Пишем во временный, чтобы вся работа шла с ним
  fs.writeFileSync(TEMP_USERS_FILE, JSON.stringify(obj, null, 2));
  return TEMP_USERS_FILE;
}

function saveAndReencrypt(passphrase) {
  if (!fs.existsSync(TEMP_USERS_FILE)) return;
  const plain = fs.readFileSync(TEMP_USERS_FILE);
  const enc = encryptUsers(passphrase, plain);
  fs.writeFileSync(ENC_USERS_FILE, enc);
  wipeFileSafe(TEMP_USERS_FILE);
}

module.exports = {
  TEMP_USERS_FILE,
  ENC_USERS_FILE,
  ensureDecryptedOnStart,
  saveAndReencrypt,
  md4Hex,
  wipeFileSafe
};