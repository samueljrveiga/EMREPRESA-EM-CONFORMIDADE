'use strict';
/* Criptografia em repouso (AES-256-GCM), índices cegos e hash de senha. */
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const config = require('../config');

const scrypt = promisify(crypto.scrypt);
const SCRYPT = { N: 2 ** 16, r: 8, p: 2, maxmem: 256 * 1024 * 1024 };
const VERSION = 'v1';

// Chaves independentes derivadas da chave mestra: uma para cifrar, outra para buscar.
const subkey = info => Buffer.from(crypto.hkdfSync('sha256', config.dataKey, 'em-conformidade', info, 32));
const ENC_KEY = subkey('data-encryption-v1');
const IDX_KEY = subkey('blind-index-v1');

const b64 = buf => Buffer.from(buf).toString('base64url');

/* `aad` amarra o valor cifrado à sua coluna e linha: copiar um valor
   cifrado para outro registro faz a leitura falhar. */
function encrypt(plain, aad) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  cipher.setAAD(Buffer.from(aad));
  const data = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return [VERSION, b64(iv), b64(data), b64(cipher.getAuthTag())].join('.');
}

function decrypt(value, aad) {
  const [version, iv, data, tag] = String(value).split('.');
  if (version !== VERSION || !iv || data === undefined || !tag) throw new Error('Valor cifrado inválido');
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(data, 'base64url')), decipher.final()]).toString('utf8');
}

/* Permite procurar por igualdade (ex: e-mail) sem guardar o valor aberto. */
function blindIndex(value, context) {
  return crypto.createHmac('sha256', IDX_KEY).update(`${context}\0${value}`).digest('hex');
}

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const newId = prefix => `${prefix}_${crypto.randomBytes(15).toString('hex')}`;

function safeEqualHex(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password.normalize('NFKC'), salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${b64(salt)}$${b64(hash)}`;
}

async function verifyPassword(stored, password) {
  const [kind, N, r, p, salt, hash] = String(stored).split('$');
  if (kind !== 'scrypt') return false;
  const expected = Buffer.from(hash, 'base64url');
  const actual = await scrypt(password.normalize('NFKC'), Buffer.from(salt, 'base64url'), expected.length,
    { N: Number(N), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem });
  return crypto.timingSafeEqual(actual, expected);
}

// Hash fixo usado quando o e-mail não existe, para o tempo de resposta não revelar quem é cadastrado.
let dummy;
const dummyHash = async () => (dummy ||= await hashPassword(randomToken()));

function temporaryPassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  return Array.from({ length: 18 }, () => alphabet[crypto.randomInt(alphabet.length)]).join('');
}

module.exports = {
  encrypt, decrypt, blindIndex, sha256, randomToken, newId, safeEqualHex,
  hashPassword, verifyPassword, dummyHash, temporaryPassword
};
