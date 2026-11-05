'use strict';
const fs = require('node:fs');
const path = require('node:path');

const envFile = path.join(__dirname, '..', '.env');
if (fs.existsSync(envFile)) process.loadEnvFile(envFile);

const isProd = process.env.NODE_ENV === 'production';

function secret(name) {
  const value = process.env[name] || '';
  if (value.length < 32) {
    throw new Error(`${name} ausente ou curta demais (mínimo de 32 caracteres). Rode "npm run setup".`);
  }
  return value;
}

const appUrl = (process.env.APP_URL || 'http://localhost:3001').replace(/\/+$/, '');
if (isProd && !appUrl.startsWith('https://')) throw new Error('Em produção, APP_URL precisa começar com https://');

module.exports = Object.freeze({
  isProd,
  port: Number(process.env.PORT) || 3001,
  appUrl,
  appOrigin: new URL(appUrl).origin,
  jwtSecret: secret('JWT_SECRET'),
  dataKey: secret('DATA_ENCRYPTION_KEY'),
  dbPath: process.env.DB_PATH || path.join(__dirname, '..', 'data', 'plataforma.sqlite'),
  trustProxy: Number(process.env.TRUST_PROXY) || 0,
  bootstrapAdminEmail: process.env.BOOTSTRAP_ADMIN_EMAIL || '',
  bootstrapAdminPassword: process.env.BOOTSTRAP_ADMIN_PASSWORD || '',
  security: Object.freeze({
    accessMinutes: 10,        // validade do JWT de acesso
    preAuthMinutes: 5,        // tempo para concluir a etapa do 2FA
    traineeHours: 8,          // sessão do funcionário
    idleMinutes: 15,          // inatividade permitida
    maxSessionHours: 8,       // duração máxima da sessão
    maxAttempts: 5,           // tentativas antes do bloqueio
    lockMinutes: 15,          // duração do bloqueio
    minWatchRatio: 0.9        // parte da aula que precisa ter passado para concluí-la
  })
});
