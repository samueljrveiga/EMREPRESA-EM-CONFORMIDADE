'use strict';
/* Cria o arquivo .env com chaves aleatórias. Nunca sobrescreve um .env existente. */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const target = path.join(__dirname, '..', '.env');
if (fs.existsSync(target)) { console.log('.env já existe; nada foi alterado.'); process.exit(0); }
const key = () => crypto.randomBytes(48).toString('base64url');
const env = fs.readFileSync(path.join(__dirname, '..', '.env.example'), 'utf8')
  .replace('JWT_SECRET=', `JWT_SECRET=${key()}`)
  .replace('DATA_ENCRYPTION_KEY=', `DATA_ENCRYPTION_KEY=${key()}`);
fs.writeFileSync(target, env, { mode: 0o600 });
console.log('.env criado. Guarde uma cópia de DATA_ENCRYPTION_KEY em local seguro: sem ela os dados não podem ser lidos.');
