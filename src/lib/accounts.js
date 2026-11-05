'use strict';
const db = require('./db');
const { encrypt, decrypt, blindIndex, hashPassword, temporaryPassword, newId, randomToken } = require('./crypto');
const { audit } = require('./audit');

const emailIdx = email => blindIndex(email.toLowerCase(), 'user-email');
const userEmail = user => decrypt(user.email_enc, `users.email:${user.id}`);
const findByEmail = email => db.get('SELECT * FROM users WHERE email_idx = ?', emailIdx(email));
const findUser = id => db.get('SELECT * FROM users WHERE id = ?', id);

async function createUser({ role, companyId = null, email, password }) {
  const id = newId('usr');
  const temp = password || temporaryPassword();
  db.run(`INSERT INTO users (id, role, company_id, email_enc, email_idx, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    id, role, companyId, encrypt(email, `users.email:${id}`), emailIdx(email), await hashPassword(temp), new Date().toISOString());
  return { id, temporaryPassword: temp };
}

/* Redefinição feita pelo administrador: senha provisória nova, 2FA refeito e sessões encerradas. */
async function resetCredentials(userId) {
  const temp = temporaryPassword();
  const hash = await hashPassword(temp);
  db.tx(() => {
    db.run(`UPDATE users SET password_hash = ?, must_change_password = 1, totp_enabled = 0, totp_secret_enc = NULL,
            totp_last_step = 0, failed_attempts = 0, locked_until = 0 WHERE id = ?`, hash, userId);
    db.run('DELETE FROM recovery_codes WHERE user_id = ?', userId);
    db.run('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL', Date.now(), userId);
  });
  return temp;
}

const linkAad = id => `companies.link:${id}`;
const companyName = row => decrypt(row.name_enc, `companies.name:${row.id}`);
const companyLink = row => decrypt(row.link_token_enc, linkAad(row.id));
const linkIdx = token => blindIndex(token, 'company-link');
const findCompany = id => db.get('SELECT * FROM companies WHERE id = ? AND deleted_at IS NULL', id);
const findCompanyByLink = token => db.get('SELECT * FROM companies WHERE link_token_idx = ? AND deleted_at IS NULL', linkIdx(token));
const listCompanies = () => db.all('SELECT * FROM companies WHERE deleted_at IS NULL ORDER BY created_at');

function setCompanyLink(id) {
  const token = randomToken(32);
  db.run('UPDATE companies SET link_token_enc = ?, link_token_idx = ? WHERE id = ?', encrypt(token, linkAad(id)), linkIdx(token), id);
  return token;
}

function createCompany(name) {
  const id = newId('emp');
  const token = randomToken(32);
  db.run('INSERT INTO companies (id, name_enc, link_token_enc, link_token_idx, created_at) VALUES (?, ?, ?, ?, ?)',
    id, encrypt(name, `companies.name:${id}`), encrypt(token, linkAad(id)), linkIdx(token), new Date().toISOString());
  return id;
}

async function bootstrapAdmin(config) {
  if (db.get(`SELECT 1 AS ok FROM users WHERE role = 'admin' LIMIT 1`)) return;
  if (!config.bootstrapAdminEmail || !config.bootstrapAdminPassword) {
    console.warn('Nenhum administrador cadastrado. Defina BOOTSTRAP_ADMIN_EMAIL e BOOTSTRAP_ADMIN_PASSWORD ou rode "npm run create-admin".');
    return;
  }
  await createUser({ role: 'admin', email: config.bootstrapAdminEmail.trim().toLowerCase(), password: config.bootstrapAdminPassword });
  audit('seguranca', 'Administrador inicial criado');
}

module.exports = {
  userEmail, findByEmail, findUser, createUser, resetCredentials, bootstrapAdmin,
  companyName, companyLink, findCompany, findCompanyByLink, listCompanies, setCompanyLink, createCompany
};
