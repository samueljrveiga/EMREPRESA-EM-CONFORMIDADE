'use strict';
const express = require('express');
const config = require('../config');
const db = require('../lib/db');
const { z, email, passwordProblem } = require('../lib/validate');
const { hashPassword, verifyPassword, dummyHash, encrypt, decrypt, newId } = require('../lib/crypto');
const totp = require('../lib/totp');
const { audit } = require('../lib/audit');
const { findByEmail, findUser, userEmail } = require('../lib/accounts');
const auth = require('../middleware/auth');
const limits = require('../middleware/limits');
const { parse, publicUser } = require('./helpers');

const { HttpError } = auth;
const router = express.Router();
const { maxAttempts, lockMinutes } = config.security;

const secretAad = id => `users.totp:${id}`;
const isLocked = user => user.locked_until > Date.now();
const nextStep = user => (user.must_change_password ? 'change_password' : user.totp_enabled ? 'verify_2fa' : 'setup_2fa');

function registerFailure(user, what) {
  const count = user.failed_attempts + 1;
  if (count >= maxAttempts) {
    db.run('UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?', Date.now() + lockMinutes * 60e3, user.id);
    audit('bloqueio', `Conta bloqueada por ${lockMinutes} min após falhas de ${what}`, user.company_id);
  } else {
    db.run('UPDATE users SET failed_attempts = ? WHERE id = ?', count, user.id);
  }
  audit('login_falhou', `Falha de ${what}`, user.company_id);
}

async function finishLogin(res, user) {
  db.run('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?', user.id);
  await auth.startSession(res, user.id);
  audit('login', `Login concluído (${user.role})`, user.company_id);
}

function storeRecoveryCodes(userId) {
  const codes = totp.newRecoveryCodes();
  db.tx(() => {
    db.run('DELETE FROM recovery_codes WHERE user_id = ?', userId);
    codes.forEach(code => db.run('INSERT INTO recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)', newId('rc'), userId, totp.hashRecovery(code)));
  });
  return codes;
}

function assertSecondFactor(user, code) {
  if (isLocked(user)) throw new HttpError(429, `Acesso bloqueado por ${lockMinutes} minutos após tentativas incorretas.`);
  const step = user.totp_secret_enc
    ? totp.verifyCode(decrypt(user.totp_secret_enc, secretAad(user.id)), code, user.totp_last_step) : null;
  if (step === null) {
    registerFailure(user, '2FA');
    throw new HttpError(401, 'Código inválido ou já utilizado.');
  }
  db.run('UPDATE users SET totp_last_step = ? WHERE id = ?', step, user.id);
}

router.post('/login', limits.login, async (req, res) => {
  const body = z.object({ email: z.string().max(200), senha: z.string().max(200) }).safeParse(req.body);
  const fail = () => new HttpError(401, 'E-mail ou senha inválidos, ou acesso temporariamente bloqueado.');
  if (!body.success) throw fail();

  const parsed = email.safeParse(body.data.email);
  const user = parsed.success ? findByEmail(parsed.data) : null;
  const passwordOk = await verifyPassword(user ? user.password_hash : await dummyHash(), body.data.senha);
  if (!user) throw fail();
  if (!user.active || isLocked(user)) throw fail();
  if (!passwordOk) { registerFailure(user, 'senha'); throw fail(); }

  await auth.setPreAuth(res, user.id);
  res.json({ next: nextStep(user) });
});

router.post('/first-password', limits.login, auth.requirePreAuth, async (req, res) => {
  const { novaSenha } = parse(z.object({ novaSenha: z.string() }), req.body);
  const user = req.user;
  if (!user.must_change_password) throw new HttpError(409, 'A senha já foi definida.');
  const problem = passwordProblem(novaSenha, userEmail(user));
  if (problem) throw new HttpError(400, problem);
  if (await verifyPassword(user.password_hash, novaSenha)) throw new HttpError(400, 'Escolha uma senha diferente da provisória.');
  db.run('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?', await hashPassword(novaSenha), user.id);
  audit('seguranca', 'Senha provisória substituída', user.company_id);
  res.json({ next: nextStep(findUser(user.id)) });
});

router.post('/2fa/setup', limits.login, auth.requirePreAuth, async (req, res) => {
  const user = req.user;
  if (user.must_change_password || user.totp_enabled) throw new HttpError(409, 'Etapa de 2FA indisponível.');
  const secret = totp.newSecret();
  db.run('UPDATE users SET totp_secret_enc = ?, totp_last_step = 0 WHERE id = ?', encrypt(secret, secretAad(user.id)), user.id);
  res.json(await totp.enrollment(secret, userEmail(user)));
});

router.post('/2fa/enable', limits.login, auth.requirePreAuth, async (req, res) => {
  const { codigo } = parse(z.object({ codigo: z.string().trim().max(10) }), req.body);
  const user = req.user;
  if (user.must_change_password || user.totp_enabled || !user.totp_secret_enc) throw new HttpError(409, 'Etapa de 2FA indisponível.');
  assertSecondFactor(user, codigo);
  db.run('UPDATE users SET totp_enabled = 1 WHERE id = ?', user.id);
  const recoveryCodes = storeRecoveryCodes(user.id);
  audit('seguranca', '2FA ativado', user.company_id);
  await finishLogin(res, user);
  res.json({ user: publicUser(findUser(user.id)), recoveryCodes });
});

router.post('/2fa/verify', limits.login, auth.requirePreAuth, async (req, res) => {
  const { codigo, recuperacao } = parse(z.object({
    codigo: z.string().trim().max(10).optional(), recuperacao: z.string().trim().max(40).optional()
  }), req.body);
  const user = req.user;
  if (user.must_change_password || !user.totp_enabled) throw new HttpError(409, 'Etapa de 2FA indisponível.');

  if (recuperacao) {
    if (isLocked(user)) throw new HttpError(429, `Acesso bloqueado por ${lockMinutes} minutos após tentativas incorretas.`);
    const row = db.get('SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL', user.id, totp.hashRecovery(recuperacao));
    if (!row) { registerFailure(user, 'código de recuperação'); throw new HttpError(401, 'Código de recuperação inválido.'); }
    db.run('UPDATE recovery_codes SET used_at = ? WHERE id = ?', new Date().toISOString(), row.id);
    audit('seguranca', 'Login com código de recuperação', user.company_id);
  } else {
    assertSecondFactor(user, codigo || '');
  }
  await finishLogin(res, user);
  const left = db.get('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL', user.id).n;
  res.json({ user: publicUser(findUser(user.id)), recoveryCodesLeft: left });
});

router.post('/refresh', async (req, res) => {
  if (!(await auth.refreshSession(req, res))) {
    auth.clearSessionCookies(res);
    throw new HttpError(401, 'Sua sessão expirou. Entre novamente.', 'unauthenticated');
  }
  res.json({ ok: true });
});

router.post('/logout', async (req, res) => {
  const current = await auth.loadUser(req);
  if (current) {
    auth.revokeSession(current.sessionId);
    audit('logout', `Saída (${current.user.role})`, current.user.company_id);
  }
  auth.clearSessionCookies(res);
  res.json({ ok: true });
});

router.post('/change-password', limits.login, auth.requireAuth, async (req, res) => {
  const { senhaAtual, novaSenha } = parse(z.object({ senhaAtual: z.string().max(200), novaSenha: z.string() }), req.body);
  const user = req.user;
  if (isLocked(user)) throw new HttpError(429, `Acesso bloqueado por ${lockMinutes} minutos após tentativas incorretas.`);
  if (!(await verifyPassword(user.password_hash, senhaAtual))) {
    registerFailure(user, 'senha');
    throw new HttpError(400, 'A senha atual está incorreta.');
  }
  const problem = passwordProblem(novaSenha, userEmail(user));
  if (problem) throw new HttpError(400, problem);
  db.run('UPDATE users SET password_hash = ?, failed_attempts = 0 WHERE id = ?', await hashPassword(novaSenha), user.id);
  auth.revokeUserSessions(user.id, req.sessionId);
  audit('seguranca', 'Senha alterada', user.company_id);
  res.json({ ok: true });
});

router.post('/recovery-codes', limits.login, auth.requireAuth, async (req, res) => {
  const { codigo } = parse(z.object({ codigo: z.string().trim().max(10) }), req.body);
  assertSecondFactor(req.user, codigo);
  const recoveryCodes = storeRecoveryCodes(req.user.id);
  audit('seguranca', 'Códigos de recuperação gerados novamente', req.user.company_id);
  res.json({ recoveryCodes });
});

module.exports = router;
