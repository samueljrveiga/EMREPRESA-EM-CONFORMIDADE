'use strict';
const config = require('../config');
const db = require('../lib/db');
const tokens = require('../lib/tokens');
const { randomToken, sha256, newId } = require('../lib/crypto');
const { findUser, findCompany } = require('../lib/accounts');

const prefix = config.isProd ? '__Host-' : '';
const COOKIE = { access: `${prefix}ec_at`, refresh: `${prefix}ec_rt`, preAuth: `${prefix}ec_mfa`, trainee: `${prefix}ec_tr` };

// httpOnly: inacessível ao JavaScript da página, o que protege o token contra XSS.
const cookieOptions = ms => ({ httpOnly: true, secure: config.isProd, sameSite: 'strict', path: '/', maxAge: ms });
const { accessMinutes, preAuthMinutes, traineeHours, idleMinutes, maxSessionHours } = config.security;
const HOUR = 3600e3, MIN = 60e3;

class HttpError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code; }
}

const setCookie = (res, name, value, ms) => res.cookie(name, value, cookieOptions(ms));
const dropCookie = (res, name) => res.clearCookie(name, { httpOnly: true, secure: config.isProd, sameSite: 'strict', path: '/' });

async function setAccess(res, userId, sessionId) {
  setCookie(res, COOKIE.access, await tokens.signAccess(userId, sessionId), accessMinutes * MIN);
}

async function setPreAuth(res, userId) {
  setCookie(res, COOKIE.preAuth, await tokens.signPreAuth(userId), preAuthMinutes * MIN);
}

async function setTrainee(res, companyId) {
  setCookie(res, COOKIE.trainee, await tokens.signTrainee(companyId), traineeHours * HOUR);
}

async function startSession(res, userId) {
  const id = newId('ses');
  const refresh = randomToken(32);
  const now = Date.now();
  const expires = now + maxSessionHours * HOUR;
  db.run('INSERT INTO sessions (id, user_id, refresh_hash, created_at, last_used_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
    id, userId, sha256(refresh), now, now, expires);
  await setAccess(res, userId, id);
  setCookie(res, COOKIE.refresh, `${id}.${refresh}`, maxSessionHours * HOUR);
  dropCookie(res, COOKIE.preAuth);
  return id;
}

const revokeSession = id => db.run('UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL', Date.now(), id);
const revokeUserSessions = (userId, exceptId = '') =>
  db.run('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id <> ? AND revoked_at IS NULL', Date.now(), userId, exceptId);

function clearSessionCookies(res) {
  [COOKIE.access, COOKIE.refresh, COOKIE.preAuth].forEach(name => dropCookie(res, name));
}

/* Renovação com rotação: cada token de renovação vale uma vez. O reuso de um token
   antigo indica roubo e encerra a sessão. A tolerância de 30s evita falso alarme
   quando duas abas renovam ao mesmo tempo. */
async function refreshSession(req, res) {
  const [id, secret] = String(req.cookies[COOKIE.refresh] || '').split('.');
  const session = id && secret ? db.get('SELECT * FROM sessions WHERE id = ?', id) : null;
  const now = Date.now();
  const valid = session && !session.revoked_at && now < session.expires_at
    && now - session.last_used_at <= (accessMinutes + idleMinutes) * MIN;
  const user = valid ? findUser(session.user_id) : null;
  if (!valid || !user || !user.active) return false;

  const hash = sha256(secret);
  if (hash === session.refresh_hash) {
    const next = randomToken(32);
    db.run('UPDATE sessions SET refresh_hash = ?, prev_refresh_hash = ?, prev_valid_until = ?, last_used_at = ? WHERE id = ?',
      sha256(next), hash, now + 30e3, now, id);
    await setAccess(res, user.id, id);
    setCookie(res, COOKIE.refresh, `${id}.${next}`, session.expires_at - now);
    return true;
  }
  if (hash === session.prev_refresh_hash && now < session.prev_valid_until) {
    await setAccess(res, user.id, id);
    return true;
  }
  revokeSession(id);
  return false;
}

/* O JWT é verificado e a sessão é conferida no banco, então sair ou
   redefinir a senha corta o acesso na hora, sem esperar o token expirar. */
async function loadUser(req) {
  const payload = await tokens.verifyAccess(req.cookies[COOKIE.access]);
  if (!payload) return null;
  const session = db.get('SELECT * FROM sessions WHERE id = ? AND user_id = ?', payload.sid, payload.sub);
  if (!session || session.revoked_at || Date.now() >= session.expires_at) return null;
  const user = findUser(payload.sub);
  if (!user || !user.active) return null;
  return { user, sessionId: session.id };
}

async function requireAuth(req, res, next) {
  const auth = await loadUser(req);
  if (!auth) throw new HttpError(401, 'Sua sessão expirou. Entre novamente.', 'unauthenticated');
  req.user = auth.user; req.sessionId = auth.sessionId;
  next();
}

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) throw new HttpError(403, 'Acesso não autorizado.');
  next();
};

async function requirePreAuth(req, res, next) {
  const payload = await tokens.verifyPreAuth(req.cookies[COOKIE.preAuth]);
  const user = payload && findUser(payload.sub);
  if (!user || !user.active) throw new HttpError(401, 'A etapa de login expirou. Comece novamente.', 'pre_auth_expired');
  req.user = user;
  next();
}

async function loadTrainee(req) {
  const payload = await tokens.verifyTrainee(req.cookies[COOKIE.trainee]);
  return (payload && findCompany(payload.sub)) || null;
}

async function requireTrainee(req, res, next) {
  const company = await loadTrainee(req);
  if (!company) throw new HttpError(401, 'Abra novamente o link enviado pela sua empresa.', 'trainee_required');
  req.company = company;
  next();
}

const hasRefreshCookie = req => Boolean(req.cookies[COOKIE.refresh]);

module.exports = {
  HttpError, setPreAuth, setTrainee, startSession, refreshSession, revokeSession, revokeUserSessions,
  clearSessionCookies, loadUser, requireAuth, requireRole, requirePreAuth, loadTrainee, requireTrainee, hasRefreshCookie
};
