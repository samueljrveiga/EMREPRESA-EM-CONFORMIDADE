'use strict';
/* JWT HS256. Cada tipo de token tem sua própria audiência: um token de
   funcionário ou de etapa pré-2FA nunca é aceito como token de acesso. */
const { SignJWT, jwtVerify } = require('jose');
const config = require('../config');
const { randomToken } = require('./crypto');

const KEY = new TextEncoder().encode(config.jwtSecret);
const ISSUER = 'em-conformidade';
const AUD = { access: 'ec:access', preAuth: 'ec:pre-auth', trainee: 'ec:trainee' };

const sign = (claims, subject, audience, seconds) => new SignJWT(claims)
  .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
  .setIssuer(ISSUER).setAudience(audience).setSubject(subject)
  .setIssuedAt().setJti(randomToken(12))
  .setExpirationTime(`${seconds}s`)
  .sign(KEY);

async function verify(token, audience) {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, KEY, { issuer: ISSUER, audience, algorithms: ['HS256'] });
    return payload;
  } catch { return null; }
}

const { accessMinutes, preAuthMinutes, traineeHours } = config.security;
module.exports = {
  signAccess: (userId, sessionId) => sign({ sid: sessionId }, userId, AUD.access, accessMinutes * 60),
  signPreAuth: userId => sign({}, userId, AUD.preAuth, preAuthMinutes * 60),
  signTrainee: companyId => sign({}, companyId, AUD.trainee, traineeHours * 3600),
  verifyAccess: t => verify(t, AUD.access),
  verifyPreAuth: t => verify(t, AUD.preAuth),
  verifyTrainee: t => verify(t, AUD.trainee)
};
