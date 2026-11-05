'use strict';
/* 2FA por aplicativo autenticador (TOTP, RFC 6238) e códigos de recuperação. */
const crypto = require('node:crypto');
const OTPAuth = require('otpauth');
const QRCode = require('qrcode');
const { blindIndex } = require('./crypto');

const PERIOD = 30;
const make = (secret, label) => new OTPAuth.TOTP({
  issuer: 'Em Conformidade', label: label || 'conta', algorithm: 'SHA1', digits: 6, period: PERIOD,
  secret: OTPAuth.Secret.fromBase32(secret)
});

const newSecret = () => new OTPAuth.Secret({ size: 20 }).base32;

async function enrollment(secret, label) {
  const otpauthUrl = make(secret, label).toString();
  return { secret, otpauthUrl, qr: await QRCode.toDataURL(otpauthUrl, { margin: 1, width: 240 }) };
}

/* Devolve o passo de tempo do código ou null. Aceita 30s de diferença de relógio
   e recusa passo já usado, de modo que um código capturado não sirva duas vezes. */
function verifyCode(secret, code, lastStep) {
  if (!/^\d{6}$/.test(code)) return null;
  const delta = make(secret).validate({ token: code, window: 1 });
  if (delta === null) return null;
  const step = Math.floor(Date.now() / 1000 / PERIOD) + delta;
  return step > lastStep ? step : null;
}

const hashRecovery = code => blindIndex(code.toUpperCase().replace(/[^A-Z0-9]/g, ''), 'recovery');

function newRecoveryCodes(count = 10) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from({ length: count }, () => {
    const c = Array.from({ length: 16 }, () => alphabet[crypto.randomInt(alphabet.length)]).join('');
    return c.match(/.{4}/g).join('-');
  });
}

module.exports = { newSecret, enrollment, verifyCode, hashRecovery, newRecoveryCodes };
