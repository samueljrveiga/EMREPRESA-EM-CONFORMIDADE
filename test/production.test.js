'use strict';
/* Confere o comportamento em produção em um processo separado. */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');

test('produção exige https, chaves fortes e cookies protegidos', async () => {
  const PORT = 39872;
  const env = { ...process.env, NODE_ENV: 'production', PORT, APP_URL: 'https://treinamentos.exemplo.test', TRUST_PROXY: '1',
    JWT_SECRET: 'p'.repeat(48), DATA_ENCRYPTION_KEY: 'q'.repeat(48), DB_PATH: ':memory:',
    BOOTSTRAP_ADMIN_EMAIL: 'admin@exemplo.test', BOOTSTRAP_ADMIN_PASSWORD: 'provisoria-de-teste-123' };
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(__dirname, '..', 'src/server.js')], { env, stdio: 'pipe' });
  try {
    await new Promise((resolve, reject) => {
      child.stdout.on('data', resolve); child.once('exit', c => reject(new Error(`saiu com ${c}`)));
    });
    const base = `http://127.0.0.1:${PORT}`;
    const http = await fetch(`${base}/`, { redirect: 'manual' });
    assert.equal(http.status, 301);
    assert.equal(http.headers.get('location'), 'https://treinamentos.exemplo.test/');
    assert.equal((await fetch(`${base}/healthz`)).status, 200);

    const proxied = { 'x-forwarded-proto': 'https', 'Content-Type': 'application/json', 'X-Requested-With': 'em-conformidade', Origin: 'https://treinamentos.exemplo.test' };
    const page = await fetch(`${base}/`, { headers: proxied });
    assert.match(page.headers.get('strict-transport-security'), /max-age=31536000/);
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: proxied, body: JSON.stringify({ email: 'admin@exemplo.test', senha: 'provisoria-de-teste-123' }) });
    assert.equal(login.status, 200);
    const cookie = login.headers.getSetCookie().join(';');
    assert.match(cookie, /__Host-ec_mfa=/);
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /Secure/);
    assert.match(cookie, /SameSite=Strict/);
  } finally { child.kill(); }
});

test('sem chaves o servidor se recusa a iniciar', async () => {
  const env = { ...process.env, NODE_ENV: 'production', APP_URL: 'https://x.test', JWT_SECRET: 'curta', DATA_ENCRYPTION_KEY: '', DB_PATH: ':memory:' };
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(__dirname, '..', 'src/server.js')], { env, stdio: 'ignore' });
  const code = await new Promise(resolve => child.once('exit', resolve));
  assert.notEqual(code, 0);
});
