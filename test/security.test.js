'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ec-test-'));
const PORT = 39871;
const BASE = `http://127.0.0.1:${PORT}`;
Object.assign(process.env, {
  NODE_ENV: 'test', PORT: String(PORT), APP_URL: BASE,
  JWT_SECRET: 'j'.repeat(48), DATA_ENCRYPTION_KEY: 'k'.repeat(48),
  DB_PATH: path.join(dir, 'test.sqlite')
});

const OTPAuth = require('otpauth');
const { SignJWT } = require('jose');
const app = require('../src/app');
const db = require('../src/lib/db');
const accounts = require('../src/lib/accounts');
const { seedCourses } = require('../src/lib/courses');

const ADMIN = 'dona@emconformidade.test';
const NEW_PASSWORD = 'Cavalo-Bateria-Grampo-42';
let server;

class Client {
  constructor() { this.cookies = new Map(); }
  async req(method, url, body, headers = {}) {
    const res = await fetch(BASE + url, {
      method, redirect: 'manual',
      headers: {
        'Content-Type': 'application/json', 'X-Requested-With': 'em-conformidade',
        Cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '), ...headers
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(';');
      const i = pair.indexOf('=');
      const name = pair.slice(0, i), value = pair.slice(i + 1);
      if (value) this.cookies.set(name, value); else this.cookies.delete(name);
    }
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text, headers: res.headers };
  }
  get(url) { return this.req('GET', url); }
  post(url, body = {}) { return this.req('POST', url, body); }
  put(url, body) { return this.req('PUT', url, body); }
}

const code = (secret, offset = 0) => new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret), digits: 6, period: 30 })
  .generate({ timestamp: Date.now() + offset * 30000 });

// Espera o próximo passo de 30s para gerar um código ainda não usado.
const clearLastStep = email => db.run('UPDATE users SET totp_last_step = 0, failed_attempts = 0, locked_until = 0 WHERE id = ?', accounts.findByEmail(email).id);

async function onboard(email, temp) {
  const c = new Client();
  let r = await c.post('/api/auth/login', { email, senha: temp });
  assert.equal(r.json.next, 'change_password');
  r = await c.post('/api/auth/first-password', { novaSenha: NEW_PASSWORD });
  assert.equal(r.json.next, 'setup_2fa');
  r = await c.post('/api/auth/2fa/setup');
  const secret = r.json.secret;
  r = await c.post('/api/auth/2fa/enable', { codigo: code(secret) });
  assert.equal(r.status, 200, r.text);
  return { client: c, secret, recoveryCodes: r.json.recoveryCodes };
}

async function signIn(email, secret) {
  clearLastStep(email);
  const c = new Client();
  const r = await c.post('/api/auth/login', { email, senha: NEW_PASSWORD });
  assert.equal(r.json.next, 'verify_2fa');
  assert.equal((await c.post('/api/auth/2fa/verify', { codigo: code(secret) })).status, 200);
  return c;
}

const S = {};
before(async () => {
  seedCourses();
  await accounts.createUser({ role: 'admin', email: ADMIN, password: 'provisoria-inicial-123' });
  await new Promise(r => { server = app.listen(PORT, r); });
});
after(() => { server.close(); fs.rmSync(dir, { recursive: true, force: true }); });

test('senha fraca é recusada e a senha provisória não pode ser mantida', async () => {
  const c = new Client();
  await c.post('/api/auth/login', { email: ADMIN, senha: 'provisoria-inicial-123' });
  assert.equal((await c.post('/api/auth/first-password', { novaSenha: 'curta' })).status, 400);
  assert.equal((await c.post('/api/auth/first-password', { novaSenha: 'provisoria-inicial-123' })).status, 400);
  assert.equal((await c.post('/api/auth/first-password', { novaSenha: 'dona-dona-dona-dona' })).status, 400);
});

test('nada do painel abre antes de concluir o 2FA', async () => {
  const c = new Client();
  await c.post('/api/auth/login', { email: ADMIN, senha: 'provisoria-inicial-123' });
  assert.equal((await c.get('/api/admin/data')).status, 401);
  assert.equal((await c.get('/api/gestor/data')).status, 401);
  assert.equal((await new Client().get('/api/admin/data')).status, 401);
});

test('administrador conclui senha, 2FA e recebe 10 códigos de recuperação', async () => {
  const a = await onboard(ADMIN, 'provisoria-inicial-123');
  assert.equal(a.recoveryCodes.length, 10);
  S.admin = a;
  assert.equal((await a.client.get('/api/admin/data')).status, 200);
  const r = await a.client.post('/api/admin/companies', { name: 'Nortec Engenharia', emailRh: 'rh@nortec.test', emailGerente: 'gerente@nortec.test' });
  assert.equal(r.status, 201, r.text);
  const r2 = await a.client.post('/api/admin/companies', { name: 'Vitalis Saúde', emailRh: 'rh@vitalis.test', emailGerente: 'gerente@vitalis.test' });
  S.nortec = await onboard('rh@nortec.test', r.json.credentials[0].temporaryPassword);
  S.vitalis = await onboard('rh@vitalis.test', r2.json.credentials[0].temporaryPassword);
  S.nortecId = r.json.id; S.vitalisId = r2.json.id;
});

test('código de 2FA errado, código reutilizado e bloqueio após 5 falhas', async () => {
  const email = 'rh@nortec.test';
  clearLastStep(email);
  const c = new Client();
  await c.post('/api/auth/login', { email, senha: NEW_PASSWORD });
  const valid = code(S.nortec.secret);
  assert.equal((await c.post('/api/auth/2fa/verify', { codigo: valid })).status, 200);

  const replay = new Client();
  await replay.post('/api/auth/login', { email, senha: NEW_PASSWORD });
  assert.equal((await replay.post('/api/auth/2fa/verify', { codigo: valid })).status, 401, 'código já usado precisa ser recusado');

  clearLastStep(email);
  const wrong = String((Number(valid) + 1) % 1000000).padStart(6, '0');
  const brute = new Client();
  await brute.post('/api/auth/login', { email, senha: NEW_PASSWORD });
  for (let i = 0; i < 5; i++) await brute.post('/api/auth/2fa/verify', { codigo: wrong });
  assert.equal((await brute.post('/api/auth/2fa/verify', { codigo: code(S.nortec.secret) })).status, 429, 'código certo não entra durante o bloqueio');
  const blocked = await new Client().post('/api/auth/login', { email, senha: NEW_PASSWORD });
  assert.equal(blocked.status, 401);
  clearLastStep(email);
});

test('login não revela se o e-mail existe', async () => {
  const known = await new Client().post('/api/auth/login', { email: ADMIN, senha: 'errada-errada-errada' });
  const unknown = await new Client().post('/api/auth/login', { email: 'ninguem@x.test', senha: 'errada-errada-errada' });
  assert.equal(known.status, unknown.status);
  assert.equal(known.text, unknown.text);
  clearLastStep(ADMIN);
});

test('código de recuperação entra uma única vez', async () => {
  clearLastStep(ADMIN);
  const c1 = new Client();
  await c1.post('/api/auth/login', { email: ADMIN, senha: NEW_PASSWORD });
  const r = await c1.post('/api/auth/2fa/verify', { recuperacao: S.admin.recoveryCodes[0].toLowerCase() });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.recoveryCodesLeft, 9);
  const c2 = new Client();
  await c2.post('/api/auth/login', { email: ADMIN, senha: NEW_PASSWORD });
  assert.equal((await c2.post('/api/auth/2fa/verify', { recuperacao: S.admin.recoveryCodes[0] })).status, 401);
  clearLastStep(ADMIN);
});

test('JWT forjado, sem assinatura ou de outro tipo é recusado', async () => {
  const session = await signIn(ADMIN, S.admin.secret);
  const real = session.cookies.get('ec_at');
  const [h, p] = real.split('.');
  const none = `${Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url')}.${p}.`;
  const tampered = `${h}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url')), sub: 'outro' })).toString('base64url')}.${real.split('.')[2]}`;
  const wrongKey = await new SignJWT(JSON.parse(Buffer.from(p, 'base64url'))).setProtectedHeader({ alg: 'HS256' }).sign(new TextEncoder().encode('z'.repeat(48)));
  for (const token of [none, tampered, wrongKey, 'lixo']) {
    const c = new Client(); c.cookies.set('ec_at', token);
    assert.equal((await c.get('/api/admin/data')).status, 401, token.slice(0, 30));
  }
  const trainee = new Client();
  const link = (await S.nortec.client.get('/api/gestor/data')).json?.link;
  S.nortecClient = await signIn('rh@nortec.test', S.nortec.secret);
  S.vitalisClient = await signIn('rh@vitalis.test', S.vitalis.secret);
  const gestor = await S.nortecClient.get('/api/gestor/data');
  S.nortecLink = (link || gestor.json.link).split('/#/t/')[1];
  await trainee.post('/api/trainee/enter', { token: S.nortecLink });
  const asAccess = new Client(); asAccess.cookies.set('ec_at', trainee.cookies.get('ec_tr'));
  assert.equal((await asAccess.get('/api/admin/data')).status, 401, 'token de funcionário não vale como acesso');
});

test('logout corta o token na hora e reuso de token de renovação derruba a sessão', async () => {
  const c = await signIn(ADMIN, S.admin.secret);
  const stolen = c.cookies.get('ec_at');
  const oldRefresh = c.cookies.get('ec_rt');
  assert.equal((await c.post('/api/auth/refresh')).status, 200);
  assert.notEqual(c.cookies.get('ec_rt'), oldRefresh);
  db.run('UPDATE sessions SET prev_valid_until = 0');
  const thief = new Client(); thief.cookies.set('ec_rt', oldRefresh);
  assert.equal((await thief.post('/api/auth/refresh')).status, 401);
  assert.equal((await c.get('/api/admin/data')).status, 401, 'sessão precisa cair após reuso');

  const d = await signIn(ADMIN, S.admin.secret);
  const token = d.cookies.get('ec_at');
  await d.post('/api/auth/logout');
  const replay = new Client(); replay.cookies.set('ec_at', token);
  assert.equal((await replay.get('/api/admin/data')).status, 401);
  assert.ok(stolen);
});

test('sessão parada além do limite não renova', async () => {
  const c = await signIn(ADMIN, S.admin.secret);
  db.run('UPDATE sessions SET last_used_at = ?', Date.now() - 26 * 60e3);
  assert.equal((await c.post('/api/auth/refresh')).status, 401);
});

test('CSRF: escrita sem cabeçalho próprio ou de outra origem é recusada', async () => {
  const c = await signIn(ADMIN, S.admin.secret);
  assert.equal((await c.req('POST', '/api/auth/logout', {}, { 'X-Requested-With': '' })).status, 403);
  assert.equal((await c.req('POST', '/api/auth/logout', {}, { Origin: 'https://site-malicioso.test' })).status, 403);
  S.adminClient = c;
});

test('catálogo público não expõe vídeo nem perguntas, e link é obrigatório', async () => {
  const video = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
  const admin = S.adminClient;
  const data = (await admin.get('/api/admin/data')).json;
  const course = data.courses.find(c => c.id === 'crs_lgpd');
  course.modules[0].lessons[0].videoUrl = video;
  assert.equal((await admin.put('/api/admin/courses/crs_lgpd', course)).status, 200);
  course.modules[0].lessons[0].videoUrl = 'javascript:alert(1)';
  assert.equal((await admin.put('/api/admin/courses/crs_lgpd', course)).status, 400);

  const pub = await new Client().get('/api/bootstrap');
  assert.ok(!pub.text.includes('dQw4w9WgXcQ'));
  assert.ok(!pub.text.includes('Lei 13.709/2018'));
  assert.ok(!pub.text.includes('correct'));
  assert.equal((await new Client().post('/api/enrollments', { courseId: 'crs_lgpd', employeeName: 'Ana Ribeiro' })).status, 401);
  assert.equal((await new Client().post('/api/trainee/enter', { token: 'a'.repeat(43) })).status, 404);
});

test('funcionário nunca recebe o gabarito e não consegue certificado sem cumprir tudo', async () => {
  const t = new Client();
  await t.post('/api/trainee/enter', { token: S.nortecLink });
  const r = await t.post('/api/enrollments', { courseId: 'crs_lgpd', employeeName: 'Ana Paula Ribeiro' });
  assert.equal(r.status, 200, r.text);
  assert.ok(!r.text.includes('correct'));
  assert.ok(r.text.includes('dQw4w9WgXcQ'), 'funcionário com link vê o vídeo');
  const en = r.json.enrollment;
  S.trainee = t; S.en = en;

  // Forçar conclusão pelo corpo da requisição não tem efeito.
  await t.post(`/api/enrollments/${en.id}/quiz`, { answers: [0, 0, 0, 0, 1], quizPassed: true, score: 5 });
  let cur = (await t.get(`/api/enrollments/${en.id}`)).json.enrollment;
  assert.equal(cur.quizPassed, false);
  assert.equal(cur.certCode, null);

  // Passa no questionário, mas faltam as aulas.
  const pass = await t.post(`/api/enrollments/${en.id}/quiz`, { answers: [1, 2, 0, 2, 0] });
  assert.equal(pass.json.passed, true);
  assert.equal(pass.json.enrollment.certCode, null, 'questionário sozinho não libera certificado');
  assert.equal(pass.json.enrollment.complete, false);

  const done = await t.post(`/api/enrollments/${en.id}/lessons/l1/complete`);
  assert.equal(done.json.finished, true);
  assert.match(done.json.enrollment.certCode, /^CERT-[A-Z2-9]{4}-[A-Z2-9]{6}$/);
  assert.equal((await t.post(`/api/enrollments/${en.id}/lessons/inexistente/complete`)).status, 404);
});

test('aula com duração só conclui depois do tempo, contado pelo servidor', async () => {
  const admin = S.adminClient;
  const course = (await admin.get('/api/admin/data')).json.courses.find(c => c.id === 'crs_nr1');
  course.modules[0].lessons[0].durationMin = 10;
  await admin.put('/api/admin/courses/crs_nr1', course);
  const t = S.trainee;
  const en = (await t.post('/api/enrollments', { courseId: 'crs_nr1', employeeName: 'Ana Paula Ribeiro' })).json.enrollment;
  assert.equal((await t.post(`/api/enrollments/${en.id}/lessons/l1/complete`)).status, 409, 'sem abrir a aula');
  await t.post(`/api/enrollments/${en.id}/lessons/l1/start`);
  assert.equal((await t.post(`/api/enrollments/${en.id}/lessons/l1/complete`)).status, 409, 'logo depois de abrir');
  await t.post(`/api/enrollments/${en.id}/lessons/l1/start`);
  db.run('UPDATE enrollments SET lesson_starts = ? WHERE id = ?', JSON.stringify({ l1: Date.now() - 9.1 * 60e3 }), en.id);
  assert.equal((await t.post(`/api/enrollments/${en.id}/lessons/l1/complete`)).status, 200);
});

test('uma empresa nunca acessa dados de outra', async () => {
  const v = S.vitalisClient;
  const data = (await v.get('/api/gestor/data')).json;
  assert.equal(data.company.name, 'Vitalis Saúde');
  assert.equal(data.enrollments.length, 0);
  assert.equal((await v.get(`/api/gestor/data?companyId=${S.nortecId}`)).json.company.name, 'Vitalis Saúde');
  assert.ok(!(await v.get('/api/gestor/export.csv')).text.includes('Ana Paula'));

  const other = new Client();
  await other.post('/api/trainee/enter', { token: data.link.split('/#/t/')[1] });
  assert.equal((await other.get(`/api/enrollments/${S.en.id}`)).status, 404);
  assert.equal((await other.post(`/api/enrollments/${S.en.id}/lessons/l1/complete`)).status, 404);
  assert.equal((await S.nortecClient.get(`/api/enrollments/${S.en.id}`)).status, 401);
  assert.equal((await v.get('/api/admin/data')).status, 403, 'gestor não abre a administração');
});

test('painel do gestor vê a própria equipe e o CSV neutraliza fórmulas', async () => {
  const t = S.trainee;
  await t.post('/api/enrollments', { courseId: 'crs_compliance', employeeName: "D'Ávila Souza" });
  await t.post('/api/enrollments', { courseId: 'crs_compliance', employeeName: '-Cmd Exec' });
  const csv = await S.nortecClient.get('/api/gestor/export.csv');
  assert.match(csv.text, /Ana Paula Ribeiro/);
  assert.ok(csv.text.includes(`"'-Cmd Exec"`), 'célula iniciada por sinal precisa ser neutralizada');
  const data = (await S.nortecClient.get('/api/gestor/data')).json;
  assert.ok(data.enrollments.find(e => e.certCode));
  assert.ok(!(await new Client().post('/api/enrollments', {})).text.includes('Ana'));
  assert.equal((await t.post('/api/enrollments', { courseId: 'crs_lgpd', employeeName: '=cmd|calc' })).status, 400);
});

test('trocar o link desativa o anterior', async () => {
  const old = S.nortecLink;
  const r = await S.nortecClient.post('/api/gestor/link/rotate');
  assert.equal((await new Client().post('/api/trainee/enter', { token: old })).status, 404);
  assert.equal((await new Client().post('/api/trainee/enter', { token: r.json.link.split('/#/t/')[1] })).status, 200);
});

test('redefinição pelo administrador derruba a sessão e exige novo 2FA', async () => {
  const admin = await signIn(ADMIN, S.admin.secret);
  const user = accounts.findByEmail('rh@vitalis.test');
  const r = await admin.post(`/api/admin/users/${user.id}/reset`);
  assert.equal(r.status, 200);
  assert.equal((await S.vitalisClient.get('/api/gestor/data')).status, 401);
  const c = new Client();
  assert.equal((await c.post('/api/auth/login', { email: 'rh@vitalis.test', senha: r.json.temporaryPassword })).json.next, 'change_password');
});

test('excluir a empresa corta link e acessos, mantendo os registros', async () => {
  const admin = await signIn(ADMIN, S.admin.secret);
  const link = (await S.vitalisClient.get('/api/gestor/data'));
  assert.equal(link.status, 401);
  assert.equal((await admin.req('DELETE', `/api/admin/companies/${S.vitalisId}`)).status, 200);
  assert.equal((await new Client().post('/api/auth/login', { email: 'gerente@vitalis.test', senha: 'qualquer-senha-123' })).status, 401);
});

test('banco de dados não guarda dados legíveis', () => {
  db.raw.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  const file = fs.readFileSync(process.env.DB_PATH);
  for (const secretText of ['Ana Paula Ribeiro', 'rh@nortec.test', ADMIN, 'Nortec', 'dQw4w9WgXcQ', 'Lei 13.709/2018', 'Compliance e integridade', S.nortec.secret, NEW_PASSWORD]) {
    assert.equal(file.includes(Buffer.from(secretText)), false, `"${secretText}" apareceu aberto no banco`);
  }
});

test('valor cifrado copiado para outro registro não pode ser lido', async () => {
  const rows = db.all('SELECT id, employee_name_enc FROM enrollments');
  assert.ok(rows.length >= 2);
  db.run('UPDATE enrollments SET employee_name_enc = ? WHERE id = ?', rows[0].employee_name_enc, rows[1].id);
  const enrollments = require('../src/lib/enrollments');
  assert.throws(() => enrollments.view(enrollments.findById(rows[1].id)));
  db.run('UPDATE enrollments SET employee_name_enc = ? WHERE id = ?', rows[1].employee_name_enc, rows[1].id);
});

test('cabeçalhos de segurança e arquivos internos', async () => {
  const r = await fetch(`${BASE}/`);
  const csp = r.headers.get('content-security-policy');
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('x-powered-by'), null);
  for (const file of ['/.env', '/package.json', '/src/config.js', '/data/plataforma.sqlite']) {
    assert.notEqual((await fetch(BASE + file)).status, 200, file);
  }
});
