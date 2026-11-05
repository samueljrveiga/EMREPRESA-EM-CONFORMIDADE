'use strict';
const express = require('express');
const db = require('../lib/db');
const { z, id, email, LIMITS, course: courseSchema, httpsUrl, normalizeName } = require('../lib/validate');
const { encrypt } = require('../lib/crypto');
const { audit, recentAudit } = require('../lib/audit');
const { listCourses, saveCourse, getCourse, adminCourse } = require('../lib/courses');
const accounts = require('../lib/accounts');
const enrollments = require('../lib/enrollments');
const auth = require('../middleware/auth');
const { parse } = require('./helpers');

const { HttpError } = auth;
const router = express.Router();
router.use(auth.requireAuth, auth.requireRole('admin'));

const companyName = z.string().transform(normalizeName).pipe(z.string().min(1, 'Informe o nome da empresa.').max(LIMITS.name));

function userView(user) {
  return { id: user.id, role: user.role, email: accounts.userEmail(user), totpEnabled: Boolean(user.totp_enabled), locked: user.locked_until > Date.now() };
}

router.get('/data', (req, res) => {
  const companyRows = accounts.listCompanies();
  const companies = new Map(companyRows.map(c => [c.id, c]));
  const courses = new Map(db.all('SELECT id FROM courses').map(c => [c.id, getCourse(c.id, { includeDeleted: true })]));
  const rows = db.all('SELECT * FROM enrollments ORDER BY started_at DESC').map(r => enrollments.view(r, { courses, companies }));
  res.json({
    companies: companyRows.map(c => ({
      id: c.id,
      name: accounts.companyName(c),
      employees: new Set(rows.filter(e => e.companyId === c.id).map(e => e.employeeName)).size,
      users: db.all('SELECT * FROM users WHERE company_id = ? AND active = 1 ORDER BY role DESC', c.id).map(userView)
    })),
    courses: listCourses().map(adminCourse),
    enrollments: rows,
    audit: recentAudit(100)
  });
});

router.post('/companies', async (req, res) => {
  const body = parse(z.object({ name: companyName, emailRh: email, emailGerente: email }), req.body);
  if (body.emailRh === body.emailGerente) throw new HttpError(400, 'Use um e-mail diferente para o RH e para o Gerente.');
  if (accounts.findByEmail(body.emailRh) || accounts.findByEmail(body.emailGerente)) throw new HttpError(409, 'Um desses e-mails já está cadastrado.');
  const companyId = accounts.createCompany(body.name);
  const rh = await accounts.createUser({ role: 'rh', companyId, email: body.emailRh });
  const gerente = await accounts.createUser({ role: 'gerente', companyId, email: body.emailGerente });
  audit('empresa', `Empresa criada: ${body.name}`, companyId);
  res.status(201).json({
    id: companyId,
    credentials: [
      { profile: 'RH', email: body.emailRh, temporaryPassword: rh.temporaryPassword },
      { profile: 'Gerente', email: body.emailGerente, temporaryPassword: gerente.temporaryPassword }
    ]
  });
});

router.put('/companies/:id', (req, res) => {
  const { name } = parse(z.object({ name: companyName }), req.body);
  const company = accounts.findCompany(req.params.id);
  if (!company) throw new HttpError(404, 'Empresa não encontrada.');
  db.run('UPDATE companies SET name_enc = ? WHERE id = ?', encrypt(name, `companies.name:${company.id}`), company.id);
  audit('empresa', `Empresa editada: ${name}`, company.id);
  res.json({ ok: true });
});

/* A empresa é desativada: os registros de treinamento continuam guardados. */
router.delete('/companies/:id', (req, res) => {
  const company = accounts.findCompany(req.params.id);
  if (!company) throw new HttpError(404, 'Empresa não encontrada.');
  db.tx(() => {
    db.run('UPDATE companies SET deleted_at = ? WHERE id = ?', new Date().toISOString(), company.id);
    db.run('UPDATE users SET active = 0 WHERE company_id = ?', company.id);
    db.run(`UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL AND user_id IN (SELECT id FROM users WHERE company_id = ?)`, Date.now(), company.id);
  });
  audit('empresa', `Empresa desativada: ${accounts.companyName(company)}`, company.id);
  res.json({ ok: true });
});

router.post('/users/:id/reset', async (req, res) => {
  const user = accounts.findUser(req.params.id);
  if (!user || !user.active || user.role === 'admin') throw new HttpError(404, 'Usuário não encontrado.');
  const temporaryPassword = await accounts.resetCredentials(user.id);
  audit('seguranca', `Acesso redefinido (${user.role})`, user.company_id);
  res.json({ email: accounts.userEmail(user), temporaryPassword });
});

router.put('/courses/:id', (req, res) => {
  parse(id, req.params.id);
  const data = parse(courseSchema, req.body);
  saveCourse(req.params.id, data);
  audit('treinamento', `Treinamento salvo: ${data.title}`);
  res.json({ ok: true });
});

router.delete('/courses/:id', (req, res) => {
  const course = getCourse(req.params.id);
  if (!course) throw new HttpError(404, 'Treinamento não encontrado.');
  db.run('UPDATE courses SET deleted_at = ? WHERE id = ?', new Date().toISOString(), course.id);
  audit('treinamento', `Treinamento excluído: ${course.title}`);
  res.json({ ok: true });
});

router.put('/settings/denuncia', (req, res) => {
  const { url } = parse(z.object({ url: z.string().trim().max(LIMITS.url) }), req.body);
  const safe = url ? httpsUrl(url) : '';
  if (url && !safe) throw new HttpError(400, 'Informe um endereço seguro começando com https://');
  db.run(`INSERT INTO settings (key, value_enc) VALUES ('denounceUrl', ?) ON CONFLICT(key) DO UPDATE SET value_enc = excluded.value_enc`,
    encrypt(safe, 'settings:denounceUrl'));
  audit('configuracao', 'Link do canal de denúncias alterado');
  res.json({ url: safe });
});

module.exports = router;
