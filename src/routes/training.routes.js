'use strict';
const express = require('express');
const config = require('../config');
const db = require('../lib/db');
const { z, id, employeeName } = require('../lib/validate');
const { decrypt } = require('../lib/crypto');
const { audit } = require('../lib/audit');
const { listCourses, getCourse, allLessons, publicCourse } = require('../lib/courses');
const { findCompanyByLink, companyName } = require('../lib/accounts');
const enrollments = require('../lib/enrollments');
const auth = require('../middleware/auth');
const limits = require('../middleware/limits');
const { parse, publicUser } = require('./helpers');

const { HttpError } = auth;
const router = express.Router();

function denounceUrl() {
  const row = db.get(`SELECT value_enc FROM settings WHERE key = 'denounceUrl'`);
  return row ? decrypt(row.value_enc, 'settings:denounceUrl') : '';
}

router.get('/bootstrap', async (req, res) => {
  const [current, trainee] = await Promise.all([auth.loadUser(req), auth.loadTrainee(req)]);
  res.json({
    courses: listCourses().map(publicCourse),
    settings: { denounceUrl: denounceUrl() },
    user: current ? publicUser(current.user) : null,
    trainee: trainee ? { companyName: companyName(trainee) } : null,
    canRefresh: !current && auth.hasRefreshCookie(req),
    security: config.security
  });
});

/* O link da empresa é a credencial do funcionário: um token aleatório de 256 bits
   que o gestor pode trocar. Ele vira uma sessão JWT em cookie httpOnly. */
router.post('/trainee/enter', limits.link, async (req, res) => {
  const { token } = parse(z.object({ token: z.string().regex(/^[A-Za-z0-9_-]{20,64}$/) }), req.body);
  const company = findCompanyByLink(token);
  if (!company) throw new HttpError(404, 'Link inválido ou desativado. Peça um link novo ao RH.');
  await auth.setTrainee(res, company.id);
  res.json({ trainee: { companyName: companyName(company) } });
});

function ownEnrollment(req) {
  const row = enrollments.findById(req.params.id);
  // Mesma resposta para "não existe" e "é de outra empresa".
  if (!row || row.company_id !== req.company.id) throw new HttpError(404, 'Sessão de treinamento não encontrada.');
  const course = getCourse(row.course_id, { includeDeleted: true });
  if (!course) throw new HttpError(404, 'Treinamento não encontrado.');
  return { row, course };
}

router.post('/enrollments', auth.requireTrainee, (req, res) => {
  const body = parse(z.object({ courseId: id, employeeName }), req.body);
  const course = getCourse(body.courseId);
  if (!course) throw new HttpError(404, 'Treinamento não encontrado.');
  const row = enrollments.findOrCreate(req.company.id, course, body.employeeName);
  res.json({ enrollment: enrollments.traineeView(row) });
});

router.get('/enrollments/:id', auth.requireTrainee, (req, res) => {
  const { row } = ownEnrollment(req);
  res.json({ enrollment: enrollments.traineeView(row) });
});

function lessonOf(course, lessonId) {
  const lesson = allLessons(course).find(l => l.id === lessonId);
  if (!lesson) throw new HttpError(404, 'Aula não encontrada.');
  return lesson;
}

router.post('/enrollments/:id/lessons/:lessonId/start', auth.requireTrainee, (req, res) => {
  const { row, course } = ownEnrollment(req);
  const lesson = lessonOf(course, req.params.lessonId);
  const starts = JSON.parse(row.lesson_starts);
  if (!starts[lesson.id]) {
    starts[lesson.id] = Date.now();
    db.run('UPDATE enrollments SET lesson_starts = ? WHERE id = ?', JSON.stringify(starts), row.id);
  }
  res.json({ ok: true });
});

/* Uma aula com duração cadastrada só pode ser concluída depois que
   90% desse tempo tiver passado desde a abertura, medido pelo servidor. */
router.post('/enrollments/:id/lessons/:lessonId/complete', auth.requireTrainee, (req, res) => {
  const { row, course } = ownEnrollment(req);
  const lesson = lessonOf(course, req.params.lessonId);
  const completed = JSON.parse(row.completed_lessons);
  if (!completed.includes(lesson.id)) {
    const minimumMs = lesson.durationMin * 60e3 * config.security.minWatchRatio;
    const started = JSON.parse(row.lesson_starts)[lesson.id];
    const elapsed = started ? Date.now() - started : 0;
    if (minimumMs > 0 && (!started || elapsed < minimumMs)) {
      const left = Math.ceil((minimumMs - elapsed) / 60e3);
      throw new HttpError(409, `Assista à aula até o fim antes de concluí-la. Falta cerca de ${left} min.`);
    }
    completed.push(lesson.id);
    db.run('UPDATE enrollments SET completed_lessons = ? WHERE id = ?', JSON.stringify(completed), row.id);
  }
  const finished = enrollments.issueIfFinished(row.id, course);
  if (finished) audit('certificado', `Certificado emitido: ${course.title}`, row.company_id);
  res.json({ enrollment: enrollments.traineeView(enrollments.findById(row.id)), finished });
});

/* O gabarito nunca vai ao navegador: a correção acontece aqui. */
router.post('/enrollments/:id/quiz', limits.quiz, auth.requireTrainee, (req, res) => {
  const { row, course } = ownEnrollment(req);
  const quiz = course.quiz || [];
  if (!quiz.length) throw new HttpError(409, 'Este treinamento não tem questionário.');
  const { answers } = parse(z.object({ answers: z.array(z.number().int().min(0)).length(quiz.length, 'Responda todas as perguntas antes de enviar.') }), req.body);
  if (row.quiz_passed) return res.json({ enrollment: enrollments.traineeView(row), passed: true, score: row.quiz_score, total: quiz.length, finished: false });

  const score = quiz.reduce((sum, q, i) => sum + (answers[i] === q.correct ? 1 : 0), 0);
  const passed = score >= Math.ceil(quiz.length * 0.7);
  db.run('UPDATE enrollments SET quiz_score = ?, quiz_passed = ? WHERE id = ?', score, passed ? 1 : 0, row.id);
  const finished = passed && enrollments.issueIfFinished(row.id, course);
  if (finished) audit('certificado', `Certificado emitido: ${course.title}`, row.company_id);
  res.json({ enrollment: enrollments.traineeView(enrollments.findById(row.id)), passed, score, total: quiz.length, finished });
});

module.exports = router;
