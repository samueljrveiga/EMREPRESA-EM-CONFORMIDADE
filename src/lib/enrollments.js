'use strict';
const crypto = require('node:crypto');
const db = require('./db');
const { encrypt, decrypt, blindIndex, newId } = require('./crypto');
const { getCourse, allLessons, traineeCourse } = require('./courses');
const { companyName, findCompany } = require('./accounts');

const nameAad = id => `enrollments.name:${id}`;
const nameIdx = (companyId, name) => blindIndex(`${companyId}:${name.toLocaleLowerCase('pt-BR')}`, 'employee-name');

function certCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const pick = n => Array.from({ length: n }, () => alphabet[crypto.randomInt(alphabet.length)]).join('');
  return `CERT-${pick(4)}-${pick(6)}`;
}

function findOrCreate(companyId, course, employeeName) {
  const idx = nameIdx(companyId, employeeName);
  const existing = db.get('SELECT * FROM enrollments WHERE company_id = ? AND course_id = ? AND name_idx = ?', companyId, course.id, idx);
  if (existing) return existing;
  const id = newId('en');
  db.run(`INSERT INTO enrollments (id, company_id, course_id, employee_name_enc, name_idx, started_at) VALUES (?, ?, ?, ?, ?, ?)`,
    id, companyId, course.id, encrypt(employeeName, nameAad(id)), idx, new Date().toISOString());
  return db.get('SELECT * FROM enrollments WHERE id = ?', id);
}

const findById = id => db.get('SELECT * FROM enrollments WHERE id = ?', id);

/* A conclusão é decidida aqui, no servidor: as aulas da versão atual do curso
   precisam estar feitas e o questionário aprovado. */
function isFinished(row, course) {
  const done = new Set(JSON.parse(row.completed_lessons));
  const lessons = allLessons(course);
  return lessons.length > 0 && lessons.every(l => done.has(l.id)) && (!(course.quiz || []).length || Boolean(row.quiz_passed));
}

function issueIfFinished(id, course) {
  const row = findById(id);
  if (row.completed_at || !isFinished(row, course)) return false;
  db.run('UPDATE enrollments SET completed_at = ?, cert_code = ? WHERE id = ?', new Date().toISOString(), row.cert_code || certCode(), id);
  return true;
}

function view(row, { courses, companies } = {}) {
  const course = courses ? courses.get(row.course_id) : getCourse(row.course_id, { includeDeleted: true });
  const company = companies ? companies.get(row.company_id) : findCompany(row.company_id);
  const lessons = course ? allLessons(course) : [];
  const completed = JSON.parse(row.completed_lessons).filter(id => lessons.some(l => l.id === id));
  return {
    id: row.id,
    employeeName: decrypt(row.employee_name_enc, nameAad(row.id)),
    companyId: row.company_id,
    companyName: company ? companyName(company) : '',
    courseId: row.course_id,
    courseTitle: course ? course.title : '',
    completedLessons: completed,
    progress: lessons.length ? Math.round((completed.length / lessons.length) * 100) : 0,
    quizPassed: Boolean(row.quiz_passed),
    quizScore: row.quiz_score,
    startedAt: row.started_at,
    completedAt: row.completed_at,
    certCode: row.cert_code,
    complete: Boolean(row.completed_at)
  };
}

const traineeView = row => ({ ...view(row), course: traineeCourse(getCourse(row.course_id, { includeDeleted: true })) });

module.exports = { findOrCreate, findById, issueIfFinished, view, traineeView };
