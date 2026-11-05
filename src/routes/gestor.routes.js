'use strict';
const express = require('express');
const config = require('../config');
const db = require('../lib/db');
const { audit } = require('../lib/audit');
const { findCompany, companyName, companyLink, setCompanyLink } = require('../lib/accounts');
const enrollments = require('../lib/enrollments');
const auth = require('../middleware/auth');

const router = express.Router();
router.use(auth.requireAuth, auth.requireRole('rh', 'gerente'));

/* A empresa vem sempre da sessão, nunca de um parâmetro enviado pelo navegador. */
const companyEnrollments = companyId =>
  db.all('SELECT * FROM enrollments WHERE company_id = ? ORDER BY started_at DESC', companyId).map(r => enrollments.view(r));

const linkUrl = token => `${config.appUrl}/#/t/${token}`;

router.get('/data', (req, res) => {
  const company = findCompany(req.user.company_id);
  res.json({
    company: { id: company.id, name: companyName(company) },
    link: linkUrl(companyLink(company)),
    enrollments: companyEnrollments(company.id)
  });
});

router.post('/link/rotate', (req, res) => {
  const token = setCompanyLink(req.user.company_id);
  audit('seguranca', 'Link dos funcionários trocado', req.user.company_id);
  res.json({ link: linkUrl(token) });
});

/* Impede "CSV injection": fórmulas executadas ao abrir no Excel. */
function csvCell(value) {
  let s = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

router.get('/export.csv', (req, res) => {
  const date = iso => (iso ? new Date(iso).toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' }) : '');
  const rows = companyEnrollments(req.user.company_id).map(e =>
    [e.employeeName, e.courseTitle, e.progress, e.complete ? 'Concluido' : 'Em andamento', date(e.completedAt)].map(csvCell).join(','));
  audit('exportacao', 'CSV da equipe exportado', req.user.company_id);
  res.type('text/csv; charset=utf-8').attachment('relatorio_equipe.csv')
    .send(`﻿Funcionario,Treinamento,Progresso(%),Status,Concluido em\n${rows.join('\n')}\n`);
});

module.exports = router;
