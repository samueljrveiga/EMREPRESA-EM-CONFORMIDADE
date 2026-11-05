'use strict';
const db = require('./db');
const { encrypt, decrypt } = require('./crypto');

const aad = id => `courses.data:${id}`;

/* Título, aulas, links de vídeo, perguntas e gabarito ficam cifrados no banco. */
function saveCourse(id, data) {
  const now = new Date().toISOString();
  const enc = encrypt(JSON.stringify(data), aad(id));
  db.run(`INSERT INTO courses (id, data_enc, created_at, updated_at) VALUES (?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET data_enc = excluded.data_enc, updated_at = excluded.updated_at, deleted_at = NULL`,
  id, enc, now, now);
}

const readRow = row => ({ id: row.id, ...JSON.parse(decrypt(row.data_enc, aad(row.id))) });
const listCourses = () => db.all('SELECT * FROM courses WHERE deleted_at IS NULL ORDER BY created_at, id').map(readRow);

function getCourse(id, { includeDeleted = false } = {}) {
  const row = db.get('SELECT * FROM courses WHERE id = ?', id);
  return row && (includeDeleted || !row.deleted_at) ? readRow(row) : null;
}

const allLessons = course => course.modules.flatMap(m => m.lessons);

/* Visão pública: sem links de vídeo e sem perguntas. */
const publicCourse = c => ({
  id: c.id, title: c.title, description: c.description, cover: c.cover, color: c.color,
  quizCount: (c.quiz || []).length,
  modules: c.modules.map(m => ({
    id: m.id, title: m.title,
    lessons: m.lessons.map(l => ({ id: l.id, title: l.title, durationMin: l.durationMin }))
  }))
});

/* Visão do funcionário: inclui vídeos e perguntas, nunca o gabarito. */
const traineeCourse = c => ({
  ...publicCourse(c),
  modules: c.modules,
  quiz: (c.quiz || []).map(q => ({ q: q.q, options: q.options }))
});

const adminCourse = c => ({ ...c, quizCount: (c.quiz || []).length });

const defaults = () => {
  const one = title => [{ id: 'm1', title: 'Videoaula', lessons: [{ id: 'l1', title, videoUrl: '', durationMin: 0 }] }];
  return [
    { id: 'crs_compliance', title: 'Compliance', cover: '⚖️', color: '#1F5C4A',
      description: 'Ética, integridade e a Lei Anticorrupção no dia a dia: conflito de interesses, brindes e presentes, e o papel de cada funcionário.',
      modules: one('Compliance e integridade no trabalho'),
      quiz: [
        { q: 'O que significa compliance?', options: ['Bater as metas de vendas do mês', 'Agir de acordo com as leis, as normas e as políticas internas da empresa', 'Reduzir custos operacionais'], correct: 1 },
        { q: 'Pela Lei Anticorrupção (Lei 12.846/2013), a empresa responde por atos lesivos à administração pública:', options: ['Mesmo sem prova de culpa dos dirigentes (responsabilidade objetiva)', 'Somente se o presidente tiver participado', 'Apenas em contratos acima de R$ 1 milhão'], correct: 0 },
        { q: 'Um fornecedor oferece um presente caro durante uma negociação. O que fazer?', options: ['Aceitar, desde que ninguém fique sabendo', 'Aceitar e retribuir com outro presente', 'Recusar ou seguir a política de brindes e informar o responsável'], correct: 2 },
        { q: 'Conflito de interesses acontece quando:', options: ['Um interesse pessoal pode influenciar uma decisão profissional', 'Duas áreas discordam sobre um projeto', 'Um cliente faz uma reclamação'], correct: 0 },
        { q: 'Ao perceber uma possível irregularidade, você deve:', options: ['Ignorar, porque não é da sua área', 'Relatar pelo canal de denúncias ou à área de compliance', 'Comentar com os colegas para saber se é verdade'], correct: 1 }
      ] },
    { id: 'crs_lgpd', title: 'LGPD', cover: '🛡️', color: '#2C4A63',
      description: 'Como tratar dados pessoais de clientes, fornecedores e colegas de acordo com a Lei Geral de Proteção de Dados.',
      modules: one('LGPD na prática'),
      quiz: [
        { q: 'Qual é o número da Lei Geral de Proteção de Dados?', options: ['Lei 8.078/1990', 'Lei 13.709/2018', 'Lei 12.965/2014'], correct: 1 },
        { q: 'O que é dado pessoal?', options: ['Somente CPF e RG', 'Qualquer dado de uma empresa', 'Informação relacionada a uma pessoa identificada ou identificável'], correct: 2 },
        { q: 'Qual destes é um dado pessoal sensível?', options: ['Informação de saúde', 'E-mail corporativo', 'Cargo na empresa'], correct: 0 },
        { q: 'Qual órgão fiscaliza o cumprimento da LGPD?', options: ['Procon', 'Receita Federal', 'ANPD (Autoridade Nacional de Proteção de Dados)'], correct: 2 },
        { q: 'Você precisa enviar uma planilha com dados de clientes. O que fazer?', options: ['Usar apenas os canais autorizados pela empresa', 'Mandar para o seu e-mail pessoal se for urgente', 'Enviar e apagar depois'], correct: 0 }
      ] },
    { id: 'crs_nr1', title: 'NR-1', cover: '🦺', color: '#6B5000',
      description: 'Gerenciamento de riscos ocupacionais, o PGR e os riscos psicossociais incluídos na atualização da norma.',
      modules: one('NR-1 e o gerenciamento de riscos'),
      quiz: [
        { q: 'Do que trata a NR-1?', options: ['Disposições gerais e gerenciamento de riscos ocupacionais', 'Instalações elétricas', 'Trabalho em altura'], correct: 0 },
        { q: 'O PGR (Programa de Gerenciamento de Riscos) deve conter:', options: ['Apenas a lista de EPIs', 'Inventário de riscos e plano de ação', 'Somente o organograma da empresa'], correct: 1 },
        { q: 'Com a atualização da NR-1, o gerenciamento de riscos passou a incluir:', options: ['Apenas riscos de ruído', 'Somente riscos de incêndio', 'Fatores de risco psicossociais relacionados ao trabalho'], correct: 2 },
        { q: 'Qual é um exemplo de risco psicossocial?', options: ['Sobrecarga de trabalho e metas excessivas', 'Piso molhado', 'Ruído de máquinas'], correct: 0 },
        { q: 'Qual é o papel do trabalhador no gerenciamento de riscos?', options: ['Esperar a fiscalização', 'Seguir os procedimentos de segurança e informar situações de risco', 'Ajustar sozinho os equipamentos'], correct: 1 }
      ] }
  ];
};

function seedCourses() {
  if (db.get('SELECT COUNT(*) AS n FROM courses').n > 0) return;
  defaults().forEach(({ id, ...data }) => saveCourse(id, data));
}

module.exports = { saveCourse, listCourses, getCourse, allLessons, publicCourse, traineeCourse, adminCourse, seedCourses };
