'use strict';
const { z } = require('zod');

const LIMITS = { name: 120, title: 140, desc: 1000, url: 500, option: 200 };
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const id = z.string().regex(ID);

function httpsUrl(value) {
  try { const url = new URL(String(value || '').trim()); return url.protocol === 'https:' ? url.href : ''; }
  catch { return ''; }
}

/* Somente YouTube, Vimeo ou arquivo https direto. */
function isAllowedVideo(value) {
  const href = httpsUrl(value);
  if (!href) return false;
  const url = new URL(href);
  const host = url.hostname.replace(/^www\./, '');
  if (host === 'youtu.be') return /^\/[A-Za-z0-9_-]{6,20}$/.test(url.pathname);
  if (['youtube.com', 'm.youtube.com', 'youtube-nocookie.com'].includes(host)) {
    const v = url.pathname === '/watch' ? url.searchParams.get('v') : (url.pathname.match(/^\/(?:embed|shorts)\/([^/?]+)/) || [])[1];
    return /^[A-Za-z0-9_-]{6,20}$/.test(v || '');
  }
  if (host === 'vimeo.com' || host === 'player.vimeo.com') return /\d{5,12}/.test(url.pathname);
  return /\.(mp4|webm|ogg)$/i.test(url.pathname);
}

const normalizeName = s => String(s || '').trim().replace(/\s+/g, ' ');

const employeeName = z.string().transform(normalizeName).pipe(
  z.string().min(3).max(LIMITS.name)
    .regex(/^[\p{L}\p{M}' .-]+$/u, 'O nome deve conter apenas letras, espaços, apóstrofo ou hífen.')
    .refine(v => v.split(' ').length >= 2, 'Informe seu nome completo.')
);

const email = z.string().trim().toLowerCase().max(160).email();

function passwordProblem(password, userEmail = '') {
  if (typeof password !== 'string' || password.length < 12) return 'A senha deve ter pelo menos 12 caracteres.';
  if (password.length > 128) return 'A senha deve ter no máximo 128 caracteres.';
  if (/^(.)\1+$/.test(password)) return 'A senha não pode ser um único caractere repetido.';
  const lower = password.toLowerCase();
  if (['123456789012', '1234567890123', 'qwertyuiopas', 'senhasenhasenha', 'emconformidade', 'empresaemconformidade'].some(w => lower.includes(w))) {
    return 'Essa senha é fácil demais de adivinhar.';
  }
  const local = userEmail.split('@')[0];
  if (local.length >= 4 && lower.includes(local)) return 'A senha não pode conter o seu e-mail.';
  return null;
}

const FILL = 'Preencha todas as perguntas e opções do questionário.';
const lesson = z.object({
  id,
  title: z.string().trim().max(LIMITS.title),
  durationMin: z.coerce.number().int().min(0).max(600).catch(0),
  videoUrl: z.string().trim().max(LIMITS.url).optional().default('')
    .refine(v => !v || isAllowedVideo(v), 'Link de vídeo inválido. Use YouTube, Vimeo ou um arquivo https (.mp4/.webm).')
});
const quizQuestion = z.object({
  q: z.string().trim().min(1, FILL).max(LIMITS.option),
  options: z.array(z.string().trim().min(1, FILL).max(LIMITS.option)).min(2).max(8),
  correct: z.coerce.number().int().min(0)
}).refine(q => q.correct < q.options.length, 'Marque a resposta correta de cada pergunta.');

const course = z.object({
  title: z.string().trim().min(1).max(LIMITS.title),
  description: z.string().max(LIMITS.desc).default(''),
  cover: z.string().transform(s => Array.from(s).slice(0, 4).join('') || '📘'),
  color: z.string().regex(/^#[0-9a-fA-F]{6}$/).catch('#1F5C4A'),
  modules: z.array(z.object({ id, title: z.string().trim().max(LIMITS.title), lessons: z.array(lesson).max(200) })).max(50),
  quiz: z.array(quizQuestion).max(100).default([])
}).superRefine((c, ctx) => {
  const ids = c.modules.flatMap(m => m.lessons.map(l => l.id));
  if (new Set(ids).size !== ids.length) ctx.addIssue({ code: 'custom', message: 'Há aulas com identificador repetido.' });
});

module.exports = { z, id, ID, LIMITS, email, employeeName, course, httpsUrl, normalizeName, passwordProblem };
