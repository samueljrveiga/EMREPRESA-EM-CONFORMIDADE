'use strict';
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const config = require('./config');
const limits = require('./middleware/limits');
const { HttpError } = require('./middleware/auth');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', config.trustProxy);

app.get('/healthz', (req, res) => res.json({ ok: true }));

if (config.isProd) {
  app.use((req, res, next) => (req.secure ? next() : res.redirect(301, config.appUrl + req.originalUrl)));
}

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      // Os botões usam onclick; <script> embutido continua bloqueado.
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ['https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      mediaSrc: ["'self'", 'https:', 'blob:'],
      frameSrc: ['https://www.youtube-nocookie.com', 'https://player.vimeo.com'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
      frameAncestors: ["'none'"],
      ...(config.isProd ? { upgradeInsecureRequests: [] } : {})
    }
  },
  strictTransportSecurity: config.isProd ? { maxAge: 31536000, includeSubDomains: true } : false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginEmbedderPolicy: false
}));
app.use(cookieParser());

/* Proteção contra CSRF, além do SameSite=Strict: toda escrita precisa vir da
   própria origem e trazer um cabeçalho que outro site não consegue enviar. */
function sameOrigin(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin');
  if (req.get('x-requested-with') !== 'em-conformidade' || (origin && origin !== config.appOrigin)) {
    throw new HttpError(403, 'Requisição recusada.');
  }
  next();
}

app.use('/api', limits.general, (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); },
  sameOrigin, express.json({ limit: '256kb' }));
app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api/gestor', require('./routes/gestor.routes'));
app.use('/api/admin', require('./routes/admin.routes'));
app.use('/api', require('./routes/training.routes'));
app.use('/api', (req, res) => res.status(404).json({ erro: 'Endereço não encontrado.' }));

const modules = path.join(__dirname, '..', 'node_modules');
app.get('/vendor/chart.js', (req, res) => res.sendFile(path.join(modules, 'chart.js/dist/chart.umd.min.js')));
app.get('/vendor/jspdf.js', (req, res) => res.sendFile(path.join(modules, 'jspdf/dist/jspdf.umd.min.js')));
app.use(express.static(path.join(__dirname, '..', 'public'), { etag: true, lastModified: false, setHeaders: res => res.set('Cache-Control', 'no-cache') }));

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err instanceof HttpError) return res.status(err.status).json({ erro: err.message, code: err.code });
  if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') return res.status(400).json({ erro: 'Dados inválidos.' });
  console.error(err);
  res.status(500).json({ erro: 'Erro interno. Tente novamente.' });
});

module.exports = app;
