'use strict';
const { rateLimit } = require('express-rate-limit');

const limiter = (windowMinutes, limit, extra = {}) => rateLimit({
  windowMs: windowMinutes * 60e3, limit, standardHeaders: 'draft-8', legacyHeaders: false,
  message: { erro: 'Muitas tentativas. Aguarde um pouco e tente novamente.' }, ...extra
});

/* Limites por IP folgados: funcionários de uma mesma empresa costumam compartilhar o IP.
   As tentativas de senha e de 2FA também têm bloqueio por conta. */
module.exports = {
  general: limiter(1, 1500),
  login: limiter(15, 60),
  link: limiter(15, 300),
  quiz: limiter(1, 10, { keyGenerator: req => `quiz:${req.params.id}` })
};
