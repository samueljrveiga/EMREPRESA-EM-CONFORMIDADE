'use strict';
const db = require('./db');
const { encrypt, decrypt, newId } = require('./crypto');

function audit(type, detail, companyId = null) {
  const id = newId('aud');
  db.run('INSERT INTO audit (id, at, type, company_id, detail_enc) VALUES (?, ?, ?, ?, ?)',
    id, new Date().toISOString(), type, companyId, encrypt(String(detail).slice(0, 300), `audit:${id}`));
}

function recentAudit(limit = 100) {
  return db.all('SELECT * FROM audit ORDER BY seq DESC LIMIT ?', limit)
    .map(a => ({ at: a.at, type: a.type, detail: decrypt(a.detail_enc, `audit:${a.id}`) }));
}

module.exports = { audit, recentAudit };
