'use strict';
const { HttpError } = require('../middleware/auth');
const { userEmail, companyName, findCompany } = require('../lib/accounts');

function parse(schema, data) {
  const result = schema.safeParse(data);
  if (result.success) return result.data;
  const message = result.error.issues[0]?.message || '';
  throw new HttpError(400, message.endsWith('.') ? message : 'Dados inválidos. Confira os campos.');
}

function publicUser(user) {
  const company = user.company_id ? findCompany(user.company_id) : null;
  return {
    role: user.role === 'admin' ? 'admin' : 'gestor',
    profile: user.role,
    email: userEmail(user),
    companyId: user.company_id,
    companyName: company ? companyName(company) : null
  };
}

module.exports = { parse, publicUser };
