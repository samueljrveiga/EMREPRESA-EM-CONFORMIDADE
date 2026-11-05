'use strict';
/* Uso: npm run create-admin -- email@empresa.com
   Cria um administrador ou redefine o acesso de um existente (senha provisória nova e 2FA refeito). */
const { email } = require('../src/lib/validate');
const accounts = require('../src/lib/accounts');

(async () => {
  const parsed = email.safeParse(process.argv[2] || '');
  if (!parsed.success) { console.error('Informe um e-mail válido: npm run create-admin -- voce@empresa.com'); process.exit(1); }
  const existing = accounts.findByEmail(parsed.data);
  if (existing && existing.role !== 'admin') { console.error('Esse e-mail pertence a um usuário de empresa.'); process.exit(1); }
  const temp = existing ? await accounts.resetCredentials(existing.id) : (await accounts.createUser({ role: 'admin', email: parsed.data })).temporaryPassword;
  console.log(`Administrador: ${parsed.data}\nSenha provisória (aparece só agora): ${temp}`);
})();
