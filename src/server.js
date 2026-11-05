'use strict';
const config = require('./config');
const app = require('./app');
const { seedCourses } = require('./lib/courses');
const { bootstrapAdmin } = require('./lib/accounts');

(async () => {
  seedCourses();
  await bootstrapAdmin(config);
  app.listen(config.port, () => console.log(`Em Conformidade rodando em ${config.appUrl} (porta ${config.port})`));
})().catch(err => { console.error(err); process.exit(1); });
