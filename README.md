# Em Conformidade

Plataforma de treinamentos corporativos com certificado automático, separada por empresa.

Esta versão roda com servidor próprio (Node.js). **Ela não funciona no GitHub Pages**, que só publica páginas estáticas.

## Segurança

| Proteção | Como funciona |
|---|---|
| **JWT** | Token de 10 minutos em cookie `httpOnly`, `Secure` e `SameSite=Strict`, com renovação de uso único. Sair, trocar a senha ou redefinir o acesso corta a sessão na hora. |
| **Criptografia** | AES-256-GCM no banco para nomes, e-mails, empresas, conteúdo dos treinamentos, links de vídeo, questionários, segredos do 2FA e registro de atividades. HTTPS obrigatório em produção. |
| **2FA** | Código de aplicativo autenticador, obrigatório para administrador, RH e Gerente, com 10 códigos de recuperação de uso único. Código já usado é recusado. |
| **Senhas** | Hash scrypt, mínimo de 12 caracteres e bloqueio de 15 minutos após 5 falhas. |
| **Funcionários** | Sem conta. Cada empresa tem um link secreto, que o gestor pode trocar. Sem o link, não há acesso a vídeos nem a questionários. |
| **Certificados** | O gabarito nunca vai ao navegador. Correção, progresso e emissão acontecem no servidor. |
| **Separação entre empresas** | A empresa vem sempre da sessão, nunca de um dado enviado pelo navegador. |
| **Navegador** | CSP, HSTS, proteção contra CSRF e clickjacking, e limite de requisições. |

## Rodar no computador

Requer Node.js 22.13 ou mais recente.

```bash
npm install
npm run setup
npm run create-admin -- voce@empresa.com
npm start
```

Abra `http://localhost:3001/#/admin` e entre com a senha provisória exibida. Rode os testes com `npm test`.

## Publicar

O arquivo `render.yaml` prepara a publicação no [Render](https://render.com). Qualquer hospedagem de Node.js com disco permanente também serve.

1. No Render, crie um **Blueprint** ligado a este repositório.
2. Preencha `APP_URL` com o endereço `https://` do site, `BOOTSTRAP_ADMIN_EMAIL` com o seu e-mail e `BOOTSTRAP_ADMIN_PASSWORD` com uma senha provisória.
3. Abra `/#/admin` no site, entre e conclua a troca de senha e o 2FA.
4. **Guarde uma cópia de `DATA_ENCRYPTION_KEY` em local seguro.** Sem ela, os dados não podem ser lidos, nem mesmo com backup.

Se usar outra hospedagem, defina as variáveis listadas em `.env.example`, com `NODE_ENV=production` e `TRUST_PROXY=1`.

## Uso

1. O administrador cadastra a empresa com os e-mails do RH e do Gerente e entrega as senhas provisórias.
2. RH e Gerente criam a própria senha e ativam o 2FA no primeiro acesso.
3. O gestor copia o link em **Link da equipe** e envia aos funcionários.
4. O funcionário abre o link, escolhe o treinamento e informa o nome.

Esqueceu a senha ou perdeu o celular e os códigos? O administrador usa **Redefinir** em Empresas. Para o próprio administrador, rode `npm run create-admin -- email` no servidor.

## Limites conhecidos

- **Vídeos:** o link só é entregue a quem tem acesso, mas um vídeo do YouTube ou do Vimeo comum ainda pode ser aberto por quem copiar o endereço. Para restringir de verdade, use um serviço com links assinados, como Bunny Stream ou Mux.
- **Tempo de aula:** o servidor exige que 90% da duração cadastrada tenha passado desde a abertura da aula, mas não confirma que o vídeo ficou tocando. Aulas com duração 0 não têm essa exigência.
- **Identidade do funcionário:** o nome é informado por quem usa o link. Quem tiver o link e souber o nome de um colega pode continuar o treinamento dele.
- **Banco:** SQLite em um único servidor. Configure backups do disco. Para vários servidores, será preciso migrar para PostgreSQL.
- **E-mail:** não há envio de e-mail, por isso a redefinição de senha é feita pelo administrador.
