/* ============================= CAMADA DE DADOS =============================
   O navegador não guarda nem decide nada importante: login, progresso, correção
   do questionário e certificados são validados pelo servidor. Os tokens ficam em
   cookies httpOnly, fora do alcance do JavaScript desta página. */
const API_HEADERS = { 'Content-Type':'application/json', 'X-Requested-With':'em-conformidade' };
let DB = { settings:{denounceUrl:''}, companies:[], courses:[], enrollments:[], audit:[] };
let TRAINING = {};              // treinamentos abertos pelo funcionário (por id)
let TRAINEE = null;             // empresa do link usado pelo funcionário
let GESTOR_LINK = '';

class ApiError extends Error { constructor(status, message, code){ super(message); this.status = status; this.code = code; } }

let refreshing = null;
function refreshSession(){
  refreshing = refreshing || fetch('/api/auth/refresh', { method:'POST', headers:API_HEADERS, credentials:'same-origin' })
    .then(r=>r.ok).catch(()=>false).finally(()=>{ refreshing = null; });
  return refreshing;
}
async function api(path, { method='GET', body, retry=true, raw=false } = {}){
  let res;
  try{
    res = await fetch('/api'+path, { method, headers:API_HEADERS, credentials:'same-origin', body: body===undefined ? undefined : JSON.stringify(body) });
  }catch(e){ throw new ApiError(0, 'Sem conexão com o servidor. Tente novamente.'); }
  if(raw && res.ok) return res;
  const data = await res.json().catch(()=>({}));
  if(res.status===401 && data.code==='unauthenticated' && SESSION.role){
    if(retry && await refreshSession()) return api(path, { method, body, retry:false, raw });
    endSession('Sua sessão expirou. Entre novamente.');
  }
  if(!res.ok) throw new ApiError(res.status, data.erro || 'Não foi possível concluir a operação.', data.code);
  return data;
}
function applySession(user){ SESSION = { ...user, startedAt:Date.now() }; lastActivity = Date.now(); }
function endSession(message){
  SESSION = { role:null, companyId:null };
  DB.companies = []; DB.enrollments = []; DB.audit = []; GESTOR_LINK = '';
  if(message) toast(message);
  goTo('#/');
}
async function loadBootstrap(){
  let b = await api('/bootstrap');
  if(b.canRefresh && await refreshSession()) b = await api('/bootstrap');
  DB.courses = b.courses; DB.settings = b.settings; TRAINEE = b.trainee;
  if(b.user) applySession(b.user);
}
async function loadGestor(){
  const d = await api('/gestor/data');
  DB.companies = [d.company]; DB.enrollments = d.enrollments; GESTOR_LINK = d.link;
}
async function loadAdmin(){
  const d = await api('/admin/data');
  DB.companies = d.companies; DB.courses = d.courses; DB.enrollments = d.enrollments; DB.audit = d.audit;
}

/* Identificadores de módulos e aulas novos no editor de treinamentos. */
function randStr(len){
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = new Uint8Array(len); crypto.getRandomValues(bytes);
  return Array.from(bytes, b=>alphabet[b % alphabet.length]).join('');
}
function uid(prefix){ return prefix + "_" + randStr(12).toLowerCase(); }

/* ============================= SEGURANÇA ============================= */
const SEC = { MAX_ATTEMPTS:5, LOCK_MINUTES:15, IDLE_MINUTES:15, MIN_PASSWORD:12 };
const LIMITS = { name:120, title:140, desc:1000, url:500, option:200 };
const sleep = ms => new Promise(r=>setTimeout(r,ms));

/* ---------- Saneamento de entradas ---------- */
function clampStr(s, max){ return String(s??'').slice(0, max); }
function safeColor(c){ return /^#[0-9a-fA-F]{6}$/.test(c||'') ? c : '#1F5C4A'; }
function safeId(s){ return /^[A-Za-z0-9_-]{1,64}$/.test(s||'') ? s : ''; }
/* Só aceita links https:// (bloqueia javascript:, data:, http: etc.). */
function safeHttpsUrl(u){
  try{ const url = new URL(String(u||'').trim()); return url.protocol==='https:' ? url.href : ''; }catch(e){ return ''; }
}
/* Vídeos: aceita apenas YouTube, Vimeo (convertidos para URL de incorporação) ou arquivo https direto. */
function videoSource(u){
  const href = safeHttpsUrl(u); if(!href) return null;
  const url = new URL(href); const host = url.hostname.replace(/^www\./,'');
  let id = null;
  if(host==='youtu.be') id = url.pathname.slice(1);
  else if(host==='youtube.com' || host==='m.youtube.com' || host==='youtube-nocookie.com'){
    if(url.pathname==='/watch') id = url.searchParams.get('v');
    else { const m = url.pathname.match(/^\/(embed|shorts)\/([^/?]+)/); if(m) id = m[2]; }
  }
  if(id !== null) return /^[A-Za-z0-9_-]{6,20}$/.test(id) ? { kind:'iframe', src:`https://www.youtube-nocookie.com/embed/${id}` } : null;
  if(host==='vimeo.com' || host==='player.vimeo.com'){
    const m = url.pathname.match(/(\d{5,12})/); return m ? { kind:'iframe', src:`https://player.vimeo.com/video/${m[1]}` } : null;
  }
  if(/\.(mp4|webm|ogg)$/i.test(url.pathname)) return { kind:'video', src:href };
  return null;
}

/* ---------- Sessão com expiração ---------- */
let lastActivity = Date.now();
['click','keydown','mousemove','touchstart','scroll'].forEach(ev=>window.addEventListener(ev, ()=>{ lastActivity = Date.now(); }, {passive:true}));
setInterval(()=>{
  if(!SESSION.role) return;
  if(Date.now() - lastActivity > SEC.IDLE_MINUTES*60000) logout('Sua sessão expirou por segurança. Entre novamente.');
}, 30000);
/* Mantém a sessão viva enquanto a pessoa usa a tela sem chamar o servidor. */
setInterval(()=>{ if(SESSION.role && Date.now() - lastActivity < 5*60000) refreshSession(); }, 5*60000);
async function logout(message){
  try{ await api('/auth/logout', { method:'POST', body:{}, retry:false }); }catch(e){}
  endSession(message);
}


/* ---------- Confirmação dentro da página (a página publicada não exibe confirm/prompt do navegador) ---------- */
function askConfirm(message, okLabel, requireText){
  return new Promise(resolve=>{
    const root = document.getElementById('modalRoot') || (()=>{ const d=document.createElement('div'); d.id='modalRoot'; document.getElementById('app').appendChild(d); return d; })();
    root.innerHTML = `<div class="modal-backdrop"><div class="modal" role="dialog" aria-modal="true">
      <div class="modal-head"><h3 style="margin:0; font-size:17px">Confirmar</h3></div>
      <div class="modal-body"><p style="margin:0 0 16px">${escapeHtml(message)}</p>
        ${requireText?`<div class="field"><label class="field-label" for="cfText">Digite ${escapeHtml(requireText)} para confirmar</label><input class="input" id="cfText" autocomplete="off"></div>`:''}
        <div style="display:flex; gap:8px; justify-content:flex-end"><button class="btn btn-ghost" id="cfNo">Cancelar</button><button class="btn btn-danger" id="cfYes">${escapeHtml(okLabel||'Confirmar')}</button></div></div></div></div>`;
    const done = v=>{ root.innerHTML=''; resolve(v); };
    document.getElementById('cfNo').onclick = ()=>done(false);
    document.getElementById('cfYes').onclick = ()=>{
      if(requireText && document.getElementById('cfText').value.trim()!==requireText){ toast(`Digite ${requireText} para confirmar.`); return; }
      done(true);
    };
    (document.getElementById('cfText')||document.getElementById('cfNo')).focus();
  });
}
function fmtDate(iso){ if(!iso) return "—"; const d = new Date(iso); return d.toLocaleDateString('pt-BR', {day:'2-digit',month:'2-digit',year:'numeric'}); }
function totalLessons(course){ return course.modules.reduce((a,m)=>a+m.lessons.length,0); }
function totalDuration(course){ const min = course.modules.reduce((a,m)=>a+m.lessons.reduce((b,l)=>b+(l.durationMin||0),0),0); if(!min) return ''; const h=Math.floor(min/60), m=min%60; return h>0? (h+"h "+(m?m+"min":"")).trim() : (m+"min"); }
function fmtDur(n){ return n>0 ? n+' min' : ''; }
function lessonsLabel(n){ return n+' aula'+(n!==1?'s':''); }
function courseById(id){ return DB.courses.find(c=>c.id===id); }
function companyById(id){ return DB.companies.find(c=>c.id===id); }
function enrollmentProgress(en){ return en.progress||0; }
function isEnrollmentComplete(en){ return !!en.complete; }


function toast(msg){
  const wrap = document.getElementById('toastWrap');
  const el = document.createElement('div'); el.className='toast'; el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(()=>{ el.style.transition='opacity .3s'; el.style.opacity='0'; setTimeout(()=>el.remove(),300); }, 2600);
}

/* ============================= SESSION ============================= */
let SESSION = { role:null, companyId:null }; // role: 'admin' | 'gestor'


/* ============================= ROUTER ============================= */
window.addEventListener('hashchange', route);
window.addEventListener('DOMContentLoaded', async ()=>{
  try{ await loadBootstrap(); }
  catch(e){ document.getElementById('app').innerHTML = `<div class="wrap empty" style="padding-top:60px"><div class="emoji">⚠️</div><b>Não foi possível carregar a plataforma.</b><br>Atualize a página em instantes.</div>`; return; }
  route();
});
function nav(hash){ window.location.hash = hash; window.scrollTo({top:0,behavior:'instant' in window?'instant':'auto'}); }
/* Navega e recarrega os dados mesmo que o endereço já seja o de destino. */
function goTo(hash){ if(window.location.hash===hash) route(); else nav(hash); }
async function route(){
  const parts = currentRoute();
  try{
    if(parts[0]==='t' && parts[1]){
      // O link da empresa vira uma sessão e sai do histórico do navegador.
      try{
        const r = await api('/trainee/enter', { method:'POST', body:{ token:parts[1] } });
        TRAINEE = r.trainee; toast(`Acesso liberado: ${TRAINEE.companyName}.`);
      }catch(e){ toast(e.message); }
      location.replace('#/'); return;
    }
    if((parts[0]==='aula' || parts[0]==='certificado') && parts[1] && !TRAINING[parts[1]]){
      TRAINING[parts[1]] = (await api('/enrollments/'+parts[1])).enrollment;
    }
    if(parts[0]==='gestor' && SESSION.role==='gestor'){
      if(parts[1]!=='dashboard'){ location.replace('#/gestor/dashboard/visao'); return; }
      await loadGestor();
    }
    if(parts[0]==='admin' && SESSION.role==='admin'){
      if(parts[1]!=='dashboard'){ location.replace('#/admin/dashboard/visao'); return; }
      await loadAdmin();
    }
  }catch(e){ toast(e.message); }
  render();
}

function currentRoute(){
  const h = window.location.hash.replace(/^#\/?/, '');
  // Só aceita segmentos de rota com caracteres seguros (evita injeção via URL).
  const parts = h.split('/').filter(Boolean).map(p=>safeId(decodeURIComponentSafe(p)));
  return parts;
}
function decodeURIComponentSafe(s){ try{ return decodeURIComponent(s); }catch(e){ return ''; }
}

/* ============================= SHELL / NAV ============================= */
function topbar(activeKey){
  const links = [
    {key:'catalogo', label:'Treinamentos', hash:'#/'},
    {key:'gestor', label:'Painel do Gestor', hash:'#/gestor'},
    {key:'admin', label:'Administração', hash:'#/admin'},
    {key:'denuncias', label:'Canal de Denúncias', hash:'#/denuncias'},
  ];
  const linksHtml = links.map(l=>`<button class="nav-link ${activeKey===l.key?'active':''}" onclick="nav('${l.hash}')">${l.label}</button>`).join('');
  return `
  <div class="topbar">
    <div class="wrap topbar-inner">
      <button class="brand" onclick="nav('#/')"><svg class="brand-mark" viewBox="0 0 30 30" aria-hidden="true"><circle cx="15" cy="15" r="13.5" fill="none" stroke="#1F5C4A" stroke-width="2.5"/><circle cx="15" cy="15" r="9" fill="#F2C230"/><path d="M10.5 15.2l3 3 5.8-6.2" fill="none" stroke="#17201B" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>Em Conformidade</button>
      <div class="nav-links desktop">${linksHtml}</div>
      <button class="nav-mobile-toggle" onclick="toggleMobileMenu()">☰</button>
    </div>
    <div class="wrap"><div class="mobile-menu" id="mobileMenu">${linksHtml}</div></div>
  </div>`;
}
function toggleMobileMenu(){ document.getElementById('mobileMenu').classList.toggle('open'); }

function footer(){
  return `<footer class="site-footer wrap">Em Conformidade, plataforma de treinamentos corporativos. Dados protegidos com criptografia.</footer>`;
}

/* ============================= MAIN RENDER ============================= */
function render(){
  const parts = currentRoute();
  const root = document.getElementById('app');
  let activeKey = 'catalogo', body = '';

  if(parts.length===0){ body = viewCatalog(); activeKey='catalogo'; }
  else if(parts[0]==='curso'){ body = viewCourseDetail(parts[1]); activeKey='catalogo'; }
  else if(parts[0]==='aula'){ body = viewPlayer(parts[1]); activeKey='catalogo'; }
  else if(parts[0]==='certificado'){ body = viewCertificate(parts[1]); activeKey='catalogo'; }
  else if(parts[0]==='denuncias'){ body = viewDenuncias(); activeKey='denuncias'; }
  else if(parts[0]==='gestor'){
    activeKey='gestor';
    if(SESSION.role==='gestor' && parts[1]==='dashboard'){ body = viewGestorDashboard(parts[2]||'visao'); }
    else { body = viewLogin('gestor'); }
  }
  else if(parts[0]==='admin'){
    activeKey='admin';
    if(SESSION.role==='admin' && parts[1]==='dashboard'){ body = viewAdminDashboard(parts[2]||'visao'); }
    else { body = viewLogin('admin'); }
  }
  else { body = viewCatalog(); }

  root.innerHTML = topbar(activeKey) + `<main class="wrap" style="padding-top:28px; padding-bottom:40px; min-height:60vh">${body}</main>` + footer();
  afterRenderHooks();
}
let pendingChartJobs = [];
function afterRenderHooks(){
  const jobs = pendingChartJobs; pendingChartJobs = [];
  jobs.forEach(fn=>{ try{ fn(); }catch(e){ console.error(e); } });
}

/* ============================= PUBLIC CATALOG ============================= */
function sealSvg(){
  return `<svg class="seal" viewBox="0 0 200 200" role="img" aria-label="Selo Em Conformidade">
    <defs><path id="sealPath" d="M100,100 m-74,0 a74,74 0 1,1 148,0 a74,74 0 1,1 -148,0"/></defs>
    <circle cx="100" cy="100" r="96" fill="none" stroke="currentColor" stroke-width="3"/>
    <circle cx="100" cy="100" r="56" fill="none" stroke="currentColor" stroke-width="2"/>
    <g class="seal-ring"><text font-family="Bricolage Grotesque, sans-serif" font-size="14" font-weight="700" fill="currentColor">
      <textPath href="#sealPath" textLength="458" lengthAdjust="spacing">EM CONFORMIDADE ✦ TREINAMENTO CONCLUÍDO ✦</textPath></text></g>
    <circle cx="100" cy="100" r="44" fill="var(--signal)"/>
    <path d="M80 101 l14 14 l27 -30" fill="none" stroke="var(--ink)" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}
function viewCatalog(){
  const courses = DB.courses;
  const list = courses.map(c=>`
    <div class="course-item">
      <div class="course-icon" aria-hidden="true">${escapeHtml(c.cover)}</div>
      <div>
        <h3>${escapeHtml(c.title)}</h3>
        <p>${escapeHtml(c.description)}</p>
        <div class="course-meta">${[lessonsLabel(totalLessons(c)), totalDuration(c) ? totalDuration(c)+' no total' : '', c.quizCount ? 'questionário final' : '', 'certificado'].filter(Boolean).join(', ')}</div>
      </div>
      <button class="btn btn-primary" onclick="nav('#/curso/${c.id}')">Começar treinamento</button>
    </div>`).join('');

  return `
  <section class="home-hero">
    <div>
      <h1>Seu treinamento obrigatório, sem complicação.</h1>
      <p>Abra o link enviado pela sua empresa, escolha o treinamento, informe seu nome e assista às aulas. O certificado sai assim que você termina.</p>
      <ol class="home-steps">
        <li>Escolha o treinamento</li>
        <li>Assista às aulas</li>
        <li>Baixe o certificado</li>
      </ol>
    </div>
    ${sealSvg()}
  </section>

  <section class="home-section">
    <h2>Treinamentos disponíveis</h2>
    <p class="lead">${TRAINEE ? `Você está acessando pela empresa <b>${escapeHtml(TRAINEE.companyName)}</b>. Não precisa criar conta.` : 'Para começar, abra o link de acesso enviado pelo RH da sua empresa.'}</p>
    <div class="course-list">
      ${list || `<div class="empty">Nenhum treinamento publicado ainda. O administrador pode cadastrar treinamentos no painel de Administração.</div>`}
    </div>
  </section>

  <nav class="access-row" aria-label="Outros acessos">
    <button class="access-link" onclick="nav('#/gestor')"><strong>Painel do gestor</strong><span>Acompanhe sua equipe e baixe certificados.</span></button>
    <button class="access-link" onclick="nav('#/admin')"><strong>Administração</strong><span>Cadastre empresas, treinamentos e aulas.</span></button>
    <button class="access-link danger" onclick="nav('#/denuncias')"><strong>Canal de denúncias</strong><span>Relate uma conduta de forma confidencial.</span></button>
  </nav>`;
}

function viewCourseDetail(courseId){
  const course = courseById(courseId);
  if(!course) return `<div class="empty">Treinamento não encontrado.</div>`;
  const modulesHtml = course.modules.map((m,i)=>`
    <div class="card pad" style="margin-bottom:10px">
      <div style="font-weight:700; font-size:14.5px; margin-bottom:8px">Módulo ${i+1} · ${escapeHtml(m.title)}</div>
      ${m.lessons.map(l=>`<div style="display:flex; justify-content:space-between; padding:7px 0; font-size:13.5px; color:var(--ink-soft); border-top:1px solid var(--border-soft)"><span>▸ ${escapeHtml(l.title)}</span><span>${fmtDur(l.durationMin)}</span></div>`).join('')}
    </div>`).join('');

  return `
  <button class="btn btn-ghost btn-sm" style="margin-bottom:18px" onclick="nav('#/')">← Voltar</button>
  <div style="display:grid; grid-template-columns:1.4fr 1fr; gap:28px" class="course-detail-grid">
  <div>
    <div class="course-cover" style="background:${safeColor(course.color)}; height:170px; border-radius:16px; font-size:52px; margin-bottom:18px">${escapeHtml(course.cover)}</div>
    <h1 style="font-size:26px; margin:0 0 10px">${escapeHtml(course.title)}</h1>
    <p style="color:var(--ink-soft); font-size:15px; line-height:1.6">${escapeHtml(course.description)}</p>
    <div style="display:flex; gap:18px; margin:18px 0; font-size:13.5px; color:var(--ink-soft)">
      <span>📚 ${lessonsLabel(totalLessons(course))}</span>${totalDuration(course)?`<span>⏱ ${totalDuration(course)}</span>`:''}
      ${course.quizCount ? `<span>📝 Questionário final</span>`:''}
    </div>
    <h3 style="font-size:15px; margin:22px 0 12px">Conteúdo do treinamento</h3>
    ${modulesHtml}
  </div>
  <div>
    <div class="card pad">
      <div class="section-title">Começar treinamento</div>
      ${TRAINEE ? `<p style="font-size:13.5px; color:var(--ink-soft); margin:4px 0 16px">Informe seu nome completo para iniciar ou continuar. Empresa: <b>${escapeHtml(TRAINEE.companyName)}</b>.</p>
      <div class="field"><label class="field-label" for="empName">Nome completo</label><input class="input" id="empName" placeholder="Ex: Ana Paula Ribeiro" maxlength="${LIMITS.name}" autocomplete="name"></div>
      <button class="btn btn-accent btn-block" id="startBtn" onclick="startOrResume('${course.id}')">Iniciar treinamento →</button>`
      : `<p style="font-size:13.5px; color:var(--ink-soft); margin:4px 0 0">🔒 Os treinamentos são liberados pelo link de acesso da sua empresa. Peça o link ao RH e abra-o neste aparelho.</p>`}
    </div>
  </div>
  </div>
  <style>@media(max-width:860px){.course-detail-grid{grid-template-columns:1fr !important}}</style>
  `;
}

function normName(s){ return s.trim().replace(/\s+/g,' '); }
async function startOrResume(courseId){
  const nameEl = document.getElementById('empName');
  const name = normName(nameEl.value||'');
  if(!name || name.split(' ').length<2){ toast('Informe seu nome completo.'); return; }
  if(name.length > LIMITS.name){ toast(`O nome deve ter no máximo ${LIMITS.name} caracteres.`); return; }
  if(!/^[\p{L}\p{M}' .-]+$/u.test(name)){ toast('O nome deve conter apenas letras, espaços, apóstrofo ou hífen.'); return; }
  const btn = document.getElementById('startBtn'); if(btn) btn.disabled = true;
  try{
    const { enrollment } = await api('/enrollments', { method:'POST', body:{ courseId, employeeName:name } });
    TRAINING[enrollment.id] = enrollment;
    nav('#/aula/'+enrollment.id);
  }catch(e){
    if(e.code==='trainee_required') TRAINEE = null;
    toast(e.message); render();
  }
}

/* ============================= PLAYER ============================= */
let PLAYER_STATE = {};
function viewPlayer(enId){
  const en = TRAINING[enId];
  if(!en) return `<div class="empty">Sessão de treinamento não encontrada. Abra novamente o link enviado pela sua empresa.</div>`;
  const course = en.course;
  const allLessons = []; course.modules.forEach(m=>m.lessons.forEach(l=>allLessons.push({...l, moduleTitle:m.title})));
  if(!PLAYER_STATE[enId]) PLAYER_STATE[enId] = allLessons.find(l=>!en.completedLessons.includes(l.id))?.id || allLessons[0]?.id;
  const activeLessonId = PLAYER_STATE[enId];
  const activeLesson = allLessons.find(l=>l.id===activeLessonId) || allLessons[0];
  const progress = enrollmentProgress(en);
  const total = totalLessons(course);
  const complete = isEnrollmentComplete(en);
  const hasQuiz = course.quiz && course.quiz.length>0;

  let sidebarLessons = '';
  course.modules.forEach((m,mi)=>{
    sidebarLessons += `<div style="font-size:12px; font-weight:700; color:var(--ink-soft); text-transform:uppercase; letter-spacing:.03em; margin:14px 0 6px 4px">${escapeHtml(m.title)}</div>`;
    m.lessons.forEach(l=>{
      const done = en.completedLessons.includes(l.id);
      sidebarLessons += `<div class="lesson-row ${l.id===activeLessonId?'active':''}" onclick="selectLesson('${enId}','${l.id}')">
        <div class="lesson-check ${done?'done':''}">${done?'✓':''}</div>
        <div style="flex:1; min-width:0">
          <div style="font-size:13.5px; font-weight:600; overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(l.title)}</div>
          ${l.durationMin>0?`<div style="font-size:11.5px; color:var(--ink-soft)">${l.durationMin} min</div>`:''}
        </div>
      </div>`;
    });
  });
  if(hasQuiz){
    sidebarLessons += `<div class="lesson-row ${activeLessonId==='__quiz__'?'active':''}" onclick="selectLesson('${enId}','__quiz__')">
      <div class="lesson-check ${en.quizPassed?'done':''}">${en.quizPassed?'✓':'📝'}</div>
      <div><div style="font-size:13.5px; font-weight:600">Questionário final</div><div style="font-size:11.5px; color:var(--ink-soft)">Obrigatório</div></div>
    </div>`;
  }
  sidebarLessons += `<div class="lesson-row ${activeLessonId==='__cert__'?'active':''}" onclick="selectLesson('${enId}','__cert__')">
    <div class="lesson-check ${complete?'done':''}">${complete?'✓':'🏆'}</div>
    <div><div style="font-size:13.5px; font-weight:600">Certificado</div><div style="font-size:11.5px; color:var(--ink-soft)">${complete?'Disponível':'Bloqueado'}</div></div>
  </div>`;

  let mainContent = '';
  if(activeLessonId==='__quiz__'){
    mainContent = renderQuiz(en, course);
  } else if(activeLessonId==='__cert__'){
    mainContent = complete ? `
      <div class="card pad" style="text-align:center; padding:44px 24px">
        <div style="font-size:40px; margin-bottom:10px">🏆</div>
        <h2 style="margin:0 0 8px">Treinamento concluído!</h2>
        <p style="color:var(--ink-soft); margin:0 0 20px">Parabéns, ${escapeHtml(en.employeeName)}. Seu certificado já está disponível.</p>
        <button class="btn btn-accent" onclick="nav('#/certificado/${en.id}')">Ver certificado →</button>
      </div>` : `
      <div class="card pad empty">
        <div class="emoji">🔒</div>
        <div style="font-weight:700; margin-bottom:4px">Certificado bloqueado</div>
        <div>Conclua todas as aulas${hasQuiz?' e o questionário':''} para liberar seu certificado.</div>
      </div>`;
  } else if(activeLesson){
    const done = en.completedLessons.includes(activeLesson.id);
    if(!done) pendingChartJobs.push(()=>markLessonStart(en.id, activeLesson.id));
    mainContent = `
      <div class="video-box">
        ${(()=>{ const v = videoSource(activeLesson.videoUrl);
          if(v && v.kind==='iframe') return `<iframe src="${escapeAttr(v.src)}" sandbox="allow-scripts allow-same-origin allow-presentation" allow="fullscreen; encrypted-media; picture-in-picture" referrerpolicy="strict-origin-when-cross-origin" loading="lazy" allowfullscreen></iframe>`;
          if(v && v.kind==='video') return `<video src="${escapeAttr(v.src)}" controls controlslist="nodownload" preload="metadata"></video>`;
          return `<div class="lesson-cover">
            <div class="lesson-cover-module">${escapeHtml(course.title)}</div>
            <div class="lesson-cover-title">${escapeHtml(activeLesson.title)}</div>
            <div class="lesson-cover-foot"><span class="play-dot">▶</span>${activeLesson.durationMin>0?`<span>${activeLesson.durationMin} min</span>`:''}</div>
            <div class="lesson-cover-note">${activeLesson.videoUrl ? 'Link de vídeo não permitido (use YouTube, Vimeo ou arquivo https)' : 'Vídeo ainda não cadastrado pelo administrador'}</div>
          </div>`;
        })()}
      </div>
      <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:16px; margin-top:18px; flex-wrap:wrap">
        <div>
          <div style="font-size:12.5px; color:var(--ink-soft); font-weight:600; margin-bottom:4px">${escapeHtml(activeLesson.moduleTitle)}</div>
          <h2 style="margin:0; font-size:21px">${escapeHtml(activeLesson.title)}</h2>
          ${activeLesson.durationMin>0?`<div style="color:var(--ink-soft); font-size:13.5px; margin-top:4px">Duração: ${activeLesson.durationMin} min</div>`:''}
        </div>
        <button class="btn ${done?'btn-ghost':'btn-accent'}" id="doneBtn" ${done?'disabled':''} onclick="completeLesson('${en.id}','${activeLesson.id}')">${done? '✓ Aula concluída' : 'Marcar como concluída'}</button>
      </div>`;
  }

  return `
  <div style="margin-bottom:18px">
    <button class="btn btn-ghost btn-sm" onclick="nav('#/curso/${course.id}')">← ${escapeHtml(course.title)}</button>
  </div>
  <div class="card pad" style="margin-bottom:20px">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; flex-wrap:wrap; gap:6px">
      <div style="font-weight:700; font-size:14.5px">${escapeHtml(en.employeeName)} · ${escapeHtml(en.companyName)}</div>
      <div style="font-size:13px; color:var(--ink-soft)">${en.completedLessons.length} de ${total} ${total===1?"aula concluída":"aulas concluídas"}</div>
    </div>
    <div class="progress-track"><div class="progress-fill" style="width:${progress}%"></div></div>
  </div>
  <div style="display:grid; grid-template-columns:280px 1fr; gap:24px" class="player-grid">
    <div class="card pad" style="max-height:70vh; overflow-y:auto">${sidebarLessons}</div>
    <div>${mainContent}</div>
  </div>
  <style>@media(max-width:860px){.player-grid{grid-template-columns:1fr !important}}</style>
  `;
}
function selectLesson(enId, lessonId){ PLAYER_STATE[enId] = lessonId; render(); }
const STARTED_LESSONS = new Set();
function markLessonStart(enId, lessonId){
  const key = enId+':'+lessonId;
  if(STARTED_LESSONS.has(key)) return;
  STARTED_LESSONS.add(key);
  api(`/enrollments/${enId}/lessons/${lessonId}/start`, { method:'POST', body:{} }).catch(()=>STARTED_LESSONS.delete(key));
}
async function completeLesson(enId, lessonId){
  const btn = document.getElementById('doneBtn'); if(btn) btn.disabled = true;
  try{
    const r = await api(`/enrollments/${enId}/lessons/${lessonId}/complete`, { method:'POST', body:{} });
    const en = TRAINING[enId] = r.enrollment, course = en.course;
    if(r.finished) toast('🎉 Treinamento concluído! Certificado liberado.');
    const lessons = course.modules.flatMap(m=>m.lessons);
    const next = lessons.find(l=>!en.completedLessons.includes(l.id));
    PLAYER_STATE[enId] = next ? next.id : (course.quiz.length ? '__quiz__' : '__cert__');
    render();
  }catch(e){ toast(e.message); if(btn) btn.disabled = false; }
}
function renderQuiz(en, course){
  const quiz = course.quiz;
  if(en.quizPassed){
    return `<div class="card pad" style="text-align:center; padding:40px"><div style="font-size:36px">✅</div><h2>Questionário concluído</h2><p style="color:var(--ink-soft)">Você acertou ${en.quizScore} de ${quiz.length} perguntas.</p></div>`;
  }
  const qs = quiz.map((q,qi)=>`
    <div class="card pad" style="margin-bottom:12px">
      <div style="font-weight:600; margin-bottom:10px">${qi+1}. ${escapeHtml(q.q)}</div>
      ${q.options.map((op,oi)=>`
        <label style="display:flex; align-items:center; gap:10px; padding:9px 4px; cursor:pointer; font-size:14px">
          <input type="radio" name="q${qi}" value="${oi}"> ${escapeHtml(op)}
        </label>`).join('')}
    </div>`).join('');
  return `<h2 style="margin:0 0 4px">Questionário final</h2><p style="color:var(--ink-soft); margin:0 0 18px">Responda todas as perguntas para concluir o treinamento.</p>
    ${qs}
    <button class="btn btn-accent" onclick="submitQuiz('${en.id}')">Enviar respostas</button>`;
}
async function submitQuiz(enId){
  const quiz = TRAINING[enId].course.quiz;
  const answers = quiz.map((q,qi)=>{ const sel = document.querySelector(`input[name="q${qi}"]:checked`); return sel ? parseInt(sel.value) : null; });
  if(answers.includes(null)){ toast('Responda todas as perguntas antes de enviar.'); return; }
  try{
    const r = await api(`/enrollments/${enId}/quiz`, { method:'POST', body:{ answers } });
    TRAINING[enId] = r.enrollment;
    if(!r.passed){ toast(`Você acertou ${r.score} de ${r.total}. Tente novamente.`); render(); return; }
    toast(`Questionário concluído! ${r.score}/${r.total} acertos.`);
    PLAYER_STATE[enId] = '__cert__';
    render();
  }catch(e){ toast(e.message); }
}

/* ============================= DOWNLOADS ============================= */
function saveFile(filename, blob){
  try{
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(url), 4000);
    return true;
  }catch(e){ console.error(e); return false; }
}

/* ============================= CERTIFICATE ============================= */
function viewCertificate(enId){
  const en = TRAINING[enId];
  if(!en || !isEnrollmentComplete(en)) return `<div class="empty">Certificado indisponível.</div>`;
  return `
  <button class="btn btn-ghost btn-sm" style="margin-bottom:18px" onclick="nav('#/aula/${en.id}')">← Voltar ao treinamento</button>
  <div class="card" style="max-width:800px; margin:0 auto; padding:0; overflow:hidden">
    <div style="padding:52px 44px; border:10px solid var(--gold-soft); margin:14px; border-radius:8px; text-align:center; background:linear-gradient(180deg,#fff,#FDFCF8)">
      <div style="font-size:12px; letter-spacing:.12em; color:var(--gold-deep); font-weight:700">CERTIFICADO DE CONCLUSÃO</div>
      <div style="font-family:'Bricolage Grotesque',sans-serif; font-size:15px; font-weight:700; margin-top:18px; color:var(--ink-soft)">Em Conformidade · Treinamentos Corporativos</div>
      <div style="margin:30px 0 6px; font-size:14px; color:var(--ink-soft)">Certificamos que</div>
      <div style="font-family:'Bricolage Grotesque',sans-serif; font-size:30px; font-weight:800; color:var(--primary)">${escapeHtml(en.employeeName)}</div>
      <div style="margin:16px 0 6px; font-size:14px; color:var(--ink-soft)">concluiu com êxito o treinamento</div>
      <div style="font-size:20px; font-weight:700">${escapeHtml(en.courseTitle)}</div>
      <div style="margin-top:26px; display:flex; justify-content:center; gap:40px; flex-wrap:wrap; font-size:13px; color:var(--ink-soft)">
        <div><div style="font-weight:700; color:var(--ink)">${fmtDate(en.completedAt)}</div>Data de conclusão</div>
        <div><div style="font-weight:700; color:var(--ink)">${escapeHtml(en.companyName||'—')}</div>Empresa</div>
        <div><div style="font-weight:700; color:var(--ink)" class="mono">${escapeHtml(en.certCode)}</div>Código de validação</div>
      </div>
    </div>
  </div>
  <div style="text-align:center; margin-top:20px; display:flex; gap:10px; justify-content:center; flex-wrap:wrap">
    <button class="btn btn-primary" onclick="downloadCertificatePDF('${en.id}')">⬇ Baixar certificado (PDF)</button>
    <button class="btn btn-ghost" onclick="nav('#/')">Voltar aos treinamentos</button>
  </div>`;
}
async function downloadCertificatePDF(enId){
  const en = TRAINING[enId] || DB.enrollments.find(e=>e.id===enId); if(!en) return;
  try{
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({orientation:'landscape', unit:'pt', format:'a4'});
    const W = doc.internal.pageSize.getWidth(), H = doc.internal.pageSize.getHeight();
    doc.setFillColor('#F4F5F7'); doc.rect(0,0,W,H,'F');
    doc.setDrawColor('#17201B'); doc.setLineWidth(2); doc.rect(30,30,W-60,H-60);
    doc.setDrawColor('#1F5C4A'); doc.setLineWidth(1); doc.rect(38,38,W-76,H-76);
    doc.setTextColor('#1F5C4A'); doc.setFont('helvetica','bold'); doc.setFontSize(13);
    doc.text('CERTIFICADO DE CONCLUSAO', W/2, 100, {align:'center'});
    doc.setTextColor('#7A8296'); doc.setFontSize(12); doc.setFont('helvetica','normal');
    doc.text('Em Conformidade - Treinamentos Corporativos', W/2, 122, {align:'center'});
    doc.setTextColor('#454C5C'); doc.setFontSize(13);
    doc.text('Certificamos que', W/2, 175, {align:'center'});
    doc.setTextColor('#17201B'); doc.setFont('helvetica','bold'); doc.setFontSize(30);
    doc.text(en.employeeName, W/2, 212, {align:'center'});
    doc.setTextColor('#3B4353'); doc.setFont('helvetica','normal'); doc.setFontSize(13);
    doc.text('concluiu com exito o treinamento', W/2, 244, {align:'center'});
    doc.setTextColor('#151A24'); doc.setFont('helvetica','bold'); doc.setFontSize(19);
    doc.text(en.courseTitle, W/2, 270, {align:'center'});
    doc.setFont('helvetica','normal'); doc.setFontSize(11); doc.setTextColor('#3B4353');
    const y2 = H-90;
    doc.text('Data de conclusao: ' + fmtDate(en.completedAt), W/2-260, y2, {align:'left'});
    doc.text('Empresa: ' + (en.companyName||'-'), W/2-60, y2, {align:'left'});
    doc.text('Codigo: ' + en.certCode, W/2+140, y2, {align:'left'});
    const blob = doc.output('blob');
    const ok = saveFile(`certificado-${en.employeeName.replace(/\s+/g,'_')}.pdf`, blob);
    if(ok) toast('Certificado baixado com sucesso.');
  }catch(e){ console.error(e); toast('Não foi possível gerar o PDF.'); }
}

/* ============================= DENÚNCIAS ============================= */
function viewDenuncias(){
  const url = safeHttpsUrl(DB.settings.denounceUrl);
  return `
  <div style="max-width:640px; margin:0 auto">
    <div class="card pad" style="text-align:center; padding:44px 30px">
      <div style="font-size:36px; margin-bottom:12px">📣</div>
      <h1 style="font-size:22px; margin:0 0 10px">Canal de Denúncias</h1>
      <p style="color:var(--ink-soft); line-height:1.6">Espaço confidencial para relatar condutas inadequadas, violações éticas ou de compliance. Este canal está preparado para integração com um sistema externo dedicado (ex: um provedor de canal de denúncias).</p>
      ${url ? `<a class="btn btn-primary" href="${escapeAttr(url)}" target="_blank" rel="noopener noreferrer">Acessar canal de denúncias →</a>`
            : `<div class="badge badge-progress" style="margin-top:14px">Ainda não configurado pelo administrador</div>`}
    </div>
  </div>`;
}

/* ============================= HELPERS: escaping ============================= */
function escapeHtml(s){ return String(s??'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function escapeAttr(s){ return escapeHtml(s); }

/* ============================= GESTOR (COMPANY MANAGER) ============================= */
/* ============================= LOGIN EM ETAPAS: SENHA → 2FA ============================= */
let LOGIN = { step:'credentials', setup:null, recovery:false, codes:null, user:null };
let loginBusy = false;
function resetLogin(){ LOGIN = { step:'credentials', setup:null, recovery:false, codes:null, user:null }; }
function loginCard(kicker, title, text, body){
  return `<div style="max-width:440px; margin:40px auto"><div class="card pad">
    <div class="section-title">${kicker}</div>
    <h2 style="margin:2px 0 4px">${title}</h2>
    <p style="color:var(--ink-soft); font-size:13.5px; margin:0 0 18px">${text}</p>${body}</div></div>`;
}
function codeField(onEnter){
  return `<div class="field"><label class="field-label" for="lgCode">Código de 6 dígitos</label>
    <input class="input code-input" id="lgCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000" onkeydown="if(event.key==='Enter')${onEnter}()"></div>`;
}
function viewLogin(kind){
  const kicker = kind==='admin' ? 'Administração' : 'Painel do Gestor';
  if(SESSION.role){
    const home = SESSION.role==='admin' ? '#/admin/dashboard/visao' : '#/gestor/dashboard/visao';
    return loginCard(kicker, 'Você já entrou', `Sua conta atual não tem acesso a esta área.`, `<button class="btn btn-primary btn-block" onclick="nav('${home}')">Ir para o meu painel</button>`);
  }
  const step = LOGIN.step;
  if(step==='change_password') return loginCard(kicker, 'Crie sua senha', 'A senha recebida é provisória. Defina uma senha só sua para continuar.', `
    <div class="field"><label class="field-label" for="lgNew">Nova senha</label><input class="input" id="lgNew" type="password" autocomplete="new-password" placeholder="Mínimo de ${SEC.MIN_PASSWORD} caracteres"></div>
    <div class="field"><label class="field-label" for="lgNew2">Confirmar nova senha</label><input class="input" id="lgNew2" type="password" autocomplete="new-password" onkeydown="if(event.key==='Enter')submitFirstPassword()"></div>
    <button class="btn btn-primary btn-block" id="lgBtn" onclick="submitFirstPassword()">Salvar e continuar</button>`);
  if(step==='setup_2fa'){
    if(!LOGIN.setup){ pendingChartJobs.push(loadTotpSetup); return loginCard(kicker, 'Ative o 2FA', 'Preparando o código…', ''); }
    return loginCard(kicker, 'Ative o 2FA', 'Escaneie o QR Code com um aplicativo autenticador, como Google Authenticator ou Microsoft Authenticator.', `
      <img class="qr" src="${escapeAttr(LOGIN.setup.qr)}" alt="QR Code para cadastrar o 2FA" width="200" height="200">
      <details class="manual-key"><summary>Não consegue escanear?</summary><p>Digite esta chave no aplicativo:</p><code class="mono">${escapeHtml(LOGIN.setup.secret)}</code></details>
      ${codeField('submitTotpEnable')}
      <button class="btn btn-primary btn-block" id="lgBtn" onclick="submitTotpEnable()">Ativar 2FA</button>`);
  }
  if(step==='verify_2fa') return loginCard(kicker, 'Verificação em duas etapas', LOGIN.recovery ? 'Digite um dos seus códigos de recuperação. Cada código funciona uma única vez.' : 'Digite o código que aparece no seu aplicativo autenticador.', `
    ${LOGIN.recovery
      ? `<div class="field"><label class="field-label" for="lgRecovery">Código de recuperação</label><input class="input mono" id="lgRecovery" autocomplete="off" placeholder="XXXX-XXXX-XXXX-XXXX" onkeydown="if(event.key==='Enter')submitTotpVerify()"></div>`
      : codeField('submitTotpVerify')}
    <button class="btn btn-primary btn-block" id="lgBtn" onclick="submitTotpVerify()">Confirmar</button>
    <p style="font-size:13px; margin:14px 0 0; text-align:center"><span class="link-plain" onclick="LOGIN.recovery=!LOGIN.recovery; render()">${LOGIN.recovery?'Usar o aplicativo autenticador':'Perdi acesso ao aplicativo'}</span></p>`);
  if(step==='recovery_codes') return loginCard(kicker, 'Guarde seus códigos', 'Se perder o celular, estes códigos permitem entrar. Eles aparecem só agora. Guarde em um local seguro, fora deste computador.', `
    ${recoveryCodesList(LOGIN.codes)}
    <label style="display:flex; gap:10px; align-items:center; font-size:13.5px; margin:16px 0"><input type="checkbox" id="lgSaved" onchange="document.getElementById('lgDone').disabled=!this.checked"> Guardei meus códigos</label>
    <button class="btn btn-primary btn-block" id="lgDone" disabled onclick="completeLogin()">Entrar</button>`);
  return loginCard(kicker, kind==='admin' ? 'Acesso restrito' : 'Acessar minha empresa', kind==='admin' ? 'Entre com sua conta de administrador.' : 'Entre com o e-mail de RH ou de Gerente da sua empresa.', `
    <div class="field"><label class="field-label" for="lgEmail">E-mail</label><input class="input" id="lgEmail" type="email" autocomplete="username"></div>
    <div class="field"><label class="field-label" for="lgPass">Senha</label><input class="input" id="lgPass" type="password" autocomplete="current-password" onkeydown="if(event.key==='Enter')submitLogin()"></div>
    <button class="btn btn-primary btn-block" id="lgBtn" onclick="submitLogin()">Continuar</button>
    <p style="font-size:12px; color:var(--ink-soft); margin-top:14px">🔒 Após ${SEC.MAX_ATTEMPTS} tentativas incorretas o acesso é bloqueado por ${SEC.LOCK_MINUTES} minutos. Esqueceu a senha? Peça a redefinição ao administrador.</p>`);
}
function recoveryCodesList(codes){
  return `<div class="code-list mono">${codes.map(c=>`<span>${escapeHtml(c)}</span>`).join('')}</div>
    <button class="btn btn-ghost btn-sm" style="margin-top:10px" onclick="copyText(${escapeAttr(JSON.stringify(codes.join('\n')))})">Copiar códigos</button>`;
}
async function copyText(text){
  try{ await navigator.clipboard.writeText(text); toast('Copiado.'); }catch(e){ toast('Não foi possível copiar. Selecione o texto manualmente.'); }
}
/* Executa uma etapa do login. A tela só é redesenhada depois de liberar a etapa
   atual, porque a próxima pode iniciar sozinha (caso do QR Code do 2FA). */
async function loginAction(fn){
  if(loginBusy) return;
  loginBusy = true; const btn = document.getElementById('lgBtn'); if(btn) btn.disabled = true;
  let done = false, expired = false;
  try{ await fn(); done = true; }
  catch(e){
    expired = e.code==='pre_auth_expired';
    if(expired) resetLogin();
    toast(e.message);
    const code = document.getElementById('lgCode'); if(code) code.value = '';
    const pass = document.getElementById('lgPass'); if(pass) pass.value = '';
    if(btn) btn.disabled = false;
  }
  finally{ loginBusy = false; }
  if((done && !SESSION.role) || expired) render();
}
function submitLogin(){
  const email = document.getElementById('lgEmail').value.trim(), senha = document.getElementById('lgPass').value;
  if(!email || !senha){ toast('Informe e-mail e senha.'); return; }
  return loginAction(async ()=>{ LOGIN.step = (await api('/auth/login', { method:'POST', body:{ email, senha } })).next; });
}
function submitFirstPassword(){
  const n1 = document.getElementById('lgNew').value, n2 = document.getElementById('lgNew2').value;
  if(n1 !== n2){ toast('A confirmação não confere com a nova senha.'); return; }
  return loginAction(async ()=>{ LOGIN.step = (await api('/auth/first-password', { method:'POST', body:{ novaSenha:n1 } })).next; });
}
function loadTotpSetup(){
  return loginAction(async ()=>{ LOGIN.setup = await api('/auth/2fa/setup', { method:'POST', body:{} }); });
}
function submitTotpEnable(){
  const codigo = document.getElementById('lgCode').value.trim();
  if(!/^\d{6}$/.test(codigo)){ toast('Digite os 6 dígitos do aplicativo.'); return; }
  return loginAction(async ()=>{
    const r = await api('/auth/2fa/enable', { method:'POST', body:{ codigo } });
    LOGIN.user = r.user; LOGIN.codes = r.recoveryCodes; LOGIN.step = 'recovery_codes';
  });
}
function submitTotpVerify(){
  const body = LOGIN.recovery ? { recuperacao:document.getElementById('lgRecovery').value.trim() } : { codigo:document.getElementById('lgCode').value.trim() };
  if(!(body.recuperacao || /^\d{6}$/.test(body.codigo||''))){ toast('Digite o código.'); return; }
  return loginAction(async ()=>{
    const r = await api('/auth/2fa/verify', { method:'POST', body });
    LOGIN.user = r.user;
    if(LOGIN.recovery) toast(`Restam ${r.recoveryCodesLeft} código(s) de recuperação.`);
    completeLogin();
  });
}
function completeLogin(){
  const user = LOGIN.user; resetLogin(); applySession(user);
  goTo(user.role==='admin' ? '#/admin/dashboard/visao' : '#/gestor/dashboard/visao');
}

/* ---------- Segurança da conta (administrador, RH e Gerente) ---------- */
function accountSecurityCards(){
  return `
  <div class="card pad" style="margin-bottom:16px">
    <div class="section-title" style="margin-bottom:10px">Alterar senha</div>
    <div class="field"><label class="field-label" for="secCur">Senha atual</label><input class="input" id="secCur" type="password" autocomplete="current-password"></div>
    <div class="field"><label class="field-label" for="secNew">Nova senha</label><input class="input" id="secNew" type="password" autocomplete="new-password" placeholder="Mínimo de ${SEC.MIN_PASSWORD} caracteres"></div>
    <div class="field"><label class="field-label" for="secNew2">Confirmar nova senha</label><input class="input" id="secNew2" type="password" autocomplete="new-password"></div>
    <button class="btn btn-primary" id="secBtn" onclick="changePassword()">Salvar nova senha</button>
  </div>
  <div class="card pad" style="margin-bottom:16px">
    <div class="section-title" style="margin-bottom:10px">Códigos de recuperação do 2FA</div>
    <p style="font-size:13.5px; color:var(--ink-soft); margin:0 0 12px">Gerar códigos novos invalida os anteriores. Confirme com o código do aplicativo autenticador.</p>
    <div class="field"><label class="field-label" for="secCode">Código de 6 dígitos</label><input class="input code-input" id="secCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000"></div>
    <button class="btn btn-ghost" onclick="regenerateRecovery()">Gerar novos códigos</button>
  </div>`;
}
async function changePassword(){
  const senhaAtual = document.getElementById('secCur').value, novaSenha = document.getElementById('secNew').value;
  if(novaSenha !== document.getElementById('secNew2').value){ toast('A confirmação não confere com a nova senha.'); return; }
  const btn = document.getElementById('secBtn'); if(btn) btn.disabled = true;
  try{
    await api('/auth/change-password', { method:'POST', body:{ senhaAtual, novaSenha } });
    toast('Senha atualizada. As outras sessões foram encerradas.');
    ['secCur','secNew','secNew2'].forEach(id=>{ document.getElementById(id).value=''; });
  }catch(e){ toast(e.message); }
  if(btn) btn.disabled = false;
}
async function regenerateRecovery(){
  try{
    const { recoveryCodes } = await api('/auth/recovery-codes', { method:'POST', body:{ codigo:document.getElementById('secCode').value.trim() } });
    showModal('Novos códigos de recuperação', `<p style="margin:0 0 12px; font-size:14px">Guarde em local seguro. Eles aparecem só agora.</p>${recoveryCodesList(recoveryCodes)}`);
  }catch(e){ toast(e.message); }
}
function gestorLogout(){ logout(); }

function viewGestorDashboard(tab){
  const company = companyById(SESSION.companyId);
  if(!company) return `<div class="empty">Carregando…</div>`;
  const ens = DB.enrollments.filter(e=>e.companyId===company.id);
  const employees = [...new Set(ens.map(e=>e.employeeName))];
  const inProgress = ens.filter(e=>!isEnrollmentComplete(e)).length;
  const completed = ens.filter(e=>isEnrollmentComplete(e)).length;
  const certs = ens.filter(e=>e.certCode).length;

  const sidebar = `
    <div class="side-link ${tab==='visao'?'active':''}" onclick="nav('#/gestor/dashboard/visao')">📊 Visão geral</div>
    <div class="side-link ${tab==='equipe'?'active':''}" onclick="nav('#/gestor/dashboard/equipe')">👥 Equipe</div>
    <div class="side-link ${tab==='certificados'?'active':''}" onclick="nav('#/gestor/dashboard/certificados')">🏆 Certificados</div>
    <div class="side-link ${tab==='link'?'active':''}" onclick="nav('#/gestor/dashboard/link')">🔗 Link da equipe</div>
    <div class="side-link ${tab==='seguranca'?'active':''}" onclick="nav('#/gestor/dashboard/seguranca')">🛡️ Segurança</div>
    <div class="side-link" onclick="gestorLogout()">⏻ Sair</div>`;

  let content = '';
  if(tab==='visao'){
    content = `
    <div class="grid-4" style="margin-bottom:20px">
      <div class="card stat"><div class="num">${employees.length}</div><div class="label">Funcionários engajados</div></div>
      <div class="card stat"><div class="num" style="color:var(--amber)">${inProgress}</div><div class="label">Treinamentos em andamento</div></div>
      <div class="card stat"><div class="num" style="color:var(--accent)">${completed}</div><div class="label">Treinamentos concluídos</div></div>
      <div class="card stat"><div class="num">${certs}</div><div class="label">Certificados emitidos</div></div>
    </div>
    <div class="grid-3" style="grid-template-columns:1fr 1fr">
      <div class="card pad"><div class="section-title" style="margin-bottom:12px">Status dos treinamentos</div><canvas id="gestorChart1" height="180"></canvas></div>
      <div class="card pad"><div class="section-title" style="margin-bottom:12px">Por treinamento</div><canvas id="gestorChart2" height="180"></canvas></div>
    </div>`;
    pendingChartJobs.push(()=>{
      const statusCtx = document.getElementById('gestorChart1');
      if(statusCtx) new Chart(statusCtx, { type:'doughnut', data:{ labels:['Concluídos','Em andamento'], datasets:[{data:[completed, inProgress], backgroundColor:['#1F5C4A','#D9A21B']}]}, options:{plugins:{legend:{position:'bottom'}}} });
      const byCourse = {}; ens.forEach(e=>{ const c = courseById(e.courseId); const k = c?c.title:'—'; byCourse[k]=(byCourse[k]||0)+1; });
      const courseCtx = document.getElementById('gestorChart2');
      if(courseCtx) new Chart(courseCtx, { type:'bar', data:{ labels:Object.keys(byCourse), datasets:[{label:'Inscrições', data:Object.values(byCourse), backgroundColor:'#1F5C4A', borderRadius:6}]}, options:{plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true, ticks:{precision:0}}}} });
    });
  } else if(tab==='equipe'){
    content = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px">
      <h2 style="margin:0; font-size:18px">Equipe · ${escapeHtml(company.name)}</h2>
      <button class="btn btn-ghost btn-sm" onclick="exportCSV()">⬇ Exportar CSV</button>
    </div>
    <div class="card table-scroll">
      <table>
        <thead><tr><th>Funcionário</th><th>Treinamento</th><th>Progresso</th><th>Status</th></tr></thead>
        <tbody>
          ${ens.length? ens.map(e=>{
            const c = courseById(e.courseId); const p = enrollmentProgress(e); const done = isEnrollmentComplete(e);
            return `<tr><td>${escapeHtml(e.employeeName)}</td><td>${escapeHtml(c?c.title:'—')}</td>
              <td style="min-width:140px"><div class="progress-track" style="width:110px; display:inline-block; vertical-align:middle"><div class="progress-fill" style="width:${p}%"></div></div> <span style="font-size:12.5px; color:var(--ink-soft)">${p}%</span></td>
              <td>${done?`<span class="badge badge-done">Concluído</span>`:`<span class="badge badge-progress">Em andamento</span>`}</td></tr>`;
          }).join('') : `<tr><td colspan="4" style="text-align:center; color:var(--ink-soft); padding:30px">Nenhum funcionário iniciou treinamentos ainda.</td></tr>`}
        </tbody>
      </table>
    </div>`;
  } else if(tab==='certificados'){
    const withCert = ens.filter(e=>e.certCode);
    content = `
    <h2 style="margin:0 0 14px; font-size:18px">Certificados emitidos</h2>
    <div class="card table-scroll">
      <table>
        <thead><tr><th>Funcionário</th><th>Treinamento</th><th>Emitido em</th><th>Código</th><th></th></tr></thead>
        <tbody>
        ${withCert.length? withCert.map(e=>{ const c = courseById(e.courseId); return `<tr><td>${escapeHtml(e.employeeName)}</td><td>${escapeHtml(c?c.title:'—')}</td><td>${fmtDate(e.completedAt)}</td><td class="mono" style="font-size:12px">${escapeHtml(e.certCode)}</td><td><button class="btn btn-ghost btn-sm" onclick="downloadCertificatePDF('${e.id}')">⬇ Baixar</button></td></tr>`; }).join('')
        : `<tr><td colspan="5" style="text-align:center; color:var(--ink-soft); padding:30px">Nenhum certificado emitido ainda.</td></tr>`}
        </tbody>
      </table>
    </div>`;
  } else if(tab==='link'){
    content = `
    <h2 style="margin:0 0 14px; font-size:18px">Link da equipe</h2>
    <div class="card pad">
      <p style="font-size:13.5px; color:var(--ink-soft); margin:0 0 12px">Envie este link aos funcionários da sua empresa. Quem o abre pode fazer os treinamentos sem criar conta, por isso compartilhe apenas por canais internos.</p>
      <div class="field"><label class="field-label" for="teamLink">Link de acesso</label><input class="input mono" id="teamLink" readonly value="${escapeAttr(GESTOR_LINK)}" onclick="this.select()"></div>
      <div style="display:flex; gap:8px; flex-wrap:wrap">
        <button class="btn btn-primary btn-sm" onclick="copyText(GESTOR_LINK)">Copiar link</button>
        <button class="btn btn-danger btn-sm" onclick="rotateLink()">Trocar link</button>
      </div>
      <p style="font-size:12.5px; color:var(--ink-soft); margin:12px 0 0">Trocar o link desativa o anterior. Use se ele tiver sido compartilhado com quem não deveria.</p>
    </div>`;
  } else if(tab==='seguranca'){
    content = `<h2 style="margin:0 0 14px; font-size:18px">Segurança</h2>${accountSecurityCards()}`;
  }

  return `
  <div style="margin-bottom:16px">
    <div class="section-title">PAINEL DO GESTOR</div>
    <h1 style="margin:2px 0 0; font-size:22px">${escapeHtml(company.name)}</h1>
  </div>
  <div class="sidebar-layout">
    <div class="sidebar">${sidebar}</div>
    <div>${content}</div>
  </div>`;
}
async function rotateLink(){
  if(!(await askConfirm('Trocar o link? O link atual deixa de funcionar para novos acessos.','Trocar link'))) return;
  try{ GESTOR_LINK = (await api('/gestor/link/rotate', { method:'POST', body:{} })).link; toast('Link trocado.'); render(); }
  catch(e){ toast(e.message); }
}
async function exportCSV(){
  try{
    const res = await api('/gestor/export.csv', { raw:true });
    if(saveFile('relatorio_equipe.csv', await res.blob())) toast('Relatório baixado com sucesso.');
  }catch(e){ toast(e.message); }
}

/* ============================= ADMIN ============================= */
function adminLogout(){ logout(); }
function requireAdmin(){ if(SESSION.role!=='admin'){ toast('Acesso não autorizado.'); return false; } return true; }

function viewAdminDashboard(tab){
  const ens = DB.enrollments;
  const sidebar = `
    <div class="side-link ${tab==='visao'?'active':''}" onclick="nav('#/admin/dashboard/visao')">📊 Visão geral</div>
    <div class="side-link ${tab==='empresas'?'active':''}" onclick="nav('#/admin/dashboard/empresas')">🏢 Empresas</div>
    <div class="side-link ${tab==='cursos'?'active':''}" onclick="nav('#/admin/dashboard/cursos')">📚 Treinamentos</div>
    <div class="side-link ${tab==='funcionarios'?'active':''}" onclick="nav('#/admin/dashboard/funcionarios')">👥 Funcionários</div>
    <div class="side-link ${tab==='certificados'?'active':''}" onclick="nav('#/admin/dashboard/certificados')">🏆 Certificados</div>
    <div class="side-link ${tab==='denuncias'?'active':''}" onclick="nav('#/admin/dashboard/denuncias')">📣 Canal de Denúncias</div>
    <div class="side-link ${tab==='seguranca'?'active':''}" onclick="nav('#/admin/dashboard/seguranca')">🛡️ Segurança</div>
    <div class="side-link" onclick="adminLogout()">⏻ Sair</div>`;

  let content = '';
  if(tab==='seguranca') content = adminTabSeguranca();
  else if(tab==='visao') content = adminTabVisao();
  else if(tab==='empresas') content = adminTabEmpresas();
  else if(tab==='cursos') content = adminTabCursos();
  else if(tab==='funcionarios') content = adminTabFuncionarios();
  else if(tab==='certificados') content = adminTabCertificados();
  else if(tab==='denuncias') content = adminTabDenuncias();

  return `
  <div style="margin-bottom:16px">
    <div class="section-title">ADMINISTRAÇÃO</div>
    <h1 style="margin:2px 0 0; font-size:22px">Visão geral da plataforma</h1>
  </div>
  <div class="sidebar-layout">
    <div class="sidebar">${sidebar}</div>
    <div>${content}</div>
  </div>
  <div id="modalRoot"></div>`;
}
function adminTabVisao(){
  const ens = DB.enrollments, completed = ens.filter(isEnrollmentComplete).length;
  return `
  <div class="grid-4" style="margin-bottom:20px">
    <div class="card stat"><div class="num">${DB.companies.length}</div><div class="label">Empresas</div></div>
    <div class="card stat"><div class="num">${DB.courses.length}</div><div class="label">Treinamentos</div></div>
    <div class="card stat"><div class="num">${new Set(ens.map(e=>e.employeeName+e.companyId)).size}</div><div class="label">Funcionários ativos</div></div>
    <div class="card stat"><div class="num" style="color:var(--accent)">${completed}</div><div class="label">Certificados emitidos</div></div>
  </div>
  <div class="card pad"><div class="section-title" style="margin-bottom:12px">Conclusões por treinamento</div><canvas id="adminChart1" height="110"></canvas></div>
  ${pendingChartJobs.push(()=>{
    const byCourse = {}; DB.courses.forEach(c=>byCourse[c.title]=0);
    ens.filter(isEnrollmentComplete).forEach(e=>{ const c=courseById(e.courseId); if(c) byCourse[c.title]=(byCourse[c.title]||0)+1; });
    const ctx = document.getElementById('adminChart1');
    if(ctx) new Chart(ctx, {type:'bar', data:{labels:Object.keys(byCourse), datasets:[{label:'Concluídos', data:Object.values(byCourse), backgroundColor:'#1F5C4A', borderRadius:6}]}, options:{plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true,ticks:{precision:0}}}}});
  }) ? '' : ''}`;
}
function adminTabEmpresas(){
  return `
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px">
    <h2 style="margin:0; font-size:18px">Empresas</h2>
    <button class="btn btn-primary btn-sm" onclick="openCompanyModal()">+ Nova empresa</button>
  </div>
  <div class="card table-scroll">
    <table><thead><tr><th>Empresa</th><th>Acessos</th><th>Funcionários</th><th></th></tr></thead>
    <tbody>
    ${DB.companies.map(c=>`<tr><td style="font-weight:600">${escapeHtml(c.name)}</td>
      <td>${c.users.map(u=>`<div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; padding:3px 0; font-size:13px">
        <b>${u.role==='rh'?'RH':'Gerente'}</b> ${escapeHtml(u.email)}
        ${u.totpEnabled?`<span class="badge badge-done">2FA ativo</span>`:`<span class="badge badge-progress">2FA pendente</span>`}
        ${u.locked?`<span class="badge badge-progress">Bloqueado</span>`:''}
        <button class="btn btn-ghost btn-sm" onclick="resetUser('${safeId(u.id)}')">Redefinir</button></div>`).join('')}</td>
      <td>${c.employees}</td>
      <td style="white-space:nowrap"><button class="btn btn-ghost btn-sm" onclick="openCompanyModal('${c.id}')">Editar</button>
      <button class="btn btn-danger btn-sm" onclick="deleteCompany('${c.id}')">Excluir</button></td></tr>`).join('') || `<tr><td colspan="4" style="text-align:center;color:var(--ink-soft);padding:30px">Nenhuma empresa cadastrada.</td></tr>`}
    </tbody></table>
  </div>`;
}
function openCompanyModal(companyId){
  const c = companyId ? companyById(companyId) : null;
  showModal(`${c?'Editar':'Nova'} empresa`, `
    <div class="field"><label class="field-label" for="mCompanyName">Nome da empresa</label><input class="input" id="mCompanyName" maxlength="${LIMITS.name}" value="${c?escapeAttr(c.name):''}"></div>
    ${c?'':`<div class="field"><label class="field-label" for="mEmailRh">E-mail do RH</label><input class="input" id="mEmailRh" type="email"></div>
    <div class="field"><label class="field-label" for="mEmailGerente">E-mail do Gerente</label><input class="input" id="mEmailGerente" type="email"></div>`}
    <button class="btn btn-primary btn-block" id="mCompanySave" onclick="saveCompany('${safeId(companyId)}')">Salvar</button>
  `);
}
function showCredentials(list){
  showModal('Senhas provisórias', `
    <p style="margin:0 0 14px; font-size:14px">Elas aparecem só agora. Entregue cada uma à pessoa por um canal seguro. No primeiro acesso, ela criará uma senha própria e ativará o 2FA.</p>
    ${list.map(c=>`<div class="card pad" style="margin-bottom:10px; background:var(--paper)"><b>${escapeHtml(c.profile)}</b> · ${escapeHtml(c.email)}<div class="mono" style="margin-top:6px; word-break:break-all">${escapeHtml(c.temporaryPassword)}</div></div>`).join('')}
    <button class="btn btn-ghost btn-sm" onclick="copyText(${escapeAttr(JSON.stringify(list.map(c=>`${c.email}: ${c.temporaryPassword}`).join('\n')))})">Copiar</button>`);
}
async function saveCompany(companyId){
  if(!requireAdmin()) return;
  const name = normName(clampStr(document.getElementById('mCompanyName').value, LIMITS.name));
  if(!name){ toast('Informe o nome da empresa.'); return; }
  const btn = document.getElementById('mCompanySave'); if(btn) btn.disabled = true;
  try{
    if(companyId){
      await api('/admin/companies/'+companyId, { method:'PUT', body:{ name } });
      closeModal(); toast('Empresa salva.');
    } else {
      const emailRh = document.getElementById('mEmailRh').value.trim(), emailGerente = document.getElementById('mEmailGerente').value.trim();
      const r = await api('/admin/companies', { method:'POST', body:{ name, emailRh, emailGerente } });
      await loadAdmin(); render(); showCredentials(r.credentials); return;
    }
    await loadAdmin(); render();
  }catch(e){ toast(e.message); if(btn) btn.disabled = false; }
}
async function resetUser(userId){
  if(!requireAdmin()) return;
  if(!(await askConfirm('Redefinir este acesso? A pessoa sai de todas as sessões e precisará criar nova senha e ativar o 2FA de novo.','Redefinir'))) return;
  try{
    const r = await api(`/admin/users/${userId}/reset`, { method:'POST', body:{} });
    await loadAdmin(); render(); showCredentials([{ profile:'Acesso', email:r.email, temporaryPassword:r.temporaryPassword }]);
  }catch(e){ toast(e.message); }
}
async function deleteCompany(companyId){
  if(!requireAdmin()) return;
  if(!companyById(companyId)) return;
  if(!(await askConfirm('Excluir esta empresa? Os acessos e o link são desativados na hora. Os registros de treinamento continuam guardados.','Excluir empresa'))) return;
  try{ await api('/admin/companies/'+companyId, { method:'DELETE' }); await loadAdmin(); render(); }
  catch(e){ toast(e.message); }
}

function adminTabCursos(){
  return `
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px">
    <h2 style="margin:0; font-size:18px">Treinamentos</h2>
    <button class="btn btn-primary btn-sm" onclick="openCourseModal()">+ Novo treinamento</button>
  </div>
  <div class="grid-3">
    ${DB.courses.map(c=>`
    <div class="card" style="overflow:hidden">
      <div class="course-cover" style="background:${safeColor(c.color)}; height:90px; font-size:28px">${escapeHtml(c.cover)}</div>
      <div class="pad">
        <div style="font-weight:700; margin-bottom:4px">${escapeHtml(c.title)}</div>
        <div style="font-size:12.5px; color:var(--ink-soft); margin-bottom:12px">${totalLessons(c)} aulas · ${c.modules.length} módulos${c.quiz?.length?' · com questionário':''}</div>
        <div style="display:flex; gap:8px">
          <button class="btn btn-ghost btn-sm" style="flex:1" onclick="openCourseModal('${c.id}')">Editar</button>
          <button class="btn btn-danger btn-sm" onclick="deleteCourse('${c.id}')">Excluir</button>
        </div>
      </div>
    </div>`).join('') || `<div class="empty">Nenhum treinamento cadastrado.</div>`}
  </div>`;
}
async function deleteCourse(courseId){
  if(!requireAdmin()) return;
  if(!courseById(courseId)) return;
  if(!(await askConfirm('Excluir este treinamento? Ele sai do catálogo, e o histórico de quem já concluiu continua guardado.','Excluir treinamento'))) return;
  try{ await api('/admin/courses/'+courseId, { method:'DELETE' }); await loadAdmin(); render(); }
  catch(e){ toast(e.message); }
}
let EDIT_COURSE = null;
function openCourseModal(courseId){
  EDIT_COURSE = courseId ? JSON.parse(JSON.stringify(courseById(courseId))) : { id:uid('crs'), title:'', description:'', cover:'📘', color:'#1F5C4A', modules:[{id:uid('m'),title:'Módulo 1',lessons:[]}], quiz:[] };
  showModal(`${courseId?'Editar':'Novo'} treinamento`, courseModalBody(), true);
}
function courseModalBody(){
  const c = EDIT_COURSE;
  return `
  <div class="field"><label class="field-label">Título</label><input class="input" id="mCTitle" value="${escapeAttr(c.title)}" oninput="EDIT_COURSE.title=this.value"></div>
  <div class="field"><label class="field-label">Descrição</label><textarea class="input" id="mCDesc" rows="2" oninput="EDIT_COURSE.description=this.value">${escapeHtml(c.description)}</textarea></div>
  <div style="display:flex; gap:10px">
    <div class="field" style="flex:1"><label class="field-label">Ícone (emoji)</label><input class="input" value="${escapeAttr(c.cover)}" oninput="EDIT_COURSE.cover=this.value; renderCourseModal()"></div>
    <div class="field" style="flex:1"><label class="field-label">Cor</label><input class="input" type="color" value="${safeColor(c.color)}" style="padding:4px; height:42px" oninput="EDIT_COURSE.color=this.value"></div>
  </div>
  <div class="dash-divider"></div>
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px">
    <label class="field-label" style="margin:0">Módulos e aulas</label>
    <button class="btn btn-ghost btn-sm" onclick="addModule()">+ Módulo</button>
  </div>
  ${c.modules.map((m,mi)=>`
    <div class="card pad" style="margin-bottom:10px; background:var(--paper)">
      <div style="display:flex; gap:8px; margin-bottom:8px">
        <input class="input" value="${escapeAttr(m.title)}" oninput="EDIT_COURSE.modules[${mi}].title=this.value">
        <button class="btn btn-danger btn-sm" onclick="removeModule(${mi})">✕</button>
      </div>
      ${m.lessons.map((l,li)=>`
        <div style="display:flex; gap:6px; margin-bottom:6px; align-items:center">
          <input class="input" style="flex:2" placeholder="Título da aula" value="${escapeAttr(l.title)}" oninput="EDIT_COURSE.modules[${mi}].lessons[${li}].title=this.value">
          <input class="input" style="flex:1; max-width:70px" type="number" min="0" placeholder="min" title="Duração em minutos (0 = não informada)" value="${l.durationMin||''}" oninput="EDIT_COURSE.modules[${mi}].lessons[${li}].durationMin=parseInt(this.value)||0">
          <input class="input" style="flex:2" placeholder="URL do vídeo (opcional)" value="${escapeAttr(l.videoUrl||'')}" oninput="EDIT_COURSE.modules[${mi}].lessons[${li}].videoUrl=this.value">
          <button class="icon-btn" onclick="removeLesson(${mi},${li})">✕</button>
        </div>`).join('')}
      <button class="btn btn-ghost btn-sm" onclick="addLesson(${mi})">+ Aula</button>
    </div>`).join('')}
  <div class="dash-divider"></div>
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px">
    <label class="field-label" style="margin:0">Questionário final (opcional)</label>
    <button class="btn btn-ghost btn-sm" onclick="addQuizQuestion()">+ Pergunta</button>
  </div>
  ${(c.quiz||[]).map((q,qi)=>`
    <div class="card pad" style="margin-bottom:10px; background:var(--paper)">
      <div style="display:flex; gap:8px; margin-bottom:8px">
        <input class="input" placeholder="Pergunta" value="${escapeAttr(q.q)}" oninput="EDIT_COURSE.quiz[${qi}].q=this.value">
        <button class="btn btn-danger btn-sm" onclick="removeQuizQuestion(${qi})">✕</button>
      </div>
      ${q.options.map((op,oi)=>`
        <div style="display:flex; gap:6px; margin-bottom:6px; align-items:center">
          <input type="radio" name="correct${qi}" ${q.correct===oi?'checked':''} onchange="EDIT_COURSE.quiz[${qi}].correct=${oi}">
          <input class="input" placeholder="Opção ${oi+1}" value="${escapeAttr(op)}" oninput="EDIT_COURSE.quiz[${qi}].options[${oi}]=this.value">
        </div>`).join('')}
    </div>`).join('')}
  <button class="btn btn-primary btn-block" style="margin-top:8px" onclick="saveCourse()">Salvar treinamento</button>
  `;
}
function renderCourseModal(){ document.getElementById('modalBody').innerHTML = courseModalBody(); }
function addModule(){ EDIT_COURSE.modules.push({id:uid('m'), title:'Novo módulo', lessons:[]}); renderCourseModal(); }
function removeModule(mi){ EDIT_COURSE.modules.splice(mi,1); renderCourseModal(); }
function addLesson(mi){ EDIT_COURSE.modules[mi].lessons.push({id:uid('l'), title:'', durationMin:5, videoUrl:''}); renderCourseModal(); }
function removeLesson(mi,li){ EDIT_COURSE.modules[mi].lessons.splice(li,1); renderCourseModal(); }
function addQuizQuestion(){ EDIT_COURSE.quiz = EDIT_COURSE.quiz||[]; EDIT_COURSE.quiz.push({q:'', options:['','',''], correct:0}); renderCourseModal(); }
function removeQuizQuestion(qi){ EDIT_COURSE.quiz.splice(qi,1); renderCourseModal(); }
async function saveCourse(){
  if(!requireAdmin()) return;
  const c = EDIT_COURSE;
  c.title = clampStr(c.title, LIMITS.title).trim();
  c.description = clampStr(c.description, LIMITS.desc);
  c.cover = Array.from(String(c.cover||'📘')).slice(0,4).join('') || '📘';
  c.color = safeColor(c.color);
  if(!c.title){ toast('Informe o título do treinamento.'); return; }
  for(const m of c.modules){
    m.title = clampStr(m.title, LIMITS.title);
    for(const l of m.lessons){
      l.title = clampStr(l.title, LIMITS.title);
      l.durationMin = Math.max(0, Math.min(600, parseInt(l.durationMin)||0));
      l.videoUrl = clampStr(l.videoUrl, LIMITS.url).trim();
      if(l.videoUrl && !videoSource(l.videoUrl)){ toast(`Link de vídeo inválido na aula "${l.title||'sem título'}". Use YouTube, Vimeo ou um arquivo https (.mp4/.webm).`); return; }
    }
  }
  for(const q of (c.quiz||[])){ q.q = clampStr(q.q, LIMITS.option); q.options = q.options.map(o=>clampStr(o, LIMITS.option)); }
  try{
    await api('/admin/courses/'+c.id, { method:'PUT', body:c });
    await loadAdmin(); closeModal(); toast('Treinamento salvo.'); render();
  }catch(e){ toast(e.message); }
}

function adminTabFuncionarios(){
  const ens = DB.enrollments;
  return `
  <h2 style="margin:0 0 14px; font-size:18px">Funcionários</h2>
  <div class="card table-scroll">
    <table><thead><tr><th>Funcionário</th><th>Empresa</th><th>Treinamento</th><th>Progresso</th><th>Status</th></tr></thead>
    <tbody>
    ${ens.length? ens.map(e=>{ const c=courseById(e.courseId), comp=companyById(e.companyId); const p=enrollmentProgress(e); const done=isEnrollmentComplete(e);
      return `<tr><td>${escapeHtml(e.employeeName)}</td><td>${escapeHtml(comp?comp.name:'—')}</td><td>${escapeHtml(c?c.title:'—')}</td>
      <td>${p}%</td><td>${done?`<span class="badge badge-done">Concluído</span>`:`<span class="badge badge-progress">Em andamento</span>`}</td></tr>`; }).join('')
    : `<tr><td colspan="5" style="text-align:center;color:var(--ink-soft);padding:30px">Nenhum funcionário registrado ainda.</td></tr>`}
    </tbody></table>
  </div>`;
}
function adminTabCertificados(){
  const withCert = DB.enrollments.filter(e=>e.certCode);
  return `
  <h2 style="margin:0 0 14px; font-size:18px">Certificados emitidos</h2>
  <div class="card pad" style="margin-bottom:16px">
    <label class="field-label">Validar certificado por código</label>
    <div style="display:flex; gap:8px"><input class="input" id="validateCode" placeholder="Ex: CERT-AB12-XYZ99"><button class="btn btn-primary" onclick="validateCert()">Validar</button></div>
    <div id="validateResult" style="margin-top:10px; font-size:13.5px"></div>
  </div>
  <div class="card table-scroll">
    <table><thead><tr><th>Funcionário</th><th>Empresa</th><th>Treinamento</th><th>Emitido em</th><th>Código</th></tr></thead>
    <tbody>
    ${withCert.length? withCert.map(e=>{ const c=courseById(e.courseId), comp=companyById(e.companyId);
      return `<tr><td>${escapeHtml(e.employeeName)}</td><td>${escapeHtml(comp?comp.name:'—')}</td><td>${escapeHtml(c?c.title:'—')}</td><td>${fmtDate(e.completedAt)}</td><td class="mono" style="font-size:12px">${escapeHtml(e.certCode)}</td></tr>`; }).join('')
    : `<tr><td colspan="5" style="text-align:center;color:var(--ink-soft);padding:30px">Nenhum certificado emitido ainda.</td></tr>`}
    </tbody></table>
  </div>`;
}
function validateCert(){
  const code = document.getElementById('validateCode').value.trim().toUpperCase();
  const en = DB.enrollments.find(e=>e.certCode===code);
  const el = document.getElementById('validateResult');
  if(!en){ el.innerHTML = `<span style="color:var(--danger)">Código não encontrado.</span>`; return; }
  const c = courseById(en.courseId), comp = companyById(en.companyId);
  el.innerHTML = `<span style="color:var(--accent); font-weight:600">✓ Válido</span> — ${escapeHtml(en.employeeName)} concluiu "${escapeHtml(c?.title||'')}" em ${fmtDate(en.completedAt)} (${escapeHtml(comp?.name||'')})`;
}
function adminTabDenuncias(){
  return `
  <h2 style="margin:0 0 14px; font-size:18px">Canal de Denúncias</h2>
  <div class="card pad">
    <p style="color:var(--ink-soft); font-size:13.5px; margin-top:0">Configure aqui o link do sistema externo de canal de denúncias (ex: um provedor dedicado de compliance). Enquanto não configurado, o link ficará indisponível para os usuários.</p>
    <div class="field"><label class="field-label">URL do canal de denúncias</label><input class="input" id="denounceUrlInput" value="${escapeAttr(DB.settings.denounceUrl)}" placeholder="https://..."></div>
    <button class="btn btn-primary" onclick="saveDenounceUrl()">Salvar</button>
  </div>`;
}
async function saveDenounceUrl(){
  if(!requireAdmin()) return;
  const raw = clampStr(document.getElementById('denounceUrlInput').value, LIMITS.url).trim();
  try{
    DB.settings.denounceUrl = (await api('/admin/settings/denuncia', { method:'PUT', body:{ url:raw } })).url;
    toast('Link atualizado.');
  }catch(e){ toast(e.message); }
}

/* ============================= ADMIN · SEGURANÇA ============================= */
function adminTabSeguranca(){
  const labels = { login:'Login', login_falhou:'Falha de login', bloqueio:'Bloqueio', logout:'Saída', empresa:'Empresa', treinamento:'Treinamento', certificado:'Certificado', configuracao:'Configuração', exportacao:'Exportação', seguranca:'Segurança' };
  const rows = DB.audit.map(a=>`<tr>
    <td style="white-space:nowrap; font-size:12.5px">${escapeHtml(new Date(a.at).toLocaleString('pt-BR'))}</td>
    <td><span class="badge ${a.type==='login_falhou'||a.type==='bloqueio'?'badge-progress':'badge-new'}">${escapeHtml(labels[a.type]||a.type)}</span></td>
    <td style="font-size:13px">${escapeHtml(a.detail)}</td></tr>`).join('');
  return `
  <h2 style="margin:0 0 14px; font-size:18px">Segurança</h2>
  ${accountSecurityCards()}
  <div class="card pad" style="margin-bottom:16px">
    <div class="section-title" style="margin-bottom:8px">Proteções ativas</div>
    <ul style="margin:0; padding-left:18px; font-size:13.5px; color:var(--ink-soft); line-height:1.8">
      <li>Login com JWT em cookie httpOnly e sessão encerrada no servidor</li>
      <li>2FA obrigatório para administrador, RH e Gerente</li>
      <li>Nomes, e-mails, conteúdo dos treinamentos e segredos do 2FA cifrados no banco com AES-256-GCM</li>
      <li>Gabarito dos questionários e emissão de certificados somente no servidor</li>
      <li>Bloqueio de ${SEC.LOCK_MINUTES} min após ${SEC.MAX_ATTEMPTS} tentativas incorretas</li>
      <li>Sessão expira após ${SEC.IDLE_MINUTES} min sem atividade (máximo de 8 h)</li>
    </ul>
  </div>
  <div class="card table-scroll">
    <div class="pad" style="padding-bottom:0"><div class="section-title">Registro de atividades (últimos 100)</div></div>
    <table><thead><tr><th>Data</th><th>Evento</th><th>Detalhe</th></tr></thead>
    <tbody>${rows || `<tr><td colspan="3" style="text-align:center;color:var(--ink-soft);padding:30px">Nenhum evento registrado.</td></tr>`}</tbody></table>
  </div>`;
}

/* ============================= MODAL ============================= */
function showModal(title, bodyHtml, wide){
  const root = document.getElementById('modalRoot') || (()=>{ const d=document.createElement('div'); d.id='modalRoot'; document.getElementById('app').appendChild(d); return d; })();
  root.innerHTML = `
  <div class="modal-backdrop" onclick="if(event.target===this)closeModal()">
    <div class="modal" style="${wide?'max-width:640px':''}">
      <div class="modal-head"><h3 style="margin:0; font-size:17px">${title}</h3><button class="icon-btn" onclick="closeModal()">✕</button></div>
      <div class="modal-body" id="modalBody">${bodyHtml}</div>
    </div>
  </div>`;
}
function closeModal(){ const root = document.getElementById('modalRoot'); if(root) root.innerHTML=''; }
