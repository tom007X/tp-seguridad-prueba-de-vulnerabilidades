// LABORATORIO DIDÁCTICO DE XSS - solo localhost, datos en memoria.
// Las rutas/paneles "vuln" son vulnerables A PROPÓSITO.
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const { escapeHtml } = require('./lib/escape');
const store = require('./lib/store');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- helpers ----------
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const currentSession = (req) => store.sessions.get(req.cookies.cid);   // { username, httpOnly }
const currentUser = (req) => currentSession(req)?.username;

function page(req, title, body) {
  const u = currentUser(req);
  const link = (href, label) =>
    `<a href="${href}"${req.path === href ? ' aria-current="page"' : ''}>${label}</a>`;
  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light dark">
<title>${escapeHtml(title)} · AutoMax</title><link rel="stylesheet" href="/style.css"></head><body>
<header class="topbar"><div class="wrap bar">
  <a class="brand" href="/"><span class="brand-mark">A</span>AutoMax</a>
  <nav aria-label="Principal">${u ? link('/reflected', 'Buscar autos') + link('/dom', 'Cotizador') + link('/stored', 'Opiniones') + link('/tarjeta', 'Mi tarjeta') : ''}</nav>
  <div class="user">${u ? `<span class="chip">${escapeHtml(u)}</span><form method="post" action="/logout"><button class="btn ghost sm">Salir</button></form>` : ''}</div>
</div></header>
<main class="wrap"><h1>${escapeHtml(title)}</h1>${body}</main>
<footer class="wrap foot">Laboratorio didáctico · solo localhost · datos en Postgres</footer></body></html>`;
}

const VULN_BANNER = '<span class="badge bad">⚠ Vulnerable a propósito</span>';
const SAFE_BANNER = '<span class="badge good">✔ Corregida</span>';
const PAYLOAD = `&lt;img src=x onerror=alert('XSS')&gt;`;
const PAYLOAD_COOKIE = `&lt;img src=x onerror=alert(document.cookie)&gt;`;

// ---------- auth ----------
app.get('/', (req, res) => {
  const u = currentUser(req);
  const field = (name, label, type) =>
    `<label>${label}<input type="${type}" name="${name}" placeholder="${label}" required></label>`;
  res.send(page(req, 'AutoMax Concesionaria', u
    ? `<p class="lead">Sesión iniciada como <b>${escapeHtml(u)}</b>. Elegí una demo para ver el fallo y su corrección.</p>
<div class="grid">
  <a class="card link" href="/reflected"><h3>Buscar autos</h3><span class="badge">Reflejado</span><p>La búsqueda se refleja en la respuesta del servidor.</p></a>
  <a class="card link" href="/dom"><h3>Cotizador</h3><span class="badge">DOM</span><p>El payload vive en el hash y nunca llega al servidor.</p></a>
  <a class="card link" href="/stored"><h3>Opiniones</h3><span class="badge">Persistente</span><p>El comentario queda guardado y afecta a todos.</p></a>
  <a class="card link" href="/tarjeta"><h3>Mi tarjeta</h3><span class="badge">Dato privado</span><p>Guardá una tarjeta falsa que solo vos ves. Es lo que un XSS intentaría robar.</p></a>
</div>
<div class="note ${currentSession(req).httpOnly ? 'good' : 'bad'}">
  <b>Tu cookie <code>cid</code> está ${currentSession(req).httpOnly ? 'PROTEGIDA con HttpOnly' : 'SIN HttpOnly (vulnerable)'}.</b><br>
  ${currentSession(req).httpOnly
    ? 'Un script inyectado no puede leerla: <code>document.cookie</code> no la incluye.'
    : 'Cualquier script inyectado puede leerla con <code>document.cookie</code>.'}
  Para comparar, cerrá sesión y volvé a ingresar con la casilla ${currentSession(req).httpOnly ? 'desmarcada' : 'marcada'}.
</div>
<p class="muted">Payload simple: <code>${PAYLOAD}</code><br>Payload que muestra la cookie: <code>${PAYLOAD_COOKIE}</code></p>`
    : (req.query.modo === 'registro'
      ? `<div class="auth card"><h3>Crear cuenta</h3>
  <form method="post" action="/register">${field('username', 'Usuario', 'text')}${field('password', 'Contraseña', 'password')}<button class="btn primary block">Registrarse</button></form>
  <p class="switch">¿Ya tenés cuenta? <a href="/">Ingresá</a></p></div>`
      : `<div class="auth card"><h3>Ingresar</h3>
  ${req.query.ok ? '<p class="note good">Cuenta creada. Ya podés ingresar.</p>' : ''}
  <form method="post" action="/login">${field('username', 'Usuario', 'text')}${field('password', 'Contraseña', 'password')}
    <label class="check"><input type="checkbox" name="httponly" value="1"><span>Proteger la cookie <code>cid</code> con HttpOnly (versión corregida)</span></label>
    <button class="btn primary block">Ingresar</button></form>
  <p class="switch">¿No tenés cuenta? <a href="/?modo=registro">Registrate</a></p></div>`)));
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || await store.getUser(username)) return res.status(400).send(page(req, 'Error', '<p>Usuario inválido o ya existe. <a href="/">Volver</a></p>'));
  const salt = crypto.randomBytes(16).toString('hex');
  await store.createUser(username, salt, hashPw(password, salt));
  res.redirect('/?ok=1');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const u = await store.getUser(username);
  if (!u || !crypto.timingSafeEqual(Buffer.from(u.hash), Buffer.from(hashPw(password, u.salt)))) {
    return res.status(401).send(page(req, 'Error', '<p>Credenciales incorrectas. <a href="/">Volver</a></p>'));
  }
  const cid = crypto.randomBytes(24).toString('hex');
  const httpOnly = req.body.httponly === '1';
  store.sessions.set(cid, { username, httpOnly });
  // 'cid' = id de sesión. Se puede elegir al ingresar:
  //  - SIN HttpOnly (vulnerable): document.cookie la devuelve, así que un script inyectado por XSS
  //    puede leer el id de sesión y robar la sesión.
  //  - CON HttpOnly (corregida): el navegador la oculta a JavaScript. El XSS sigue ejecutándose,
  //    pero ya no puede leer el id de sesión por esta vía. sameSite=lax frena envíos cross-site.
  res.cookie('cid', cid, { httpOnly, sameSite: 'lax' });
  res.redirect('/');
});

app.post('/logout', (req, res) => {
  store.sessions.delete(req.cookies.cid);
  res.clearCookie('cid');
  res.redirect('/');
});

// ---------- 1. XSS reflejado ----------
app.get('/reflected', (req, res) => {
  res.send(page(req, 'Buscador de autos (XSS reflejado)', `
<p>Probá: <code>${PAYLOAD}</code> o, para ver la cookie: <code>${PAYLOAD_COOKIE}</code></p>
<form class="search" method="get" action="/reflected"><input type="text" name="q" placeholder="marca o modelo (ej: Corolla)" aria-label="Buscar autos"><button class="btn primary">Buscar</button></form>
<div class="cols">
 <div class="panel vuln">${VULN_BANNER}<h3>Versión vulnerable</h3>
  <pre>// q se concatena tal cual en el HTML
res.send(\`Autos encontrados para: \${q}\`);</pre>
  <iframe src="/reflected/vuln?q=${encodeURIComponent(req.query.q || '')}" class="frame" title="Respuesta del servidor"></iframe></div>
 <div class="panel safe">${SAFE_BANNER}<h3>Versión corregida</h3>
  <pre>// escapeHtml convierte &lt; &gt; &amp; " ' en entidades
res.send(\`Autos encontrados para: \${escapeHtml(q)}\`);</pre>
  <iframe src="/reflected/safe?q=${encodeURIComponent(req.query.q || '')}" class="frame" title="Respuesta del servidor"></iframe></div>
</div>`));
});

app.get('/reflected/vuln', (req, res) => {
  const q = req.query.q || '';
  // VULNERABLE: la entrada del usuario va directo al HTML de la respuesta.
  res.send(`<!DOCTYPE html><meta charset="utf-8"><body>Autos encontrados para: ${q}</body>`);
});

app.get('/reflected/safe', (req, res) => {
  const q = req.query.q || '';
  // CORREGIDA: al escapar, el navegador recibe "&lt;img ...&gt;" y lo muestra
  // como texto. Sin caracteres "<" ni ">" reales no se puede abrir ninguna etiqueta.
  res.send(`<!DOCTYPE html><meta charset="utf-8"><body>Autos encontrados para: ${escapeHtml(q)}</body>`);
});

// ---------- 2. XSS basado en DOM ----------
app.get('/dom', (req, res) => {
  const hashEx = encodeURIComponent("<img src=x onerror=alert(document.cookie)>");
  res.send(page(req, 'Cotizador (XSS basado en DOM)', `
<div class="card">
  <h3>¿Qué es un XSS basado en DOM?</h3>
  <p>En el XSS reflejado y en el persistente el <b>servidor</b> mete el dato peligroso en el HTML. Acá no: la página llega limpia y es el <b>JavaScript del navegador</b> el que lee un dato de la URL y lo escribe en la página de forma insegura. El servidor nunca ve el payload.</p>
  <ol class="steps">
    <li><b>Fuente (source)</b>: un dato que controla el atacante, como <code>location.hash</code> o <code>location.search</code>.</li>
    <li><b>Sumidero (sink)</b>: una función que interpreta ese dato como código o HTML, como <code>innerHTML</code>, <code>a.href</code>, <code>document.write</code> o <code>eval</code>.</li>
    <li><b>La falla</b> aparece cuando el dato viaja de la fuente al sumidero <i>sin validarlo</i>. La solución es usar un sumidero seguro (<code>textContent</code>) o validar el dato antes.</li>
  </ol>
  <p class="muted">Comprobalo: abrí DevTools → Red (Network) y recargá. Verás que el hash <b>no</b> se envía al servidor, así que escapar en el servidor no puede arreglar esto.</p>
</div>

<h2 class="case">Caso 1 · Cotizador: <code>location.hash</code> → <code>innerHTML</code></h2>
<p>El cotizador toma el nombre del auto del hash de la URL (lo que va después del <code>#</code>) y lo muestra en pantalla.</p>
<p><a class="btn sm" href="/dom#Corolla">Cotizar “Corolla” (uso normal)</a>
   <a class="btn sm primary" href="/dom#${hashEx}">Cargar payload que muestra la cookie</a></p>
<form class="search" id="f1"><input type="text" id="in1" placeholder="Escribí el nombre del auto (o un payload) a mano" aria-label="Valor del caso 1"><button class="btn primary">Cotizar</button></form>
<div class="trace"><b>Fuente leída:</b> <code id="src1">(vacío)</code></div>
<div class="cols">
 <div class="panel vuln">${VULN_BANNER}<h3>Versión vulnerable</h3>
  <pre>// innerHTML INTERPRETA el texto como HTML
el.innerHTML = 'Cotización para: ' + data</pre>
  <div class="out" id="out-vuln"></div>
  <p class="muted">Un <code>&lt;img onerror=…&gt;</code> se convierte en una etiqueta real y el navegador ejecuta el <code>onerror</code>.</p></div>
 <div class="panel safe">${SAFE_BANNER}<h3>Versión corregida</h3>
  <pre>// textContent trata todo como TEXTO plano
el.textContent = 'Cotización para: ' + data</pre>
  <div class="out" id="out-safe"></div>
  <p class="muted">Se ve el texto literal del payload: nunca se convierte en etiqueta, así que no hay nada que ejecutar.</p></div>
</div>

<h2 class="case">Caso 2 · Ficha técnica: <code>location.search</code> → <code>a.href</code></h2>
<p>Acá el sumidero no es <code>innerHTML</code> sino el atributo <code>href</code> de un enlace. La ficha técnica del auto se abre desde la URL <code>?ficha=…</code>. Si el valor empieza con <code>javascript:</code>, al <b>hacer clic</b> el navegador ejecuta ese código en vez de navegar.</p>
<p><a class="btn sm" href="/dom?ficha=https://example.com/corolla.pdf">Ficha normal (https)</a>
   <a class="btn sm primary" href="/dom?ficha=javascript:alert(document.cookie)">Cargar enlace malicioso</a></p>
<form class="search" id="f2"><input type="text" id="in2" placeholder="Escribí la URL de la ficha (o javascript:…) a mano" aria-label="Valor del caso 2"><button class="btn primary">Cargar ficha</button></form>
<div class="trace"><b>Fuente leída:</b> <code id="src2">(vacío)</code></div>
<div class="cols">
 <div class="panel vuln">${VULN_BANNER}<h3>Versión vulnerable</h3>
  <pre>// se confía en el valor de la URL
link.href = params.get('ficha')</pre>
  <div class="out"><a id="link-vuln" href="#">Ver ficha técnica</a></div>
  <p class="muted" id="note-vuln"></p></div>
 <div class="panel safe">${SAFE_BANNER}<h3>Versión corregida</h3>
  <pre>// se permite solo http: y https: (lista blanca)
const u = new URL(valor, location.origin)
link.href = ['http:','https:'].includes(u.protocol) ? u.href : '#'</pre>
  <div class="out"><a id="link-safe" href="#">Ver ficha técnica</a></div>
  <p class="muted" id="note-safe"></p></div>
</div>
<script src="/dom.js"></script>`));
});

// ---------- Mi tarjeta (dato privado, solo lo ve su dueño) ----------
// Número FALSO de práctica. Se guarda en la base asociado al usuario; las consultas siempre
// filtran por el usuario de la sesión, así que nadie más puede verlo ni borrarlo.
const groupCard = (n) => n.replace(/(.{4})/g, '$1 ').trim();

app.get('/tarjeta', async (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).send(page(req, 'Mi tarjeta', '<p>Necesitás <a href="/">iniciar sesión</a>.</p>'));
  const cards = await store.getCards(u);
  res.send(page(req, 'Mi tarjeta (dato privado)', `
<p class="lead">Guardá una tarjeta <b>ficticia</b>. Solo vos la ves: es el tipo de dato que un XSS intentaría robar.</p>
${req.query.err ? '<p class="note bad">El número debe tener entre 13 y 19 dígitos.</p>' : ''}
<div class="card">
  <h3>Agregar tarjeta</h3>
  <form class="search" method="post" action="/tarjeta">
    <input type="text" name="number" inputmode="numeric" placeholder="4242 4242 4242 4242" aria-label="Número de tarjeta falsa" required>
    <button class="btn primary">Guardar</button>
  </form>
  <p class="muted">⚠ Usá solo números inventados. Esta app es un laboratorio y el número se guarda en la base sin cifrar.</p>
</div>
<h2 class="case">Tus tarjetas</h2>
${cards.length ? cards.map((c) => `<div class="card cardrow"><span class="pan">💳 ${escapeHtml(groupCard(c.number))}</span>
  <form method="post" action="/tarjeta/delete/${Number(c.id)}" onsubmit="return confirm('¿Borrar esta tarjeta?')"><button class="btn danger sm">🗑 Borrar</button></form></div>`).join('')
  : '<p class="muted">Todavía no guardaste ninguna tarjeta.</p>'}`));
});

app.post('/tarjeta', async (req, res) => {
  const u = currentUser(req); if (!u) return res.redirect('/');
  const number = String(req.body.number || '').replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(number)) return res.redirect('/tarjeta?err=1');
  await store.addCard(u, number);
  res.redirect('/tarjeta');
});

app.post('/tarjeta/delete/:id', async (req, res) => {
  const u = currentUser(req); if (!u) return res.redirect('/');
  await store.deleteCard(u, Number(req.params.id));   // filtra por dueño: no se puede borrar la de otro
  res.redirect('/tarjeta');
});

// ---------- 3. XSS persistente ----------
function commentList(list, safe) {
  return list.map((c) => safe
    ? `<div class="out comment"><b>${escapeHtml(c.user)}</b>: ${escapeHtml(c.text)}</div>`   // CORREGIDA
    : `<div class="out comment"><b>${c.user}</b>: ${c.text}</div>`).join('');               // VULNERABLE
}

app.get('/stored', async (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).send(page(req, 'Opiniones de clientes (XSS persistente)', '<p>Necesitás <a href="/">iniciar sesión</a>.</p>'));
  res.send(page(req, 'Opiniones de clientes (XSS persistente)', `
<p>Probá: <code>${PAYLOAD}</code> o, para ver la cookie: <code>${PAYLOAD_COOKIE}</code></p>
<div class="cols">
 <div class="panel vuln">${VULN_BANNER}<h3>Versión vulnerable</h3>
  <pre>// se guarda crudo y se imprime crudo a TODOS los visitantes
div.innerHTML = comment.text</pre>
  <form method="post" action="/stored/clear/vuln" onsubmit="return confirm('¿Borrar TODAS las opiniones de este panel?')"><button class="btn danger sm">🗑 Borrar todo</button></form>
  <form method="post" action="/stored/vuln"><textarea name="text" aria-label="Opinión" placeholder="Escribí tu opinión…" required></textarea><button class="btn primary">Publicar</button></form>
  ${commentList(await store.getComments('vuln'), false)}</div>
 <div class="panel safe">${SAFE_BANNER}<h3>Versión corregida</h3>
  <pre>// se escapa en la SALIDA (al renderizar)
div.innerHTML = escapeHtml(comment.text)</pre>
  <form method="post" action="/stored/clear/safe" onsubmit="return confirm('¿Borrar TODAS las opiniones de este panel?')"><button class="btn danger sm">🗑 Borrar todo</button></form>
  <form method="post" action="/stored/safe"><textarea name="text" aria-label="Opinión" placeholder="Escribí tu opinión…" required></textarea><button class="btn primary">Publicar</button></form>
  ${commentList(await store.getComments('safe'), true)}</div>
</div>`));
});

app.post('/stored/vuln', async (req, res) => {
  const u = currentUser(req); if (!u) return res.redirect('/');
  await store.addComment('vuln', u, req.body.text || '');  // sin sanear
  res.redirect('/stored');
});

app.post('/stored/safe', async (req, res) => {
  const u = currentUser(req); if (!u) return res.redirect('/');
  // Se guarda el dato original; el escape se aplica según el contexto de salida
  // (HTML aquí). Escapar al renderizar es la defensa principal contra XSS persistente.
  await store.addComment('safe', u, req.body.text || '');
  res.redirect('/stored');
});

app.post('/stored/clear/:variant', async (req, res) => {
  const u = currentUser(req); if (!u) return res.redirect('/');
  if (!['vuln', 'safe'].includes(req.params.variant)) return res.status(400).send('Variante inválida');
  await store.clearComments(req.params.variant);
  res.redirect('/stored');
});

const PORT = process.env.PORT || 3002;
// Express 5 propaga a este handler los errores de handlers async (p. ej. Postgres caído).
app.use((err, req, res, next) => { console.error(err); res.status(500).send('Error interno'); });
store.init().then(() => app.listen(PORT, '127.0.0.1', () => console.log('AutoMax XSS lab en http://localhost:' + PORT)))
  .catch((e) => { console.error('No se pudo conectar a Postgres:', e.message); process.exit(1); });
