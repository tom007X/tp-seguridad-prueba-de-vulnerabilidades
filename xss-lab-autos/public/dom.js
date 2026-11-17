// XSS basado en DOM: todo ocurre en el navegador. El servidor entrega la página limpia y
// es ESTE script el que lee un dato de la URL (fuente) y lo escribe en la página (sumidero).
// El hash (#...) ni siquiera se envía al servidor: escapar en el servidor no puede arreglarlo.
const $ = (id) => document.getElementById(id);
const decode = (s) => { try { return decodeURIComponent(s); } catch { return s; } };

// ---------- Caso 1: location.hash -> innerHTML ----------
function caso1() {
  const data = decode(location.hash.slice(1));
  $('src1').textContent = location.hash || '(vacío)';   // textContent: acá mostramos, no ejecutamos

  // VULNERABLE: innerHTML interpreta el string como HTML -> ejecuta <img onerror=...>
  $('out-vuln').innerHTML = 'Cotización para: ' + data;

  // CORREGIDA: textContent trata el string como texto plano, nunca como marcado.
  // Es una API "segura por diseño": no hay nada que escapar.
  $('out-safe').textContent = 'Cotización para: ' + data;
}

// ---------- Caso 2: location.search -> a.href ----------
function seguro(valor) {
  // Lista blanca de protocolos: solo http y https. "javascript:", "data:", etc. se descartan.
  try {
    const u = new URL(valor, location.origin);   // new URL normaliza mayúsculas, espacios, etc.
    return ['http:', 'https:'].includes(u.protocol) ? u.href : null;
  } catch { return null; }
}

function caso2() {
  const ficha = new URLSearchParams(location.search).get('ficha') || '';
  $('src2').textContent = ficha || '(vacío)';
  if (!ficha) return;

  // VULNERABLE: si el valor es "javascript:...", al hacer clic el navegador ejecuta ese código.
  $('link-vuln').href = ficha;
  $('note-vuln').textContent = 'href = ' + ficha + '  → hacé clic en el enlace para ver qué pasa.';

  // CORREGIDA: se valida el protocolo antes de asignarlo.
  const ok = seguro(ficha);
  $('link-safe').href = ok || '#';
  $('note-safe').textContent = ok
    ? 'Protocolo permitido → href = ' + ok
    : 'Protocolo bloqueado → el enlace quedó en "#". Hacer clic no ejecuta nada.';
}

// ---------- Ingreso manual de valores ----------
// Caso 1: se escribe en el hash (no recarga la página, dispara 'hashchange').
$('f1').addEventListener('submit', (e) => {
  e.preventDefault();
  location.hash = encodeURIComponent($('in1').value);
  caso1();   // por si el hash no cambió (mismo valor)
});
// Caso 2: se escribe en la query (?ficha=...), lo que recarga la página.
$('f2').addEventListener('submit', (e) => {
  e.preventDefault();
  location.search = '?ficha=' + encodeURIComponent($('in2').value);
});
$('in1').value = decode(location.hash.slice(1));
$('in2').value = new URLSearchParams(location.search).get('ficha') || '';

window.addEventListener('hashchange', caso1);
caso1();
caso2();
