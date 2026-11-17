// Escapa los 5 caracteres que el parser HTML interpreta como marcado.
// Con esto, "<img onerror=...>" llega al navegador como "&lt;img onerror=...&gt;",
// que se dibuja como TEXTO y nunca se ejecuta.
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')   // primero & para no re-escapar las demás entidades
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
module.exports = { escapeHtml };
