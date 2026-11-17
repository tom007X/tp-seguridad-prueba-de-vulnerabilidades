# AutoMax - Laboratorio XSS (tienda de autos, solo localhost)

    npm install && npm start   # http://localhost:3002

Registrate, ingresá y visitá las tres demos (reflejado, DOM, persistente). Cada una muestra
la versión vulnerable (rojo) y la corregida (verde). Payload de demostración:

    <img src=x onerror=alert('XSS')>

- Buscador de autos (reflejado): `/reflected?q=<payload>`
- Cotizador (DOM): `/dom#<payload>`
- Opiniones de clientes (persistente): publicar el payload en `/stored`

Mitigaciones: `escapeHtml()` en la salida (`lib/escape.js`), `textContent` en el DOM,
y cookie de sesión `cid` con `HttpOnly` + `SameSite=Lax`. Usuarios y comentarios en Postgres (`docker compose up -d` en la carpeta padre; sesiones en memoria).
