# Seguridad · Vulnerabilidades y soluciones por capa

Las mismas fallas del laboratorio, separadas según **dónde se origina el problema** y **dónde se corrige**: frontend (navegador) o backend (servidor).

## Resumen

| Vulnerabilidad | Origen | Dónde se corrige |
|---|---|---|
| XSS reflejado | Backend | Backend |
| XSS persistente | Backend (almacenamiento y salida) | Backend |
| XSS basado en DOM | Frontend | Frontend |
| Cookie de sesión legible por JavaScript | Backend (configuración de la cookie) | Backend |
| Acceso a datos de otros usuarios | Backend | Backend |
| Falta de CSP | Ambos | Backend (cabecera) + Frontend (sin scripts en línea) |

---

## Backend

### B1. XSS reflejado
- **Problema:** el servidor incluye un parámetro de la URL en el HTML de la respuesta sin escapar.
- **Solución:** escapar la salida antes de insertarla (`escapeHtml()` en `lib/escape.js`) o usar un motor de plantillas que lo haga por defecto.
- **Dónde está en el lab:** `/reflected/vuln` (falla) y `/reflected/safe` (corrección).

### B2. XSS persistente
- **Problema:** se guarda el comentario y luego se imprime sin escapar a todos los usuarios.
- **Solución:**
  - Escapar **al renderizar**, según el contexto de salida. Guardar el dato original facilita reutilizarlo en otros contextos.
  - Validar tipo y longitud de lo que se recibe.
  - Si hay que permitir HTML, usar una librería de saneamiento con lista blanca de etiquetas.
- **Dónde está en el lab:** `/stored/vuln` y `/stored/safe`.

### B3. Cookie de sesión
- **Problema:** una cookie sin `HttpOnly` puede ser leída por cualquier script de la página.
- **Solución:** emitirla con:
  - `HttpOnly`: oculta la cookie a JavaScript.
  - `SameSite=Lax` o `Strict`: limita su envío desde otros sitios.
  - `Secure`: solo por HTTPS (en producción; en `localhost` por HTTP no aplica).
  - Vencimiento razonable, regeneración del id al iniciar sesión e invalidación al cerrarla.
- **Dónde está en el lab:** `POST /login`, con la casilla que activa o no `HttpOnly`.

### B4. Control de acceso a datos privados
- **Problema:** si el servidor no verifica quién pide un dato, cualquiera podría leer o borrar el de otro.
- **Solución:** filtrar siempre por el usuario de la sesión en cada consulta, incluido el borrado, y no confiar en ids enviados por el cliente.
- **Dónde está en el lab:** `/tarjeta` (`WHERE username = $1`).

### B5. Consultas a la base de datos
- **Problema:** concatenar entradas en SQL permite inyección SQL.
- **Solución:** consultas parametrizadas (`$1, $2…`). El lab las usa en todo `lib/store.js`.

### B6. Cabeceras de seguridad
- **Content-Security-Policy:** limita desde dónde se pueden cargar y ejecutar scripts. Es una segunda barrera si falla el escape.
- **`X-Content-Type-Options: nosniff`** y **`Referrer-Policy`** como complemento.
- **No implementado en el lab**, que prioriza mostrar el fallo.

### B7. Datos sensibles
- **Problema:** guardar números de tarjeta sin cifrar.
- **Solución:** no almacenar datos de tarjeta reales; delegar en un procesador de pagos (tokenización) o cifrar y cumplir las normas aplicables. En el lab los números son ficticios.

---

## Frontend

### F1. XSS basado en DOM
- **Problema:** el JavaScript del cliente toma un dato de una fuente controlable (`location.hash`, `location.search`) y lo escribe con un sumidero peligroso.
- **Solución:**
  - Usar **`textContent`** en lugar de `innerHTML`.
  - Evitar `document.write`, `eval`, `setTimeout` con cadenas y asignaciones de HTML sin tratar.
  - Si hace falta insertar HTML, sanear con una librería (por ejemplo DOMPurify).
- **Dónde está en el lab:** `public/dom.js`, caso 1.

### F2. Enlaces con protocolos peligrosos
- **Problema:** asignar a `href` un valor sin validar permite protocolos como `javascript:`.
- **Solución:** validar con `new URL()` y una **lista blanca** de protocolos (`http:` y `https:`); ante cualquier otro valor, usar un destino seguro.
- **Dónde está en el lab:** `public/dom.js`, caso 2.

### F3. Confiar en datos del navegador
- **Problema:** tratar la URL, el hash, el almacenamiento local o los mensajes entre ventanas como si fueran de confianza.
- **Solución:** considerar toda esa información como **entrada no confiable** y validarla antes de usarla.

### F4. Compatibilidad con CSP
- **Problema:** el código con scripts y manejadores en línea (`onclick`, `onsubmit`) obliga a una CSP permisiva.
- **Solución:** mover el JavaScript a archivos externos y registrar eventos con `addEventListener`, para poder aplicar una CSP estricta.
- **Nota del lab:** usa `onsubmit` en línea en los formularios de borrado, por simplicidad. En una aplicación real convendría moverlos a un archivo.

### F5. Uso de frameworks
- Los frameworks modernos (React, Vue, Angular) escapan por defecto. Los riesgos reaparecen al usar sus "escapes" explícitos (`dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust…`): evitarlos o sanear antes.

---

## Por capa, en una frase

- **Backend:** escapar la salida, configurar bien la cookie de sesión, controlar el acceso por usuario, parametrizar SQL y enviar cabeceras como CSP.
- **Frontend:** usar APIs seguras (`textContent`), validar URLs con lista blanca, tratar los datos del navegador como no confiables y evitar código en línea.

## Lo que el lab no cubre

Protección contra CSRF más allá de `SameSite`, límite de intentos de login, vencimiento de sesiones, HTTPS, CSP y cifrado de datos sensibles.
