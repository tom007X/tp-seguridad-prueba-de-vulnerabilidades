# Presentación · XSS en AutoMax

## 1. ¿Qué es XSS?

**Cross-Site Scripting (XSS)** ocurre cuando una aplicación incluye datos que controla un tercero dentro de una página **sin tratarlos como texto**, y el navegador los interpreta como **código**. Ese código se ejecuta con los permisos de la página: el navegador de la víctima cree que el sitio legítimo lo envió.

La causa raíz es siempre la misma: **mezclar datos con código** sin separarlos.

| Tipo | ¿Dónde se inserta el dato? | ¿Pasa por el servidor? | ¿Persiste? |
|---|---|---|---|
| Reflejado | En la respuesta del servidor | Sí | No (hay que llevar a la víctima a un enlace) |
| Basado en DOM | En el navegador, vía JavaScript | No | No |
| Persistente | En la base de datos y luego en la página | Sí | Sí (afecta a todos los que la vean) |

En la demo se usa `alert()` como prueba inocua de que el script se ejecuta.

---

## 2. Las vulnerabilidades del laboratorio

### 2.1 XSS reflejado · Buscador de autos (`/reflected`)

- **Qué pasa:** el servidor devuelve lo que se buscó dentro del HTML sin escapar (`Autos encontrados para: ${q}`).
- **Cómo se llega a la víctima:** un enlace manipulado, por ejemplo enviado por mensaje o correo. Al abrirlo, el servidor "refleja" el contenido y el navegador lo ejecuta.
- **Versión corregida:** la salida pasa por `escapeHtml()`, que convierte `<`, `>`, `&`, `"` y `'` en entidades. El navegador muestra el texto, no lo interpreta.

### 2.2 XSS basado en DOM · Cotizador y ficha técnica (`/dom`)

Aquí la página llega limpia del servidor y es el **JavaScript del cliente** el que escribe datos de la URL de forma insegura. El servidor nunca ve el contenido, así que **escapar en el servidor no lo arregla**.

- **Concepto clave:** *fuente* (dato que controla el atacante: `location.hash`, `location.search`) → *sumidero* (función que lo interpreta: `innerHTML`, `a.href`, `document.write`, `eval`).
- **Caso 1 · `location.hash` → `innerHTML`:** `innerHTML` interpreta el texto como HTML. Corrección: `textContent`, que trata todo como texto plano.
- **Caso 2 · `location.search` → `a.href`:** un enlace con protocolo `javascript:` ejecuta código al hacer clic. Corrección: validar el protocolo con una lista blanca (`http:` y `https:`) usando `new URL()`.

### 2.3 XSS persistente · Opiniones de clientes (`/stored`)

- **Qué pasa:** un comentario se guarda tal cual en la base y se imprime sin escapar a **todos** los visitantes.
- **Por qué es el más grave:** no hace falta engañar a nadie para que abra un enlace. Basta con que la víctima visite la página normal. Un solo comentario afecta a todos los usuarios.
- **Versión corregida:** se guarda el dato original y se **escapa en la salida**, según el contexto donde se imprime (HTML, atributo, JavaScript, URL).

### 2.4 Cookie de sesión sin HttpOnly (`cid`)

- **Qué pasa:** al ingresar se puede elegir si la cookie `cid` lleva la bandera **HttpOnly**. Sin ella, cualquier script de la página puede leerla con `document.cookie`.
- **Por qué importa:** la cookie es la "llave" de la sesión. Quien la obtiene puede presentarse ante el servidor como la víctima.
- **Corrección:** con HttpOnly el navegador no la expone a JavaScript. El XSS sigue ejecutándose, pero ya no puede leer esa credencial.

### 2.5 Dato privado · Mi tarjeta (`/tarjeta`)

- **Rol en el lab:** representa información sensible que solo debe ver su dueño. Sirve para ilustrar qué se pone en riesgo cuando existe un XSS.
- **Protección implementada:** cada consulta filtra por el usuario de la sesión, y el borrado también, así que nadie puede ver ni eliminar la tarjeta de otro.
- **Limitación honesta:** los números se guardan sin cifrar. Es aceptable solo porque son ficticios.

---

## 3. ¿Cómo puede perjudicar a la víctima?

Un script inyectado corre **como si fuera la propia página**. Las consecuencias generales son:

| Daño | Descripción |
|---|---|
| **Robo de sesión** | Si la cookie es legible por JavaScript, se puede obtener y reutilizar para suplantar al usuario sin conocer su contraseña. |
| **Acciones en su nombre** | Aunque la cookie esté protegida, el navegador la sigue enviando automáticamente. El script puede publicar, borrar o modificar datos usando la sesión abierta. |
| **Lectura de datos privados** | El script puede leer lo que la víctima ve en pantalla (por ejemplo, sus tarjetas guardadas). |
| **Suplantación visual / phishing** | Se pueden insertar formularios falsos dentro de una página legítima para pedir contraseñas. |
| **Redirecciones y contenido falso** | Llevar a la víctima a otro sitio o modificar lo que lee. |
| **Propagación** | En el XSS persistente, cada visitante que carga la página queda afectado. |

Idea central: **HttpOnly reduce el daño, pero no elimina el XSS.** La defensa principal es impedir que el script se ejecute.

---

## 4. ¿Cómo se soluciona?

1. **Escapar la salida según el contexto** (HTML, atributos, JavaScript, URL). Es la defensa principal contra XSS reflejado y persistente.
2. **Usar APIs seguras en el cliente:** `textContent` en lugar de `innerHTML`; `setAttribute` y validación de URL en lugar de asignar valores sin revisar a `href`.
3. **Validar con lista blanca** los protocolos y formatos permitidos.
4. **Cookie de sesión con `HttpOnly`, `SameSite` y, en producción, `Secure`.**
5. **Content Security Policy (CSP)** como segunda línea de defensa: restringe qué scripts puede ejecutar el navegador.
6. **Control de acceso por usuario** en el servidor para los datos privados.
7. **Frameworks que escapan por defecto** y revisión de código que busque sumideros peligrosos.

Detalle por capa (frontend y backend) en [Seguridad.md](Seguridad.md).

---

## 5. Conclusiones

- XSS nace de **tratar datos como código**; las tres variantes difieren en *dónde* ocurre la mezcla.
- Cada defensa cubre una parte: escape de salida (causa), HttpOnly (reduce el impacto), CSP (red de seguridad), control de acceso (limita el alcance).
- Ninguna medida aislada alcanza: se combinan en capas.
