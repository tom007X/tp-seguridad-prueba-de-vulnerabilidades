# Probar · ¿Cómo me afecta un XSS si el atacante es otra persona?

En el laboratorio hacés los dos papeles: escribís el payload (atacante) y lo ves ejecutarse (víctima). En un ataque real son personas distintas. Esta guía explica cómo se conectan y cómo comprobarlo en el lab.

---

## 1. XSS reflejado (`/reflected`)

### La clave: lo que escribís viaja en la URL
Después de buscar, mirá la barra de direcciones: queda algo como `/reflected?q=...lo que escribiste...`. El buscador usa GET, así que el contenido de la búsqueda **es parte del enlace**, y un enlace se puede copiar y mandar a otra persona.

### Cómo se ve con dos personas
1. **El atacante** arma una URL de AutoMax con el payload ya puesto en `?q=`. No necesita acceso al servidor ni a tu cuenta.
2. **Te la hace llegar** por un mensaje, un correo, un comentario o una publicación ("mirá esta oferta"). Puede acortarla o disimularla.
3. **Vos la abrís.** Tu navegador pide esa URL al servidor legítimo. El servidor, que no escapa la búsqueda, la **refleja** dentro del HTML.
4. **Tu navegador ejecuta el script.** Para él, ese código vino del sitio confiable, así que corre con los permisos de la página **y con tu sesión abierta**, no la del atacante.

El atacante nunca tocó tu computadora: solo te llevó a hacer vos mismo la búsqueda maliciosa sin saberlo.

### Por qué es peligroso aunque "lo ejecute la víctima"
- El script corre en **tu** navegador, con **tus** cookies y **tu** sesión.
- Puede actuar como vos dentro del sitio o mostrarte contenido falso que parece del sitio real.
- El atacante solo necesita que hagas clic.

### Por qué se llama "reflejado"
El payload no queda guardado: rebota del enlace al servidor y de vuelta al navegador. Hay que enviar el enlace a cada víctima. En el XSS **persistente** (Opiniones) no hace falta: el comentario queda en la base y le llega a todo el que entre a la página.

---

## 2. XSS basado en DOM (`/dom`)

La forma de llegar a la víctima es casi igual: un enlace armado por el atacante que la víctima abre. Lo que cambia es **dónde** se inserta el contenido.

| | Reflejado | Basado en DOM |
|---|---|---|
| ¿Quién inserta el payload en la página? | El **servidor**, en el HTML de la respuesta | El **JavaScript del navegador**, con la página ya cargada |
| ¿El servidor ve el payload? | Sí, llega en `?q=` | En el caso del hash (`#...`), **no**: el navegador nunca lo envía |
| ¿Dónde se arregla? | En el servidor, escapando la salida | En el cliente, con `textContent` o validando la URL |

### En el lab
- **Caso 1 · Cotizador:** el payload va después del `#` de la URL. En DevTools → Red vas a ver que el servidor recibe `/dom` sin nada más. `dom.js` lee el hash y lo escribe con `innerHTML`.
- **Caso 2 · Ficha técnica:** el valor va en `?ficha=`. Acá hace falta además que la víctima haga **clic** en el enlace "Ver ficha técnica", porque un `javascript:` en un `href` solo se ejecuta al seguirlo.

### Por qué importa la diferencia
Si el servidor filtrara todo lo que recibe, el XSS reflejado quedaría arreglado, pero **el de DOM no**: con el hash, el servidor no ve el dato, así que no tiene nada que filtrar. La defensa tiene que estar en el JavaScript de la página.

---

## 3. Cómo comprobarlo en el lab

Levantá el lab según el [README.md](README.md) (http://localhost:3002) e ingresá con un usuario.

### Reflejado
1. Buscá el payload de demostración en `/reflected` y comprobá que se ejecuta en el panel vulnerable.
2. **Copiá la URL completa** de la barra de direcciones.
3. Pegala en **otra pestaña** (o en otro navegador con la sesión iniciada).
4. Se ejecuta igual, sin escribir nada: ese es el recorrido de un enlace que te manda otra persona.
5. Repetí con el panel corregido: la misma URL se muestra como texto y no se ejecuta.

### DOM, caso 1 (hash)
1. En `/dom`, usá el campo del caso 1 (o el botón de ejemplo) con el payload.
2. Copiá la URL (termina en `#...`) y abrila en otra pestaña: se ejecuta.
3. Abrí DevTools → Red y recargá: el servidor recibe `/dom` sin el contenido del hash.

### DOM, caso 2 (`?ficha=`)
1. Cargá un valor con protocolo `javascript:` en el campo del caso 2.
2. Hacé clic en "Ver ficha técnica" del panel vulnerable: se ejecuta.
3. En el panel corregido el enlace queda en `#` y el clic no hace nada.

### Cookie `cid` (opcional)
- Ingresá con la casilla HttpOnly **desmarcada** y repetí las pruebas con el payload que muestra `document.cookie`: el valor de `cid` aparece.
- Cerrá sesión, ingresá con la casilla **marcada** y repetí: `cid` ya no aparece. El XSS se ejecuta igual, pero no puede leer esa cookie.

---

## 4. Cómo se evita

- **Servidor:** escapar la entrada antes de insertarla en el HTML (versión corregida del reflejado).
- **Cliente:** `textContent` en lugar de `innerHTML`, y validar las URLs con lista blanca de protocolos (versión corregida del DOM).
- **Cookie con HttpOnly y una CSP:** reducen el daño si algo se escapa.
- **Usuarios:** desconfiar de enlaces con parámetros largos o raros, aunque apunten a un sitio conocido.

Más detalle en [Presentacion.md](Presentacion.md) y [Seguridad.md](Seguridad.md).
