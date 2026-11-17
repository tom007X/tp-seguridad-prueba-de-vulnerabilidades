# AutoMax · Laboratorio didáctico de XSS

Concesionaria ficticia hecha a propósito con fallas de **Cross-Site Scripting (XSS)** para estudiarlas en la materia de Seguridad. Cada demo muestra una **versión vulnerable** y una **versión corregida** lado a lado.

> ⚠ Es intencionalmente vulnerable. Usalo **solo en localhost**, nunca lo expongas a una red ni lo uses con datos reales.

## Estructura

```
.
├── docker-compose.yml        # Postgres 16 (base "floreria")
├── xss-lab-autos/            # La aplicación (Node.js + Express 5)
│   ├── server.js             # Rutas, páginas HTML y lógica de las demos
│   ├── lib/
│   │   ├── store.js          # Acceso a Postgres (usuarios, comentarios, tarjetas) y sesiones en memoria
│   │   └── escape.js         # escapeHtml(): escape de salida usado en las versiones corregidas
│   └── public/
│       ├── dom.js            # JavaScript del cliente para las demos de XSS basado en DOM
│       └── style.css         # Estilos
├── Presentacion.md           # Explicación de cada vulnerabilidad, su impacto y su solución
└── Seguridad.md              # Vulnerabilidades y soluciones separadas en frontend y backend
```

## Cómo levantarlo

Requisitos: Docker, Node.js 18+ y npm.

```bash
# 1. Base de datos (desde la carpeta raíz)
docker compose up -d

# 2. Aplicación
cd xss-lab-autos
npm install
npm start
```

Abrí **http://localhost:3002**.

## Puertos

| Servicio | Puerto | Notas |
|---|---|---|
| Aplicación (Express) | **3002** | Solo escucha en `127.0.0.1`. Se cambia con `PORT=XXXX npm start`. |
| Postgres | **5433** (host) → 5432 (contenedor) | Usuario/clave `postgres`/`postgres`, base `floreria`. |

Las tablas (`users`, `comments`, `cards`) las crea la app sola al arrancar.

## Secciones

| Ruta | Demo | Tipo |
|---|---|---|
| `/` | Login / registro (una pantalla por vez) | Casilla para proteger la cookie `cid` con HttpOnly |
| `/reflected` | Buscador de autos | XSS reflejado |
| `/dom` | Cotizador y ficha técnica (valor escrito a mano) | XSS basado en DOM |
| `/stored` | Opiniones de clientes (con "Borrar todo") | XSS persistente |
| `/tarjeta` | Tarjeta ficticia, visible solo para su dueño | Dato privado a proteger |

## Detalles a tener en cuenta

- **Sesión:** cookie `cid`, con un id aleatorio guardado en la memoria del servidor. Al reiniciar la app hay que volver a ingresar. Usuarios, comentarios y tarjetas persisten en Postgres.
- **Contraseñas:** se guardan con hash (scrypt) y salt.
- **Consultas SQL:** parametrizadas, para que el foco quede en XSS.
- **Tarjetas:** usá solo números inventados. Se guardan sin cifrar.

## Detener y limpiar

```bash
# detener la base conservando los datos
docker compose down
# detener y borrar también los datos
docker compose down -v
```

Más detalle en [Presentacion.md](Presentacion.md) y [Seguridad.md](Seguridad.md).
