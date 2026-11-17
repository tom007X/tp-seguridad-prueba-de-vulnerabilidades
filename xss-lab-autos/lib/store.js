// Usuarios y comentarios viven en Postgres (la base "floreria", docker-compose.yml).
// Todas las consultas están PARAMETRIZADAS ($1, $2...): el foco del lab es XSS, no inyección SQL.
// Las sesiones siguen en memoria: se pierden al reiniciar el servidor (hay que volver a loguearse).
const { Pool } = require('pg');

const pool = new Pool({
  host: 'localhost', port: 5433, database: 'floreria', user: 'postgres', password: 'postgres',
});

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL)`);
  // variant: 'vuln' o 'safe' (cada panel de /stored tiene su propia lista)
  await pool.query(`CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY, variant TEXT NOT NULL, username TEXT NOT NULL,
    text TEXT NOT NULL, created_at TIMESTAMP DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS cards (
    id SERIAL PRIMARY KEY, username TEXT NOT NULL, number TEXT NOT NULL, created_at TIMESTAMP DEFAULT now())`);
}

module.exports = {
  init,
  sessions: new Map(), // cid -> { username, httpOnly }
  async getUser(username) {
    const r = await pool.query('SELECT salt, hash FROM users WHERE username = $1', [username]);
    return r.rows[0];
  },
  async createUser(username, salt, hash) {
    await pool.query('INSERT INTO users (username, salt, hash) VALUES ($1, $2, $3)', [username, salt, hash]);
  },
  async getComments(variant) {
    const r = await pool.query('SELECT username AS "user", text FROM comments WHERE variant = $1 ORDER BY id', [variant]);
    return r.rows;
  },
  async getCards(username) {
    const r = await pool.query('SELECT id, number FROM cards WHERE username = $1 ORDER BY id', [username]);
    return r.rows;
  },
  async addCard(username, number) {
    await pool.query('INSERT INTO cards (username, number) VALUES ($1, $2)', [username, number]);
  },
  async deleteCard(username, id) {
    await pool.query('DELETE FROM cards WHERE id = $1 AND username = $2', [id, username]);
  },
  async clearComments(variant) {
    await pool.query('DELETE FROM comments WHERE variant = $1', [variant]);
  },
  async addComment(variant, username, text) {
    await pool.query('INSERT INTO comments (variant, username, text) VALUES ($1, $2, $3)', [variant, username, text]);
  },
};
