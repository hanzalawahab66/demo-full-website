import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
dotenv.config();

const {
  DB_HOST,
  DB_PORT,
  DB_USER,
  DB_PASSWORD,
  DB_NAME
} = process.env;

export const pool = mysql.createPool({
  host: DB_HOST || '127.0.0.1',
  port: Number(DB_PORT || 3306),
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

export async function ping() {
  const [rows] = await pool.query('SELECT 1 AS ok');
  return rows[0].ok === 1;
}