import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const { Client } = pg;
const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error('DATABASE_URL is required.');

const directory = path.dirname(fileURLToPath(import.meta.url));
const migrationsDirectory = path.join(directory, 'migrations');
const migrationFiles = (await readdir(migrationsDirectory))
  .filter((name) => /^\d+.*\.sql$/.test(name))
  .sort();
const client = new Client({ connectionString });
await client.connect();
try {
  await client.query('BEGIN');
  for (const name of migrationFiles) {
    await client.query(await readFile(path.join(migrationsDirectory, name), 'utf8'));
    console.log(`Applied ${name}.`);
  }
  await client.query('COMMIT');
  console.log('Dashboard database migration completed.');
} catch (error) {
  await client.query('ROLLBACK').catch(() => undefined);
  throw error;
} finally {
  await client.end();
}
