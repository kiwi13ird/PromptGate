import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAppServer } from './app.mjs';
import { gatewayProcessingCutoff, requiredGatewayProcessingSince } from './processing-time.mjs';
import { PostgresEventStore } from './postgres-event-store.mjs';

// 운영 시작은 처리 시간 기준 시각이 있어야 한다(비우면 시작하지 않음, processing-time.mjs). 다른 검사·DB 연결보다 먼저
const gatewayProcessingSince = requiredGatewayProcessingSince(process.env.GATEWAY_PROCESSING_MS_SINCE);
const serverDirectory = path.dirname(fileURLToPath(import.meta.url));
const host = process.env.BACKEND_HOST ?? '127.0.0.1';
const port = Number(process.env.BACKEND_PORT ?? 9100);
const storePath =
  process.env.EVENT_DB_PATH ?? path.join(serverDirectory, 'data', 'events.json');
const eventStore = process.env.DATABASE_URL
  ? new PostgresEventStore({ connectionString: process.env.DATABASE_URL })
  : undefined;

if (!Number.isInteger(port) || port < 1 || port > 65_535)
  throw new Error('BACKEND_PORT must be an integer between 1 and 65535.');

const server = createAppServer({
  store: eventStore,
  storePath,
  allowedOrigin: process.env.FRONTEND_ORIGIN ?? 'http://127.0.0.1:4173',
  adminEmail: process.env.LOCAL_ADMIN_EMAIL,
  adminPassword: process.env.LOCAL_ADMIN_PASSWORD,
  ingestToken: process.env.EVENT_INGEST_TOKEN,
  policyBaseUrl: process.env.DETECTION_POLICY_URL,
  gatewayProcessingSince,
});

server.listen(port, host, () => {
  console.log(`Local event backend listening on http://${host}:${port}`);
  console.log(
    eventStore
      ? 'Persistent event store: PostgreSQL'
      : `Persistent event store: ${path.resolve(storePath)}`,
  );
  console.log(
    `Gateway processing time shown for events since ${new Date(gatewayProcessingCutoff(gatewayProcessingSince)).toISOString()} (GATEWAY_PROCESSING_MS_SINCE)`,
  );
});

function shutdown(signal) {
  console.log(`Received ${signal}; shutting down local event backend.`);
  server.close(async (error) => {
    if (error) {
      console.error('Failed to close local event backend:', error.message);
      process.exitCode = 1;
    }
    await eventStore?.close().catch((closeError) => {
      console.error('Failed to close PostgreSQL pool:', closeError.message);
      process.exitCode = 1;
    });
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
