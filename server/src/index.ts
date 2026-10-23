import mongoose from 'mongoose';
import { connectMongo, createApp } from './app.js';
import { config } from './config.js';
import { logger } from './logger.js';

await connectMongo();
const app = createApp();
app.httpServer.listen(config.PORT, () => logger.info({ port: config.PORT }, 'echocrypt server listening'));

let stopping = false;
async function shutdown(signal: string) {
  if (stopping) return;
  stopping = true;
  logger.info({ signal }, 'shutting down');
  const force = setTimeout(() => process.exit(1), 10_000);
  force.unref();
  await app.close();
  await mongoose.disconnect();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
