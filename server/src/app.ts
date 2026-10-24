import { existsSync } from 'node:fs';
import { createServer, type Server as HttpServer } from 'node:http';
import { join, resolve } from 'node:path';
import { createAdapter } from '@socket.io/redis-adapter';
import express from 'express';
import helmet from 'helmet';
import { Redis } from 'ioredis';
import mongoose from 'mongoose';
import { pinoHttp } from 'pino-http';
import { Server } from 'socket.io';
import { config } from './config.js';
import type { AppContext } from './context.js';
import { HttpError, errorHandler } from './lib/http.js';
import { logger } from './logger.js';
import { mailerFromConfig, type Mailer } from './lib/mailer.js';
import { oauthFromConfig, type OAuthProviders } from './lib/oauth.js';
import { authRoutes } from './routes/auth.js';
import { emailRoutes } from './routes/email.js';
import { oauthRoutes } from './routes/oauth.js';
import { passkeyRoutes } from './routes/passkeys.js';
import { conversationRoutes } from './routes/conversations.js';
import { userRoutes } from './routes/users.js';
import { attachSocketHandlers } from './socket/index.js';

export interface App {
  httpServer: HttpServer;
  io: Server;
  close: () => Promise<void>;
}

/**
 * Builds one server instance. Several instances can share the same Mongo and Redis:
 * the Socket.io Redis adapter relays every emit through Redis Pub/Sub, so a message
 * sent to instance A reaches sockets connected to instance B.
 */
export function createApp(
  opts: { redisUrl?: string; instanceId?: string; mailer?: Mailer | null; oauth?: OAuthProviders } = {},
): App {
  const redisUrl = opts.redisUrl ?? config.REDIS_URL;
  const redis = new Redis(redisUrl, { maxRetriesPerRequest: 3 });
  const pub = new Redis(redisUrl);
  const sub = pub.duplicate();
  for (const c of [redis, pub, sub]) c.on('error', (err) => logger.error({ err }, 'redis error'));

  const app = express();
  const httpServer = createServer(app);
  const io = new Server(httpServer, {
    adapter: createAdapter(pub, sub),
    maxHttpBufferSize: 64 * 1024,
    serveClient: false,
  });
  const ctx: AppContext = {
    redis,
    io,
    mailer: opts.mailer === undefined ? mailerFromConfig() : opts.mailer,
    oauth: opts.oauth ?? oauthFromConfig(),
  };

  app.disable('x-powered-by');
  app.set('trust proxy', config.TRUST_PROXY);
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          connectSrc: ["'self'", 'ws:', 'wss:'],
          imgSrc: ["'self'", 'data:'],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
        },
      },
    }),
  );
  app.use(
    pinoHttp({
      logger,
      autoLogging: { ignore: (req) => req.url === '/health' },
      // The IP the rate limits use; check it in the logs when setting TRUST_PROXY.
      customProps: (req) => ({ clientIp: (req as express.Request).ip }),
    }),
  );
  app.use(express.json({ limit: '32kb' }));

  app.get('/health', async (_req, res) => {
    const mongoOk = mongoose.connection.readyState === 1;
    const redisOk = await redis.ping().then(
      (r) => r === 'PONG',
      () => false,
    );
    res.status(mongoOk && redisOk ? 200 : 503).json({
      ok: mongoOk && redisOk,
      instance: opts.instanceId ?? config.INSTANCE_ID,
      mongo: mongoOk,
      redis: redisOk,
    });
  });

  app.use('/api/auth', authRoutes(ctx), passkeyRoutes(ctx), oauthRoutes(ctx), emailRoutes(ctx));
  app.use('/api/users', userRoutes());
  app.use('/api/conversations', conversationRoutes(ctx));
  app.use('/api', (_req, _res, next) => next(new HttpError(404, 'Not found')));

  if (config.STATIC_DIR && existsSync(config.STATIC_DIR)) {
    const dir = resolve(config.STATIC_DIR);
    app.use(express.static(dir, { index: false, maxAge: '1h' }));
    app.get('*', (_req, res) => res.sendFile(join(dir, 'index.html')));
  }

  app.use(errorHandler);

  const stopSockets = attachSocketHandlers(io, ctx);

  return {
    httpServer,
    io,
    close: async () => {
      stopSockets();
      await io.close();
      // Let disconnect handlers (presence cleanup) finish before Redis goes away.
      await new Promise((r) => setTimeout(r, 50));
      await Promise.all([redis, pub, sub].map((c) => c.quit().catch(() => undefined)));
    },
  };
}

export async function connectMongo(url = config.MONGO_URL): Promise<void> {
  if (mongoose.connection.readyState === 1) return;
  await mongoose.connect(url, { serverSelectionTimeoutMS: 10_000 });
  await mongoose.syncIndexes();
}
