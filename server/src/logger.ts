import pino from 'pino';
import { config } from './config.js';

export const logger = pino({
  level: config.NODE_ENV === 'test' ? 'silent' : config.LOG_LEVEL,
  base: { instance: config.INSTANCE_ID },
  // Never log credentials or anything that looks like key material.
  redact: ['req.headers.cookie', 'req.headers.authorization', '*.authKey', '*.keys'],
});
