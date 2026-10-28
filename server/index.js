import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

import { config } from './config.js';
import analyzeRouter from './routes/analyze.js';
import healthRouter from './routes/health.js';
import samplesRouter from './routes/samples.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Security Headers
app.use(
  helmet({
    contentSecurityPolicy: false, // Allow Vite inline scripts/styles in dev/production
    crossOriginEmbedderPolicy: false
  })
);

// CORS
app.use(cors());

// Rate Limiting to prevent brute-force abuse or DoS
const limiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX_REQUESTS,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Rate limit exceeded',
    message: 'Too many analysis requests from this IP address. Please wait 15 minutes before submitting more files.'
  }
});
app.use('/api/', limiter);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API Routes
app.use('/api', analyzeRouter);
app.use('/api', healthRouter);
app.use('/api', samplesRouter);

// Serve frontend static files if built
const clientDistPath = path.resolve(__dirname, '..', 'client', 'dist');
if (fs.existsSync(clientDistPath)) {
  app.use(express.static(clientDistPath));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(clientDistPath, 'index.html'));
  });
}

// Global Safe Error Handler
app.use((err, req, res, next) => {
  console.error('[ANVESH UNHANDLED ERROR]', err);

  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      error: 'File Too Large',
      message: `The uploaded file exceeds the maximum allowed size limit of ${config.MAX_FILE_SIZE_MB} MB.`
    });
  }

  res.status(500).json({
    error: 'Internal Server Error',
    message: 'An internal error occurred during request processing.',
    details: config.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start server only if executed directly as main entrypoint
const isMainModule = () => {
  if (!process.argv[1]) return false;
  const currentPath = fileURLToPath(import.meta.url).toLowerCase();
  const entryPath = path.resolve(process.argv[1]).toLowerCase();
  return currentPath === entryPath;
};

if (isMainModule()) {
  app.listen(config.PORT, () => {
    console.log('================================================================');
    console.log('  ANVESH: AI Malware Detector (Static Security Engine)');
    console.log('  "Uncover what your files hide."');
    console.log('================================================================');
    console.log(`  Server running on http://localhost:${config.PORT}`);
    console.log(`  ClamAV Target:      ${config.CLAMAV_HOST}:${config.CLAMAV_PORT}`);
    console.log(`  VirusTotal Status:  ${config.VIRUSTOTAL_API_KEY ? 'Configured' : 'Not Configured'}`);
    console.log(`  Max File Size:      ${config.MAX_FILE_SIZE_MB} MB`);
    console.log('================================================================');
  });
}

export default app;
