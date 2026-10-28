import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const config = {
  PORT: parseInt(process.env.PORT || '5000', 10),
  NODE_ENV: process.env.NODE_ENV || 'development',
  MAX_FILE_SIZE_MB: parseInt(process.env.MAX_FILE_SIZE_MB || '30', 10),
  MAX_FILE_SIZE_BYTES: parseInt(process.env.MAX_FILE_SIZE_MB || '30', 10) * 1024 * 1024,
  TEMP_UPLOAD_DIR: process.env.VERCEL
    ? path.join(os.tmpdir(), 'anvesh_uploads')
    : path.resolve(__dirname, 'uploads', 'temp'),
  
  // ClamAV Settings
  CLAMAV_HOST: process.env.CLAMAV_HOST || '127.0.0.1',
  CLAMAV_PORT: parseInt(process.env.CLAMAV_PORT || '3310', 10),
  CLAMSCAN_PATH: process.env.CLAMSCAN_PATH || 'clamscan',
  CLAMAV_TIMEOUT_MS: parseInt(process.env.CLAMAV_TIMEOUT_MS || '10000', 10),

  // VirusTotal (Optional)
  VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY || '',

  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000, // 15 mins
  RATE_LIMIT_MAX_REQUESTS: 100
};
