import express from 'express';
import { checkClamavAvailability } from '../services/clamavScanner.js';
import { config } from '../config.js';

const router = express.Router();

router.get('/health', async (req, res) => {
  const clamavStatus = await checkClamavAvailability();
  const vtConfigured = Boolean(config.VIRUSTOTAL_API_KEY && config.VIRUSTOTAL_API_KEY.trim().length > 0);

  res.json({
    status: 'ONLINE',
    app: 'ANVESH AI Malware Detector',
    version: '1.0.0',
    capabilities: {
      static_analysis: true,
      sha256_hashing: true,
      pe_binary_parser: true,
      pdf_inspector: true,
      office_macro_detector: true,
      archive_safeguard: true,
      script_analyzer: true,
      clamav_engine: clamavStatus.available,
      virustotal_reputation: vtConfigured
    },
    services: {
      clamav: clamavStatus,
      virustotal: {
        configured: vtConfigured,
        status: vtConfigured ? 'READY' : 'UNCONFIGURED'
      }
    },
    system: {
      nodeVersion: process.version,
      platform: process.platform,
      uptimeSeconds: Math.floor(process.uptime()),
      maxUploadMb: config.MAX_FILE_SIZE_MB
    }
  });
});

export default router;
