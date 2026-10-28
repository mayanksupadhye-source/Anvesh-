import express from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { promises as fsp } from 'node:fs';
import { config } from '../config.js';
import { performFullAnalysis } from '../services/staticAnalyzer.js';

const router = express.Router();

// Ensure temporary isolated directory exists
if (!fs.existsSync(config.TEMP_UPLOAD_DIR)) {
  fs.mkdirSync(config.TEMP_UPLOAD_DIR, { recursive: true });
}

// Multer storage with randomized filenames in isolated temporary folder
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, config.TEMP_UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // Generate secure random UUID-style filename to prevent path traversal
    const randomName = `${crypto.randomBytes(16).toString('hex')}_${Date.now()}`;
    cb(null, randomName);
  }
});

// Multer instance with strict limits
const upload = multer({
  storage,
  limits: {
    fileSize: config.MAX_FILE_SIZE_BYTES,
    files: 1
  }
});

/**
 * POST /api/analyze
 * Receives multipart file upload, performs complete static analysis,
 * and cleans up the temporary file immediately.
 */
router.post('/analyze', upload.single('file'), async (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({
      error: 'No file provided',
      message: 'Please select a file to analyze.'
    });
  }

  const tempFilePath = req.file.path;
  const originalFilename = req.file.originalname || 'unknown_file';
  const fileSize = req.file.size;
  const mimeType = req.file.mimetype || 'application/octet-stream';

  try {
    const report = await performFullAnalysis({
      filePath: tempFilePath,
      originalFilename,
      fileSize,
      mimeType
    });

    return res.json({
      success: true,
      report
    });
  } catch (err) {
    console.error(`[ANVESH ERROR] Analysis failed for ${originalFilename}:`, err);
    return res.status(500).json({
      error: 'Analysis Error',
      message: 'An unexpected error occurred while analyzing the file. Static analysis could not be completed.',
      technicalDetails: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  } finally {
    // Safe server-side cleanup: delete untrusted uploaded file immediately
    try {
      if (fs.existsSync(tempFilePath)) {
        await fsp.unlink(tempFilePath);
      }
    } catch (cleanupErr) {
      console.warn(`[ANVESH CLEANUP] Could not remove temp file ${tempFilePath}:`, cleanupErr.message);
    }
  }
});

export default router;
