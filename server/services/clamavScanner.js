import net from 'node:net';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { config } from '../config.js';

/**
 * Real ClamAV Integration.
 * Supports:
 * 1. clamd persistent TCP daemon (preferred, INSTREAM protocol over port 3310).
 * 2. clamscan CLI binary fallback.
 * 3. Honest unavailability reporting when no engine is reachable.
 * NEVER fabricates an antivirus result!
 */

/**
 * Scans a file or buffer using clamd TCP INSTREAM protocol
 */
function scanWithClamdTcp(filePathOrBuffer) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let response = '';
    let isConnected = false;

    socket.setTimeout(config.CLAMAV_TIMEOUT_MS);

    socket.connect(config.CLAMAV_PORT, config.CLAMAV_HOST, () => {
      isConnected = true;
      // Initiate INSTREAM command (zINSTREAM\0 format)
      socket.write(Buffer.from('zINSTREAM\0'));

      const sendStream = (readStream) => {
        readStream.on('data', (chunk) => {
          // Packet format: [4 bytes uint32 big-endian length][chunk]
          const header = Buffer.alloc(4);
          header.writeUInt32BE(chunk.length, 0);
          socket.write(header);
          socket.write(chunk);
        });

        readStream.on('end', () => {
          // Terminating packet: length 0 (4 zero bytes)
          const zeroHeader = Buffer.alloc(4, 0);
          socket.write(zeroHeader);
        });

        readStream.on('error', (err) => {
          socket.destroy();
          reject(err);
        });
      };

      if (Buffer.isBuffer(filePathOrBuffer)) {
        // Stream from buffer in 32KB chunks
        const CHUNK_SIZE = 32 * 1024;
        for (let i = 0; i < filePathOrBuffer.length; i += CHUNK_SIZE) {
          const chunk = filePathOrBuffer.subarray(i, i + CHUNK_SIZE);
          const header = Buffer.alloc(4);
          header.writeUInt32BE(chunk.length, 0);
          socket.write(header);
          socket.write(chunk);
        }
        const zeroHeader = Buffer.alloc(4, 0);
        socket.write(zeroHeader);
      } else {
        const fileStream = fs.createReadStream(filePathOrBuffer);
        sendStream(fileStream);
      }
    });

    socket.on('data', (data) => {
      response += data.toString('utf8');
    });

    socket.on('end', () => {
      resolve(response.trim());
    });

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`ClamAV connection timed out after ${config.CLAMAV_TIMEOUT_MS}ms`));
    });

    socket.on('error', (err) => {
      socket.destroy();
      reject(err);
    });
  });
}

/**
 * Scans a file using the local clamscan CLI executable
 */
function scanWithClamscanBinary(filePath) {
  return new Promise((resolve, reject) => {
    // If input is not a physical file on disk, clamscan binary can't be used directly
    if (typeof filePath !== 'string' || !fs.existsSync(filePath)) {
      return reject(new Error('clamscan CLI requires a physical file path'));
    }

    const proc = spawn(config.CLAMSCAN_PATH, ['--no-summary', filePath]);
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d) => (stdout += d.toString()));
    proc.stderr.on('data', (d) => (stderr += d.toString()));

    proc.on('close', (code) => {
      // Exit code 0 = Clean, 1 = Virus found, 2 = Error
      if (code === 0 || code === 1) {
        resolve(stdout.trim());
      } else {
        reject(new Error(stderr || `clamscan exited with code ${code}`));
      }
    });

    proc.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Checks if clamd TCP daemon is reachable
 */
export async function checkClamavAvailability() {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(2000);

    socket.connect(config.CLAMAV_PORT, config.CLAMAV_HOST, () => {
      socket.write(Buffer.from('nPING\n'));
    });

    socket.on('data', (data) => {
      const resp = data.toString('utf8').trim();
      socket.destroy();
      if (resp === 'PONG') {
        resolve({ available: true, mode: 'clamd_daemon', host: `${config.CLAMAV_HOST}:${config.CLAMAV_PORT}` });
      } else {
        resolve({ available: false, reason: `Unexpected ping response: ${resp}` });
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ available: false, reason: 'Daemon connection timed out' });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({ available: false, reason: err.message });
    });
  });
}

/**
 * Main scan method for ANVESH.
 * Attempts clamd TCP first, then clamscan binary, and returns a verified result or honest unavailability.
 */
export async function scanFileWithClamav(filePathOrBuffer) {
  // 1. Try clamd TCP daemon
  try {
    const rawResult = await scanWithClamdTcp(filePathOrBuffer);
    // Parse result: 'stream: OK' or 'stream: Win.Test.EICAR_HDB-1 FOUND'
    if (rawResult.includes('FOUND')) {
      const match = rawResult.match(/stream:\s+(.+)\s+FOUND/i);
      const signature = match ? match[1] : 'Malware Signature Detected';
      return {
        available: true,
        scanned: true,
        detected: true,
        threatName: signature,
        engine: 'ClamAV (clamd TCP Daemon)',
        status: 'MALWARE_DETECTED',
        rawOutput: rawResult,
        plainLanguage: `A verified antivirus signature (${signature}) matched this file. Do not run or open it.`
      };
    } else if (rawResult.includes('OK')) {
      return {
        available: true,
        scanned: true,
        detected: false,
        threatName: null,
        engine: 'ClamAV (clamd TCP Daemon)',
        status: 'CLEAN',
        rawOutput: rawResult,
        plainLanguage: 'ClamAV signature database scanned this file and found no known malware signatures.'
      };
    }
  } catch (clamdErr) {
    // clamd TCP failed, proceed to try CLI if on disk
  }

  // 2. Try clamscan CLI fallback if filePath is a string
  if (typeof filePathOrBuffer === 'string') {
    try {
      const rawResult = await scanWithClamscanBinary(filePathOrBuffer);
      if (rawResult.includes('FOUND')) {
        const parts = rawResult.split(':');
        const threatName = parts[1] ? parts[1].replace('FOUND', '').trim() : 'Malware Detected';
        return {
          available: true,
          scanned: true,
          detected: true,
          threatName,
          engine: 'ClamAV (clamscan CLI)',
          status: 'MALWARE_DETECTED',
          rawOutput: rawResult,
          plainLanguage: `A verified antivirus signature (${threatName}) matched this file. Do not run or open it.`
        };
      } else if (rawResult.includes('OK')) {
        return {
          available: true,
          scanned: true,
          detected: false,
          threatName: null,
          engine: 'ClamAV (clamscan CLI)',
          status: 'CLEAN',
          rawOutput: rawResult,
          plainLanguage: 'ClamAV signature database scanned this file and found no known malware signatures.'
        };
      }
    } catch (cliErr) {
      // clamscan CLI also unavailable
    }
  }

  // 3. Honest Unavailability Reporting
  return {
    available: false,
    scanned: false,
    detected: false,
    threatName: null,
    engine: 'ClamAV',
    status: 'UNAVAILABLE',
    rawOutput: null,
    reason: `ClamAV daemon not connected at ${config.CLAMAV_HOST}:${config.CLAMAV_PORT} and clamscan CLI not found in PATH.`,
    plainLanguage: 'The ClamAV antivirus engine is not currently running or reachable on this server. Deep static analysis and file structural analysis were completed, but signature scanning was unavailable.'
  };
}
