import crypto from 'node:crypto';
import fs from 'node:fs';

/**
 * Calculates cryptographic hashes (SHA-256, SHA-1, MD5) for a file or buffer.
 * SHA-256 is the primary unique identifier for malware tracking.
 */
export async function calculateHashes(filePathOrBuffer) {
  if (Buffer.isBuffer(filePathOrBuffer)) {
    const sha256 = crypto.createHash('sha256').update(filePathOrBuffer).digest('hex');
    const sha1 = crypto.createHash('sha1').update(filePathOrBuffer).digest('hex');
    const md5 = crypto.createHash('md5').update(filePathOrBuffer).digest('hex');
    return { sha256, sha1, md5 };
  }

  return new Promise((resolve, reject) => {
    const sha256Hash = crypto.createHash('sha256');
    const sha1Hash = crypto.createHash('sha1');
    const md5Hash = crypto.createHash('md5');

    const stream = fs.createReadStream(filePathOrBuffer);

    stream.on('data', (chunk) => {
      sha256Hash.update(chunk);
      sha1Hash.update(chunk);
      md5Hash.update(chunk);
    });

    stream.on('end', () => {
      resolve({
        sha256: sha256Hash.digest('hex'),
        sha1: sha1Hash.digest('hex'),
        md5: md5Hash.digest('hex')
      });
    });

    stream.on('error', (err) => {
      reject(new Error(`Failed to calculate hashes: ${err.message}`));
    });
  });
}
