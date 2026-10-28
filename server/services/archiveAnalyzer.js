import yauzl from 'yauzl';
import path from 'node:path';

/**
 * Safe ZIP Archive Static Analyzer.
 * Inspects archive headers, file tables, compression ratios, and entry names
 * WITHOUT writing or extracting any files to disk.
 */

const DANGEROUS_EXTENSIONS = [
  '.exe',
  '.scr',
  '.bat',
  '.cmd',
  '.ps1',
  '.vbs',
  '.js',
  '.hta',
  '.cpl',
  '.dll',
  '.sys',
  '.wsf',
  '.iso',
  '.vhd',
  '.lnk'
];

const ARCHIVE_EXTENSIONS = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab'];

export async function analyzeArchive(buffer) {
  const result = {
    isArchive: false,
    format: 'ZIP',
    fileCount: 0,
    totalCompressedSize: 0,
    totalUncompressedSize: 0,
    compressionRatio: 0,
    isZipBomb: false,
    hasPathTraversal: false,
    hasExecutableFiles: false,
    hasNestedArchives: false,
    hasDoubleExtensions: false,
    suspiciousEntries: [],
    entries: [],
    findings: []
  };

  if (!buffer || buffer.length < 4) return result;

  // Verify ZIP magic PK\x03\x04
  if (buffer[0] !== 0x50 || buffer[1] !== 0x4b || buffer[2] !== 0x03 || buffer[3] !== 0x04) {
    return result;
  }

  result.isArchive = true;

  return new Promise((resolve) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
      if (err || !zipfile) {
        result.findings.push({
          name: 'Malformed Archive Structure',
          severity: 'MEDIUM',
          description: `Archive headers are corrupt or unreadable: ${err ? err.message : 'Unknown error'}`
        });
        return resolve(result);
      }

      zipfile.readEntry();

      zipfile.on('entry', (entry) => {
        result.fileCount++;
        result.totalCompressedSize += entry.compressedSize;
        result.totalUncompressedSize += entry.uncompressedSize;

        const fileName = entry.fileName;
        const ext = path.extname(fileName).toLowerCase();

        // 1. Path Traversal Detection (e.g., ../ or absolute / or C:\)
        const isTraversal =
          fileName.includes('../') ||
          fileName.includes('..\\') ||
          fileName.startsWith('/') ||
          fileName.startsWith('\\') ||
          /^[a-zA-Z]:/.test(fileName);

        if (isTraversal) {
          result.hasPathTraversal = true;
          result.suspiciousEntries.push({
            name: fileName,
            reason: 'Path traversal sequence detected (attempts to write outside destination)',
            severity: 'CRITICAL'
          });
        }

        // 2. Dangerous Executable or Script inside archive
        if (DANGEROUS_EXTENSIONS.includes(ext)) {
          result.hasExecutableFiles = true;
          result.suspiciousEntries.push({
            name: fileName,
            reason: `Direct executable / script payload (${ext}) inside archive`,
            severity: 'HIGH'
          });
        }

        // 3. Double extension spoofing (e.g. invoice.pdf.exe)
        const parts = fileName.split('.');
        if (parts.length > 2) {
          const secondExt = `.${parts[parts.length - 2].toLowerCase()}`;
          if (['.pdf', '.docx', '.xlsx', '.txt', '.jpg', '.png'].includes(secondExt) && DANGEROUS_EXTENSIONS.includes(ext)) {
            result.hasDoubleExtensions = true;
            result.suspiciousEntries.push({
              name: fileName,
              reason: `Double extension spoofing detected (${secondExt}${ext})`,
              severity: 'CRITICAL'
            });
          }
        }

        // 4. Nested archive detection
        if (ARCHIVE_EXTENSIONS.includes(ext)) {
          result.hasNestedArchives = true;
          result.suspiciousEntries.push({
            name: fileName,
            reason: `Nested archive detected (${ext})`,
            severity: 'LOW'
          });
        }

        if (result.entries.length < 50) {
          result.entries.push({
            name: fileName,
            uncompressedSize: entry.uncompressedSize,
            compressedSize: entry.compressedSize,
            isDir: fileName.endsWith('/') || fileName.endsWith('\\')
          });
        }

        zipfile.readEntry();
      });

      zipfile.on('end', () => {
        // Zip Bomb safeguards
        if (result.totalCompressedSize > 0) {
          result.compressionRatio = Number((result.totalUncompressedSize / result.totalCompressedSize).toFixed(2));
        }

        // If compression ratio > 100:1 and uncompressed > 10MB, or uncompressed > 200MB from tiny archive
        if (
          (result.compressionRatio > 100 && result.totalUncompressedSize > 10 * 1024 * 1024) ||
          (result.totalUncompressedSize > 250 * 1024 * 1024 && buffer.length < 5 * 1024 * 1024)
        ) {
          result.isZipBomb = true;
          result.findings.push({
            name: 'Potential Zip Bomb (Decompression Denial of Service)',
            severity: 'CRITICAL',
            description: `Abnormal compression ratio (${result.compressionRatio}:1). Uncompressed size expands to ${(result.totalUncompressedSize / (1024 * 1024)).toFixed(1)}MB.`
          });
        }

        if (result.hasPathTraversal) {
          result.findings.push({
            name: 'Directory Traversal Archive (Zip Slip)',
            severity: 'CRITICAL',
            description: 'Archive contains filenames with relative directory escape sequences (e.g., ../). Extracting would risk overwriting system files.'
          });
        }

        if (result.hasDoubleExtensions) {
          result.findings.push({
            name: 'Double-Extension Disguised Payload',
            severity: 'CRITICAL',
            description: 'Archive contains files pretending to be documents but carrying executable suffixes (e.g. .pdf.exe).'
          });
        } else if (result.hasExecutableFiles) {
          result.findings.push({
            name: 'Executable Files Stored in Archive',
            severity: 'HIGH',
            description: 'Archive directly bundles binary executables or command scripts.'
          });
        }

        resolve(result);
      });

      zipfile.on('error', (err) => {
        result.findings.push({
          name: 'Archive Parsing Error',
          severity: 'MEDIUM',
          description: `Archive error: ${err.message}`
        });
        resolve(result);
      });
    });
  });
}
