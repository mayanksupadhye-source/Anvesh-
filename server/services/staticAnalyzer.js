import fs from 'node:fs/promises';
import path from 'node:path';
import { calculateHashes } from './hashService.js';
import { calculateEntropy } from './entropyService.js';
import { identifyFile } from './fileIdentifier.js';
import { analyzePE } from './peAnalyzer.js';
import { analyzePDF } from './pdfAnalyzer.js';
import { analyzeOfficeDocument } from './officeAnalyzer.js';
import { analyzeArchive } from './archiveAnalyzer.js';
import { analyzeScript } from './scriptAnalyzer.js';
import { extractStringsAndIndicators } from './stringExtractor.js';
import { scanFileWithClamav } from './clamavScanner.js';
import { lookupHashReputation } from './virustotalService.js';
import { evaluateRisk } from './riskEngine.js';

/**
 * Master Static Analysis Orchestrator.
 * Safely analyzes an untrusted file buffer without executing it.
 */
export async function performFullAnalysis({ filePath, originalFilename, fileSize, mimeType }) {
  const startTime = Date.now();

  // Read file into buffer safely
  const buffer = await fs.readFile(filePath);

  // 1. Calculate Hashes
  const hashes = await calculateHashes(buffer);

  // 2. Identify File Format & Check Extension Mismatch
  const typeAnalysis = identifyFile(buffer, originalFilename);

  // 3. Calculate Shannon Entropy
  const entropyAnalysis = calculateEntropy(buffer);

  // 4. Extract Strings, URLs, IPs, Keywords
  const stringAnalysis = extractStringsAndIndicators(buffer);

  // 5. Deep Format-Specific Analyzers
  let peAnalysis = null;
  let pdfAnalysis = null;
  let officeAnalysis = null;
  let archiveAnalysis = null;
  let scriptAnalysis = null;

  // PE analysis if executable signature or extension
  if (
    typeAnalysis.detectedType.includes('PE Executable') ||
    typeAnalysis.detectedType.includes('DOS MZ') ||
    (buffer.length >= 64 && buffer[0] === 0x4d && buffer[1] === 0x5a)
  ) {
    peAnalysis = analyzePE(buffer);
  }

  // PDF analysis
  if (typeAnalysis.detectedType.includes('PDF') || buffer.subarray(0, 5).toString('latin1').startsWith('%PDF-')) {
    pdfAnalysis = analyzePDF(buffer);
  }

  // Office Document analysis
  if (
    typeAnalysis.detectedType.includes('Microsoft') ||
    typeAnalysis.detectedType.includes('OpenXML') ||
    typeAnalysis.detectedType.includes('OLE')
  ) {
    officeAnalysis = await analyzeOfficeDocument(filePath, buffer);
  }

  // ZIP / Archive analysis
  if (
    typeAnalysis.detectedType.includes('Archive') ||
    (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04)
  ) {
    archiveAnalysis = await analyzeArchive(buffer);
  }

  // Script analysis
  if (
    typeAnalysis.category === 'script' ||
    typeAnalysis.category === 'text' ||
    ['.ps1', '.bat', '.cmd', '.vbs', '.js', '.sh', '.py'].includes(typeAnalysis.declaredExtension)
  ) {
    scriptAnalysis = analyzeScript(buffer, typeAnalysis.category);
  }

  // 6. Real Antivirus Scan (ClamAV)
  const clamavScan = await scanFileWithClamav(filePath);

  // 7. Optional External Threat Reputation (VirusTotal)
  const virusTotalReputation = await lookupHashReputation(hashes.sha256);

  // 8. Aggregate Risk Engine Evaluation
  const riskAssessment = evaluateRisk({
    fileInfo: {
      originalFilename: path.basename(originalFilename),
      fileSize,
      clientMime: mimeType
    },
    typeAnalysis,
    hashes,
    entropyAnalysis,
    peAnalysis,
    pdfAnalysis,
    officeAnalysis,
    archiveAnalysis,
    scriptAnalysis,
    stringAnalysis,
    clamavScan,
    virusTotalReputation
  });

  const scanDurationMs = Date.now() - startTime;

  return {
    meta: {
      scanTimestamp: new Date().toISOString(),
      scanDurationMs,
      engineVersion: 'ANVESH v1.0.0 (Static Security Engine)'
    },
    file: {
      filename: path.basename(originalFilename),
      sizeBytes: fileSize,
      sizeFormatted: formatBytes(fileSize),
      clientMime: mimeType
    },
    hashes,
    typeAnalysis,
    entropy: entropyAnalysis,
    pe: peAnalysis,
    pdf: pdfAnalysis,
    office: officeAnalysis,
    archive: archiveAnalysis,
    script: scriptAnalysis,
    stringsAndNetwork: {
      urls: stringAnalysis.urls,
      ips: stringAnalysis.ips,
      suspiciousKeywords: stringAnalysis.suspiciousKeywords,
      totalStringsFound: stringAnalysis.stringCount
    },
    antivirus: clamavScan,
    reputation: virusTotalReputation,
    risk: riskAssessment
  };
}

function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
