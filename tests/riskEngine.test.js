import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateRisk } from '../server/services/riskEngine.js';

test('Risk Engine: Clean file produces LOW RISK verdict', () => {
  const result = evaluateRisk({
    fileInfo: { originalFilename: 'report.pdf', fileSize: 1024, clientMime: 'application/pdf' },
    typeAnalysis: {
      declaredExtension: '.pdf',
      detectedType: 'PDF Document',
      extensionMatch: true,
      isSpoofed: false
    },
    hashes: { sha256: 'abcd1234', sha1: '1234', md5: '5678' },
    entropyAnalysis: { entropy: 4.5, isSuspicious: false },
    peAnalysis: null,
    pdfAnalysis: { isPDF: true, findings: [] },
    officeAnalysis: null,
    archiveAnalysis: null,
    scriptAnalysis: null,
    stringAnalysis: { urls: [], ips: [], suspiciousKeywords: [] },
    clamavScan: { available: true, scanned: true, detected: false, engine: 'ClamAV' },
    virusTotalReputation: { available: false, configured: false }
  });

  assert.equal(result.riskLevel, 'LOW');
  assert.equal(result.riskColor, 'safe');
  assert.ok(result.recommendation.action.includes('STANDARD CAUTION'));
});

test('Risk Engine: Extension spoofing produces HIGH RISK verdict with plain-English explanation', () => {
  const result = evaluateRisk({
    fileInfo: { originalFilename: 'invoice.pdf', fileSize: 2048, clientMime: 'application/pdf' },
    typeAnalysis: {
      declaredExtension: '.pdf',
      detectedType: 'Windows PE Executable',
      extensionMatch: false,
      isSpoofed: true,
      magicBytesHex: '4D 5A 90 00',
      spoofDetails: { severity: 'HIGH', warning: 'Extension spoofing detected' }
    },
    hashes: { sha256: 'abcd1234', sha1: '1234', md5: '5678' },
    entropyAnalysis: { entropy: 5.5, isSuspicious: false },
    peAnalysis: { isPE: true, numberOfSections: 2, sections: [], suspiciousApis: [], digitalSignature: { present: false, plainLanguage: 'Unsigned' }, overlay: { present: false } },
    pdfAnalysis: null,
    officeAnalysis: null,
    archiveAnalysis: null,
    scriptAnalysis: null,
    stringAnalysis: { urls: [], ips: [], suspiciousKeywords: [] },
    clamavScan: { available: false },
    virusTotalReputation: { available: false, configured: false }
  });

  assert.equal(result.riskLevel, 'HIGH');
  const spoofSignal = result.signals.find((s) => s.signal_id === 'FILE_EXTENSION_SPOOFING');
  assert.ok(spoofSignal, 'Expected FILE_EXTENSION_SPOOFING signal');
  assert.match(spoofSignal.plain_language, /masquerading as a '\.pdf'/);
});

test('Risk Engine: Confirmed malware detection produces CRITICAL RISK verdict', () => {
  const result = evaluateRisk({
    fileInfo: { originalFilename: 'eicar.com', fileSize: 68, clientMime: 'text/plain' },
    typeAnalysis: { declaredExtension: '.com', detectedType: 'Plain Text / Script', extensionMatch: true, isSpoofed: false },
    hashes: { sha256: 'eicarhash', sha1: '1234', md5: '5678' },
    entropyAnalysis: { entropy: 4.0, isSuspicious: false },
    peAnalysis: null,
    pdfAnalysis: null,
    officeAnalysis: null,
    archiveAnalysis: null,
    scriptAnalysis: null,
    stringAnalysis: { urls: [], ips: [], suspiciousKeywords: [] },
    clamavScan: {
      available: true,
      scanned: true,
      detected: true,
      threatName: 'Win.Test.EICAR_HDB-1',
      engine: 'ClamAV',
      rawOutput: 'stream: Win.Test.EICAR_HDB-1 FOUND'
    },
    virusTotalReputation: { available: false, configured: false }
  });

  assert.equal(result.riskLevel, 'CRITICAL');
  assert.equal(result.riskColor, 'critical');
  assert.ok(result.recommendation.action.includes('DO NOT OPEN'));
  const avSignal = result.signals.find((s) => s.signal_id === 'ANTIVIRUS_DETECTION_CONFIRMED');
  assert.ok(avSignal, 'Expected ANTIVIRUS_DETECTION_CONFIRMED signal');
  assert.match(avSignal.plain_language, /Win\.Test\.EICAR_HDB-1/);
});
