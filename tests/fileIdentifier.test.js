import { test } from 'node:test';
import assert from 'node:assert/strict';
import { identifyFile } from '../server/services/fileIdentifier.js';

test('File Identifier: Correctly identifies Windows PE Executable from magic bytes', () => {
  const buf = Buffer.alloc(256, 0);
  buf[0] = 0x4d; // 'M'
  buf[1] = 0x5a; // 'Z'
  buf.writeUInt32LE(0x80, 0x3c); // e_lfanew
  buf[0x80] = 0x50; // 'P'
  buf[0x81] = 0x45; // 'E'
  buf[0x82] = 0x00;
  buf[0x83] = 0x00;

  const result = identifyFile(buf, 'program.exe');
  assert.equal(result.detectedType, 'Windows PE Executable');
  assert.equal(result.isExecutable, true);
  assert.equal(result.extensionMatch, true);
  assert.equal(result.isSpoofed, false);
});

test('File Identifier: Detects high-risk extension spoofing (PE disguised as PDF)', () => {
  const buf = Buffer.alloc(256, 0);
  buf[0] = 0x4d;
  buf[1] = 0x5a;
  buf.writeUInt32LE(0x80, 0x3c);
  buf[0x80] = 0x50;
  buf[0x81] = 0x45;
  buf[0x82] = 0x00;
  buf[0x83] = 0x00;

  const result = identifyFile(buf, 'statement.pdf');
  assert.equal(result.detectedType, 'Windows PE Executable');
  assert.equal(result.extensionMatch, false);
  assert.equal(result.isSpoofed, true);
  assert.equal(result.spoofDetails?.severity, 'HIGH');
  assert.match(result.spoofDetails?.warning, /Extension spoofing detected/);
});

test('File Identifier: Correctly identifies PDF Document', () => {
  const buf = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF');
  const result = identifyFile(buf, 'document.pdf');
  assert.equal(result.detectedType, 'PDF Document');
  assert.equal(result.isExecutable, false);
  assert.equal(result.extensionMatch, true);
  assert.equal(result.isSpoofed, false);
});

test('File Identifier: Correctly identifies PNG image', () => {
  const buf = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00]);
  const result = identifyFile(buf, 'photo.png');
  assert.equal(result.detectedType, 'PNG Image');
  assert.equal(result.extensionMatch, true);
});

test('File Identifier: Correctly identifies Linux ELF binary', () => {
  const buf = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
  const result = identifyFile(buf, 'payload.bin');
  assert.equal(result.detectedType, 'Linux ELF Executable');
  assert.equal(result.isExecutable, true);
});
