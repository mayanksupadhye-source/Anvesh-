import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzePE } from '../server/services/peAnalyzer.js';

test('PE Analyzer: Rejects non-PE buffers cleanly', () => {
  const buf = Buffer.from('Just normal text file');
  const result = analyzePE(buf);
  assert.equal(result.isPE, false);
});

test('PE Analyzer: Successfully parses structured PE headers', () => {
  const buf = Buffer.alloc(1024, 0);
  buf[0] = 0x4d; // 'M'
  buf[1] = 0x5a; // 'Z'
  buf.writeUInt32LE(0x80, 0x3c); // e_lfanew -> 0x80

  // PE Signature
  buf[0x80] = 0x50; // 'P'
  buf[0x81] = 0x45; // 'E'
  buf[0x82] = 0x00;
  buf[0x83] = 0x00;

  // COFF Header (20 bytes)
  const coff = 0x84;
  buf.writeUInt16LE(0x8664, coff); // AMD64
  buf.writeUInt16LE(1, coff + 2); // 1 section
  buf.writeUInt32LE(1600000000, coff + 4); // Timestamp
  buf.writeUInt16LE(0xf0, coff + 16); // SizeOfOptionalHeader
  buf.writeUInt16LE(0x0002, coff + 18); // Characteristics: Executable

  // Optional Header (PE32+ 64-bit)
  const opt = coff + 20;
  buf.writeUInt16LE(0x20b, opt); // PE32+
  buf.writeUInt32LE(0x1000, opt + 16); // EntryPoint

  // Section Table
  const sec = opt + 0xf0;
  Buffer.from('.text\0\0\0').copy(buf, sec);
  buf.writeUInt32LE(0x1000, sec + 8); // VirtualSize
  buf.writeUInt32LE(0x1000, sec + 12); // VirtualAddress
  buf.writeUInt32LE(0x200, sec + 16); // SizeOfRawData
  buf.writeUInt32LE(0x200, sec + 20); // PointerToRawData
  buf.writeUInt32LE(0x60000020, sec + 36); // Characteristics: Read, Execute, Code

  const result = analyzePE(buf);
  assert.equal(result.isPE, true);
  assert.equal(result.format, 'PE32+ (64-bit)');
  assert.equal(result.machine, 'AMD64 (x64 64-bit)');
  assert.equal(result.numberOfSections, 1);
  assert.equal(result.sections[0].name, '.text');
  assert.equal(result.digitalSignature.present, false);
});
