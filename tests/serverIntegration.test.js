process.env.NODE_ENV = 'test';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import app from '../server/index.js';

test('Server Integration: GET /api/health responds with engine status and capabilities', async () => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;

  try {
    const res = await fetch(`http://localhost:${port}/api/health`);
    assert.equal(res.status, 200);

    const json = await res.json();
    assert.equal(json.status, 'ONLINE');
    assert.equal(json.app, 'ANVESH AI Malware Detector');
    assert.ok(json.capabilities.static_analysis);
    assert.ok(json.capabilities.sha256_hashing);
    assert.ok('clamav' in json.services);
  } finally {
    server.close();
  }
});

test('Server Integration: GET /api/samples returns sample test catalog', async () => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;

  try {
    const res = await fetch(`http://localhost:${port}/api/samples`);
    assert.equal(res.status, 200);

    const json = await res.json();
    assert.ok(Array.isArray(json.samples));
    assert.ok(json.samples.length >= 4);
    assert.ok(json.samples.some((s) => s.id === 'clean-pdf'));
    assert.ok(json.samples.some((s) => s.id === 'extension-mismatch'));
  } finally {
    server.close();
  }
});

test('Server Integration: POST /api/analyze returns 400 when no file is uploaded', async () => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;

  try {
    const res = await fetch(`http://localhost:${port}/api/analyze`, {
      method: 'POST'
    });
    assert.equal(res.status, 400);
    const json = await res.json();
    assert.equal(json.error, 'No file provided');
  } finally {
    server.close();
  }
});

test('Server Integration: POST /api/analyze performs full analysis on clean PDF', async () => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;

  try {
    const pdfData = `%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\nxref\n0 2\ntrailer\n<< /Root 1 0 R >>\nstartxref\n100\n%%EOF`;
    const blob = new Blob([pdfData], { type: 'application/pdf' });
    const formData = new FormData();
    formData.append('file', blob, 'invoice_clean.pdf');

    const res = await fetch(`http://localhost:${port}/api/analyze`, {
      method: 'POST',
      body: formData
    });

    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.ok(json.report);
    assert.equal(json.report.file.filename, 'invoice_clean.pdf');
    assert.ok(json.report.hashes.sha256);
    assert.equal(json.report.typeAnalysis.detectedType, 'PDF Document');
    assert.equal(json.report.typeAnalysis.extensionMatch, true);
    assert.equal(json.report.risk.riskLevel, 'LOW');
    assert.ok(Array.isArray(json.report.risk.signals));
  } finally {
    server.close();
  }
});

test('Server Integration: POST /api/analyze detects extension spoofing on PE binary disguised as docx', async () => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;

  try {
    const peBuf = Buffer.alloc(512, 0);
    peBuf[0] = 0x4d; // 'M'
    peBuf[1] = 0x5a; // 'Z'
    peBuf.writeUInt32LE(0x80, 0x3c);
    peBuf[0x80] = 0x50; // 'P'
    peBuf[0x81] = 0x45; // 'E'
    peBuf[0x82] = 0x00;
    peBuf[0x83] = 0x00;

    const blob = new Blob([peBuf], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
    const formData = new FormData();
    formData.append('file', blob, 'resume.docx');

    const res = await fetch(`http://localhost:${port}/api/analyze`, {
      method: 'POST',
      body: formData
    });

    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.report.typeAnalysis.detectedType, 'Windows PE Executable');
    assert.equal(json.report.typeAnalysis.isSpoofed, true);
    assert.equal(json.report.risk.riskLevel, 'HIGH');
  } finally {
    server.close();
  }
});
