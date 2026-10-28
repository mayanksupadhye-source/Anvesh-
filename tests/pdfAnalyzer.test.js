import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzePDF } from '../server/services/pdfAnalyzer.js';

test('PDF Analyzer: Identifies safe clean PDF', () => {
  const safePdf = `%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\nxref\n0 2\ntrailer\n<< /Root 1 0 R >>\nstartxref\n100\n%%EOF`;
  const result = analyzePDF(Buffer.from(safePdf, 'latin1'));

  assert.equal(result.isPDF, true);
  assert.equal(result.hasDangerousTags, false);
  assert.equal(result.findings.length, 0);
});

test('PDF Analyzer: Detects dangerous /JavaScript and /OpenAction tags', () => {
  const malPdf = `%PDF-1.5\n1 0 obj\n<< /Type /Catalog /OpenAction 3 0 R /Pages 2 0 R >>\nendobj\n3 0 obj\n<< /S /JavaScript /JS (app.alert("Pwned")) >>\nendobj\nxref\ntrailer\nstartxref\n200\n%%EOF`;
  const result = analyzePDF(Buffer.from(malPdf, 'latin1'));

  assert.equal(result.isPDF, true);
  assert.equal(result.hasDangerousTags, true);

  const tags = result.findings.map((f) => f.tag);
  assert.ok(tags.includes('/OpenAction'), 'Expected /OpenAction tag detected');
  assert.ok(tags.includes('/JavaScript'), 'Expected /JavaScript tag detected');
  assert.ok(tags.includes('/JS'), 'Expected /JS tag detected');
});
