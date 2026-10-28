import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { calculateEntropy } from '../server/services/entropyService.js';

test('Entropy Service: Zero entropy for all identical bytes', () => {
  const buf = Buffer.alloc(1000, 0x00);
  const result = calculateEntropy(buf);
  assert.equal(result.entropy, 0);
  assert.equal(result.isSuspicious, false);
});

test('Entropy Service: Very high entropy for cryptographically random bytes', () => {
  const buf = crypto.randomBytes(4096);
  const result = calculateEntropy(buf);
  assert.ok(result.entropy >= 7.8, `Expected entropy >= 7.8, got ${result.entropy}`);
  assert.equal(result.isSuspicious, true);
  assert.match(result.interpretation, /Very high entropy/);
});

test('Entropy Service: Normal entropy for standard ASCII text', () => {
  const text = 'The quick brown fox jumps over the lazy dog. Cybersecurity static analysis inspection.'.repeat(20);
  const buf = Buffer.from(text, 'utf8');
  const result = calculateEntropy(buf);
  assert.ok(result.entropy >= 3.5 && result.entropy <= 5.5, `Expected 3.5-5.5, got ${result.entropy}`);
  assert.equal(result.isSuspicious, false);
});
