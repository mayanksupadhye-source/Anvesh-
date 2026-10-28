import path from 'node:path';

/**
 * File identification service based on magic bytes (file signatures)
 * instead of relying on the untrusted file extension.
 */

// Magic signatures dictionary
const SIGNATURES = [
  {
    type: 'Windows PE Executable',
    mime: 'application/x-dosexec',
    category: 'executable',
    isExecutable: true,
    check: (buf) => {
      if (buf.length < 64) return false;
      // 'MZ' at 0x00
      if (buf[0] === 0x4d && buf[1] === 0x5a) {
        // Read e_lfanew at 0x3C (little-endian uint32)
        const peOffset = buf.readUInt32LE(0x3c);
        if (peOffset > 0 && peOffset + 4 <= buf.length) {
          // 'PE\0\0'
          return (
            buf[peOffset] === 0x50 &&
            buf[peOffset + 1] === 0x45 &&
            buf[peOffset + 2] === 0x00 &&
            buf[peOffset + 3] === 0x00
          );
        }
        return true; // DOS MZ executable
      }
      return false;
    }
  },
  {
    type: 'Linux ELF Executable',
    mime: 'application/x-executable',
    category: 'executable',
    isExecutable: true,
    check: (buf) =>
      buf.length >= 4 &&
      buf[0] === 0x7f &&
      buf[1] === 0x45 &&
      buf[2] === 0x4c &&
      buf[3] === 0x46
  },
  {
    type: 'macOS Mach-O Binary',
    mime: 'application/x-mach-binary',
    category: 'executable',
    isExecutable: true,
    check: (buf) => {
      if (buf.length < 4) return false;
      const magic = buf.readUInt32BE(0);
      return (
        magic === 0xfeedface ||
        magic === 0xfeedfacf ||
        magic === 0xcefaedfe ||
        magic === 0xcffaedfe ||
        magic === 0xcafebabe
      );
    }
  },
  {
    type: 'PDF Document',
    mime: 'application/pdf',
    category: 'document',
    isExecutable: false,
    check: (buf) => {
      if (buf.length < 5) return false;
      // %PDF-
      return (
        buf[0] === 0x25 &&
        buf[1] === 0x50 &&
        buf[2] === 0x44 &&
        buf[3] === 0x46 &&
        buf[4] === 0x2d
      );
    }
  },
  {
    type: 'ZIP / OpenXML Archive',
    mime: 'application/zip',
    category: 'archive',
    isExecutable: false,
    check: (buf) => {
      if (buf.length < 4) return false;
      // PK\x03\x04 or PK\x05\x06 (empty) or PK\x07\x08 (spanned)
      return (
        buf[0] === 0x50 &&
        buf[1] === 0x4b &&
        ((buf[2] === 0x03 && buf[3] === 0x04) ||
          (buf[2] === 0x05 && buf[3] === 0x06) ||
          (buf[2] === 0x07 && buf[3] === 0x08))
      );
    }
  },
  {
    type: 'Microsoft Office Compound OLE Document',
    mime: 'application/x-cfb',
    category: 'document',
    isExecutable: false,
    check: (buf) => {
      if (buf.length < 8) return false;
      // D0 CF 11 E0 A1 B1 1A E1
      return (
        buf[0] === 0xd0 &&
        buf[1] === 0xcf &&
        buf[2] === 0x11 &&
        buf[3] === 0xe0 &&
        buf[4] === 0xa1 &&
        buf[5] === 0xb1 &&
        buf[6] === 0x1a &&
        buf[7] === 0xe1
      );
    }
  },
  {
    type: '7-Zip Archive',
    mime: 'application/x-7z-compressed',
    category: 'archive',
    isExecutable: false,
    check: (buf) =>
      buf.length >= 6 &&
      buf[0] === 0x37 &&
      buf[1] === 0x7a &&
      buf[2] === 0xbc &&
      buf[3] === 0xaf &&
      buf[4] === 0x27 &&
      buf[5] === 0x1c
  },
  {
    type: 'RAR Archive',
    mime: 'application/vnd.rar',
    category: 'archive',
    isExecutable: false,
    check: (buf) =>
      buf.length >= 7 &&
      buf[0] === 0x52 &&
      buf[1] === 0x61 &&
      buf[2] === 0x72 &&
      buf[3] === 0x21 &&
      buf[4] === 0x1a &&
      buf[5] === 0x07
  },
  {
    type: 'GZIP Compressed File',
    mime: 'application/gzip',
    category: 'archive',
    isExecutable: false,
    check: (buf) => buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b
  },
  {
    type: 'PNG Image',
    mime: 'image/png',
    category: 'image',
    isExecutable: false,
    check: (buf) =>
      buf.length >= 8 &&
      buf[0] === 0x89 &&
      buf[1] === 0x50 &&
      buf[2] === 0x4e &&
      buf[3] === 0x47 &&
      buf[4] === 0x0d &&
      buf[5] === 0x0a &&
      buf[6] === 0x1a &&
      buf[7] === 0x0a
  },
  {
    type: 'JPEG Image',
    mime: 'image/jpeg',
    category: 'image',
    isExecutable: false,
    check: (buf) =>
      buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff
  },
  {
    type: 'GIF Image',
    mime: 'image/gif',
    category: 'image',
    isExecutable: false,
    check: (buf) =>
      buf.length >= 6 &&
      buf[0] === 0x47 &&
      buf[1] === 0x49 &&
      buf[2] === 0x46 &&
      buf[3] === 0x38 &&
      (buf[4] === 0x37 || buf[4] === 0x39) &&
      buf[5] === 0x61
  }
];

const EXTENSION_TYPE_MAP = {
  '.exe': ['Windows PE Executable', 'DOS MZ Executable'],
  '.dll': ['Windows PE Executable'],
  '.sys': ['Windows PE Executable'],
  '.scr': ['Windows PE Executable'],
  '.pdf': ['PDF Document'],
  '.zip': ['ZIP / OpenXML Archive'],
  '.docx': ['ZIP / OpenXML Archive', 'Microsoft Office Compound OLE Document'],
  '.xlsx': ['ZIP / OpenXML Archive', 'Microsoft Office Compound OLE Document'],
  '.pptx': ['ZIP / OpenXML Archive', 'Microsoft Office Compound OLE Document'],
  '.docm': ['ZIP / OpenXML Archive', 'Microsoft Office Compound OLE Document'],
  '.xlsm': ['ZIP / OpenXML Archive', 'Microsoft Office Compound OLE Document'],
  '.doc': ['Microsoft Office Compound OLE Document', 'Plain Text'],
  '.xls': ['Microsoft Office Compound OLE Document', 'Plain Text'],
  '.ppt': ['Microsoft Office Compound OLE Document'],
  '.7z': ['7-Zip Archive'],
  '.rar': ['RAR Archive'],
  '.gz': ['GZIP Compressed File'],
  '.tar': ['TAR Archive'],
  '.png': ['PNG Image'],
  '.jpg': ['JPEG Image'],
  '.jpeg': ['JPEG Image'],
  '.gif': ['GIF Image'],
  '.ps1': ['PowerShell Script', 'Plain Text / Script'],
  '.bat': ['Windows Batch File', 'Plain Text / Script'],
  '.cmd': ['Windows Batch File', 'Plain Text / Script'],
  '.vbs': ['VBScript', 'Plain Text / Script'],
  '.js': ['JavaScript File', 'Plain Text / Script'],
  '.sh': ['Shell Script', 'Plain Text / Script'],
  '.py': ['Python Script', 'Plain Text / Script'],
  '.txt': ['Plain Text', 'Plain Text / Script']
};

/**
 * Checks if a buffer represents a text file or script
 */
function checkTextOrScript(buffer) {
  if (buffer.length === 0) return { isText: true, subType: 'Empty File' };
  
  // Inspect first 2048 bytes
  const sample = buffer.subarray(0, Math.min(2048, buffer.length));
  
  // Check for Shebang
  if (sample.length >= 2 && sample[0] === 0x23 && sample[1] === 0x21) {
    const firstLine = sample.toString('utf8').split('\n')[0].toLowerCase();
    if (firstLine.includes('bash') || firstLine.includes('sh')) {
      return { isText: true, subType: 'Shell Script (Shebang)', category: 'script', isExecutable: true };
    }
    if (firstLine.includes('python')) {
      return { isText: true, subType: 'Python Script (Shebang)', category: 'script', isExecutable: true };
    }
    return { isText: true, subType: 'Unix Script (Shebang)', category: 'script', isExecutable: true };
  }

  // Count printable characters vs binary null/control bytes
  let printable = 0;
  let nonPrintable = 0;
  for (let i = 0; i < sample.length; i++) {
    const b = sample[i];
    if (b === 0) {
      nonPrintable += 5; // Null bytes are strong indicators of binary
    } else if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) {
      printable++;
    } else if (b > 127) {
      printable++; // UTF-8 text
    } else {
      nonPrintable++;
    }
  }

  if (printable > 0 && printable / (printable + nonPrintable) > 0.85) {
    const textSample = sample.toString('utf8', 0, Math.min(sample.length, 1024)).toLowerCase();
    if (textSample.includes('@echo off') || textSample.includes('rem ') || textSample.includes('setlocal')) {
      return { isText: true, subType: 'Windows Batch File', category: 'script', isExecutable: true };
    }
    if (textSample.includes('param(') || textSample.includes('write-host') || textSample.includes('get-process')) {
      return { isText: true, subType: 'PowerShell Script', category: 'script', isExecutable: true };
    }
    return { isText: true, subType: 'Plain Text / Script', category: 'text', isExecutable: false };
  }

  return { isText: false };
}

export function identifyFile(buffer, originalFilename = '') {
  const ext = path.extname(originalFilename || '').toLowerCase();
  
  // 1. Check known binary signatures
  let detected = null;
  for (const sig of SIGNATURES) {
    if (sig.check(buffer)) {
      detected = sig;
      break;
    }
  }

  // 2. If no binary signature matched, check if it's text/script
  if (!detected) {
    const textCheck = checkTextOrScript(buffer);
    if (textCheck.isText) {
      detected = {
        type: textCheck.subType,
        mime: 'text/plain',
        category: textCheck.category || 'text',
        isExecutable: Boolean(textCheck.isExecutable)
      };
    } else {
      detected = {
        type: 'Unknown Binary Data',
        mime: 'application/octet-stream',
        category: 'binary',
        isExecutable: false
      };
    }
  }

  // Refine Office OpenXML detection from raw ZIP
  if (detected.type === 'ZIP / OpenXML Archive') {
    const sampleStr = buffer.subarray(0, Math.min(4096, buffer.length)).toString('latin1');
    if (sampleStr.includes('word/') || ext === '.docx' || ext === '.docm') {
      detected = {
        type: 'Microsoft Word Document (OpenXML)',
        mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        category: 'document',
        isExecutable: false
      };
    } else if (sampleStr.includes('xl/') || ext === '.xlsx' || ext === '.xlsm') {
      detected = {
        type: 'Microsoft Excel Spreadsheet (OpenXML)',
        mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        category: 'document',
        isExecutable: false
      };
    } else if (sampleStr.includes('ppt/') || ext === '.pptx') {
      detected = {
        type: 'Microsoft PowerPoint Presentation (OpenXML)',
        mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        category: 'document',
        isExecutable: false
      };
    }
  }

  // 3. Extension Mismatch / Spoofing Detection
  let extensionMatch = true;
  let isSpoofed = false;
  let spoofDetails = null;

  const validTypesForExt = EXTENSION_TYPE_MAP[ext];
  if (validTypesForExt && ext.length > 0) {
    const matched = validTypesForExt.some((t) => detected.type.includes(t));
    if (!matched) {
      extensionMatch = false;
      // High-risk spoofing: An executable or script masquerading as document, image, or text
      if (detected.isExecutable && !['.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.sh'].includes(ext)) {
        isSpoofed = true;
        spoofDetails = {
          declaredExt: ext,
          declaredCategory: 'Document / Media',
          detectedType: detected.type,
          severity: 'HIGH',
          warning: `Extension spoofing detected: File is named '${path.basename(originalFilename)}' with extension '${ext}', but header analysis confirms it is actually a '${detected.type}'. This is a common malware evasion tactic.`
        };
      } else {
        spoofDetails = {
          declaredExt: ext,
          detectedType: detected.type,
          severity: 'MEDIUM',
          warning: `Extension mismatch: File extension '${ext}' does not match detected internal type '${detected.type}'.`
        };
      }
    }
  }

  // Magic bytes hex string (first 16 bytes)
  const magicBytesHex = buffer
    .subarray(0, Math.min(16, buffer.length))
    .toString('hex')
    .match(/.{1,2}/g)
    ?.join(' ')
    .toUpperCase() || '';

  return {
    declaredExtension: ext,
    detectedType: detected.type,
    mimeType: detected.mime,
    category: detected.category,
    isExecutable: detected.isExecutable,
    magicBytesHex,
    extensionMatch,
    isSpoofed,
    spoofDetails
  };
}
