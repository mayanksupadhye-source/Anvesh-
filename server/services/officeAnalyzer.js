import yauzl from 'yauzl';

/**
 * Safe Microsoft Office document static structural analyzer.
 * Inspects OpenXML packages and legacy OLE compounds for VBA macros,
 * external relationship targets (remote template injection), and embedded OLE payloads.
 * Never executes macros or application runtimes.
 */

export async function analyzeOfficeDocument(filePath, buffer) {
  const result = {
    isOffice: false,
    format: 'Unknown',
    hasMacros: false,
    macroDetails: null,
    hasExternalRelations: false,
    externalTargets: [],
    hasEmbeddedObjects: false,
    embeddedObjects: [],
    findings: []
  };

  if (!buffer || buffer.length < 8) return result;

  // 1. Check Legacy OLE Compound Document (D0 CF 11 E0 A1 B1 1A E1)
  const isOLE =
    buffer[0] === 0xd0 &&
    buffer[1] === 0xcf &&
    buffer[2] === 0x11 &&
    buffer[3] === 0xe0 &&
    buffer[4] === 0xa1 &&
    buffer[5] === 0xb1 &&
    buffer[6] === 0x1a &&
    buffer[7] === 0xe1;

  if (isOLE) {
    result.isOffice = true;
    result.format = 'Legacy Microsoft Office OLE Compound Document (97-2003)';

    // Search for macro signatures in OLE stream names
    const latinContent = buffer.toString('latin1');
    const hasVBAStream =
      latinContent.includes('_VBA_PROJECT_CUR') ||
      latinContent.includes('VBA') ||
      latinContent.includes('Macros');

    if (hasVBAStream) {
      result.hasMacros = true;
      result.macroDetails = {
        type: 'VBA Macro Stream',
        autoExecRoutines: []
      };

      // Check for auto-exec routines
      const autoRoutines = ['AutoOpen', 'Document_Open', 'Workbook_Open', 'AutoExec', 'AutoExit', 'Document_Close'];
      for (const routine of autoRoutines) {
        if (new RegExp(routine, 'i').test(latinContent)) {
          result.macroDetails.autoExecRoutines.push(routine);
        }
      }

      result.findings.push({
        name: 'VBA Macros Detected',
        severity: result.macroDetails.autoExecRoutines.length > 0 ? 'HIGH' : 'MEDIUM',
        description: `Legacy document contains embedded VBA macro streams${result.macroDetails.autoExecRoutines.length > 0 ? ` with auto-execution routines: ${result.macroDetails.autoExecRoutines.join(', ')}` : ''}.`
      });
    }

    return result;
  }

  // 2. Check OpenXML Document (ZIP Header PK\x03\x04)
  const isZip = buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04;
  if (!isZip) return result;

  // Inspect entries safely with yauzl from buffer
  return new Promise((resolve) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
      if (err || !zipfile) {
        return resolve(result);
      }

      let isOpenXML = false;
      const entries = [];
      const autoRoutines = ['AutoOpen', 'Document_Open', 'Workbook_Open', 'AutoExec'];

      zipfile.readEntry();

      zipfile.on('entry', (entry) => {
        entries.push(entry.fileName);
        const name = entry.fileName.toLowerCase();

        if (name.includes('[content_types].xml') || name.startsWith('word/') || name.startsWith('xl/') || name.startsWith('ppt/')) {
          isOpenXML = true;
        }

        // Check for VBA project binary
        if (name.endsWith('vbaproject.bin') || name.includes('vba')) {
          result.hasMacros = true;
          result.macroDetails = {
            type: 'VBA Project Binary (OpenXML)',
            entryName: entry.fileName,
            autoExecRoutines: []
          };
        }

        // Check for embedded OLE objects
        if (name.includes('embeddings/') || name.endsWith('.bin') || name.includes('oleobject')) {
          result.hasEmbeddedObjects = true;
          result.embeddedObjects.push(entry.fileName);
        }

        // Check relationships for external template targets
        if (name.endsWith('.rels')) {
          zipfile.openReadStream(entry, (sErr, readStream) => {
            if (!sErr && readStream) {
              const chunks = [];
              readStream.on('data', (c) => chunks.push(c));
              readStream.on('end', () => {
                const relXml = Buffer.concat(chunks).toString('utf8');
                const targetRegex = /Target="([^"]+)"\s+TargetMode="External"/gi;
                let tMatch;
                while ((tMatch = targetRegex.exec(relXml)) !== null) {
                  result.hasExternalRelations = true;
                  result.externalTargets.push(tMatch[1]);
                }
                zipfile.readEntry();
              });
              readStream.on('error', () => zipfile.readEntry());
            } else {
              zipfile.readEntry();
            }
          });
        } else {
          zipfile.readEntry();
        }
      });

      zipfile.on('end', () => {
        if (isOpenXML) {
          result.isOffice = true;
          result.format = 'Modern Microsoft Office OpenXML Package';

          if (result.hasMacros) {
            result.findings.push({
              name: 'VBA Macro Code Detected',
              severity: 'HIGH',
              description: 'OpenXML package contains embedded vbaProject.bin macro code. Macros can execute arbitrary commands on the victim machine.'
            });
          }

          if (result.hasExternalRelations) {
            result.findings.push({
              name: 'External Template Injection Target',
              severity: 'HIGH',
              description: `Document links to external resources via TargetMode="External" (${result.externalTargets.slice(0, 3).join(', ')}). Frequently used in remote template injection attacks.`
            });
          }

          if (result.hasEmbeddedObjects) {
            result.findings.push({
              name: 'Embedded OLE Objects / Binaries',
              severity: 'MEDIUM',
              description: `Document contains ${result.embeddedObjects.length} embedded binary object(s) within the package structure.`
            });
          }
        }
        resolve(result);
      });

      zipfile.on('error', () => resolve(result));
    });
  });
}
