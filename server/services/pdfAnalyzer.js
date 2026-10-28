/**
 * Safe PDF document static structural analyzer.
 * Examines PDF object hierarchy, tags, and actions without rendering or executing.
 */

const PDF_TAGS = [
  { tag: '/JavaScript', name: 'Embedded JavaScript', severity: 'HIGH', description: 'Document contains embedded JavaScript routines which can trigger upon opening or interaction.' },
  { tag: '/JS', name: 'Embedded JavaScript Action', severity: 'HIGH', description: 'Abbreviated JavaScript tag representing executable script code.' },
  { tag: '/OpenAction', name: 'Automatic Execution on Open', severity: 'HIGH', description: 'Instructs the PDF reader to automatically perform an action (e.g., execute script or launch URL) immediately upon viewing.' },
  { tag: '/AA', name: 'Additional Actions Trigger', severity: 'MEDIUM', description: 'Defines actions triggered by page open, close, cursor hover, or form changes.' },
  { tag: '/Launch', name: 'External Process Launch', severity: 'CRITICAL', description: 'Requests the viewer to execute an external application, shell command, or executable binary.' },
  { tag: '/EmbeddedFiles', name: 'Embedded File Attachments', severity: 'MEDIUM', description: 'Contains embedded binary files or attachments stored within the PDF object tree.' },
  { tag: '/SubmitForm', name: 'Form Data Submission', severity: 'MEDIUM', description: 'Transmits form entries to an external web endpoint.' },
  { tag: '/RichMedia', name: 'Rich Media Object', severity: 'LOW', description: 'Contains embedded media (Flash/3D/video) objects.' }
];

export function analyzePDF(buffer) {
  if (!buffer || buffer.length < 5) {
    return { isPDF: false, reason: 'Buffer too small for PDF' };
  }

  // Check header %PDF-
  const header = buffer.subarray(0, 10).toString('latin1');
  if (!header.startsWith('%PDF-')) {
    return { isPDF: false, reason: 'Missing %PDF- header magic' };
  }

  const version = header.trim().split('\n')[0].replace('%PDF-', 'PDF ');
  const rawContent = buffer.toString('latin1');

  // Count objects and streams
  const objMatches = rawContent.match(/\b\d+\s+\d+\s+obj\b/g) || [];
  const streamMatches = rawContent.match(/\bstream\b/g) || [];
  const endStreamMatches = rawContent.match(/\bendstream\b/g) || [];
  const trailerMatches = rawContent.match(/\btrailer\b/g) || [];
  const startxrefMatches = rawContent.match(/\bstartxref\b/g) || [];

  // Match dangerous structural tags
  const findings = [];
  for (const item of PDF_TAGS) {
    // Regex looking for the tag followed by delimiter
    const regex = new RegExp(item.tag.replace('/', '\\/') + '(?=[\\s\\[\\]\\/<>()])', 'gi');
    const matches = rawContent.match(regex);
    if (matches && matches.length > 0) {
      findings.push({
        tag: item.tag,
        name: item.name,
        count: matches.length,
        severity: item.severity,
        description: item.description
      });
    }
  }

  // Extract embedded URI targets: /URI (http...)
  const uriRegex = /\/URI\s*\((https?:\/\/[^\)]+)\)/gi;
  const embeddedUrls = [];
  let uriMatch;
  while ((uriMatch = uriRegex.exec(rawContent)) !== null) {
    embeddedUrls.push(uriMatch[1]);
  }

  // Check for stream/endstream count mismatch (malformed/polyglot indicator)
  const isStreamMalformed = streamMatches.length !== endStreamMatches.length;

  return {
    isPDF: true,
    version,
    objectCount: objMatches.length,
    streamCount: streamMatches.length,
    hasTrailer: trailerMatches.length > 0,
    hasXref: startxrefMatches.length > 0,
    isStreamMalformed,
    findings,
    embeddedUrls: Array.from(new Set(embeddedUrls)),
    hasDangerousTags: findings.some((f) => f.severity === 'HIGH' || f.severity === 'CRITICAL')
  };
}
