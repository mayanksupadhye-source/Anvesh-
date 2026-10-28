/**
 * Explainable Security Risk & Decision Engine.
 * Aggregates evidence-based signals from all static and antivirus analyzers.
 * Every finding is backed by technical evidence, source attribution, and plain-English explanations.
 * Distinctly separates Risk Level from Analysis Confidence.
 */

export function evaluateRisk({
  fileInfo,
  typeAnalysis,
  hashes,
  entropyAnalysis,
  peAnalysis,
  pdfAnalysis,
  officeAnalysis,
  archiveAnalysis,
  scriptAnalysis,
  stringAnalysis,
  clamavScan,
  virusTotalReputation
}) {
  const signals = [];
  let riskScore = 0; // 0 to 100

  // ----------------------------------------------------
  // 1. ANTIVIRUS ENGINE SIGNAL
  // ----------------------------------------------------
  if (clamavScan.available && clamavScan.scanned) {
    if (clamavScan.detected) {
      signals.push({
        signal_id: 'ANTIVIRUS_DETECTION_CONFIRMED',
        category: 'Malware Engine',
        severity: 'CRITICAL',
        title: 'Antivirus Malware Signature Detected',
        description: `ClamAV signature scanner matched known threat: ${clamavScan.threatName}`,
        technical_evidence: `Engine: ${clamavScan.engine}. Detection: ${clamavScan.threatName}. Raw output: ${clamavScan.rawOutput}`,
        plain_language: `A known malicious software signature (${clamavScan.threatName}) was found in this file. It is confirmed malware. Do not open or run this file.`,
        source: 'ClamAV Engine',
        confidence: 'HIGH',
        available: true
      });
      riskScore += 95;
    } else {
      signals.push({
        signal_id: 'ANTIVIRUS_SCAN_CLEAN',
        category: 'Malware Engine',
        severity: 'INFO',
        title: 'Antivirus Signature Scan Clean',
        description: 'ClamAV signature database scanned the file and detected no known threat signatures.',
        technical_evidence: `Engine: ${clamavScan.engine}. Verdict: Clean (OK).`,
        plain_language: 'The antivirus engine found no matching malware signatures. Note that brand-new or custom malware might not yet have a signature.',
        source: 'ClamAV Engine',
        confidence: 'HIGH',
        available: true
      });
    }
  } else {
    signals.push({
      signal_id: 'ANTIVIRUS_UNAVAILABLE',
      category: 'Malware Engine',
      severity: 'INFO',
      title: 'Antivirus Engine Unavailable',
      description: clamavScan.reason || 'ClamAV daemon not connected.',
      technical_evidence: `ClamAV service unreachable on configured port. Operating purely in static analysis mode.`,
      plain_language: 'The antivirus engine could not be contacted on this server. ANVESH performed comprehensive static structure inspection instead.',
      source: 'System Monitor',
      confidence: 'MEDIUM',
      available: false
    });
  }

  // ----------------------------------------------------
  // 2. FILE TYPE & EXTENSION SPOOFING SIGNALS
  // ----------------------------------------------------
  if (typeAnalysis.isSpoofed) {
    signals.push({
      signal_id: 'FILE_EXTENSION_SPOOFING',
      category: 'File Identity',
      severity: 'HIGH',
      title: 'File Extension Disguise / Spoofing Detected',
      description: typeAnalysis.spoofDetails?.warning || 'Extension does not match binary format.',
      technical_evidence: `Declared Extension: '${typeAnalysis.declaredExtension}', but Magic Bytes identified: '${typeAnalysis.detectedType}' (${typeAnalysis.magicBytesHex}).`,
      plain_language: `This file is masquerading as a '${typeAnalysis.declaredExtension}' file, but inside it is actually a '${typeAnalysis.detectedType}'. Attackers disguise executable files this way to trick users into running them.`,
      source: 'Magic Byte Signature Analyzer',
      confidence: 'HIGH',
      available: true
    });
    riskScore += 45;
  } else if (!typeAnalysis.extensionMatch && typeAnalysis.declaredExtension) {
    signals.push({
      signal_id: 'FILE_EXTENSION_MISMATCH',
      category: 'File Identity',
      severity: 'MEDIUM',
      title: 'File Extension Mismatch',
      description: typeAnalysis.spoofDetails?.warning || 'Extension differs from header format.',
      technical_evidence: `Declared: '${typeAnalysis.declaredExtension}', Detected Format: '${typeAnalysis.detectedType}'.`,
      plain_language: `The file name extension does not match the file's internal data format. While sometimes accidental, it can indicate a mislabeled or manipulated file.`,
      source: 'Magic Byte Signature Analyzer',
      confidence: 'HIGH',
      available: true
    });
    riskScore += 15;
  }

  // ----------------------------------------------------
  // 3. SHANNON ENTROPY SIGNALS
  // ----------------------------------------------------
  if (entropyAnalysis && entropyAnalysis.isSuspicious) {
    signals.push({
      signal_id: 'HIGH_BYTE_ENTROPY',
      category: 'File Structure',
      severity: 'MEDIUM',
      title: 'Abnormally High Byte Entropy (Randomness)',
      description: entropyAnalysis.interpretation,
      technical_evidence: `Calculated Shannon entropy: ${entropyAnalysis.entropy} / 8.0. Normal compiled code is typically 4.5 - 6.5.`,
      plain_language: 'The data in this file is extremely dense or randomized. This usually means the content is compressed, encrypted, or packed to hide its actual instructions.',
      source: 'Shannon Entropy Calculator',
      confidence: 'HIGH',
      available: true
    });
    riskScore += 20;
  }

  // ----------------------------------------------------
  // 4. WINDOWS PE EXECUTABLE SIGNALS
  // ----------------------------------------------------
  if (peAnalysis && peAnalysis.isPE) {
    // Check packed sections
    if (peAnalysis.hasPackedSection) {
      signals.push({
        signal_id: 'PE_PACKED_SECTIONS',
        category: 'Executable Structure',
        severity: 'HIGH',
        title: 'Packed / Obfuscated Binary Sections Detected',
        description: 'Binary sections exhibit characteristics of software packers or runtime crypters.',
        technical_evidence: `Sections inspected: ${peAnalysis.sections
          .filter((s) => s.isKnownPackerName || (s.isWritableAndExecutable && s.isHighEntropy))
          .map((s) => `${s.name} (Entropy: ${s.entropy}, W+X: ${s.isWritableAndExecutable})`)
          .join(', ')}.`,
        plain_language: 'Part of this program appears packed or obfuscated with an evasion wrapper. Malware authors frequently pack programs so standard security tools cannot inspect the code.',
        source: 'PE Section Inspector',
        confidence: 'HIGH',
        available: true
      });
      riskScore += 35;
    }

    // Check suspicious imported APIs
    if (peAnalysis.suspiciousApis && peAnalysis.suspiciousApis.length > 0) {
      const highApis = peAnalysis.suspiciousApis.filter((a) => a.severity === 'HIGH');
      const medApis = peAnalysis.suspiciousApis.filter((a) => a.severity === 'MEDIUM');

      if (highApis.length > 0) {
        signals.push({
          signal_id: 'PE_DANGEROUS_IMPORTS',
          category: 'Executable Capabilities',
          severity: 'HIGH',
          title: 'High-Risk System APIs Imported',
          description: 'Program imports APIs capable of process injection, remote thread creation, or memory tampering.',
          technical_evidence: `High-severity imports: ${highApis.map((a) => `${a.api} (${a.category})`).join(', ')}.`,
          plain_language: 'This program contains commands to inject code into other running programs or manipulate protected system memory.',
          source: 'PE Import Directory Analyzer',
          confidence: 'HIGH',
          available: true
        });
        riskScore += 30;
      } else if (medApis.length > 0) {
        signals.push({
          signal_id: 'PE_SUSPICIOUS_IMPORTS',
          category: 'Executable Capabilities',
          severity: 'MEDIUM',
          title: 'Suspicious API Capabilities Identified',
          description: 'Program imports APIs for dynamic library loading, persistence, or network connectivity.',
          technical_evidence: `Imports: ${medApis.slice(0, 8).map((a) => `${a.api} (${a.category})`).join(', ')}.`,
          plain_language: 'This program imports functions capable of connecting to the internet or automatically restarting itself when the computer boots.',
          source: 'PE Import Directory Analyzer',
          confidence: 'HIGH',
          available: true
        });
        riskScore += 15;
      }
    }

    // Digital signature evaluation
    if (!peAnalysis.digitalSignature.present) {
      signals.push({
        signal_id: 'PE_UNSIGNED_BINARY',
        category: 'Digital Signature',
        severity: 'LOW',
        title: 'No Digital Signature Found',
        description: 'Binary does not contain an embedded Authenticode digital signature.',
        technical_evidence: `PE Security Data Directory (index 4) size is 0 bytes.`,
        plain_language: peAnalysis.digitalSignature.plainLanguage,
        source: 'Authenticode Directory Inspector',
        confidence: 'HIGH',
        available: true
      });
      riskScore += 5;
    } else {
      signals.push({
        signal_id: 'PE_SIGNED_BINARY',
        category: 'Digital Signature',
        severity: 'INFO',
        title: 'Embedded Digital Signature Present',
        description: 'Binary includes a digital signature certificate structure in its security directory.',
        technical_evidence: `Offset: 0x${peAnalysis.digitalSignature.offset.toString(16)}, Certificate structure size: ${peAnalysis.digitalSignature.size} bytes.`,
        plain_language: 'This file contains an embedded signature certificate, which is commonly found on software signed by verified publishers.',
        source: 'Authenticode Directory Inspector',
        confidence: 'HIGH',
        available: true
      });
    }

    // Overlay data
    if (peAnalysis.overlay && peAnalysis.overlay.present) {
      signals.push({
        signal_id: 'PE_OVERLAY_DATA',
        category: 'Executable Structure',
        severity: 'MEDIUM',
        title: 'Appended Overlay Data Detected',
        description: `File contains ${Math.round(peAnalysis.overlay.size / 1024)} KB of data appended past the end of the last defined PE section.`,
        technical_evidence: `Overlay Offset: 0x${peAnalysis.overlay.offset.toString(16)}, Size: ${peAnalysis.overlay.size} bytes, Overlay Entropy: ${peAnalysis.overlay.entropy}.`,
        plain_language: 'Extra data was attached to the end of this executable file outside its standard sections. Droppers sometimes store hidden secondary payloads here.',
        source: 'PE Section Inspector',
        confidence: 'HIGH',
        available: true
      });
      riskScore += 15;
    }
  }

  // ----------------------------------------------------
  // 5. PDF DOCUMENT SIGNALS
  // ----------------------------------------------------
  if (pdfAnalysis && pdfAnalysis.isPDF) {
    if (pdfAnalysis.findings && pdfAnalysis.findings.length > 0) {
      for (const finding of pdfAnalysis.findings) {
        signals.push({
          signal_id: `PDF_${finding.tag.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`,
          category: 'Document Structure',
          severity: finding.severity,
          title: `PDF Security Finding: ${finding.name}`,
          description: finding.description,
          technical_evidence: `PDF Object Tag: '${finding.tag}' occurred ${finding.count} time(s) in document tree.`,
          plain_language:
            finding.tag === '/Launch'
              ? 'This PDF tries to run external system programs on your computer. Legitimate documents almost never need to do this.'
              : finding.tag === '/JavaScript' || finding.tag === '/JS'
              ? 'This PDF contains embedded JavaScript code that runs inside your document viewer.'
              : finding.tag === '/OpenAction'
              ? 'This PDF instructs your viewer to execute an action immediately when opened without waiting for your permission.'
              : finding.description,
          source: 'PDF Structure Inspector',
          confidence: 'HIGH',
          available: true
        });

        if (finding.severity === 'CRITICAL') riskScore += 50;
        else if (finding.severity === 'HIGH') riskScore += 30;
        else if (finding.severity === 'MEDIUM') riskScore += 15;
      }
    }
  }

  // ----------------------------------------------------
  // 6. MICROSOFT OFFICE DOCUMENT SIGNALS
  // ----------------------------------------------------
  if (officeAnalysis && officeAnalysis.isOffice) {
    if (officeAnalysis.hasMacros) {
      signals.push({
        signal_id: 'OFFICE_VBA_MACROS',
        category: 'Document Macros',
        severity: officeAnalysis.macroDetails?.autoExecRoutines?.length > 0 ? 'CRITICAL' : 'HIGH',
        title: 'Embedded VBA Macro Code Present',
        description: 'Office document contains executable Visual Basic for Applications (VBA) code.',
        technical_evidence: `Format: ${officeAnalysis.format}. Macro Details: ${JSON.stringify(officeAnalysis.macroDetails)}.`,
        plain_language: 'This document contains automated macro scripts. Criminals frequently send macro-enabled documents via email to install malware when macros are enabled.',
        source: 'Office Package Analyzer',
        confidence: 'HIGH',
        available: true
      });
      riskScore += 45;
    }

    if (officeAnalysis.hasExternalRelations) {
      signals.push({
        signal_id: 'OFFICE_EXTERNAL_TEMPLATE_INJECTION',
        category: 'Document Structure',
        severity: 'HIGH',
        title: 'External Remote Template Relationship',
        description: 'Document references external URLs as document relationships.',
        technical_evidence: `External targets: ${officeAnalysis.externalTargets.slice(0, 3).join(', ')}`,
        plain_language: 'This document is designed to fetch remote templates or resources from an external server when opened. This technique can be used to bypass static email filters.',
        source: 'Office Package Analyzer',
        confidence: 'HIGH',
        available: true
      });
      riskScore += 35;
    }
  }

  // ----------------------------------------------------
  // 7. ARCHIVE (ZIP) SIGNALS
  // ----------------------------------------------------
  if (archiveAnalysis && archiveAnalysis.isArchive) {
    if (archiveAnalysis.isZipBomb) {
      signals.push({
        signal_id: 'ARCHIVE_ZIP_BOMB',
        category: 'Archive Integrity',
        severity: 'CRITICAL',
        title: 'Decompression Bomb / Zip Bomb Pattern',
        description: 'Extreme compression ratio designed to exhaust system disk or memory upon extraction.',
        technical_evidence: `Compressed: ${(archiveAnalysis.totalCompressedSize / 1024).toFixed(1)} KB, Uncompressed: ${(archiveAnalysis.totalUncompressedSize / (1024 * 1024)).toFixed(1)} MB (Ratio ${archiveAnalysis.compressionRatio}:1).`,
        plain_language: 'This archive contains a massive expansion ratio. Extracting it could freeze or crash your computer by filling memory or disk space.',
        source: 'Archive Safeguard Analyzer',
        confidence: 'HIGH',
        available: true
      });
      riskScore += 70;
    }

    if (archiveAnalysis.hasPathTraversal) {
      signals.push({
        signal_id: 'ARCHIVE_PATH_TRAVERSAL',
        category: 'Archive Integrity',
        severity: 'CRITICAL',
        title: 'Directory Traversal Exploitation Sequence (Zip Slip)',
        description: 'Archive entries contain relative path sequences (../) targeting directories outside the destination.',
        technical_evidence: `Affected entries: ${archiveAnalysis.suspiciousEntries
          .filter((e) => e.severity === 'CRITICAL' && e.reason.includes('traversal'))
          .map((e) => e.name)
          .join(', ')}.`,
        plain_language: 'This archive attempts to write files outside of its extraction folder. This is a severe exploit designed to overwrite system files.',
        source: 'Archive Safeguard Analyzer',
        confidence: 'HIGH',
        available: true
      });
      riskScore += 65;
    }

    if (archiveAnalysis.hasDoubleExtensions) {
      signals.push({
        signal_id: 'ARCHIVE_DOUBLE_EXTENSION',
        category: 'Archive Integrity',
        severity: 'HIGH',
        title: 'Double-Extension Deception Inside Archive',
        description: 'Files inside archive use disguised double extensions (e.g. .pdf.exe).',
        technical_evidence: `Entries: ${archiveAnalysis.suspiciousEntries
          .filter((e) => e.reason.includes('Double extension'))
          .map((e) => e.name)
          .join(', ')}.`,
        plain_language: 'A file inside this archive uses a double extension to pretend to be a document while actually being a program.',
        source: 'Archive Safeguard Analyzer',
        confidence: 'HIGH',
        available: true
      });
      riskScore += 40;
    } else if (archiveAnalysis.hasExecutableFiles) {
      signals.push({
        signal_id: 'ARCHIVE_CONTAINS_EXECUTABLES',
        category: 'Archive Integrity',
        severity: 'MEDIUM',
        title: 'Executable Files Bundled in Archive',
        description: 'Archive contains binary executables or command scripts.',
        technical_evidence: `Executable entries: ${archiveAnalysis.suspiciousEntries
          .filter((e) => e.reason.includes('Direct executable'))
          .map((e) => e.name)
          .join(', ')}.`,
        plain_language: 'This archive contains runnable program files or scripts. Be cautious before running any extracted applications.',
        source: 'Archive Safeguard Analyzer',
        confidence: 'HIGH',
        available: true
      });
      riskScore += 20;
    }
  }

  // ----------------------------------------------------
  // 8. SCRIPT ANALYSIS SIGNALS
  // ----------------------------------------------------
  if (scriptAnalysis && scriptAnalysis.findings && scriptAnalysis.findings.length > 0) {
    for (const finding of scriptAnalysis.findings) {
      signals.push({
        signal_id: `SCRIPT_${finding.ruleId}`,
        category: 'Script Behavior',
        severity: finding.severity,
        title: finding.name,
        description: finding.description,
        technical_evidence: `Matched Command: '${finding.matchedSnippet}'`,
        plain_language:
          finding.ruleId === 'RANSOMWARE_VSSADMIN'
            ? 'This script tries to delete your backup and shadow copies, a tactic typical of ransomware to make file recovery impossible.'
            : finding.ruleId === 'POWERSHELL_IEX_DOWNLOAD'
            ? 'This script downloads code from the internet and executes it directly in memory to evade antivirus.'
            : finding.description,
        source: 'Script Heuristic Engine',
        confidence: 'HIGH',
        available: true
      });

      if (finding.severity === 'CRITICAL') riskScore += 50;
      else if (finding.severity === 'HIGH') riskScore += 35;
      else if (finding.severity === 'MEDIUM') riskScore += 15;
    }
  }

  // ----------------------------------------------------
  // 9. NETWORK & SUSPICIOUS STRING SIGNALS
  // ----------------------------------------------------
  if (stringAnalysis) {
    const suspiciousUrls = (stringAnalysis.urls || []).filter((u) => u.isSuspicious);
    if (suspiciousUrls.length > 0) {
      signals.push({
        signal_id: 'SUSPICIOUS_EMBEDDED_URL',
        category: 'Network Indicators',
        severity: 'MEDIUM',
        title: 'Suspicious Network URLs Identified',
        description: 'File embeds URLs pointing directly to raw IP addresses or risky top-level domains.',
        technical_evidence: `Found ${suspiciousUrls.length} suspicious URL(s): ${suspiciousUrls.slice(0, 3).map((u) => `${u.url} (${u.reason})`).join(', ')}.`,
        plain_language: 'This file contains internet web links that point directly to raw computer IP addresses rather than regular website domains.',
        source: 'Static String Extractor',
        confidence: 'HIGH',
        available: true
      });
      riskScore += 15;
    }
  }

  // ----------------------------------------------------
  // 10. EXTERNAL REPUTATION (VIRUSTOTAL) SIGNALS
  // ----------------------------------------------------
  if (virusTotalReputation.configured && virusTotalReputation.available) {
    if (virusTotalReputation.status === 'DETECTIONS_FOUND') {
      const maliciousCount = virusTotalReputation.stats.malicious;
      const isHighDetections = maliciousCount >= 3;
      signals.push({
        signal_id: 'VIRUSTOTAL_MALICIOUS_REPUTATION',
        category: 'External Intelligence',
        severity: isHighDetections ? 'CRITICAL' : 'HIGH',
        title: 'External Threat Registry Flagged Hash',
        description: `${maliciousCount} security vendor(s) classified this file hash as malicious.`,
        technical_evidence: `VirusTotal detections: ${maliciousCount}/${virusTotalReputation.totalEngines}. Top flags: ${virusTotalReputation.detections.slice(0, 5).map((d) => `${d.engine}:${d.result}`).join(', ')}.`,
        plain_language: `${maliciousCount} independent cybersecurity vendors have previously cataloged this file as dangerous.`,
        source: 'VirusTotal v3',
        confidence: 'HIGH',
        available: true
      });
      riskScore += isHighDetections ? 50 : 30;
    } else if (virusTotalReputation.status === 'CLEAN') {
      signals.push({
        signal_id: 'VIRUSTOTAL_CLEAN_REPUTATION',
        category: 'External Intelligence',
        severity: 'INFO',
        title: 'External Reputation Clean',
        description: 'Known hash evaluated across participating public threat feeds with zero malicious detections.',
        technical_evidence: `0/${virusTotalReputation.totalEngines} public engines flagged this hash.`,
        plain_language: 'This exact file has been checked by public cybersecurity databases and is not known to be malicious.',
        source: 'VirusTotal v3',
        confidence: 'HIGH',
        available: true
      });
    }
  }

  // ----------------------------------------------------
  // 11. RISK SCORE & LEVEL DETERMINATION
  // ----------------------------------------------------
  // Cap risk score between 0 and 100
  riskScore = Math.min(100, Math.max(0, riskScore));

  const hasCriticalSignal = signals.some((s) => s.severity === 'CRITICAL');
  const hasHighSignal = signals.some((s) => s.severity === 'HIGH');
  const hasMediumSignal = signals.some((s) => s.severity === 'MEDIUM');

  let riskLevel = 'LOW';
  let riskColor = 'safe'; // 'safe', 'medium', 'high', 'critical'

  if (hasCriticalSignal || riskScore >= 75) {
    riskLevel = 'CRITICAL';
    riskColor = 'critical';
  } else if (hasHighSignal || riskScore >= 45) {
    riskLevel = 'HIGH';
    riskColor = 'high';
  } else if (hasMediumSignal || riskScore >= 20) {
    riskLevel = 'MEDIUM';
    riskColor = 'medium';
  } else {
    riskLevel = 'LOW';
    riskColor = 'safe';
  }

  // ----------------------------------------------------
  // 12. CONFIDENCE EVALUATION (DISTINCT FROM RISK)
  // ----------------------------------------------------
  // Confidence reflects how complete and deep our analysis was:
  // - Did file type identification succeed?
  // - Was ClamAV available?
  // - Was specific format analyzer available for this file type?
  // - Was external reputation available?
  let confidencePoints = 0;
  let totalConfidencePoints = 4;

  if (typeAnalysis.detectedType !== 'Unknown Binary Data') confidencePoints++;
  if (clamavScan.available) confidencePoints++;
  if (peAnalysis?.isPE || pdfAnalysis?.isPDF || officeAnalysis?.isOffice || archiveAnalysis?.isArchive || scriptAnalysis?.isScript) {
    confidencePoints++;
  }
  if (virusTotalReputation.available) confidencePoints++;

  let confidenceLevel = 'MEDIUM';
  if (confidencePoints >= 3) {
    confidenceLevel = 'HIGH';
  } else if (confidencePoints <= 1) {
    confidenceLevel = 'LOW';
  }

  const confidenceExplanation =
    confidenceLevel === 'HIGH'
      ? 'High Confidence: Complete static analysis performed with verified binary parsing and signature scanning.'
      : confidenceLevel === 'MEDIUM'
      ? 'Medium Confidence: Thorough static structure analysis completed. Note that ClamAV signature scanner was offline, so findings are derived solely from static structural heuristics.'
      : 'Low Confidence: Partial analysis completed on an uncommon or non-standard file structure.';

  // ----------------------------------------------------
  // 13. RECOMMENDATIONS & PLAIN-ENGLISH EXECUTIVE SUMMARY
  // ----------------------------------------------------
  let recommendation = {
    action: 'PROCEED WITH STANDARD CAUTION',
    headline: 'No Immediate Malicious Indicators Detected',
    steps: [
      'The file passed static structure checks without triggering known threat indicators.',
      'Always confirm you received this file from a trusted, expected sender.',
      'Keep your operating system and application software updated.'
    ]
  };

  let executiveSummary = 'ANVESH analyzed this file using static structural heuristics and cryptographic hashing. No dangerous signatures, obfuscation patterns, or deceptive extensions were found.';

  if (riskLevel === 'CRITICAL') {
    recommendation = {
      action: 'DO NOT OPEN OR EXECUTE THIS FILE',
      headline: 'Severe Malicious Threat or Confirmed Signature Detected',
      steps: [
        'Do NOT double-click, open, or execute this file under any circumstances.',
        'Delete or isolate the file immediately to prevent accidental activation.',
        'If this file was downloaded via email or browser, inspect the source message or download site for signs of phishing.',
        'Run a full security scan on your workstation using your endpoint protection software.'
      ]
    };
    executiveSummary = 'This file has been evaluated as CRITICAL RISK. Concrete malicious signatures or severe weaponized structural indicators (such as disguise tactics, exploit tags, or ransomware commands) were identified.';
  } else if (riskLevel === 'HIGH') {
    recommendation = {
      action: 'TREAT AS HIGH-RISK UNTRUSTED FILE',
      headline: 'Strong Suspicious Characteristics or Extension Disguise Detected',
      steps: [
        'Avoid opening or executing this file.',
        'Verify the file origin with the original sender through a secondary communication channel.',
        'Do NOT enable macros if prompted by an Office application.',
        'Isolate the file and do not forward it to other team members.'
      ]
    };
    executiveSummary = 'This file has been classified as HIGH RISK due to significant suspicious indicators, such as file extension disguise, dangerous system APIs, or active macro components.';
  } else if (riskLevel === 'MEDIUM') {
    recommendation = {
      action: 'EXERCISE ELEVATED CAUTION',
      headline: 'Anomalies or Suspicious Indicators Identified',
      steps: [
        'Review the specific technical findings before deciding to open this file.',
        'Ensure the file came from a known, authenticated source.',
        'If opening documents, view them in protected / read-only preview mode.'
      ]
    };
    executiveSummary = 'This file has been classified as MEDIUM RISK. While no confirmed malware signature was matched, several anomalous or packed characteristics were detected.';
  }

  return {
    riskLevel,
    riskColor,
    riskScore,
    confidenceLevel,
    confidenceExplanation,
    executiveSummary,
    recommendation,
    signals,
    signalCount: signals.length,
    criticalSignals: signals.filter((s) => s.severity === 'CRITICAL').length,
    highSignals: signals.filter((s) => s.severity === 'HIGH').length,
    mediumSignals: signals.filter((s) => s.severity === 'MEDIUM').length,
    lowSignals: signals.filter((s) => s.severity === 'LOW').length,
    infoSignals: signals.filter((s) => s.severity === 'INFO').length
  };
}
