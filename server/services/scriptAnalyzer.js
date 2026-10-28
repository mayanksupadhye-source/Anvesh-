/**
 * Static script and text payload analyzer.
 * Analyzes PowerShell, Batch, VBScript, Bash, Python, and JavaScript
 * for obfuscation, downloader routines, living-off-the-land commands, and evasion.
 */

const SCRIPT_RULES = [
  {
    id: 'RANSOMWARE_VSSADMIN',
    name: 'Volume Shadow Copy Deletion',
    severity: 'CRITICAL',
    regex: /vssadmin\s+(delete\s+shadows|resize\s+shadowstorage)/i,
    description: 'Attempts to delete Windows volume shadow copies to prevent file recovery during ransomware encryption.'
  },
  {
    id: 'POWERSHELL_ENCODED_CMD',
    name: 'Encoded PowerShell Command Execution',
    severity: 'HIGH',
    regex: /powershell(\.exe)?\s+(-(e|enc|encodedcommand))\s+[a-zA-Z0-9+/=]{10,}/i,
    description: 'Uses base64-encoded parameters to hide commands from command-line inspection and logging.'
  },
  {
    id: 'LOLBIN_CERTUTIL_DOWNLOAD',
    name: 'Certutil Remote File Retrieval',
    severity: 'HIGH',
    regex: /certutil(\.exe)?\s+(-urlcache|-decode|-decodehex)\s+(-f|-split)?/i,
    description: 'Abuses Windows certificate utility to download files from remote servers or decode staged payloads.'
  },
  {
    id: 'POWERSHELL_IEX_DOWNLOAD',
    name: 'In-Memory Download and Execute',
    severity: 'HIGH',
    regex: /(invoke-expression|iex)\s*[\(\{].*(downloadstring|downloaddata|webrequest)/i,
    description: 'Downloads code from a remote server and executes it directly in memory without saving to disk.'
  },
  {
    id: 'BITSADMIN_DOWNLOAD',
    name: 'Bitsadmin Background File Transfer',
    severity: 'HIGH',
    regex: /bitsadmin(\.exe)?\s+\/transfer/i,
    description: 'Uses Background Intelligent Transfer Service to stealthily download files.'
  },
  {
    id: 'REGISTRY_PERSISTENCE',
    name: 'Registry Run Key Modification',
    severity: 'HIGH',
    regex: /reg\s+add\s+.*(run|runonce|services)/i,
    description: 'Modifies Windows startup registry keys to maintain persistence across system reboots.'
  },
  {
    id: 'PROCESS_KILL',
    name: 'Security Process Termination',
    severity: 'HIGH',
    regex: /taskkill\s+(\/f|\/im)\s+(msmpeng|avp|windefend|csfalcon)/i,
    description: 'Attempts to forcibly terminate antivirus and endpoint security processes.'
  },
  {
    id: 'SUSPICIOUS_OBFUSCATION_BASE64',
    name: 'Large Embedded Base64 Payload',
    severity: 'MEDIUM',
    regex: /[a-zA-Z0-9+/]{80,}={0,2}/,
    description: 'Contains extended base64-encoded data blocks exceeding typical text parameters, indicative of an embedded payload.'
  },
  {
    id: 'FIREWALL_DISABLE',
    name: 'Firewall Policy Modification',
    severity: 'HIGH',
    regex: /netsh\s+advfirewall\s+set\s+.*state\s+off/i,
    description: 'Attempts to disable the Windows host firewall.'
  }
];

export function analyzeScript(buffer, declaredType = '') {
  if (!buffer || buffer.length === 0) {
    return { isScript: false, findings: [] };
  }

  const text = buffer.toString('utf8');
  const findings = [];

  for (const rule of SCRIPT_RULES) {
    const match = rule.regex.exec(text);
    if (match) {
      findings.push({
        ruleId: rule.id,
        name: rule.name,
        severity: rule.severity,
        description: rule.description,
        matchedSnippet: match[0].slice(0, 120)
      });
    }
  }

  return {
    isScript: findings.length > 0 || ['script', 'text'].includes(declaredType),
    findings,
    hasSevereIndicators: findings.some((f) => f.severity === 'HIGH' || f.severity === 'CRITICAL')
  };
}
