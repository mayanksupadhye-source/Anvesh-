/**
 * String and Network Indicator Extraction Service.
 * Safely extracts ASCII and UTF-16LE strings from binary or text buffers,
 * isolates embedded URLs, IP addresses, and flags suspicious keywords.
 * IMPORTANT: URLs are NEVER contacted or executed (SSRF safe).
 */

const SUSPICIOUS_KEYWORDS = [
  // Execution & Persistence
  { pattern: /powershell(\.exe)?/i, name: 'PowerShell Execution', severity: 'MEDIUM' },
  { pattern: /cmd\.exe\s+\/[c|k]/i, name: 'Command Prompt Shell Launch', severity: 'MEDIUM' },
  { pattern: /wscript\.shell/i, name: 'WScript Shell Object', severity: 'MEDIUM' },
  { pattern: /certutil(\.exe)?\s+(-urlcache|-decode)/i, name: 'Certutil Living-off-the-Land (LOLBin)', severity: 'HIGH' },
  { pattern: /bitsadmin(\.exe)?\s+\/transfer/i, name: 'Bitsadmin Download', severity: 'HIGH' },
  { pattern: /vssadmin\s+delete\s+shadows/i, name: 'Shadow Copy Deletion (Ransomware Tactic)', severity: 'CRITICAL' },
  { pattern: /regsvr32(\.exe)?\s+(\/s|\/u|\/i)/i, name: 'RegSvr32 Proxy Execution (Squiblydoo)', severity: 'HIGH' },
  { pattern: /rundll32(\.exe)?/i, name: 'RunDLL32 Execution', severity: 'LOW' },
  { pattern: /schtasks(\.exe)?\s+\/create/i, name: 'Scheduled Task Creation (Persistence)', severity: 'MEDIUM' },

  // Download & Ingestion
  { pattern: /downloadstring\(/i, name: 'PowerShell DownloadString Execution', severity: 'HIGH' },
  { pattern: /downloadfile\(/i, name: 'PowerShell DownloadFile Invocation', severity: 'HIGH' },
  { pattern: /invoke-webrequest/i, name: 'Invoke-WebRequest Execution', severity: 'MEDIUM' },
  { pattern: /invoke-expression|iex\b/i, name: 'Invoke-Expression (Dynamic Execution)', severity: 'HIGH' },

  // Obfuscation & Evasion
  { pattern: /frombase64string/i, name: 'Base64 Decoding Routine', severity: 'MEDIUM' },
  { pattern: /isdebuggerpresent/i, name: 'Anti-Analysis / Debugger Check', severity: 'MEDIUM' },
  { pattern: /virtualalloc(ex)?/i, name: 'Memory Allocation API (Shellcode / Injection)', severity: 'HIGH' },
  { pattern: /writeprocessmemory/i, name: 'Cross-Process Memory Injection', severity: 'HIGH' },
  { pattern: /createremotethread/i, name: 'Remote Thread Injection', severity: 'HIGH' }
];

const URL_REGEX = /https?:\/\/[a-zA-Z0-9\-\._~:\/\?#\[\]@!$&'\(\)\*\+,;=%]+/g;
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

export function extractStringsAndIndicators(buffer, maxStrings = 500) {
  if (!buffer || buffer.length === 0) {
    return {
      urls: [],
      ips: [],
      suspiciousKeywords: [],
      stringCount: 0
    };
  }

  // 1. Extract ASCII strings (min length 4)
  const asciiStrings = [];
  let currentStr = '';

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte >= 32 && byte <= 126) {
      currentStr += String.fromCharCode(byte);
    } else {
      if (currentStr.length >= 4) {
        asciiStrings.push(currentStr);
        if (asciiStrings.length >= maxStrings * 3) break;
      }
      currentStr = '';
    }
  }
  if (currentStr.length >= 4) asciiStrings.push(currentStr);

  // 2. Extract UTF-16LE strings (common in Windows PE / Office)
  const utf16Strings = [];
  let currentWideStr = '';
  for (let i = 0; i < buffer.length - 1; i += 2) {
    const charCode = buffer.readUInt16LE(i);
    if (charCode >= 32 && charCode <= 126) {
      currentWideStr += String.fromCharCode(charCode);
    } else {
      if (currentWideStr.length >= 4) {
        utf16Strings.push(currentWideStr);
        if (utf16Strings.length >= maxStrings * 2) break;
      }
      currentWideStr = '';
    }
  }
  if (currentWideStr.length >= 4) utf16Strings.push(currentWideStr);

  const combinedStrings = [...asciiStrings, ...utf16Strings];
  const combinedText = combinedStrings.join('\n');

  // 3. Extract and parse URLs safely
  const rawUrls = combinedText.match(URL_REGEX) || [];
  const uniqueUrls = Array.from(new Set(rawUrls)).slice(0, 50);

  const parsedUrls = uniqueUrls.map((rawUrl) => {
    let domain = '';
    let protocol = '';
    let isSuspicious = false;
    let reason = '';

    try {
      const urlObj = new URL(rawUrl);
      domain = urlObj.hostname;
      protocol = urlObj.protocol;

      // Check if domain is a raw IPv4 address (common C2 tactic)
      if (IPV4_REGEX.test(domain)) {
        isSuspicious = true;
        reason = 'URL points directly to a raw IP address instead of a registered domain name.';
      } else if (
        domain.endsWith('.tk') ||
        domain.endsWith('.xyz') ||
        domain.endsWith('.top') ||
        domain.endsWith('.cc')
      ) {
        isSuspicious = true;
        reason = `URL utilizes top-level domain (.${domain.split('.').pop()}) frequently correlated with malicious campaigns.`;
      }
    } catch {
      domain = rawUrl.split('/')[2] || 'malformed';
      protocol = rawUrl.startsWith('https') ? 'https:' : 'http:';
    }

    return {
      url: rawUrl,
      domain,
      protocol,
      isSuspicious,
      reason
    };
  });

  // 4. Extract IPv4 addresses safely
  const rawIps = combinedText.match(IPV4_REGEX) || [];
  const uniqueIps = Array.from(new Set(rawIps)).slice(0, 30);
  const parsedIps = uniqueIps.map((ip) => {
    const isPrivate =
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      ip.startsWith('172.16.') ||
      ip.startsWith('127.');
    const isZeroOrBroadcast = ip === '0.0.0.0' || ip === '255.255.255.255';

    return {
      ip,
      type: isPrivate ? 'Private / Internal' : isZeroOrBroadcast ? 'Special / Broadcast' : 'Public Routable',
      isRoutable: !isPrivate && !isZeroOrBroadcast
    };
  });

  // 5. Match suspicious keywords
  const matchedKeywords = [];
  for (const item of SUSPICIOUS_KEYWORDS) {
    if (item.pattern.test(combinedText)) {
      matchedKeywords.push({
        name: item.name,
        severity: item.severity,
        pattern: item.pattern.toString()
      });
    }
  }

  return {
    urls: parsedUrls,
    ips: parsedIps,
    suspiciousKeywords: matchedKeywords,
    stringCount: combinedStrings.length
  };
}
