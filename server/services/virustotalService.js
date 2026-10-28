import { config } from '../config.js';

/**
 * Optional External Intelligence: VirusTotal v3 Hash Reputation.
 * Queries file SHA-256 hash against public database if API key is provided.
 * STRICT PRINCIPLE: Never fabricates an external reputation result!
 */

export async function lookupHashReputation(sha256) {
  if (!config.VIRUSTOTAL_API_KEY || config.VIRUSTOTAL_API_KEY.trim() === '') {
    return {
      available: false,
      configured: false,
      status: 'NOT_CONFIGURED',
      engine: 'VirusTotal v3',
      message: 'VirusTotal API key is not configured in environment variables (.env). External reputation lookup skipped.',
      plainLanguage: 'External threat reputation check is not configured. To enable public malware database lookups, set VIRUSTOTAL_API_KEY in the server .env file.'
    };
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
      method: 'GET',
      headers: {
        'x-apikey': config.VIRUSTOTAL_API_KEY.trim(),
        'Accept': 'application/json'
      },
      signal: controller.signal
    });

    clearTimeout(timeout);

    if (response.status === 404) {
      return {
        available: true,
        configured: true,
        status: 'UNKNOWN_HASH',
        engine: 'VirusTotal v3',
        stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        message: 'Hash not found in VirusTotal public database. This file has not been submitted or observed before.',
        plainLanguage: 'This file hash has not been previously seen in the public VirusTotal malware catalog.'
      };
    }

    if (response.status === 429) {
      return {
        available: false,
        configured: true,
        status: 'RATE_LIMITED',
        engine: 'VirusTotal v3',
        message: 'VirusTotal API rate limit reached. Query could not be completed.',
        plainLanguage: 'Public threat database query rate limit reached. Please wait before querying external reputation again.'
      };
    }

    if (!response.ok) {
      return {
        available: false,
        configured: true,
        status: 'API_ERROR',
        engine: 'VirusTotal v3',
        message: `VirusTotal API responded with HTTP status ${response.status}.`,
        plainLanguage: 'External threat intelligence lookup encountered a service error.'
      };
    }

    const json = await response.json();
    const attributes = json?.data?.attributes;
    const stats = attributes?.last_analysis_stats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };
    const permalink = `https://www.virustotal.com/gui/file/${sha256}`;

    // Collect top detections if any
    const detections = [];
    if (attributes?.last_analysis_results) {
      for (const [engine, result] of Object.entries(attributes.last_analysis_results)) {
        if (result.category === 'malicious' || result.category === 'suspicious') {
          detections.push({
            engine,
            category: result.category,
            result: result.result
          });
        }
      }
    }

    const isMalicious = stats.malicious > 0;

    return {
      available: true,
      configured: true,
      status: isMalicious ? 'DETECTIONS_FOUND' : 'CLEAN',
      engine: 'VirusTotal v3',
      stats,
      detections: detections.slice(0, 15),
      totalEngines: Object.values(stats).reduce((a, b) => a + b, 0),
      permalink,
      plainLanguage: isMalicious
        ? `${stats.malicious} security engine(s) in the public database classified this file hash as malicious.`
        : 'No malicious verdicts were recorded for this file hash across participating public security vendors.'
    };
  } catch (err) {
    return {
      available: false,
      configured: true,
      status: 'NETWORK_ERROR',
      engine: 'VirusTotal v3',
      message: `Failed to query VirusTotal: ${err.message}`,
      plainLanguage: 'Could not connect to external threat intelligence network.'
    };
  }
}
