/**
 * Shannon Entropy calculation service.
 * Entropy measures information density and randomness on a scale from 0.0 to 8.0.
 * In malware analysis:
 * - Normal code/text: 3.5 - 6.5
 * - High entropy (> 7.2) in executable sections often indicates packing, compression, or encryption (used by malware to evade static signatures).
 * - Very low entropy (< 2.0) often indicates large sequences of padding/zeroes or uninitialized space.
 */

export function calculateEntropy(buffer) {
  if (!buffer || buffer.length === 0) {
    return {
      entropy: 0,
      interpretation: 'Empty file',
      isSuspicious: false,
      distribution: []
    };
  }

  const byteCounts = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    byteCounts[buffer[i]]++;
  }

  let entropy = 0;
  const total = buffer.length;

  for (let i = 0; i < 256; i++) {
    if (byteCounts[i] > 0) {
      const p = byteCounts[i] / total;
      entropy -= p * Math.log2(p);
    }
  }

  entropy = Number(entropy.toFixed(4));

  // Chunk distribution (up to 32 chunks for visual representation)
  const chunkCount = Math.min(32, Math.max(8, Math.floor(buffer.length / 512)));
  const chunkSize = Math.max(1, Math.floor(buffer.length / chunkCount));
  const distribution = [];

  for (let c = 0; c < chunkCount; c++) {
    const start = c * chunkSize;
    const end = c === chunkCount - 1 ? buffer.length : start + chunkSize;
    const sub = buffer.subarray(start, end);
    if (sub.length > 0) {
      const counts = new Array(256).fill(0);
      for (let j = 0; j < sub.length; j++) counts[sub[j]]++;
      let chunkEntropy = 0;
      for (let j = 0; j < 256; j++) {
        if (counts[j] > 0) {
          const p = counts[j] / sub.length;
          chunkEntropy -= p * Math.log2(p);
        }
      }
      distribution.push({
        index: c,
        entropy: Number(chunkEntropy.toFixed(2)),
        offset: start
      });
    }
  }

  let interpretation = 'Normal byte distribution';
  let isSuspicious = false;

  if (entropy >= 7.2) {
    interpretation = 'Very high entropy: Indicates packing, encryption, or strong compression. Often seen in packed malware, obfuscated droppers, or encrypted payloads.';
    isSuspicious = true;
  } else if (entropy >= 6.8) {
    interpretation = 'Moderately high entropy: Typical of compressed archives, media files, or compiled binaries with embedded resources.';
    isSuspicious = false;
  } else if (entropy <= 2.0) {
    interpretation = 'Very low entropy: File contains repetitive patterns, sparse data, or zero-byte padding.';
    isSuspicious = false;
  }

  return {
    entropy,
    interpretation,
    isSuspicious,
    distribution
  };
}
