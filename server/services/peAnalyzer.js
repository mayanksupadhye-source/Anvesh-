import { calculateEntropy } from './entropyService.js';

/**
 * Robust, safe, pure-Node.js parser for Windows Portable Executable (PE32 / PE32+) binaries.
 * Parses headers, section table, section entropy, import directory, suspicious APIs,
 * digital signature directory, and overlay data without executing any code.
 */

const MACHINE_TYPES = {
  0x014c: 'Intel 386 (x86 32-bit)',
  0x8664: 'AMD64 (x64 64-bit)',
  0x01c0: 'ARM little endian',
  0xaa64: 'ARM64 little endian'
};

const SUBSYSTEM_TYPES = {
  1: 'Native / Driver',
  2: 'Windows GUI (Graphical User Interface)',
  3: 'Windows CUI (Console User Interface)',
  7: 'POSIX CUI',
  9: 'Windows CE',
  10: 'EFI Application'
};

const SUSPICIOUS_APIS = {
  process_injection: {
    name: 'Process Injection & Memory Manipulation',
    severity: 'HIGH',
    functions: [
      'VirtualAlloc',
      'VirtualAllocEx',
      'VirtualProtect',
      'VirtualProtectEx',
      'WriteProcessMemory',
      'CreateRemoteThread',
      'QueueUserAPC',
      'NtWriteVirtualMemory',
      'NtCreateThreadEx',
      'SetThreadContext'
    ]
  },
  dynamic_loading: {
    name: 'Dynamic API Resolution & Obfuscation',
    severity: 'MEDIUM',
    functions: ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW', 'GetProcAddress', 'LdrLoadDll']
  },
  evasion_anti_debug: {
    name: 'Anti-Analysis & Debugger Detection',
    severity: 'MEDIUM',
    functions: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugStringA', 'NtQueryInformationProcess']
  },
  execution_persistence: {
    name: 'Process Spawning & Persistence',
    severity: 'MEDIUM',
    functions: [
      'CreateProcessA',
      'CreateProcessW',
      'WinExec',
      'ShellExecuteA',
      'ShellExecuteW',
      'RegSetValueExA',
      'RegSetValueExW',
      'CreateServiceA',
      'CreateServiceW'
    ]
  },
  keylogging_spyware: {
    name: 'Input Sniffing & Keylogging',
    severity: 'HIGH',
    functions: ['GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookExA', 'SetWindowsHookExW', 'GetClipboardData']
  },
  network_c2: {
    name: 'Network Connection & File Download',
    severity: 'MEDIUM',
    functions: [
      'InternetOpenA',
      'InternetOpenW',
      'InternetConnectA',
      'HttpOpenRequestA',
      'URLDownloadToFileA',
      'URLDownloadToFileW',
      'WSAStartup',
      'connect',
      'send',
      'recv'
    ]
  }
};

const PACKER_SECTION_NAMES = ['upx0', 'upx1', 'upx2', '.aspack', '.vmp0', '.vmp1', '.themida', 'packer', '.nsp0', '.petite'];

export function analyzePE(buffer) {
  if (!buffer || buffer.length < 64) {
    return { isPE: false, reason: 'File is too small to contain a PE header' };
  }

  // 1. DOS Header ('MZ')
  if (buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
    return { isPE: false, reason: 'Missing MZ signature at file offset 0' };
  }

  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 24 > buffer.length) {
    return { isPE: false, reason: 'e_lfanew points past end of file' };
  }

  // 2. PE Signature ('PE\0\0')
  if (
    buffer[peOffset] !== 0x50 ||
    buffer[peOffset + 1] !== 0x45 ||
    buffer[peOffset + 2] !== 0x00 ||
    buffer[peOffset + 3] !== 0x00
  ) {
    return { isPE: false, reason: 'Missing PE signature at e_lfanew offset' };
  }

  // 3. COFF File Header (20 bytes starting at peOffset + 4)
  const coffOffset = peOffset + 4;
  const machineId = buffer.readUInt16LE(coffOffset);
  const numberOfSections = buffer.readUInt16LE(coffOffset + 2);
  const timeDateStamp = buffer.readUInt32LE(coffOffset + 4);
  const sizeOfOptionalHeader = buffer.readUInt16LE(coffOffset + 16);
  const characteristics = buffer.readUInt16LE(coffOffset + 18);

  const machine = MACHINE_TYPES[machineId] || `Unknown Machine (0x${machineId.toString(16)})`;
  const isDLL = (characteristics & 0x2000) !== 0;

  // Format compile timestamp
  let compileTime = 'Unknown';
  let isTimestampSuspicious = false;
  if (timeDateStamp > 0) {
    const date = new Date(timeDateStamp * 1000);
    compileTime = date.toISOString();
    const nowYear = new Date().getFullYear();
    const compileYear = date.getUTCFullYear();
    if (compileYear > nowYear + 1 || compileYear < 1995) {
      isTimestampSuspicious = true;
    }
  } else {
    isTimestampSuspicious = true;
    compileTime = 'Zeroed / Stipped (0x00000000)';
  }

  // 4. Optional Header
  const optOffset = coffOffset + 20;
  let optMagic = 0;
  let entryPoint = 0;
  let imageBase = '0x0';
  let subsystem = 'Unknown';
  let dataDirectories = [];
  let isPE32Plus = false;

  if (sizeOfOptionalHeader >= 2) {
    optMagic = buffer.readUInt16LE(optOffset);
    isPE32Plus = optMagic === 0x20b; // 64-bit PE32+

    if (optOffset + 20 <= buffer.length) {
      entryPoint = buffer.readUInt32LE(optOffset + 16);
    }

    if (isPE32Plus) {
      if (optOffset + 32 <= buffer.length) {
        const high = buffer.readUInt32LE(optOffset + 28);
        const low = buffer.readUInt32LE(optOffset + 24);
        imageBase = `0x${high.toString(16)}${low.toString(16).padStart(8, '0')}`;
      }
    } else {
      if (optOffset + 32 <= buffer.length) {
        imageBase = `0x${buffer.readUInt32LE(optOffset + 28).toString(16)}`;
      }
    }

    const subsystemOffset = optOffset + (isPE32Plus ? 68 : 68);
    if (subsystemOffset + 2 <= buffer.length) {
      const subId = buffer.readUInt16LE(subsystemOffset);
      subsystem = SUBSYSTEM_TYPES[subId] || `Subsystem ${subId}`;
    }

    // Number of RvaAndSizes and Data Directories
    const numRvaOffset = optOffset + (isPE32Plus ? 108 : 92);
    if (numRvaOffset + 4 <= buffer.length) {
      const numRvas = buffer.readUInt32LE(numRvaOffset);
      const dataDirStart = numRvaOffset + 4;
      for (let i = 0; i < Math.min(16, numRvas); i++) {
        const dOffset = dataDirStart + i * 8;
        if (dOffset + 8 <= buffer.length) {
          const rva = buffer.readUInt32LE(dOffset);
          const size = buffer.readUInt32LE(dOffset + 4);
          dataDirectories.push({ index: i, rva, size });
        }
      }
    }
  }

  // Digital Signature Check (Data Directory index 4: IMAGE_DIRECTORY_ENTRY_SECURITY)
  let digitalSignature = {
    present: false,
    status: 'Missing',
    size: 0,
    offset: 0,
    plainLanguage: 'The file does not contain an embedded digital signature certificate. This removes one trust indicator, though many benign utilities are also unsigned.'
  };

  if (dataDirectories[4] && dataDirectories[4].size > 0 && dataDirectories[4].rva > 0) {
    // In PE files, Directory 4's RVA is actually a raw file offset to WIN_CERTIFICATE structure
    digitalSignature = {
      present: true,
      status: 'Present',
      size: dataDirectories[4].size,
      offset: dataDirectories[4].rva,
      plainLanguage: 'An embedded digital signature certificate structure is present in the binary security directory.'
    };
  }

  // 5. Section Table (starts right after Optional Header)
  const sectionHeaderOffset = optOffset + sizeOfOptionalHeader;
  const sections = [];
  let highestRawOffset = 0;
  let hasPackedSection = false;
  let entryPointSection = 'None / Outside Sections';

  for (let i = 0; i < numberOfSections; i++) {
    const sOffset = sectionHeaderOffset + i * 40;
    if (sOffset + 40 > buffer.length) break;

    // 8-byte ASCII name
    let name = '';
    for (let c = 0; c < 8; c++) {
      const char = buffer[sOffset + c];
      if (char === 0) break;
      name += String.fromCharCode(char);
    }
    name = name.trim();

    const virtualSize = buffer.readUInt32LE(sOffset + 8);
    const virtualAddress = buffer.readUInt32LE(sOffset + 12);
    const sizeOfRawData = buffer.readUInt32LE(sOffset + 16);
    const pointerToRawData = buffer.readUInt32LE(sOffset + 20);
    const characteristicsFlags = buffer.readUInt32LE(sOffset + 36);

    const isExecutable = (characteristicsFlags & 0x20000000) !== 0;
    const isWritable = (characteristicsFlags & 0x80000000) !== 0;
    const isReadable = (characteristicsFlags & 0x40000000) !== 0;

    // Check if entry point falls in this section
    if (entryPoint >= virtualAddress && entryPoint < virtualAddress + Math.max(virtualSize, sizeOfRawData)) {
      entryPointSection = name || `Section_${i}`;
    }

    // Calculate section entropy
    let sectionEntropy = 0;
    if (pointerToRawData > 0 && sizeOfRawData > 0 && pointerToRawData + sizeOfRawData <= buffer.length) {
      const sectionBytes = buffer.subarray(pointerToRawData, pointerToRawData + sizeOfRawData);
      sectionEntropy = calculateEntropy(sectionBytes).entropy;
      if (pointerToRawData + sizeOfRawData > highestRawOffset) {
        highestRawOffset = pointerToRawData + sizeOfRawData;
      }
    }

    // Detect packer indicators
    const lowerName = name.toLowerCase();
    const isKnownPackerName = PACKER_SECTION_NAMES.some((pn) => lowerName.includes(pn));
    const isWritableAndExecutable = isWritable && isExecutable;
    const isHighEntropy = sectionEntropy >= 7.2;
    const isSizeDiscrepancy = virtualSize > 0 && sizeOfRawData > 0 && virtualSize > sizeOfRawData * 4;

    if (isKnownPackerName || (isWritableAndExecutable && isHighEntropy)) {
      hasPackedSection = true;
    }

    sections.push({
      index: i,
      name: name || `(empty_${i})`,
      virtualSize,
      virtualAddress: `0x${virtualAddress.toString(16)}`,
      sizeOfRawData,
      rawOffset: pointerToRawData,
      entropy: sectionEntropy,
      permissions: {
        executable: isExecutable,
        writable: isWritable,
        readable: isReadable
      },
      isWritableAndExecutable,
      isHighEntropy,
      isKnownPackerName,
      isSizeDiscrepancy
    });
  }

  // 6. Overlay Detection (data appended after the last raw section)
  let overlay = {
    present: false,
    size: 0,
    offset: 0,
    entropy: 0
  };

  // If digital signature exists, it is typically in the overlay space, so account for it
  let expectedMax = highestRawOffset;
  if (digitalSignature.present && digitalSignature.offset >= highestRawOffset) {
    expectedMax = Math.max(expectedMax, digitalSignature.offset + digitalSignature.size);
  }

  if (buffer.length > expectedMax + 512 && highestRawOffset > 0) {
    const overlayBytes = buffer.subarray(expectedMax);
    const ovEntropy = calculateEntropy(overlayBytes).entropy;
    overlay = {
      present: true,
      size: overlayBytes.length,
      offset: expectedMax,
      entropy: ovEntropy
    };
  }

  // Helper to convert RVA to File Offset
  const rvaToOffset = (rva) => {
    for (const sec of sections) {
      const vAddr = parseInt(sec.virtualAddress, 16);
      const vSize = Math.max(sec.virtualSize, sec.sizeOfRawData);
      if (rva >= vAddr && rva < vAddr + vSize) {
        return sec.rawOffset + (rva - vAddr);
      }
    }
    return null;
  };

  // 7. Parse Imports & Check Suspicious APIs (Directory index 1: IMAGE_DIRECTORY_ENTRY_IMPORT)
  const imports = [];
  const detectedSuspiciousApis = [];

  if (dataDirectories[1] && dataDirectories[1].rva > 0) {
    const importDirRva = dataDirectories[1].rva;
    const importDirOffset = rvaToOffset(importDirRva);

    if (importDirOffset !== null && importDirOffset + 20 <= buffer.length) {
      let descOffset = importDirOffset;

      // Iterate through IMAGE_IMPORT_DESCRIPTORs (20 bytes each, terminates with all-zero descriptor)
      while (descOffset + 20 <= buffer.length) {
        const originalFirstThunk = buffer.readUInt32LE(descOffset);
        const nameRva = buffer.readUInt32LE(descOffset + 12);
        const firstThunk = buffer.readUInt32LE(descOffset + 16);

        if (originalFirstThunk === 0 && firstThunk === 0 && nameRva === 0) {
          break; // Null descriptor terminates list
        }

        let dllName = '';
        const nameFileOffset = rvaToOffset(nameRva);
        if (nameFileOffset !== null && nameFileOffset < buffer.length) {
          for (let p = nameFileOffset; p < Math.min(buffer.length, nameFileOffset + 128); p++) {
            if (buffer[p] === 0) break;
            dllName += String.fromCharCode(buffer[p]);
          }
        }

        const functions = [];
        const thunkRva = originalFirstThunk || firstThunk;
        const thunkFileOffset = rvaToOffset(thunkRva);

        if (thunkFileOffset !== null && thunkFileOffset < buffer.length) {
          let tOffset = thunkFileOffset;
          const entrySize = isPE32Plus ? 8 : 4;

          while (tOffset + entrySize <= buffer.length && functions.length < 200) {
            let funcRva = 0;
            let isOrdinal = false;

            if (isPE32Plus) {
              const val = buffer.readBigUInt64LE(tOffset);
              if (val === 0n) break;
              // Ordinal flag is bit 63
              if ((val & 0x8000000000000000n) !== 0n) {
                isOrdinal = true;
              } else {
                funcRva = Number(val & 0x7fffffffn);
              }
            } else {
              const val = buffer.readUInt32LE(tOffset);
              if (val === 0) break;
              if ((val & 0x80000000) !== 0) {
                isOrdinal = true;
              } else {
                funcRva = val;
              }
            }

            if (!isOrdinal && funcRva > 0) {
              const hintOffset = rvaToOffset(funcRva);
              if (hintOffset !== null && hintOffset + 2 < buffer.length) {
                let funcName = '';
                for (let f = hintOffset + 2; f < Math.min(buffer.length, hintOffset + 128); f++) {
                  if (buffer[f] === 0) break;
                  funcName += String.fromCharCode(buffer[f]);
                }
                if (funcName.length > 0) {
                  functions.push(funcName);

                  // Match against suspicious catalog
                  for (const [catKey, catVal] of Object.entries(SUSPICIOUS_APIS)) {
                    if (catVal.functions.some((fn) => fn.toLowerCase() === funcName.toLowerCase())) {
                      detectedSuspiciousApis.push({
                        api: funcName,
                        dll: dllName,
                        category: catVal.name,
                        categoryKey: catKey,
                        severity: catVal.severity
                      });
                    }
                  }
                }
              }
            }

            tOffset += entrySize;
          }
        }

        if (dllName) {
          imports.push({
            dll: dllName,
            functionCount: functions.length,
            functions: functions.slice(0, 30) // cap list for response
          });
        }

        descOffset += 20;
        if (imports.length >= 64) break; // reasonable bound
      }
    }
  }

  // De-duplicate suspicious APIs
  const uniqueSuspiciousApis = [];
  const seenApis = new Set();
  for (const item of detectedSuspiciousApis) {
    if (!seenApis.has(item.api)) {
      seenApis.add(item.api);
      uniqueSuspiciousApis.push(item);
    }
  }

  return {
    isPE: true,
    format: isPE32Plus ? 'PE32+ (64-bit)' : 'PE32 (32-bit)',
    machine,
    subsystem,
    isDLL,
    compileTime,
    isTimestampSuspicious,
    entryPoint: `0x${entryPoint.toString(16)}`,
    entryPointSection,
    imageBase,
    numberOfSections,
    sections,
    hasPackedSection,
    digitalSignature,
    overlay,
    imports,
    importedDllCount: imports.length,
    suspiciousApis: uniqueSuspiciousApis
  };
}
