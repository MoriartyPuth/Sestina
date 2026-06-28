const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3001;

// Metadata for the presets
const PRESETS = [
  {
    id: 'mirai',
    name: 'Preset 0x01: Mirai Botnet Variant (Stripped ELF)',
    type: 'ELF',
    description: 'Stripped ELF binary structure with mock system call tables, C2 domains, and packed segments.',
    story: {
      title: 'Mirai Botnet Variant (Stripped ELF)',
      class: 'IoT DDoS Agent / ELF',
      analysis: 'Automated sandboxing detected packed UPX headers followed by scanner configurations. Upon socket initiation, payload tries default credentials on telnet services (port 23/2323) using built-in dictionaries. Decrypted domain list contains active C2 links: c2.mirai-variant-tracker.net.'
    }
  },
  {
    id: 'apk',
    name: 'Preset 0x02: Simple Android Reverse-Engineering Lab (APK)',
    type: 'APK',
    description: 'Mock APK zip container layout containing AndroidManifest.xml headers and compiled classes.dex bytecode.',
    story: {
      title: 'Simple Android APK',
      class: 'Mobile Lab App / APK',
      analysis: 'Decompiled structures identified standard AndroidManifest configuration hooks combined with custom class obfuscation tracks. String descriptors indicate telemetry streams to tracking domains, with classes.dex utilizing low-level cryptographic signatures for runtime parameter verification.'
    }
  },
  {
    id: 'vm',
    name: 'Preset 0x03: Custom Virtual Machine Bytecode Challenge',
    type: 'VM',
    description: 'Custom bytecode layout featuring specific VM instruction opcodes, memory-mapped I/O definitions, and NOP slide alignment blocks.',
    story: {
      title: 'Custom VM Bytecode',
      class: 'Reversing Challenge / VM',
      analysis: 'Execution profiling of Sestina VM Bytecode maps visual registers to opcode loops. A massive NOP slide aligns the starting entry offset. Cryptographic routines operate on diagonally-mapped matrix indices to compute verification keys.'
    }
  }
];

// Helper to fill buffer with specific byte distributions
function generateElfMock() {
  const size = 16384; // 16KB
  const buffer = Buffer.alloc(size);

  // 1. ELF Header (0x7F 'E' 'L' 'F')
  buffer[0] = 0x7f;
  buffer[1] = 0x45; // 'E'
  buffer[2] = 0x4c; // 'L'
  buffer[3] = 0x46; // 'F'
  buffer[4] = 0x02; // Class (64-bit)
  buffer[5] = 0x01; // Data (Little endian)
  buffer[6] = 0x01; // Version
  buffer[7] = 0x09; // OS ABI (FreeBSD/Linux variant)

  // ELF64 specific header fields to point to section header table
  // e_shoff (offset 40, 8 bytes): SHT at offset 12000
  buffer.writeBigUInt64LE(12000n, 40);
  // e_shentsize (offset 58, 2 bytes): 64 bytes
  buffer.writeUInt16LE(64, 58);
  // e_shnum (offset 60, 2 bytes): 5 sections
  buffer.writeUInt16LE(5, 60);
  // e_shstrndx (offset 62, 2 bytes): section 4 is string table
  buffer.writeUInt16LE(4, 62);

  // 2. Program Headers and Null Section Padding
  // We fill sections of nulls (slate-grey)
  for (let i = 64; i < 256; i++) {
    buffer[i] = 0x00;
  }

  // 3. String Table / ASCII signatures (neon cyan)
  const signature = "/usr/lib/libc.so.6\x00__libc_start_main\x00setsockopt\x00connect\x00socket\x00";
  buffer.write(signature, 256, 'ascii');

  // Add Mirai string indicators
  buffer.write("POST /cdn-cgi/l/chk_cloudflare HTTP/1.1\r\nUser-Agent: Mirai\r\n", 512, 'ascii');

  // 4. Executable Text / Code Section (.text boundary: offset 1024, size 7000)
  for (let i = 1024; i < 8000; i++) {
    const rand = Math.random();
    if (rand < 0.15) {
      buffer[i] = 0x90; // NOP
    } else if (rand < 0.18) {
      buffer[i] = 0xff; // breakpoint / call instruction parts
    } else if (rand < 0.25) {
      buffer[i] = 0x00; // inner-loop null alignment
    } else {
      buffer[i] = Math.floor(Math.random() * 256); // opcodes
    }
  }

  // Let's put a distinct NOP slide (alert amber block)
  for (let i = 4000; i < 4256; i++) {
    buffer[i] = 0x90;
  }

  // 5. Read-Only Data Section (.rodata boundary: offset 8192, size 1024)
  buffer.write("c2.mirai-variant-tracker.net\x00admin:admin1234\x00", 8192, 'ascii');
  for (let i = 8300; i < 9216; i++) {
    buffer[i] = 0x20 + (i % 95); // ASCII printable letters
  }

  // 6. Data Section (.data boundary: offset 9216, size 1024)
  for (let i = 9216; i < 10240; i++) {
    buffer[i] = (i * 17) % 256; // OP/Data bytes
  }

  // 7. Section Name String Table (.shstrtab boundary: offset 10240, size 256)
  // Index: 0 -> null, 1 -> .text, 7 -> .rodata, 15 -> .data, 21 -> .shstrtab
  buffer.write("\x00.text\x00.rodata\x00.data\x00.shstrtab\x00", 10240, 'ascii');

  // 8. Section Header Table (SHT boundary: offset 12000, size 320)
  // Each entry is 64 bytes in size.
  // Helper to write ELF64 section header:
  const writeShdr = (offset, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size) => {
    buffer.writeUInt32LE(sh_name, offset);             // sh_name
    buffer.writeUInt32LE(sh_type, offset + 4);         // sh_type
    buffer.writeBigUInt64LE(BigInt(sh_flags), offset + 8);  // sh_flags
    buffer.writeBigUInt64LE(BigInt(sh_addr), offset + 16);  // sh_addr
    buffer.writeBigUInt64LE(BigInt(sh_offset), offset + 24); // sh_offset
    buffer.writeBigUInt64LE(BigInt(sh_size), offset + 32);   // sh_size
    // remaining fields (sh_link, sh_info, sh_addralign, sh_entsize) are zeroed by default
  };

  // Section 0: NULL
  writeShdr(12000, 0, 0, 0, 0, 0, 0);
  // Section 1: .text (sh_name = 1, type = 1 SHT_PROGBITS, flags = 6 SHF_ALLOC|SHF_EXECINSTR)
  writeShdr(12000 + 64, 1, 1, 6, 0, 1024, 7000);
  // Section 2: .rodata (sh_name = 7, type = 1 SHT_PROGBITS, flags = 2 SHF_ALLOC)
  writeShdr(12000 + 128, 7, 1, 2, 0, 8192, 1024);
  // Section 3: .data (sh_name = 15, type = 1 SHT_PROGBITS, flags = 3 SHF_WRITE|SHF_ALLOC)
  writeShdr(12000 + 192, 15, 1, 3, 0, 9216, 1024);
  // Section 4: .shstrtab (sh_name = 21, type = 3 SHT_STRTAB, flags = 0)
  writeShdr(12000 + 256, 21, 3, 0, 0, 10240, 256);

  // Fill rest of buffer with padding
  for (let i = 12320; i < size; i++) {
    buffer[i] = 0x00;
  }

  return buffer;
}

function generateApkMock() {
  const size = 24576; // 24KB
  const buffer = Buffer.alloc(size);

  // 1. ZIP File Local Header (PK\x03\x04)
  buffer[0] = 0x50; // P
  buffer[1] = 0x4b; // K
  buffer[2] = 0x03;
  buffer[3] = 0x04;

  // Let's lay out file entries: AndroidManifest.xml, classes.dex, resources.arsc
  buffer.write("AndroidManifest.xml", 30, 'ascii');

  // Manifest header content (mostly binary format strings)
  for (let i = 100; i < 1000; i++) {
    if (i % 8 === 0) {
      buffer[i] = 0x00;
    } else if ((i % 12) > 9) {
      buffer[i] = 0x22; // Printables
    } else {
      buffer[i] = (i * 3) % 256;
    }
  }
  buffer.write("manifest\x00application\x00activity\x00android.intent.action.MAIN\x00", 400, 'ascii');

  // 2. Classes.dex entry (PK\x03\x04)
  const dexOffset = 2000;
  buffer[dexOffset] = 0x50;
  buffer[dexOffset + 1] = 0x4b;
  buffer[dexOffset + 2] = 0x03;
  buffer[dexOffset + 3] = 0x04;
  buffer.write("classes.dex", dexOffset + 30, 'ascii');

  // DEX Magic header (dex\n035\0)
  buffer[dexOffset + 100] = 0x64; // d
  buffer[dexOffset + 101] = 0x65; // e
  buffer[dexOffset + 102] = 0x78; // x
  buffer[dexOffset + 103] = 0x0a; // \n
  buffer[dexOffset + 104] = 0x30; // 0
  buffer[dexOffset + 105] = 0x33; // 3
  buffer[dexOffset + 106] = 0x35; // 5
  buffer[dexOffset + 107] = 0x00; // \0

  // dex instructions - structured blocks
  for (let i = dexOffset + 200; i < dexOffset + 12000; i++) {
    // Generate class data: instructions, method descriptors, strings
    const block = Math.floor(i / 512);
    if (block % 4 === 0) {
      // String pool
      buffer[i] = 0x20 + (i % 95); // ASCII strings
    } else if (block % 4 === 1) {
      // Alignment padding
      buffer[i] = 0x00;
    } else if (block % 4 === 2) {
      // Opcodes
      buffer[i] = (i * 31) % 256;
    } else {
      // Mix of opcodes, NOPs, and breakpoints
      const rand = Math.random();
      buffer[i] = rand < 0.1 ? 0x90 : rand < 0.15 ? 0xff : Math.floor(Math.random() * 256);
    }
  }

  // 3. Resources.arsc entry
  const resOffset = 15000;
  buffer[resOffset] = 0x50;
  buffer[resOffset + 1] = 0x4b;
  buffer[resOffset + 2] = 0x03;
  buffer[resOffset + 3] = 0x04;
  buffer.write("resources.arsc", resOffset + 30, 'ascii');

  // Fill remainder with zip central directory structures
  const cdOffset = 22000;
  buffer[cdOffset] = 0x50; // PK\x01\x02 (Central Directory File Header)
  buffer[cdOffset + 1] = 0x4b;
  buffer[cdOffset + 2] = 0x01;
  buffer[cdOffset + 3] = 0x02;
  buffer.write("AndroidManifest.xml", cdOffset + 46, 'ascii');

  return buffer;
}

function generateVmBytecodeMock() {
  const size = 12288; // 12KB
  const buffer = Buffer.alloc(size);

  // Custom VM Header (SESTINAVM)
  buffer.write("SESTINAVM", 0, 'ascii');
  buffer[9] = 0x01; // Major version
  buffer[10] = 0x00; // Minor version

  // Create highly structured geometric patterns
  // Since columns are 256 wide, writing patterns aligned with 256 or fractions creates vertical stripes or grids
  for (let i = 32; i < size; i++) {
    const col = i % 256;
    const row = Math.floor(i / 256);

    // Let's create beautiful geometric layout tracks
    if (row < 10) {
      // Initialization vectors & registers config (mostly nulls and small configuration parameters)
      buffer[i] = col === 0 || col === 128 ? 0xff : (col % 16 === 0 ? 0x90 : 0x00);
    } else if (row >= 10 && row < 25) {
      // Instruction block 1: Vertical green opcodes and cyan strings
      if (col % 4 === 0) {
        buffer[i] = 0x22; // ASCII string reference offsets
      } else if (col % 4 === 2) {
        buffer[i] = 0x90; // Align with NOP slides
      } else {
        buffer[i] = 0x88; // Custom opcode
      }
    } else if (row >= 25 && row < 30) {
      // Large NOP sled (amber block)
      buffer[i] = 0x90;
    } else if (row >= 30 && row < 40) {
      // Diagonal/chevron logic using mathematical coordinate triggers
      if ((col + row) % 17 === 0) {
        buffer[i] = 0xff; // Alert
      } else if ((col - row) % 9 === 0) {
        buffer[i] = 0x20; // ASCII RD
      } else {
        buffer[i] = 0x00; // Null
      }
    } else {
      // Randomized bytecode blocks
      const group = Math.floor(col / 64);
      if (group === 0) {
        buffer[i] = 0x00; // Null block
      } else if (group === 1) {
        buffer[i] = 0x41 + (i % 26); // ASCII letters
      } else if (group === 2) {
        buffer[i] = 0x90; // NOP track
      } else {
        buffer[i] = 0xb0 + (i % 16); // High opcodes
      }
    }
  }

  return buffer;
}

// Get API listing
app.get('/api/presets', (req, res) => {
  res.json(PRESETS);
});

// Stream specific preset binary data
app.get('/api/presets/:id', (req, res) => {
  const { id } = req.params;
  let buffer;

  switch (id) {
    case 'mirai':
      buffer = generateElfMock();
      break;
    case 'apk':
      buffer = generateApkMock();
      break;
    case 'vm':
      buffer = generateVmBytecodeMock();
      break;
    default:
      return res.status(404).json({ error: 'Preset not found' });
  }

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename=preset_${id}.bin`);
  res.send(buffer);
});

app.listen(PORT, () => {
  console.log(`[SESTINA_BACKEND] Server running on http://localhost:${PORT}`);
});
