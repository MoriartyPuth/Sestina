import { useRef, useEffect, useState, useCallback, useMemo } from 'react';

/**
 * Byte-to-pixel color mapping rules for Sestina.
 *
 * 0x00             → #1E293B (Deep slate-grey)   — Null padding
 * 0x20–0x7E        → #22D3EE (Neon cyan)         — Readable ASCII
 * 0xFF or 0x90     → #F59E0B (Amber alert)       — Breakpoints / NOP sleds
 * Everything else  → #34D399 (Emerald green)      — Opcodes / program logic
 */

const COLOR_LUT = new Uint8Array(256 * 3);
(function buildLUT() {
  for (let i = 0; i < 256; i++) {
    const idx = i * 3;
    if (i === 0x00) {
      COLOR_LUT[idx]     = 0x26;
      COLOR_LUT[idx + 1] = 0x26;
      COLOR_LUT[idx + 2] = 0x26;
    } else if (i >= 0x20 && i <= 0x7E) {
      COLOR_LUT[idx]     = 0xD9;
      COLOR_LUT[idx + 1] = 0x77;
      COLOR_LUT[idx + 2] = 0x06;
    } else if (i === 0xFF || i === 0x90) {
      COLOR_LUT[idx]     = 0xDC;
      COLOR_LUT[idx + 1] = 0x26;
      COLOR_LUT[idx + 2] = 0x26;
    } else {
      COLOR_LUT[idx]     = 0xE5;
      COLOR_LUT[idx + 1] = 0xE5;
      COLOR_LUT[idx + 2] = 0xE5;
    }
  }
})();

// Precomputed lookup tables for O(1) rolling entropy updates
const C_LOG2_C = new Float32Array(512);
const LOG2_W = new Float32Array(512);
(function precomputeTables() {
  for (let i = 1; i < 512; i++) {
    C_LOG2_C[i] = i * Math.log2(i);
    LOG2_W[i] = Math.log2(i);
  }
})();

// Dynamic width config
const DEFAULT_ROW_WIDTH = 256;

/**
 * Map entropy value (0-8) to a gradient:
 * Deep Violet (#2E1065) to Neon Magenta (#D946EF)
 */
function getEntropyColor(h, pixels, pixelIdx) {
  const t = Math.min(1, Math.max(0, h / 8));
  pixels[pixelIdx]     = Math.floor(23 + t * (217 - 23));   // R
  pixels[pixelIdx + 1] = Math.floor(23 + t * (119 - 23));   // G
  pixels[pixelIdx + 2] = Math.floor(23 + t * (6 - 23));     // B
  pixels[pixelIdx + 3] = 255;                                // A
}

/**
 * Lightweight binary header parsing utility inside SestinaCanvas.
 * Traverses ELF/PE structures to locate sections/divisions.
 */
function parseBinarySections(data) {
  if (!data || data.length === 0) return [];
  
  const sections = [];
  
  // 1. ELF Header Check (\x7fELF)
  if (data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46) {
    const is64 = data[4] === 2;
    const isLittle = data[5] === 1;
    
    const read16 = (offset) => {
      if (offset + 2 > data.length) return 0;
      return isLittle 
        ? (data[offset] | (data[offset + 1] << 8)) 
        : ((data[offset] << 8) | data[offset + 1]);
    };
    
    const read32 = (offset) => {
      if (offset + 4 > data.length) return 0;
      return isLittle 
        ? (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0
        : ((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]) >>> 0;
    };
    
    const read64 = (offset) => {
      if (offset + 8 > data.length) return 0;
      if (isLittle) {
        const low = read32(offset);
        const high = read32(offset + 4);
        return low + high * 0x100000000;
      } else {
        const high = read32(offset);
        const low = read32(offset + 4);
        return high * 0x100000000 + low;
      }
    };
    
    try {
      if (is64) {
        const e_shoff = read64(40);
        const e_shentsize = read16(58);
        const e_shnum = read16(60);
        const e_shstrndx = read16(62);
        
        if (e_shoff > 0 && e_shnum > 0 && e_shoff + e_shnum * e_shentsize <= data.length) {
          const shstr_entry = e_shoff + e_shstrndx * e_shentsize;
          const shstr_offset = read64(shstr_entry + 24);
          
          for (let i = 0; i < e_shnum; i++) {
            const entry = e_shoff + i * e_shentsize;
            const sh_name_off = read32(entry);
            const sh_type = read32(entry + 4);
            const sh_offset = read64(entry + 24);
            const sh_size = read64(entry + 32);
            
            if (sh_size > 0 && sh_offset > 0 && sh_offset + sh_size <= data.length) {
              let name = '';
              const nameStart = shstr_offset + sh_name_off;
              if (nameStart < data.length) {
                for (let j = nameStart; j < data.length && data[j] !== 0; j++) {
                  name += String.fromCharCode(data[j]);
                }
              }
              
              if (name && name !== '.shstrtab') {
                sections.push({
                  name,
                  offset: sh_offset,
                  size: sh_size
                });
              }
            }
          }
        }
      } else {
        // ELF32
        const e_shoff = read32(32);
        const e_shentsize = read16(46);
        const e_shnum = read16(48);
        const e_shstrndx = read16(50);
        
        if (e_shoff > 0 && e_shnum > 0 && e_shoff + e_shnum * e_shentsize <= data.length) {
          const shstr_entry = e_shoff + e_shstrndx * e_shentsize;
          const shstr_offset = read32(shstr_entry + 16);
          
          for (let i = 0; i < e_shnum; i++) {
            const entry = e_shoff + i * e_shentsize;
            const sh_name_off = read32(entry);
            const sh_offset = read32(entry + 16);
            const sh_size = read32(entry + 20);
            
            if (sh_size > 0 && sh_offset > 0 && sh_offset + sh_size <= data.length) {
              let name = '';
              const nameStart = shstr_offset + sh_name_off;
              if (nameStart < data.length) {
                for (let j = nameStart; j < data.length && data[j] !== 0; j++) {
                  name += String.fromCharCode(data[j]);
                }
              }
              if (name && name !== '.shstrtab') {
                sections.push({
                  name,
                  offset: sh_offset,
                  size: sh_size
                });
              }
            }
          }
        }
      }
    } catch (err) {
      console.error('Error parsing ELF segments:', err);
    }
  }
  // 2. PE Header Check (MZ)
  else if (data[0] === 0x4d && data[1] === 0x5a) {
    try {
      const peOffset = data[0x3c] | (data[0x3d] << 8) | (data[0x3e] << 16) | (data[0x3f] << 24);
      if (peOffset + 24 <= data.length && data[peOffset] === 0x50 && data[peOffset + 1] === 0x45) { // "PE\0\0"
        const numSections = data[peOffset + 6] | (data[peOffset + 7] << 8);
        const sizeOfOptHeader = data[peOffset + 20] | (data[peOffset + 21] << 8);
        const sectionTableOffset = peOffset + 24 + sizeOfOptHeader;
        
        for (let i = 0; i < numSections; i++) {
          const entry = sectionTableOffset + i * 40;
          if (entry + 40 <= data.length) {
            let name = '';
            for (let j = 0; j < 8; j++) {
              const charVal = data[entry + j];
              if (charVal === 0) break;
              name += String.fromCharCode(charVal);
            }
            
            const size = data[entry + 16] | (data[entry + 17] << 8) | (data[entry + 18] << 16) | (data[entry + 19] << 24);
            const offset = data[entry + 20] | (data[entry + 21] << 8) | (data[entry + 22] << 16) | (data[entry + 23] << 24);
            
            if (size > 0 && offset > 0 && offset + size <= data.length) {
              sections.push({
                name,
                offset,
                size
              });
            }
          }
        }
      }
    } catch (err) {
      console.error('Error parsing PE segments:', err);
    }
  }
  
  return sections;
}

const OBSERVATORY_STENCIL = [
  "                                 .----.                         ",
  "                              .-'      '-.                      ",
  "                             /            \\                     ",
  "                            /              \\                    ",
  "                           /   ===||====    \\                   ",
  "                          /    ===||====     \\                  ",
  "                         ;        ||          ;                 ",
  "                         |   .---.||.---.     |                 ",
  "                         |  /  *  ||  *  \\    |                 ",
  "                         | |  *** || ***  |   |                 ",
  "                         |  \\  *  ||  *  /    |                 ",
  "                         |   '---'||'---'     |                 ",
  "                         ;        ||          ;                 ",
  "                          \\   .-------.      /                  ",
  "                           \\  | o o o |     /                   ",
  "                            \\ | o o o |    /                    ",
  "                             '-_______----'                     ",
  "                         ____________________                   ",
  "                        /                    \\                  ",
  "                       /  * * * * * * * * * * \\                 ",
  "                      /========================\\                ",
  "                      |                        |                ",
  "                      | # # # # # # # # # # #  |                ",
  "                      '------------------------'                "
];

const MONOLITH_STENCIL = [
  "                                  /\\                            ",
  "                                 /  \\                           ",
  "                                / || \\                          ",
  "                               /  ||  \\                         ",
  "                              /   ||   \\                        ",
  "                             /    ||    \\                       ",
  "                            /     ||     \\                      ",
  "                           /======||======\\                     ",
  "                           |  **      **  |                     ",
  "                           |  ##  ||  ##  |                     ",
  "                           |  **  ||  **  |                     ",
  "                           |  ##  ||  ##  |                     ",
  "                           |  **  ||  **  |                     ",
  "                           |  ##  ||  ##  |                     ",
  "                           |  **  ||  **  |                     ",
  "                           |  ##  ||  ##  |                     ",
  "                           |  **  ||  **  |                     ",
  "                           |  ##  ||  ##  |                     ",
  "                           |  **  ||  **  |                     ",
  "                           |======||======|                     ",
  "                           | # #  ||  # # |                     ",
  "                           | # #  ||  # # |                     ",
  "                           |      ||      |                     ",
  "                          ==================                    "
];

const BIOMORPHIC_STENCIL = [
  "                                 /\\_/\\                          ",
  "                                (=^.^=)                         ",
  "                                 )   (                          ",
  "                                /     \\                         ",
  "                               /       \\                        ",
  "                              |  *   *  |                       ",
  "                              |    #    |                       ",
  "                               \\   v   /                        ",
  "                                \\_____/                         ",
  "                                /     \\                         ",
  "                               /   |   \\                        ",
  "                              |    |    |                       ",
  "                              |  # | #  |                       ",
  "                              |  # | #  |                       ",
  "                              |  * | *  |                       ",
  "                              |  * | *  |                       ",
  "                              |  * | *  |                       ",
  "                              |    |    |                       ",
  "                               \\___|___/                        ",
  "                                |  |  |                         ",
  "                                (  |  )                         ",
  "                                |  |  |                         ",
  "                               /   |   \\                        ",
  "                              (____|____)                       "
];

const THEME_STENCILS = {
  space: OBSERVATORY_STENCIL,
  architecture: MONOLITH_STENCIL,
  biomorphic: BIOMORPHIC_STENCIL
};

/**
 * Extract unique traits from the binary buffer for dynamic kinetic matrix rendering.
 * Combines file length and sample byte values to compute stable speed and glyph pool.
 */
function extractTraits(data) {
  if (!data || data.length === 0) {
    return {
      speed: 1,
      dominantTheme: 'space',
      systemGlyphs: ['[', ']', 'X', '▲'],
      alphaGlyphs: ['1', '2', '3']
    };
  }

  // 1. Calculate a stable hash/seed from the length and sampled values
  let hash = data.length;
  const numSamples = Math.min(128, data.length);
  const step = Math.max(1, Math.floor(data.length / numSamples));
  for (let i = 0; i < data.length; i += step) {
    hash = (hash * 33) ^ data[i];
  }
  hash = Math.abs(hash);

  // 2. Select exactly one theme
  const themes = ['space', 'architecture', 'biomorphic'];
  const dominantTheme = themes[hash % themes.length];

  // 3. Build unique systemGlyphs (white)
  const baseSystemGlyphs = ['▲', '▼', '◄', '►', '■', '□', '◆', '◇', '⚙', '⚡', '⚠', '☣', '☢', '⚛', 'Ø', 'Ξ', 'Ψ', 'Ω', 'X', '[', ']', '▲', '#', '@', '&', '%'];
  const shuffledSystem = [...baseSystemGlyphs];
  let tempSeed = hash;
  for (let i = shuffledSystem.length - 1; i > 0; i--) {
    tempSeed = (tempSeed * 1103515245 + 12345) & 0x7fffffff;
    const j = tempSeed % (i + 1);
    const temp = shuffledSystem[i];
    shuffledSystem[i] = shuffledSystem[j];
    shuffledSystem[j] = temp;
  }
  const systemGlyphs = shuffledSystem.slice(0, 8 + (hash % 8));

  // 4. Build unique alphaGlyphs (gold)
  const baseAlpha = [];
  const scanStep = Math.max(1, Math.floor(data.length / 1000));
  for (let i = 0; i < data.length; i += scanStep) {
    const b = data[i];
    if ((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122)) {
      baseAlpha.push(String.fromCharCode(b));
    }
  }
  if (baseAlpha.length < 10) {
    baseAlpha.push(...'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split(''));
  }
  const uniqueAlpha = Array.from(new Set(baseAlpha));
  const shuffledAlpha = [...uniqueAlpha];
  let tempSeed2 = hash + 101;
  for (let i = shuffledAlpha.length - 1; i > 0; i--) {
    tempSeed2 = (tempSeed2 * 1103515245 + 12345) & 0x7fffffff;
    const j = tempSeed2 % (i + 1);
    const temp = shuffledAlpha[i];
    shuffledAlpha[i] = shuffledAlpha[j];
    shuffledAlpha[j] = temp;
  }
  const alphaGlyphs = shuffledAlpha.slice(0, 10 + (hash % 10));

  const speed = 1 + (hash % 8);

  return {
    speed,
    dominantTheme,
    systemGlyphs,
    alphaGlyphs
  };
}

export default function SestinaCanvas({ data, onHover, rowWidth = DEFAULT_ROW_WIDTH, hoverOffset = null, isTourActive = false }) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);
  const activeFrame = useRef(null);

  const [mode, setMode] = useState('classification'); // 'classification' | 'entropy' | 'matrix'

  // Memoize extracted traits from the data buffer
  const traits = useMemo(() => {
    return extractTraits(data);
  }, [data]);

  const [zoom, setZoom] = useState(1); // 1x to 8x
  const [hoverPos, setHoverPos] = useState(null); // { x, y, clientX, clientY }
  const [isReticleEnabled, setIsReticleEnabled] = useState(true);

  // Unmount cleanup
  useEffect(() => {
    return () => {
      if (activeFrame.current) {
        cancelAnimationFrame(activeFrame.current);
      }
    };
  }, []);

  // Parse sections/segments
  const sections = useMemo(() => {
    return parseBinarySections(data);
  }, [data]);

  // Optimized O(N) rolling window entropy calculator
  const entropyMap = useMemo(() => {
    if (!data || data.length === 0 || mode !== 'entropy') return null;

    const len = data.length;
    const entropy = new Float32Array(len);
    const half = 128;
    const counts = new Int32Array(256);

    let left = 0;
    let right = Math.min(len - 1, half);
    let sum = 0;

    // Initialize first window
    for (let j = left; j <= right; j++) {
      const b = data[j];
      const oldCount = counts[b];
      const newCount = oldCount + 1;
      counts[b] = newCount;
      sum = sum - C_LOG2_C[oldCount] + C_LOG2_C[newCount];
    }
    
    let wSize = right - left + 1;
    entropy[0] = LOG2_W[wSize] - sum / wSize;

    for (let i = 1; i < len; i++) {
      const targetLeft = Math.max(0, i - half);
      const targetRight = Math.min(len - 1, i + half);

      // Slide window left boundary
      while (left < targetLeft) {
        const b = data[left];
        const oldCount = counts[b];
        const newCount = oldCount - 1;
        counts[b] = newCount;
        sum = sum - C_LOG2_C[oldCount] + C_LOG2_C[newCount];
        left++;
      }

      // Slide window right boundary
      while (right < targetRight) {
        right++;
        const b = data[right];
        const oldCount = counts[b];
        const newCount = oldCount + 1;
        counts[b] = newCount;
        sum = sum - C_LOG2_C[oldCount] + C_LOG2_C[newCount];
      }

      wSize = right - left + 1;
      entropy[i] = LOG2_W[wSize] - sum / wSize;
    }

    return entropy;
  }, [data, mode]);

  // Synchronize hover offset from external components (e.g., HexEditor)
  useEffect(() => {
    if (mode === 'matrix') {
      setHoverPos(null);
      return;
    }
    if (hoverOffset === null) {
      setHoverPos(null);
      return;
    }

    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container || !data) return;

    const x = hoverOffset % rowWidth;
    const y = Math.floor(hoverOffset / rowWidth);
    const height = Math.ceil(data.length / rowWidth);

    if (x >= 0 && x < rowWidth && y >= 0 && y < height) {
      const rect = canvas.getBoundingClientRect();
      const containerRect = container.getBoundingClientRect();

      const pixelWidth = rect.width / rowWidth;
      const pixelHeight = rect.height / height;

      // Project the pixel center to visual container-relative coordinates
      const clientX = rect.left + (x + 0.5) * pixelWidth - containerRect.left;
      const clientY = rect.top + (y + 0.5) * pixelHeight - containerRect.top;

      setHoverPos({
        x,
        y,
        clientX,
        clientY
      });
    }
  }, [hoverOffset, rowWidth, data]);

  // Render binary data to canvas
  useEffect(() => {
    if (!data || data.length === 0 || mode === 'matrix') return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const height = Math.ceil(data.length / rowWidth);
    canvas.width = rowWidth;
    canvas.height = height;

    const ctx = canvas.getContext('2d');
    const imageData = ctx.createImageData(rowWidth, height);
    const pixels = imageData.data;

    if (mode === 'entropy' && entropyMap) {
      for (let i = 0; i < data.length; i++) {
        getEntropyColor(entropyMap[i], pixels, i * 4);
      }
    } else {
      for (let i = 0; i < data.length; i++) {
        const byteVal = data[i];
        const lutIdx = byteVal * 3;
        const pixelIdx = i * 4;

        pixels[pixelIdx]     = COLOR_LUT[lutIdx];
        pixels[pixelIdx + 1] = COLOR_LUT[lutIdx + 1];
        pixels[pixelIdx + 2] = COLOR_LUT[lutIdx + 2];
        pixels[pixelIdx + 3] = 255;
      }
    }

    // Fill remaining padding pixels with background color
    for (let i = data.length; i < rowWidth * height; i++) {
      const pixelIdx = i * 4;
      pixels[pixelIdx]     = 0x0A;
      pixels[pixelIdx + 1] = 0x0E;
      pixels[pixelIdx + 2] = 0x17;
      pixels[pixelIdx + 3] = 255;
    }

    ctx.putImageData(imageData, 0, 0);
  }, [data, mode, entropyMap, rowWidth]);

  // Matrix Stream Animation Loop using requestAnimationFrame
  useEffect(() => {
    if (mode !== 'matrix' || !data || data.length === 0) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const { speed, dominantTheme, systemGlyphs, alphaGlyphs } = traits;

    // Rigid Viewport Clamping: Stay tightly bound to parent layout container
    const scrollContainer = canvas.closest('.overflow-auto');
    const containerWidth = scrollContainer ? scrollContainer.clientWidth : 800;
    const containerHeight = scrollContainer ? scrollContainer.clientHeight : 450;

    // Force exact layout client dimensions (never expand dynamically based on file size)
    canvas.width = containerWidth || 800;
    canvas.height = containerHeight || 450;

    const cellWidth = 10;
    const cellHeight = 10;
    const cols = Math.ceil(canvas.width / cellWidth);
    const rows = Math.ceil(canvas.height / cellHeight);

    const stencilWidth = 64;
    const stencilHeight = 24;
    const stencil = THEME_STENCILS[dominantTheme].map(line => line.padEnd(stencilWidth, ' '));

    // Normalization Scaling Math: Uniform scaling choosing Math.min of scaleX and scaleY
    const scaleX = (cols * 0.75) / stencilWidth;
    const scaleY = (rows * 0.75) / stencilHeight;
    const scale = Math.min(scaleX, scaleY);

    // Centering calculations in cell coordinates
    const startRow = Math.max(0, Math.floor((rows - stencilHeight * scale) / 2));
    const startCol = Math.max(0, Math.floor((cols - stencilWidth * scale) / 2));

    let animationId;
    let lastTime = 0;

    const render = (time) => {
      if (!lastTime) lastTime = time;
      const deltaTime = time - lastTime;
      lastTime = time;

      // Clear canvas with deep obsidian black
      ctx.fillStyle = '#0A0A0A';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Monospace typography setup matching square cell dimensions
      ctx.font = 'bold 9px monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      // Shuffling timer factors
      const timeSystem = time * 0.004 * speed;
      const timeAlpha = time * 0.003 * speed;

      // Pass 1: Render all background space as quiet grey dots (#262626)
      ctx.fillStyle = '#262626';
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          let isBg = true;
          const stencilRow = Math.floor((r - startRow) / scale);
          const stencilCol = Math.floor((c - startCol) / scale);
          
          if (stencilRow >= 0 && stencilRow < stencilHeight && stencilCol >= 0 && stencilCol < stencilWidth) {
            const char = stencil[stencilRow][stencilCol];
            if (char !== ' ' && char !== undefined) {
              isBg = false;
            }
          }
          
          if (isBg) {
            const x = c * cellWidth + cellWidth / 2;
            const y = r * cellHeight + cellHeight / 2;
            ctx.fillText('.', x, y);
          }
        }
      }

      // Pass 2: Render object structural outlines and logic nodes ( titanium white #E5E5E5 )
      ctx.fillStyle = '#E5E5E5';
      for (let r = 0; r < rows; r++) {
        const stencilRow = Math.floor((r - startRow) / scale);
        if (stencilRow >= 0 && stencilRow < stencilHeight) {
          for (let c = 0; c < cols; c++) {
            const stencilCol = Math.floor((c - startCol) / scale);
            if (stencilCol >= 0 && stencilCol < stencilWidth) {
              const char = stencil[stencilRow][stencilCol];
              if (char !== ' ' && char !== undefined && !['#', '*', 'o', '^', '.'].includes(char)) {
                const x = c * cellWidth + cellWidth / 2;
                const y = r * cellHeight + cellHeight / 2;
                const idx = r * cols + c;
                const glyphIdx = Math.floor((idx + timeSystem) % systemGlyphs.length);
                const drawChar = systemGlyphs[glyphIdx];
                ctx.fillText(drawChar, x, y);
              }
            }
          }
        }
      }

      // Pass 3: Render String/Language clusters inside the object ( radiant classic gold #D97706 )
      ctx.fillStyle = '#D97706';
      for (let r = 0; r < rows; r++) {
        const stencilRow = Math.floor((r - startRow) / scale);
        if (stencilRow >= 0 && stencilRow < stencilHeight) {
          for (let c = 0; c < cols; c++) {
            const stencilCol = Math.floor((c - startCol) / scale);
            if (stencilCol >= 0 && stencilCol < stencilWidth) {
              const char = stencil[stencilRow][stencilCol];
              if (['#', '*', 'o', '^', '.'].includes(char)) {
                const x = c * cellWidth + cellWidth / 2;
                const y = r * cellHeight + cellHeight / 2;
                const idx = r * cols + c;
                const glyphIdx = Math.floor((idx + timeAlpha) % alphaGlyphs.length);
                const drawChar = alphaGlyphs[glyphIdx];
                ctx.fillText(drawChar, x, y);
              }
            }
          }
        }
      }

      animationId = requestAnimationFrame(render);
    };

    animationId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animationId);
    };
  }, [data, mode, traits, rowWidth]);

  const handleMouseMove = useCallback((e) => {
    if (mode === 'matrix') {
      setHoverPos(null);
      return;
    }
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container || !data) return;

    const rect = canvas.getBoundingClientRect();
    const containerRect = container.getBoundingClientRect();

    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;

    const x = Math.floor((e.clientX - rect.left) * scaleX);
    const y = Math.floor((e.clientY - rect.top) * scaleY);
    const height = Math.ceil(data.length / rowWidth);

    if (x >= 0 && x < rowWidth && y >= 0 && y < height) {
      const offset = y * rowWidth + x;
      if (offset < data.length) {
        // Direct-draw update for local position
        setHoverPos({
          x,
          y,
          clientX: e.clientX - containerRect.left,
          clientY: e.clientY - containerRect.top,
        });

        // Throttle parent state update to next animation frame
        if (activeFrame.current) {
          cancelAnimationFrame(activeFrame.current);
        }
        activeFrame.current = requestAnimationFrame(() => {
          onHover?.(x, y);
        });
        return;
      }
    }

    if (activeFrame.current) {
      cancelAnimationFrame(activeFrame.current);
    }
    onHover?.(null, null);
    setHoverPos(null);
  }, [data, onHover, rowWidth]);

  const handleMouseLeave = useCallback(() => {
    if (activeFrame.current) {
      cancelAnimationFrame(activeFrame.current);
    }
    onHover?.(null, null);
    setHoverPos(null);
  }, [onHover]);

  if (!data || data.length === 0) return null;

  const height = Math.ceil(data.length / rowWidth);

  // Generate loupe/magnifier grid values for reticle preview
  const loupeGrid = (() => {
    if (!hoverPos || !data) return null;
    const grid = [];
    const size = 5; // 5x5 grid
    const half = 2;

    for (let dy = -half; dy <= half; dy++) {
      const row = [];
      const targetY = hoverPos.y + dy;
      for (let dx = -half; dx <= half; dx++) {
        const targetX = hoverPos.x + dx;
        if (targetX >= 0 && targetX < rowWidth && targetY >= 0 && targetY < height) {
          const offset = targetY * rowWidth + targetX;
          if (offset < data.length) {
            const val = data[offset];
            row.push({
              x: targetX,
              y: targetY,
              val,
              color: mode === 'entropy' && entropyMap
                ? `rgb(${Math.floor(46 + (Math.min(1, Math.max(0, entropyMap[offset] / 8))) * (217 - 46))}, ${Math.floor(16 + (Math.min(1, Math.max(0, entropyMap[offset] / 8))) * (70 - 16))}, ${Math.floor(101 + (Math.min(1, Math.max(0, entropyMap[offset] / 8))) * (239 - 101))})`
                : `rgb(${COLOR_LUT[val * 3]}, ${COLOR_LUT[val * 3 + 1]}, ${COLOR_LUT[val * 3 + 2]})`
            });
            continue;
          }
        }
        row.push(null);
      }
      grid.push(row);
    }
    return grid;
  })();

  return (
    <div className="relative w-full animate-fade-in flex flex-col gap-3" id="sestina-canvas-viewport">
      
      {/* ─── Control Header Toolbar ─── */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-1 py-1.5 border-b border-sestina-border/40 bg-sestina-surface/20 rounded-md">
        
        {/* Render mode toggle */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setMode('classification')}
            className={`px-2.5 py-1 text-[10px] uppercase font-bold tracking-widest rounded border transition-all duration-200 ${
              mode === 'classification'
                ? 'border-byte-ascii text-byte-ascii bg-byte-ascii/[0.05] glow-gold'
                : 'border-sestina-border text-sestina-text-dim hover:text-sestina-text hover:border-sestina-text-dim/40'
            }`}
          >
            Byte Type
          </button>
          <button
            onClick={() => setMode('entropy')}
            className={`px-2.5 py-1 text-[10px] uppercase font-bold tracking-widest rounded border transition-all duration-200 ${
              mode === 'entropy'
                ? 'border-[#D946EF] text-[#D946EF] bg-[#D946EF]/[0.05] shadow-[0_0_8px_rgba(217,70,239,0.2)]'
                : 'border-sestina-border text-sestina-text-dim hover:text-sestina-text hover:border-sestina-text-dim/40'
            }`}
          >
            Entropy Heatmap
          </button>
          <button
            onClick={() => setMode('matrix')}
            className={`px-2.5 py-1 text-[10px] uppercase font-bold tracking-widest rounded border transition-all duration-200 ${
              mode === 'matrix'
                ? 'border-[#D97706] text-[#D97706] bg-[#D97706]/[0.05] shadow-[0_0_8px_rgba(217,119,6,0.2)]'
                : 'border-sestina-border text-sestina-text-dim hover:text-sestina-text hover:border-sestina-text-dim/40'
            }`}
          >
            [ DYN_MAT_STREAM ]
          </button>
        </div>

        {/* Reticle & Zoom controls */}
        <div className="flex items-center gap-4">
          {/* Reticle Toggle */}
          <label className="flex items-center gap-2 cursor-pointer select-none text-[9px] uppercase tracking-wider text-sestina-text-dim hover:text-sestina-text transition-colors">
            <input
              type="checkbox"
              checked={isReticleEnabled}
              onChange={(e) => setIsReticleEnabled(e.target.checked)}
              className="rounded bg-neutral-950 border-sestina-border text-byte-ascii focus:ring-0 w-3 h-3"
            />
            Zoom Loupe HUD
          </label>

          {/* Zoom Slider */}
          <div className="flex items-center gap-2">
            <span className="text-[9px] uppercase tracking-wider text-sestina-text-dim">Zoom:</span>
            <input
              type="range"
              min="1"
              max="8"
              step="0.5"
              value={zoom}
              onChange={(e) => setZoom(parseFloat(e.target.value))}
              className="w-24 h-1 bg-neutral-950 rounded-lg appearance-none cursor-pointer accent-byte-ascii border border-sestina-border/40"
            />
            <span className="text-[9px] text-byte-ascii font-bold w-6 text-right">
              {zoom.toFixed(1)}x
            </span>
          </div>
        </div>
      </div>

      {/* ─── Canvas Render Container ─── */}
      <div ref={containerRef} className="relative crt-flicker rounded-lg overflow-hidden glow-gold border border-sestina-border bg-neutral-950">
        
        {/* Visual Zoom Wrapper */}
        <div
          className={`w-full overflow-auto ${mode === 'matrix' ? 'flex items-center justify-center bg-neutral-950' : ''}`}
          style={{ 
            height: mode === 'matrix' ? 'calc(100vh - 290px)' : undefined,
            maxHeight: 'calc(100vh - 290px)' 
          }}
        >
          <div
            style={{
              width: mode === 'matrix' ? '100%' : `${100 * zoom}%`,
              height: mode === 'matrix' ? '100%' : undefined,
              transition: 'width 0.1s ease-out',
              position: 'relative',
              display: mode === 'matrix' ? 'flex' : 'block',
              alignItems: mode === 'matrix' ? 'center' : undefined,
              justifyContent: mode === 'matrix' ? 'center' : undefined,
            }}
          >
            <canvas
              ref={canvasRef}
              className="canvas-pixelated w-full block cursor-crosshair"
              style={{
                aspectRatio: mode === 'matrix' ? 'auto' : `${rowWidth} / ${height}`,
                maxHeight: mode === 'matrix' ? '100%' : undefined,
                maxWidth: mode === 'matrix' ? '100%' : undefined,
              }}
              onMouseMove={handleMouseMove}
              onMouseLeave={handleMouseLeave}
              id="sestina-canvas"
            />

            {/* Segment Overlays */}
            {mode !== 'matrix' && sections.map((sec, idx) => {
              const topPercent = (sec.offset / data.length) * 100;
              const heightPercent = (sec.size / data.length) * 100;
              
              const colors = [
                'border-red-500/40 bg-red-500/5 text-red-400',
                'border-purple-500/40 bg-purple-500/5 text-purple-400',
                'border-amber-500/40 bg-amber-500/5 text-amber-400',
                'border-blue-500/40 bg-blue-500/5 text-blue-400',
                'border-cyan-500/40 bg-cyan-500/5 text-cyan-400'
              ];
              const colorClass = colors[idx % colors.length];
              
              return (
                <div
                  key={sec.name + idx}
                  className={`absolute left-0 right-0 border-y border-dashed flex items-center pointer-events-none select-none ${colorClass}`}
                  style={{
                    top: `${topPercent}%`,
                    height: `${heightPercent}%`,
                  }}
                >
                  <div className="bg-neutral-900/90 text-[8px] px-1 py-0.5 rounded border border-sestina-border/40 ml-2 font-mono uppercase tracking-wider select-none">
                    {sec.name} (Start: 0x{sec.offset.toString(16).toUpperCase()}, Size: {sec.size} B)
                  </div>
                </div>
              );
            })}

            {/* Blinking Tour Targeting Box */}
            {mode !== 'matrix' && isTourActive && hoverOffset !== null && (
              <div
                className="absolute border-2 border-byte-ascii bg-byte-ascii/20 animate-pulse pointer-events-none z-30"
                style={{
                  left: `${((hoverOffset % rowWidth) / rowWidth) * 100}%`,
                  top: `${(Math.floor(hoverOffset / rowWidth) / height) * 100}%`,
                  width: `${(1 / rowWidth) * 100}%`,
                  height: `${(1 / height) * 100}%`,
                  transform: 'scale(1.5)',
                  transformOrigin: 'center',
                  boxShadow: '0 0 8px rgba(217, 119, 6, 0.8)',
                  minWidth: '4px',
                  minHeight: '4px',
                }}
              />
            )}
          </div>
        </div>
        <div className="scanline-overlay" />

        {/* ─── High-Tech Floating Magnification Loupe ─── */}
        {mode !== 'matrix' && isReticleEnabled && hoverPos && loupeGrid && (
          <div
            className="absolute pointer-events-none select-none z-50 flex flex-col items-center bg-neutral-950/95 border border-byte-ascii/60 rounded-lg p-2 shadow-2xl backdrop-blur-md"
            style={{
              left: `${hoverPos.clientX + 16}px`,
              top: `${hoverPos.clientY - 60}px`,
              transform: 'translate(0, -50%)',
            }}
          >
            {/* Grid display */}
            <div className="grid grid-cols-5 gap-0.5 border border-sestina-border/50 p-0.5 bg-neutral-900 rounded">
              {loupeGrid.map((row, rIdx) =>
                row.map((cell, cIdx) => {
                  const isCenter = rIdx === 2 && cIdx === 2;
                  if (!cell) {
                    return (
                      <div key={`${rIdx}-${cIdx}`} className="w-4 h-4 bg-neutral-950/40 border border-neutral-900" />
                    );
                  }
                  return (
                    <div
                      key={`${rIdx}-${cIdx}`}
                      className={`w-4 h-4 border flex items-center justify-center text-[7px] font-bold ${
                        isCenter ? 'border-byte-ascii font-black z-10 scale-105' : 'border-neutral-900/60'
                      }`}
                      style={{ backgroundColor: cell.color, color: cell.val === 0 ? '#64748B' : '#000000' }}
                    >
                      {isCenter ? cell.val.toString(16).toUpperCase().padStart(2, '0') : ''}
                    </div>
                  );
                })
              )}
            </div>

            {/* Telemetry metadata footer inside HUD reticle */}
            <div className="mt-1.5 flex flex-col items-center text-[8px] text-byte-ascii tracking-wider font-semibold border-t border-sestina-border/40 pt-1 w-full text-center">
              <span>OFFSET: {toHex8(hoverPos.y * rowWidth + hoverPos.x)}</span>
              <span className="text-[7px] text-sestina-text-dim mt-0.5">X: {hoverPos.x} &middot; Y: {hoverPos.y}</span>
            </div>
          </div>
        )}
      </div>

      {/* Canvas dimensions label */}
      <div className="flex justify-between mt-0.5 px-1">
        <span className="text-[9px] text-sestina-text-dim tracking-[0.2em] uppercase">
          {mode === 'matrix' ? 'Stream: Dynamic' : `Matrix: ${rowWidth} × ${height}`}
        </span>
        <span className="text-[9px] text-sestina-text-dim tracking-[0.2em] uppercase">
          {data.length.toLocaleString()} bytes
        </span>
      </div>
    </div>
  );
}

function toHex8(value) {
  return '0x' + value.toString(16).toUpperCase().padStart(8, '0');
}
