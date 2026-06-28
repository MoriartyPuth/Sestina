import { useState, useCallback, useEffect, useMemo } from 'react';
import DropZone from '../components/DropZone';
import SestinaCanvas from '../components/SestinaCanvas';
import HUDTelemetry from '../components/HUDTelemetry';
import SecurityStory from '../components/SecurityStory';
import StringsExtractor from '../components/StringsExtractor';
import HexEditor from '../components/HexEditor';

/**
 * Color legend data matching the Sestina byte-to-pixel mapping rules.
 */
const LEGEND_ITEMS = [
  {
    color: '#262626',
    label: 'NULL_PAD',
    desc: '0x00 — Null padding regions',
    border: 'border-[#404040]',
  },
  {
    color: '#D97706',
    label: 'ASCII_RD',
    desc: '0x20–0x7E — Readable ASCII strings',
    border: 'border-byte-ascii/30',
  },
  {
    color: '#DC2626',
    label: 'NOP_BRK',
    desc: '0xFF / 0x90 — Breakpoints & NOP sleds',
    border: 'border-byte-nop/30',
  },
  {
    color: '#E5E5E5',
    label: 'OPCODE',
    desc: 'All other — Program logic & opcodes',
    border: 'border-byte-opcode/30',
  },
];

/**
 * Guided Tour Waypoints for each binary preset.
 */
const TOUR_WAYPOINTS = {
  mirai: [
    { offset: 0, desc: "ELF Header Signature: Starts with standard magic bytes 0x7F 'ELF' (0x45, 0x4C, 0x46). Configured here as 64-bit Linux Executable." },
    { offset: 40, desc: "SHT Offset Pointer: Section Header Table offset starts at byte 12000, pointing to boundaries mapping .text, .rodata, and .data segments." },
    { offset: 1024, desc: "Compiled .text Section: Executable program code segment where malware's main networking hooks and routines run." },
    { offset: 8192, desc: "Static Decrypted Strings: Read-only memory (.rodata) storing configuration parameters, telnet scanner credentials, and C2 domains." }
  ],
  apk: [
    { offset: 0, desc: "ZIP Local File Header: Initiated with 'PK\\x03\\x04' signature. Confirming application archive layout." },
    { offset: 30, desc: "Configuration Pointer: Locates 'AndroidManifest.xml' file descriptor, setting activity definitions and hardware access." },
    { offset: 100, desc: "XML Configuration Payload: Declares background services, receiver bounds, and internet permissions." },
    { offset: 8192, desc: "classes.dex Bytecode Header: Start of dalvik machine bytecode layout, storing class templates and obfuscated structures." }
  ],
  vm: [
    { offset: 0, desc: "Hypervisor Magic Bytes: Custom signature string 'SESTINAVM' to instantiate target stack register loop." },
    { offset: 32, desc: "VM Instruction Bytecode: Direct entry commands, matching OP codes to visual canvas register patterns." },
    { offset: 2048, desc: "Register Port Mapping: Dedicated input/output address configurations for reading keyboard or screen states." },
    { offset: 8192, desc: "NOP Slide Alignment (0x90): A wide block of NOP operations to redirect execution register jumps cleanly." }
  ]
};

/**
 * Structural Mapping Utility to scan custom files.
 * Evaluates the Uint8Array buffer to isolate the file header signature block
 * and locate the highest concentration offset of contiguous printable ASCII bytes.
 */
function analyzeCustomFile(uint8Array, name) {
  const len = uint8Array.length;
  let classification = 'RAW UNCLASSIFIED DATA';
  let headerDesc = '';

  const firstBytesHex = Array.from(uint8Array.slice(0, Math.min(len, 8)))
    .map(b => b.toString(16).toUpperCase().padStart(2, '0'))
    .join(' ');

  // 1. Evaluate magic signature
  if (len >= 4 && uint8Array[0] === 0x7F && uint8Array[1] === 0x45 && uint8Array[2] === 0x4C && uint8Array[3] === 0x46) {
    classification = 'ELF BINARY FILE';
    headerDesc = `ELF Header Signature: Starts with standard magic bytes 0x7F 'ELF' (0x45, 0x4C, 0x46). Evaluation confirms 64-bit/32-bit Unix Executable boundaries. Header metadata points to sections mapping .text, .rodata, and .data segments.`;
  } else if (len >= 2 && uint8Array[0] === 0x4D && uint8Array[1] === 0x5A) {
    classification = 'PE PORTABLE EXECUTABLE';
    headerDesc = `PE Header Signature: Starts with DOS 'MZ' magic bytes (0x4D, 0x5A) at offset 0. Evaluation locates PE signature offset, indicating standard Windows executable or DLL layout boundaries.`;
  } else if (len >= 4 && uint8Array[0] === 0x50 && uint8Array[1] === 0x4B && uint8Array[2] === 0x03 && uint8Array[3] === 0x04) {
    classification = 'ZIP/APK ARCHIVE FILE';
    headerDesc = `ZIP Local File Header Signature: Starts with 'PK\\x03\\x04' (0x50, 0x4B, 0x03, 0x04) at offset 0. Confirming ZIP format local archive segment boundaries.`;
  } else if (len >= 9 && String.fromCharCode(...uint8Array.slice(0, 9)) === 'SESTINAVM') {
    classification = 'SESTINA VM BYTECODE';
    headerDesc = `Hypervisor Magic Bytes: Custom signature string 'SESTINAVM' to instantiate target stack register loop. Coordinates opcodes to visual canvas register patterns.`;
  } else if (len >= 4 && uint8Array[0] === 0xCA && uint8Array[1] === 0xFE && uint8Array[2] === 0xBA && uint8Array[3] === 0xBE) {
    classification = 'MACH-O / CLASS BINARY';
    headerDesc = `Mach-O Fat Binary / Java Class magic signature: Starts with 'CAFEBABE' (0xCA, 0xFE, 0xBA, 0xBE) at offset 0. Directs initialization logic to machine architecture tables.`;
  } else if (len >= 4 && (
    (uint8Array[0] === 0xFE && uint8Array[1] === 0xED && uint8Array[2] === 0xFA && uint8Array[3] === 0xCE) ||
    (uint8Array[0] === 0xFE && uint8Array[1] === 0xED && uint8Array[2] === 0xFA && uint8Array[3] === 0xCF) ||
    (uint8Array[0] === 0xCE && uint8Array[1] === 0xFA && uint8Array[2] === 0xED && uint8Array[3] === 0xFE) ||
    (uint8Array[0] === 0xCF && uint8Array[1] === 0xFA && uint8Array[2] === 0xED && uint8Array[3] === 0xFE)
  )) {
    classification = 'MACH-O EXECUTABLE';
    headerDesc = `Mach-O Executable Signature: Starts with 'FEEDFACE' / 'FEEDFACF' magic bytes at offset 0. Evaluation suggests macOS / iOS native system targets.`;
  } else if (len >= 4 && uint8Array[0] === 0x25 && uint8Array[1] === 0x50 && uint8Array[2] === 0x44 && uint8Array[3] === 0x46) {
    classification = 'PDF DOCUMENT';
    headerDesc = `PDF Document Signature: Starts with '%PDF' magic bytes (0x25, 0x50, 0x44, 0x46) at offset 0. Identifies layout-based document binary representation.`;
  } else if (len >= 4 && uint8Array[0] === 0x89 && uint8Array[1] === 0x50 && uint8Array[2] === 0x4E && uint8Array[3] === 0x47) {
    classification = 'PNG IMAGE FILE';
    headerDesc = `PNG Image Signature: Starts with standard PNG signature bytes (0x89, 0x50, 0x4E, 0x47) at offset 0. Identifies portable network graphics representation.`;
  } else if (len >= 4 && uint8Array[0] === 0x47 && uint8Array[1] === 0x49 && uint8Array[2] === 0x46 && uint8Array[3] === 0x38) {
    classification = 'GIF IMAGE FILE';
    headerDesc = `GIF Image Signature: Starts with 'GIF89a'/'GIF87a' magic bytes (0x47, 0x49, 0x46, 0x38) at offset 0. Identifies graphics interchange format image representation.`;
  } else {
    classification = 'RAW UNCLASSIFIED DATA';
    headerDesc = `Unknown Header Signature: Starts with unclassified bytes: [ ${firstBytesHex} ]. Evaluation suggests unclassified custom bytecode payload.`;
  }

  // 2. Locate the highest concentration offset of contiguous printable ASCII bytes
  let maxRunLength = 0;
  let maxRunStart = 0;
  let currentRunLength = 0;
  let currentRunStart = 0;

  for (let i = 0; i < len; i++) {
    const b = uint8Array[i];
    if (b >= 0x20 && b <= 0x7E) {
      if (currentRunLength === 0) {
        currentRunStart = i;
      }
      currentRunLength++;
    } else {
      if (currentRunLength > maxRunLength) {
        maxRunLength = currentRunLength;
        maxRunStart = currentRunStart;
      }
      currentRunLength = 0;
    }
  }
  if (currentRunLength > maxRunLength) {
    maxRunLength = currentRunLength;
    maxRunStart = currentRunStart;
  }

  let asciiDesc = '';
  if (maxRunLength >= 4) {
    let snippet = '';
    const snippetLen = Math.min(60, maxRunLength);
    for (let i = maxRunStart; i < maxRunStart + snippetLen; i++) {
      snippet += String.fromCharCode(uint8Array[i]);
    }
    if (maxRunLength > 60) {
      snippet += '...';
    }
    asciiDesc = `Highest concentration of contiguous printable ASCII bytes located at offset 0x${maxRunStart.toString(16).toUpperCase()} (${maxRunStart} B).\n\nRun Length: ${maxRunLength} contiguous characters.\nExtracted Segment: "${snippet}"\n\nThis indicates a static resource block containing printable text, function strings, metadata keys, or user-facing labels.`;
  } else {
    asciiDesc = `No substantial contiguous printable ASCII byte sequences (length >= 4) were detected. The binary appears to contain highly compressed or encrypted bytecode without readable static string blocks.`;
  }

  return {
    classification,
    headerDesc,
    maxRunStart,
    maxRunLength,
    asciiDesc
  };
}

/**
 * MainDisplay — Top-level standalone application hub for Sestina.
 * Split layout: left workspace (canvas + dropzone) / right control column (legend + output feed).
 */
export default function MainDisplay() {
  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const [fileData, setFileData] = useState(null);
  const [fileName, setFileName] = useState('');
  const [fileSize, setFileSize] = useState(0);
  const [hoverX, setHoverX] = useState(null);
  const [hoverY, setHoverY] = useState(null);
  const [presets, setPresets] = useState([]);
  const [loadingPresetId, setLoadingPresetId] = useState(null);
  const [activePresetStory, setActivePresetStory] = useState(null);
  const [activePresetId, setActivePresetId] = useState(null);
  const [currentTourStep, setCurrentTourStep] = useState(null);
  const [rowWidth, setRowWidth] = useState(256);
  const [hoverOffset, setHoverOffset] = useState(null);
  const [customWaypoints, setCustomWaypoints] = useState(null);
  const [outputLog, setOutputLog] = useState([
    { time: getTimestamp(), msg: 'SESTINA_OS v1.0 initialized' },
    { time: getTimestamp(), msg: 'Awaiting binary ingestion...' },
  ]);

  function getTimestamp() {
    const now = new Date();
    return now.toTimeString().split(' ')[0];
  }

  const addLog = useCallback((msg) => {
    setOutputLog((prev) => [
      ...prev.slice(-50), // Keep last 50 entries
      { time: getTimestamp(), msg },
    ]);
  }, []);

  // Fetch presets list from backend on mount
  useEffect(() => {
    fetch('http://localhost:3001/api/presets')
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load presets metadata');
        return res.json();
      })
      .then((data) => {
        setPresets(data);
        addLog('API: Loaded binary presets metadata');
      })
      .catch((err) => {
        console.error(err);
        addLog('ERROR: Could not connect to Presets backend API');
      });
  }, [addLog]);

  const loadPreset = useCallback(async (preset) => {
    setLoadingPresetId(preset.id);
    addLog(`STREAMING PRESET: Fetching ${preset.name}...`);
    try {
      const res = await fetch(`http://localhost:3001/api/presets/${preset.id}`);
      if (!res.ok) throw new Error('Preset stream failed');
      const arrayBuffer = await res.arrayBuffer();
      const uint8Array = new Uint8Array(arrayBuffer);

      setFileData(uint8Array);
      setFileName(preset.name);
      setFileSize(uint8Array.length);
      setActivePresetStory(preset.story);
      setActivePresetId(preset.id);
      setCustomWaypoints(null); // Clear custom waypoints
      setCurrentTourStep(0); // Start tour at step 0!

      addLog(`PRESET_LOADED: ${preset.name}`);
      addLog(`SIZE: ${uint8Array.length.toLocaleString()} bytes`);
      addLog('RENDERING pixel matrix...');
      addLog('CANVAS: dynamic projection active');
    } catch (err) {
      console.error(err);
      addLog(`ERROR: Failed streaming preset ${preset.id}`);
    } finally {
      setLoadingPresetId(null);
    }
  }, [addLog]);

  const handleFileLoad = useCallback((uint8Array, name, size) => {
    setFileData(uint8Array);
    setFileName(name);
    setFileSize(size);

    addLog(`FILE_LOADED: ${name}`);
    addLog(`SIZE: ${size.toLocaleString()} bytes`);
    addLog(`STREAM: Uint8Array[${uint8Array.length}]`);
    addLog('RENDERING pixel matrix...');
    addLog('CANVAS: dynamic projection active');

    // Run structural mapping utility
    addLog('ANALYSIS: Evaluating binary payload structure...');
    const analysisInfo = analyzeCustomFile(uint8Array, name);

    // Package coordinates into dynamic waypoints configuration
    const waypoints = [
      {
        offset: 0,
        desc: analysisInfo.headerDesc
      },
      {
        offset: analysisInfo.maxRunStart,
        desc: analysisInfo.asciiDesc
      }
    ];

    const customStory = {
      title: name,
      class: analysisInfo.classification,
      analysis: `Local ingestion of custom binary '${name}' complete. Structural analysis mapped 2 key coordinates of interest. Click playback steps to explore header and string parameters.`
    };

    setCustomWaypoints(waypoints);
    setActivePresetStory(customStory);
    setActivePresetId('custom');
    setCurrentTourStep(0); // Start custom tour at step 0!

    addLog(`ANALYSIS: Header detected: ${analysisInfo.classification}`);
    addLog(`ANALYSIS: Strings offset located at 0x${analysisInfo.maxRunStart.toString(16).toUpperCase()} (length: ${analysisInfo.maxRunLength})`);
    addLog('STATUS: SESTINA_OS_RUNNING');
  }, [addLog]);

  const handleCanvasHover = useCallback((x, y) => {
    setHoverX(x);
    setHoverY(y);
    if (x !== null && y !== null && fileData) {
      setHoverOffset(y * rowWidth + x);
    } else {
      setHoverOffset(null);
    }
  }, [fileData, rowWidth]);

  const handleHexEditorHover = useCallback((offset) => {
    setHoverOffset(offset);
    if (offset !== null && fileData) {
      const x = offset % rowWidth;
      const y = Math.floor(offset / rowWidth);
      setHoverX(x);
      setHoverY(y);
    } else {
      setHoverX(null);
      setHoverY(null);
    }
  }, [fileData, rowWidth]);

  // Compute active waypoints depending on whether it's custom or preset
  const activeWaypoints = useMemo(() => {
    if (activePresetId === 'custom') {
      return customWaypoints;
    }
    return activePresetId && TOUR_WAYPOINTS[activePresetId] ? TOUR_WAYPOINTS[activePresetId] : null;
  }, [activePresetId, customWaypoints]);

  // Synchronize tour step offset to hover states
  useEffect(() => {
    if (currentTourStep !== null && activeWaypoints && fileData) {
      const wp = activeWaypoints[currentTourStep];
      if (wp) {
        setHoverOffset(wp.offset);
        const x = wp.offset % rowWidth;
        const y = Math.floor(wp.offset / rowWidth);
        setHoverX(x);
        setHoverY(y);
      }
    }
  }, [currentTourStep, activeWaypoints, fileData, rowWidth]);

  // Generate dynamic modified story object with current tour waypoint descriptions
  const displayStory = useMemo(() => {
    if (!activePresetStory) return null;
    if (currentTourStep !== null && activeWaypoints && activeWaypoints[currentTourStep]) {
      const wp = activeWaypoints[currentTourStep];
      return {
        ...activePresetStory,
        analysis: `[GUIDED TOUR WAYPOINT - STEP ${currentTourStep + 1} / ${activeWaypoints.length}]\nOffset: 0x${wp.offset.toString(16).toUpperCase()} (${wp.offset} B)\n────────────────────────────────────────\n\n${wp.desc}`
      };
    }
    return activePresetStory;
  }, [activePresetStory, currentTourStep, activeWaypoints]);

  return (
    <div className="h-screen w-screen flex flex-col bg-sestina-bg font-mono text-sestina-text overflow-hidden">

      {/* ═══ Header Bar ═══ */}
      <header className="flex-shrink-0 flex items-center justify-between px-5 py-3 border-b border-sestina-border bg-sestina-surface/50">
        <div className="flex items-center gap-3">
          {/* Logo mark */}
          <div className="w-7 h-7 rounded border border-byte-ascii/30 flex items-center justify-center glow-gold">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <rect x="1" y="1" width="5" height="5" fill="#D97706" opacity="0.9" />
              <rect x="8" y="1" width="5" height="5" fill="#E5E5E5" opacity="0.7" />
              <rect x="1" y="8" width="5" height="5" fill="#DC2626" opacity="0.7" />
              <rect x="8" y="8" width="5" height="5" fill="#262626" stroke="#404040" strokeWidth="0.5" />
            </svg>
          </div>
          <div>
            <h1 className="text-sm font-semibold tracking-[0.25em] uppercase text-byte-ascii">
              Sestina
            </h1>
            <p className="text-[9px] text-sestina-text-dim tracking-[0.15em] uppercase -mt-0.5">
              Binary Pixel Visualizer
            </p>
          </div>
        </div>

        {/* Status indicator */}
        <div className="flex items-center gap-2">
          <div className={`status-dot ${fileData ? 'bg-byte-opcode' : 'bg-sestina-text-dim'}`} />
          <span className="text-[10px] text-sestina-text-dim tracking-[0.2em] uppercase">
            {fileData ? '// SESTINA_OS_RUNNING' : '// AWAITING INPUT'}
          </span>
        </div>
      </header>

      {/* ═══ Main Content ═══ */}
      <div className="flex-1 flex min-h-0">

        {/* ─── Left Panel: Workspace (75%) ─── */}
        <main className="flex-1 flex flex-col min-w-0 p-4 gap-3 overflow-y-auto">

          {/* Drop Zone or Canvas */}
          {!fileData ? (
            <div className="flex-1 flex items-center justify-center">
              <div className="w-full max-w-2xl">
                <DropZone onFileLoad={handleFileLoad} />
              </div>
            </div>
          ) : (
            <>
              {/* File info bar */}
              <div className="animate-fade-in flex items-center gap-3 px-4 py-3 rounded-lg bg-sestina-surface border border-sestina-border flex-shrink-0">
                <div className="status-dot bg-byte-opcode" />
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-byte-ascii truncate font-medium">
                    {fileName}
                  </p>
                  <p className="text-[10px] text-sestina-text-dim mt-0.5 tracking-wider uppercase">
                    {formatFileSize(fileSize)} &middot; {fileData.length.toLocaleString()} bytes loaded
                  </p>
                </div>
                <button
                  onClick={() => {
                    setFileData(null);
                    setFileName('');
                    setFileSize(0);
                    setHoverX(null);
                    setHoverY(null);
                    setActivePresetStory(null);
                    setActivePresetId(null);
                    setCustomWaypoints(null);
                    setCurrentTourStep(null);
                    addLog('STREAM: Binary unloaded');
                    addLog('STATUS: Awaiting new ingestion...');
                  }}
                  className="text-[10px] text-sestina-text-dim hover:text-byte-nop transition-colors uppercase tracking-widest px-2 py-1 rounded border border-sestina-border hover:border-byte-nop/30"
                  id="reload-binary-btn"
                >
                  Reload
                </button>
              </div>

              {/* Split view: Canvas (left) and HexEditor (right) */}
              <div className="flex-1 min-h-0 flex flex-col xl:flex-row gap-4">
                {/* Visualizer Canvas Column */}
                <div className="flex-1 min-h-0 flex flex-col gap-3">
                  {/* Canvas */}
                  <div className="flex-1 min-h-0 flex flex-col">
                    <SestinaCanvas 
                      data={fileData} 
                      onHover={handleCanvasHover} 
                      rowWidth={rowWidth}
                      hoverOffset={hoverOffset}
                      isTourActive={currentTourStep !== null}
                    />
                  </div>

                  {/* HUD Telemetry */}
                  <div className="flex-shrink-0">
                    <HUDTelemetry 
                      x={hoverX} 
                      y={hoverY} 
                      data={fileData} 
                      rowWidth={rowWidth}
                    />
                  </div>
                </div>

                {/* Classic Hex Dump Column */}
                <div className="w-full xl:w-[480px] h-[350px] xl:h-auto flex-shrink-0">
                  <HexEditor 
                    data={fileData} 
                    hoverOffset={hoverOffset}
                    onHoverOffset={handleHexEditorHover}
                  />
                </div>
              </div>

              {/* Security Story forensic panel */}
              {displayStory && (
                <div className="flex-shrink-0 mt-1">
                  <SecurityStory activePresetStory={displayStory} />
                </div>
              )}
            </>
          )}
        </main>

        {/* ─── Right Panel: Control Column (25%) ─── */}
        <aside className="w-72 flex-shrink-0 flex flex-col border-l border-sestina-border bg-sestina-surface/30 overflow-y-auto">

          {/* ── Binary Preset Laboratory ── */}
          <section className="p-4 border-b border-sestina-border" id="preset-lab">
            <h2 className="text-[10px] text-sestina-text-dim tracking-[0.25em] uppercase mb-3 font-medium">
              ▸ Binary Preset Laboratory
            </h2>
            <div className="space-y-2">
              {presets.length === 0 ? (
                <div className="text-[9px] text-sestina-text-dim italic">
                  Connecting to preset repository...
                </div>
              ) : (
                presets.map((preset) => {
                  const isLoading = loadingPresetId === preset.id;
                  const isActive = fileName === preset.name;
                  return (
                    <button
                      key={preset.id}
                      onClick={() => loadPreset(preset)}
                      disabled={loadingPresetId !== null}
                      className={`
                        w-full text-left p-2.5 rounded border transition-all duration-300
                        ${isActive
                          ? 'border-byte-ascii bg-byte-ascii/[0.04] glow-gold'
                          : 'border-sestina-border bg-sestina-bg/40 hover:bg-sestina-surface/60 hover:border-sestina-text-dim/30'
                        }
                        ${loadingPresetId !== null && !isLoading ? 'opacity-50' : ''}
                      `}
                    >
                      <div className="flex items-center justify-between">
                        <span className={`text-[10px] font-semibold tracking-wider ${
                          preset.type === 'ELF' ? 'text-byte-opcode' :
                          preset.type === 'APK' ? 'text-byte-ascii' :
                          'text-byte-nop'
                        }`}>
                          {preset.type}
                        </span>
                        {isLoading && (
                          <span className="text-[8px] text-byte-ascii animate-pulse">
                            STREAMING...
                          </span>
                        )}
                      </div>
                      <p className="text-[10px] text-sestina-text font-medium mt-1 leading-snug">
                        {preset.name.replace(`Preset 0x0${preset.type === 'ELF' ? '1' : preset.type === 'APK' ? '2' : '3'}: `, '')}
                      </p>
                      <p className="text-[9px] text-sestina-text-dim mt-1 leading-tight">
                        {preset.description}
                      </p>
                    </button>
                  );
                })
              )}
            </div>

            {/* Tour Playback HUD */}
            {currentTourStep !== null && activeWaypoints && (
              <div className="mt-3.5 p-3 border border-byte-ascii/30 bg-byte-ascii/[0.02] rounded-lg font-mono flex flex-col gap-2 shadow-[0_0_12px_rgba(217,119,6,0.05)]">
                <div className="flex justify-between items-center text-[9px] uppercase tracking-wider text-byte-ascii select-none font-bold">
                  <span>▸ Tour Playback HUD</span>
                  <span className="text-[8px] opacity-80">Step {currentTourStep + 1} of {activeWaypoints.length}</span>
                </div>
                
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setCurrentTourStep((prev) => Math.max(0, prev - 1));
                    }}
                    disabled={currentTourStep === 0}
                    className="flex-1 text-center py-1.5 rounded border border-sestina-border text-[9px] uppercase tracking-widest bg-neutral-950 hover:bg-neutral-900/60 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-150"
                  >
                    Back
                  </button>
                  <button
                    onClick={() => {
                      setCurrentTourStep((prev) => Math.min(activeWaypoints.length - 1, prev + 1));
                    }}
                    disabled={currentTourStep === activeWaypoints.length - 1}
                    className="flex-1 text-center py-1.5 rounded border border-byte-ascii text-byte-ascii bg-byte-ascii/[0.04] text-[9px] uppercase tracking-widest hover:bg-byte-ascii/[0.08] disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-150 glow-gold font-bold"
                  >
                    Next
                  </button>
                </div>
                <button
                  onClick={() => setCurrentTourStep(null)}
                  className="text-center text-[8px] text-sestina-text-dim hover:text-byte-nop transition-colors uppercase tracking-widest pt-1 border-t border-sestina-border/40 mt-1"
                >
                  Exit Tour
                </button>
              </div>
            )}
          </section>

          {/* ── Visualizer Settings ── */}
          <section className="p-4 border-b border-sestina-border" id="settings-config">
            <h2 className="text-[10px] text-sestina-text-dim tracking-[0.25em] uppercase mb-3 font-medium">
              ▸ Visualizer Settings
            </h2>
            <div className="space-y-3">
              {/* Stride Columns Width Slider */}
              <div className="flex flex-col gap-1.5">
                <div className="flex justify-between items-center text-[9px] uppercase tracking-wider text-sestina-text-dim select-none">
                  <span>Stride columns:</span>
                  <span className="text-byte-ascii font-bold">{rowWidth} columns</span>
                </div>
                <input
                  type="range"
                  min="16"
                  max="512"
                  step="1"
                  value={rowWidth}
                  onChange={(e) => {
                    const val = parseInt(e.target.value, 10);
                    setRowWidth(val);
                    // Reset hover coordinates during resizing
                    setHoverOffset(null);
                    setHoverX(null);
                    setHoverY(null);
                  }}
                  className="w-full h-1 bg-neutral-950 rounded-lg appearance-none cursor-pointer accent-byte-ascii border border-sestina-border/40"
                  id="stride-width-slider"
                />
              </div>
            </div>
          </section>

          {/* ── Color Legend ── */}
          <section className="p-4 border-b border-sestina-border" id="color-legend">
            <h2 className="text-[10px] text-sestina-text-dim tracking-[0.25em] uppercase mb-3 font-medium">
              ▸ Byte Classification Legend
            </h2>
            <div className="space-y-2.5">
              {LEGEND_ITEMS.map((item) => (
                <div
                  key={item.label}
                  className={`flex items-start gap-2.5 p-2 rounded border ${item.border} bg-sestina-bg/50`}
                >
                  <div
                    className="legend-swatch mt-0.5"
                    style={{ backgroundColor: item.color }}
                  />
                  <div className="min-w-0">
                    <span className="text-[10px] font-semibold tracking-[0.15em] uppercase block"
                      style={{ color: item.color === '#262626' ? '#737373' : item.color }}>
                      {item.label}
                    </span>
                    <span className="text-[9px] text-sestina-text-dim leading-tight block mt-0.5">
                      {item.desc}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* ── File Metadata ── */}
          {fileData && (
            <section className="p-4 border-b border-sestina-border animate-fade-in" id="file-metadata">
              <h2 className="text-[10px] text-sestina-text-dim tracking-[0.25em] uppercase mb-3 font-medium">
                ▸ Asset Metadata
              </h2>
              <div className="space-y-1.5">
                <MetaRow label="FILE" value={fileName} />
                <MetaRow label="SIZE" value={`${fileSize.toLocaleString()} bytes`} />
                <MetaRow label="ROWS" value={Math.ceil(fileData.length / rowWidth).toLocaleString()} />
                <MetaRow label="COLS" value={rowWidth.toString()} />
                <MetaRow label="FORMAT" value="Uint8Array" />
              </div>
            </section>
          )}

          {/* ── Execution Output Feed ── */}
          <section className="flex-1 flex flex-col p-4 min-h-0" id="output-feed">
            <h2 className="text-[10px] text-sestina-text-dim tracking-[0.25em] uppercase mb-3 font-medium flex-shrink-0">
              ▸ Execution Output
            </h2>
            <div className="output-feed flex-1 rounded-lg p-3 overflow-y-auto min-h-0">
              {outputLog.map((entry, i) => (
                <div key={i} className="output-feed-line flex gap-2">
                  <span className="text-[9px] text-sestina-text-dim/50 flex-shrink-0 w-16">
                    {entry.time}
                  </span>
                  <span className={`text-[10px] tracking-wider ${
                    entry.msg.includes('ERROR') ? 'text-red-400' :
                    entry.msg.includes('RUNNING') ? 'text-byte-opcode' :
                    entry.msg.includes('LOADED') || entry.msg.includes('active') ? 'text-byte-ascii' :
                    'text-sestina-text-dim'
                  }`}>
                    {entry.msg}
                  </span>
                </div>
              ))}
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}

/**
 * MetaRow — Small metadata label/value row for the sidebar.
 */
function MetaRow({ label, value }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[9px] text-sestina-text-dim tracking-[0.15em] uppercase w-12 flex-shrink-0">
        {label}
      </span>
      <span className="text-[10px] text-sestina-text tracking-wider truncate">
        {value}
      </span>
    </div>
  );
}
