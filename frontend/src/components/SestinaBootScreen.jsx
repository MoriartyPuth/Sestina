import { useState, useEffect } from 'react';

const BOOT_LOGS = [
  { text: "SESTINA(TM) SECURE BOOT ENGINE v1.0.4", type: "system" },
  { text: "--------------------------------------------------", type: "divider" },
  { text: "[+] ALLOCATING CORE MEMORY BUFFER [16384 KB] ... OK", type: "info" },
  { text: "[+] ATTACHING PIXEL SCAN MATRIX ENGINE ... OK", type: "info" },
  { text: "[+] ATTACHING HUD SCANLINE TELEMETRY NODE ... OK", type: "info" },
  { text: "[+] PARSING 112-BYTE TARGET STACK MAP STRUCTURES ... OK", type: "info" },
  { text: "[+] SECURE BAKONG API HANDSHAKE ... ESTABLISHED (200 OK)", type: "success" },
  { text: "[!] BROKEN ACCESS CONTROL SCANNING ... ZERO FAULTS DETECTED", type: "warning" },
  { text: "[+] CACHING PRESETS: ELF (MIRAI), APK (MOBILE), VM (CUSTOM) ... COMPLETED", type: "info" },
  { text: "[+] SANDBOX ENVIRONMENT INTEGRITY VERIFIED ... PASS", type: "success" },
  { text: "[*] INITIALIZING SESTINA GRAPHICS USER TERMINAL ...", type: "system" }
];

/**
 * SestinaBootScreen — A simulated cyberpunk terminal boot sequence.
 * Renders progressive diagnostic logs with realistic delays and finishes with a smooth fade-out.
 */
export default function SestinaBootScreen({ onBootComplete }) {
  const [visibleLines, setVisibleLines] = useState([]);
  const [isFading, setIsFading] = useState(false);

  useEffect(() => {
    const timers = [];

    // Variable timing delays for each boot line to simulate actual loading operations
    const delays = [0, 150, 300, 450, 600, 750, 950, 1200, 1400, 1600, 1800];

    BOOT_LOGS.forEach((log, index) => {
      const timer = setTimeout(() => {
        setVisibleLines((prev) => [...prev, log]);
      }, delays[index]);
      timers.push(timer);
    });

    // Start fade-out after all logs finish printing (approx 2.1 seconds)
    const fadeTimer = setTimeout(() => {
      setIsFading(true);
    }, 2100);
    timers.push(fadeTimer);

    // Unmount and notify parent on transition complete (2.5 seconds total)
    const completeTimer = setTimeout(() => {
      onBootComplete();
    }, 2500);
    timers.push(completeTimer);

    return () => {
      timers.forEach(clearTimeout);
    };
  }, [onBootComplete]);

  return (
    <div
      className={`fixed inset-0 bg-black z-[9999] flex flex-col p-8 font-mono select-none transition-opacity duration-[400ms] ease-out ${
        isFading ? 'opacity-0' : 'opacity-100'
      }`}
      id="boot-screen-overlay"
    >
      {/* CRT Scanline Visual Effects */}
      <div className="absolute inset-0 pointer-events-none bg-repeating-linear-gradient opacity-10 z-10" />
      <div className="absolute top-0 left-0 right-0 h-1 bg-amber-500/10 animate-scanline z-10" />

      {/* Terminal log lines */}
      <div className="flex-1 flex flex-col justify-start text-[11px] sm:text-xs text-neutral-400 leading-relaxed max-w-3xl mx-auto w-full pt-16">
        <div className="space-y-1">
          {visibleLines.map((line, idx) => (
            <div key={idx} className="flex items-start">
              <span className="mr-2.5 text-amber-700/60 select-none">$&gt;</span>
              <span
                className={
                  line.type === 'success' ? 'text-amber-500 font-semibold' :
                  line.type === 'warning' ? 'text-red-500 font-semibold' :
                  line.type === 'system' ? 'text-neutral-200 font-bold' :
                  'text-neutral-400'
                }
              >
                {line.text}
              </span>
            </div>
          ))}

          {/* Active Blinking Cursor */}
          <div className="flex items-center">
            <span className="mr-2.5 text-amber-700/60 select-none">$&gt;</span>
            <span className="inline-block w-1.5 h-3.5 bg-amber-600 animate-pulse align-middle" />
          </div>
        </div>
      </div>

      {/* Cybersecurity telemetry footer details */}
      <div className="mt-auto flex justify-between text-[9px] text-neutral-600 max-w-3xl mx-auto w-full border-t border-neutral-900 pt-4 font-mono select-none">
        <span>SECURITY_CLEARANCE: CLASS_B</span>
        <span>OS_STATUS: SYS_INITIALIZATION</span>
      </div>
    </div>
  );
}
