import React, { useState } from 'react';

/**
 * SecurityStory — Automated forensic analysis panel for Sestina.
 * Designed to mirror a high-clearance cyberpunk HUD terminal.
 *
 * @param {Object} activePresetStory - The story object containing:
 *   - {string} title - Payload identifier
 *   - {string} class - Malware/file class classification
 *   - {string} analysis - Deep behavior forensic narrative
 */
export default function SecurityStory({ activePresetStory }) {
  const [isOpen, setIsOpen] = useState(true);

  if (!activePresetStory) return null;

  const { title, class: classification, analysis } = activePresetStory;

  return (
    <div className="bg-neutral-900/40 border border-emerald-500/20 rounded-lg p-4 font-mono w-full animate-fade-in shadow-lg backdrop-blur-sm">
      {/* HUD Header */}
      <div className="flex items-center justify-between border-b border-emerald-500/10 pb-2 mb-1">
        <div className="flex items-center gap-2 cursor-pointer select-none" onClick={() => setIsOpen(!isOpen)}>
          <span className="relative flex h-2 w-2">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75 ${!isOpen ? 'hidden' : ''}`}></span>
            <span className={`relative inline-flex rounded-full h-2 w-2 ${isOpen ? 'bg-emerald-500' : 'bg-emerald-500/50'}`}></span>
          </span>
          <span className="text-[10px] text-emerald-400 tracking-[0.2em] font-bold">
            // METADATA_FORENSIC_ANALYSIS
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[9px] text-emerald-500/40 uppercase tracking-widest hidden sm:inline">
            SECURE_NODE_OK
          </span>
          <button
            onClick={() => setIsOpen(!isOpen)}
            className="text-[9px] text-emerald-400 hover:text-emerald-300 font-bold tracking-widest px-2 py-0.5 rounded border border-emerald-500/30 hover:border-emerald-400 bg-emerald-950/30 hover:bg-emerald-950/80 transition-all duration-200"
            id="toggle-forensic-panel-btn"
          >
            {isOpen ? '[ CLOSE ]' : '[ OPEN ]'}
          </button>
        </div>
      </div>

      {/* Collapsible Content */}
      {isOpen && (
        <div className="animate-fade-in mt-3">
          {/* Metadata Classification Parameters */}
          <div className="space-y-1.5 mb-4 text-[10px]">
            <div className="flex justify-between py-0.5 border-b border-neutral-800/40">
              <span className="text-emerald-500/70 uppercase tracking-wider">IDENTIFIER:</span>
              <span className="text-emerald-300 font-medium truncate max-w-[180px]">{title}</span>
            </div>
            <div className="flex justify-between py-0.5 border-b border-neutral-800/40">
              <span className="text-emerald-500/70 uppercase tracking-wider">CLASSIFICATION:</span>
              <span className="text-emerald-400 font-semibold uppercase">{classification}</span>
            </div>
            <div className="flex justify-between py-0.5 border-b border-neutral-800/40">
              <span className="text-emerald-500/70 uppercase tracking-wider">INTEL_FEED:</span>
              <span className="text-neutral-400">AUTOMATED_SANDBOX_STORY</span>
            </div>
          </div>

          {/* Shell Narrative Container */}
          <div className="relative bg-neutral-950/80 border border-neutral-800 rounded p-3 text-[11px] leading-relaxed text-emerald-400/90 overflow-hidden">
            {/* Terminal Header Info */}
            <div className="text-[9px] text-emerald-500/40 mb-2 border-b border-neutral-900 pb-1 select-none">
              SECURE_SHELL_DECRYPTION_ACTIVE
            </div>

            {/* Narrative Box with high-visibility selection colors */}
            <div className="selection:bg-emerald-500 selection:text-black">
              <span>{analysis}</span>
              <span className="inline-block w-1.5 h-3 ml-1 bg-emerald-400 animate-pulse select-none align-middle" title="cursor">&gt;</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
