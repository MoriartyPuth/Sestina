import React, { useMemo } from 'react';

/**
 * Helper to format offset as 8-character hex.
 */
function toHex8(value) {
  return '0x' + value.toString(16).toUpperCase().padStart(8, '0');
}

/**
 * StringsExtractor — Background parsing component for Sestina.
 * Scans binary data for sequences of 4 or more printable ASCII characters (0x20 to 0x7E)
 * and lists them in a dedicated scrollable viewport.
 *
 * @param {Uint8Array|null} data - Raw binary stream to parse
 */
export default function StringsExtractor({ data }) {
  const extractedStrings = useMemo(() => {
    if (!data || data.length === 0) return [];

    const list = [];
    let currentString = '';
    let startOffset = 0;

    // Scan the binary buffer
    for (let i = 0; i < data.length; i++) {
      const byteVal = data[i];

      // Printable ASCII range check
      if (byteVal >= 0x20 && byteVal <= 0x7E) {
        if (currentString === '') {
          startOffset = i;
        }
        currentString += String.fromCharCode(byteVal);
      } else {
        // End of sequence — check if it meets minimum length criteria
        if (currentString.length >= 4) {
          list.push({
            offset: startOffset,
            text: currentString,
          });
        }
        currentString = '';
      }
      
      // Safety limit to avoid performance lag with massive binaries
      if (list.length >= 800) {
        break;
      }
    }

    // Final check for trailing string at buffer boundaries
    if (currentString.length >= 4 && list.length < 800) {
      list.push({
        offset: startOffset,
        text: currentString,
      });
    }

    return list;
  }, [data]);

  if (!data) return null;

  return (
    <section className="flex flex-col p-4 border-b border-sestina-border bg-sestina-surface/20" id="strings-extractor">
      <h2 className="text-[10px] text-sestina-text-dim tracking-[0.25em] uppercase mb-3 font-medium">
        ▸ Extracted Strings Feed
      </h2>

      {/* Frame wrapper mimicking cyber console */}
      <div className="flex flex-col rounded-lg border border-sestina-border overflow-hidden bg-neutral-950/60">
        <div className="flex items-center justify-between px-3 py-1.5 bg-neutral-950/90 border-b border-sestina-border select-none">
          <span className="text-[9px] text-byte-ascii tracking-widest font-semibold animate-pulse">
            // EXTRACTED_STRINGS_FEED
          </span>
          <span className="text-[8px] text-sestina-text-dim">
            COUNT: {extractedStrings.length}
          </span>
        </div>

        {/* Scrollable list */}
        <div className="h-44 overflow-y-auto p-2 font-mono text-[9px] space-y-1.5">
          {extractedStrings.length === 0 ? (
            <div className="text-sestina-text-dim/60 italic text-center py-8">
              No printable ASCII strings identified (&gt;= 4 chars)
            </div>
          ) : (
            extractedStrings.map((str, idx) => (
              <div
                key={idx}
                className="flex items-start gap-2 hover:bg-byte-ascii/[0.04] p-1 rounded transition-colors group select-text selection:bg-byte-ascii selection:text-black"
              >
                {/* Hex Address */}
                <span className="text-byte-ascii/60 flex-shrink-0 group-hover:text-byte-ascii transition-colors font-medium">
                  {toHex8(str.offset)}
                </span>
                {/* Printable string text */}
                <span className="text-sestina-text break-all">
                  {str.text}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </section>
  );
}
