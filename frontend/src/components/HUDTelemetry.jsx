/**
 * HUDTelemetry — Reverse-coordinate tracking readout for Sestina.
 * Tracks mouse position on the canvas and reverse-maps (X, Y) back to
 * the Uint8Array byte offset: offset = Y × 256 + X.
 *
 * @param {number|null} x - Canvas X coordinate (0-255)
 * @param {number|null} y - Canvas Y coordinate
 * @param {Uint8Array|null} data - Full binary data array
 */

const ROW_WIDTH = 256;

/**
 * Format a number as an 8-char uppercase hex string.
 * e.g., 1000354 → "0x000F41A2"
 */
function toHex8(value) {
  return '0x' + value.toString(16).toUpperCase().padStart(8, '0');
}

/**
 * Format a byte value as a 2-char hex string.
 * e.g., 77 → "0x4D"
 */
function toHex2(value) {
  return '0x' + value.toString(16).toUpperCase().padStart(2, '0');
}

/**
 * Get the color class for a byte value based on Sestina's mapping rules.
 */
function getByteColorClass(byteVal) {
  if (byteVal === 0x00) return 'text-neutral-700';
  if (byteVal >= 0x20 && byteVal <= 0x7E) return 'text-byte-ascii';
  if (byteVal === 0xFF || byteVal === 0x90) return 'text-byte-nop';
  return 'text-byte-opcode';
}

/**
 * Get the byte type label for display.
 */
function getByteTypeLabel(byteVal) {
  if (byteVal === 0x00) return 'NULL_PAD';
  if (byteVal >= 0x20 && byteVal <= 0x7E) return 'ASCII_RD';
  if (byteVal === 0xFF || byteVal === 0x90) return 'NOP_BRK';
  return 'OPCODE';
}

export default function HUDTelemetry({ x, y, data, rowWidth = 256 }) {
  const isTracking = x !== null && y !== null && data;

  if (!isTracking) {
    return (
      <div className="telemetry-block rounded-lg px-4 py-3" id="hud-telemetry">
        <div className="flex items-center gap-2">
          <div className="status-dot bg-sestina-text-dim" />
          <span className="text-[10px] text-sestina-text-dim tracking-[0.2em] uppercase animate-data-stream">
            [ DATA STREAM IDLE // TRACKING OFFLINE ]
          </span>
        </div>
      </div>
    );
  }

  const offset = y * rowWidth + x;
  const byteVal = data[offset];
  const byteColorClass = getByteColorClass(byteVal);
  const byteType = getByteTypeLabel(byteVal);

  // Try to read the printable ASCII character
  const asciiChar = byteVal >= 0x20 && byteVal <= 0x7E
    ? String.fromCharCode(byteVal)
    : '·';

  return (
    <div className="telemetry-block rounded-lg px-4 py-3" id="hud-telemetry">
      {/* Status header */}
      <div className="flex items-center gap-2 mb-3">
        <div className="status-dot bg-byte-ascii" />
        <span className="text-[10px] text-byte-ascii tracking-[0.2em] uppercase font-medium">
          // TRACKING LIVE
        </span>
      </div>

      {/* Telemetry grid */}
      <div className="grid grid-cols-2 gap-x-6 gap-y-2">
        {/* MEM_OFFSET */}
        <div>
          <span className="text-[9px] text-sestina-text-dim tracking-[0.15em] uppercase block mb-0.5">
            MEM_OFFSET
          </span>
          <span className="text-sm text-byte-ascii font-semibold tracking-wider">
            {toHex8(offset)}
          </span>
        </div>

        {/* COORD */}
        <div>
          <span className="text-[9px] text-sestina-text-dim tracking-[0.15em] uppercase block mb-0.5">
            COORD
          </span>
          <span className="text-sm text-sestina-text font-medium tracking-wider">
            ({x}, {y})
          </span>
        </div>

        {/* RAW_HEX */}
        <div>
          <span className="text-[9px] text-sestina-text-dim tracking-[0.15em] uppercase block mb-0.5">
            RAW_HEX
          </span>
          <span className={`text-sm font-semibold tracking-wider ${byteColorClass}`}>
            {toHex2(byteVal)}
          </span>
        </div>

        {/* DEC_VALUE */}
        <div>
          <span className="text-[9px] text-sestina-text-dim tracking-[0.15em] uppercase block mb-0.5">
            DEC_VALUE
          </span>
          <span className="text-sm text-sestina-text font-medium tracking-wider">
            {byteVal}
          </span>
        </div>

        {/* BYTE_TYPE */}
        <div>
          <span className="text-[9px] text-sestina-text-dim tracking-[0.15em] uppercase block mb-0.5">
            BYTE_TYPE
          </span>
          <span className={`text-[10px] font-medium tracking-[0.15em] uppercase ${byteColorClass}`}>
            {byteType}
          </span>
        </div>

        {/* ASCII_CHAR */}
        <div>
          <span className="text-[9px] text-sestina-text-dim tracking-[0.15em] uppercase block mb-0.5">
            ASCII_CHAR
          </span>
          <span className="text-sm text-sestina-text font-medium">
            '{asciiChar}'
          </span>
        </div>
      </div>
    </div>
  );
}
