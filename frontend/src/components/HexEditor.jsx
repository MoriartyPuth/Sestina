import React, { useEffect, useRef, useMemo, useState, useCallback } from 'react';

/**
 * Helper to format offset as 8-character hex.
 */
function toHex8(value) {
  return value.toString(16).toUpperCase().padStart(8, '0');
}

/**
 * Helper to format byte as 2-character hex.
 */
function toHex2(value) {
  return value.toString(16).toUpperCase().padStart(2, '0');
}

/**
 * Get color class for a byte value matching the legend.
 */
function getByteColorClass(val, isActive) {
  if (isActive) {
    if (val === 0x00) return 'bg-neutral-800 text-neutral-200 font-bold';
    if (val >= 0x20 && val <= 0x7E) return 'bg-amber-600 text-black font-black';
    if (val === 0xFF || val === 0x90) return 'bg-red-600 text-white font-black';
    return 'bg-neutral-200 text-black font-black';
  }
  
  if (val === 0x00) return 'text-neutral-700 font-normal';
  if (val >= 0x20 && val <= 0x7E) return 'text-amber-500 font-medium';
  if (val === 0xFF || val === 0x90) return 'text-red-500 font-medium';
  return 'text-neutral-300 font-normal';
}

/**
 * HexRow — Memoized single row of the hex editor.
 * Only re-renders if the row data changes or its active byte state changes.
 */
const HexRow = React.memo(({ startIndex, bytes, rowIndex, activeByteIndex, onHoverOffset }) => {
  const isRowHighlighted = activeByteIndex !== null;
  
  return (
    <div
      data-row-index={rowIndex}
      className={`flex items-center h-[22px] rounded transition-colors duration-150 ${
        isRowHighlighted ? 'bg-sestina-border/10 border-l border-byte-ascii/30' : 'hover:bg-neutral-900/20'
      }`}
    >
      {/* Address */}
      <span className={`w-16 flex-shrink-0 text-slate-500 tracking-wider select-none ${isRowHighlighted ? 'text-byte-ascii/70' : ''}`}>
        {toHex8(startIndex)}
      </span>

      {/* 16 Hex Bytes */}
      <div className="flex-1 flex justify-around pl-1 max-w-[280px] select-text">
        {Array.from({ length: 16 }).map((_, bIdx) => {
          const hasByte = bIdx < bytes.length;
          if (!hasByte) {
            return <span key={bIdx} className="w-5 text-center text-slate-800 select-none">--</span>;
          }
          
          const val = bytes[bIdx];
          const byteOffset = startIndex + bIdx;
          const isByteActive = activeByteIndex === bIdx;
          
          return (
            <span
              key={bIdx}
              onMouseEnter={() => onHoverOffset?.(byteOffset)}
              onMouseLeave={() => onHoverOffset?.(null)}
              className={`w-5 text-center cursor-crosshair rounded-[2px] transition-all duration-100 ${getByteColorClass(val, isByteActive)}`}
            >
              {toHex2(val)}
            </span>
          );
        })}
      </div>

      {/* ASCII Translations */}
      <div className="w-24 flex-shrink-0 text-right font-mono text-[9px] tracking-wider select-text flex justify-end gap-[1px]">
        <span className="text-slate-600 mr-1 select-none">|</span>
        {Array.from({ length: 16 }).map((_, bIdx) => {
          const hasByte = bIdx < bytes.length;
          if (!hasByte) return <span key={bIdx} className="text-slate-800">.</span>;
          
          const val = bytes[bIdx];
          const byteOffset = startIndex + bIdx;
          const isByteActive = activeByteIndex === bIdx;
          const isPrintable = val >= 0x20 && val <= 0x7E;
          const char = isPrintable ? String.fromCharCode(val) : '.';
          
          return (
            <span
              key={bIdx}
              onMouseEnter={() => onHoverOffset?.(byteOffset)}
              onMouseLeave={() => onHoverOffset?.(null)}
              className={`cursor-crosshair rounded-[2px] w-[5.5px] text-center inline-block ${
                isByteActive ? 'bg-amber-600 text-black font-black' : isPrintable ? 'text-amber-500/80 hover:text-amber-400' : 'text-neutral-700'
              }`}
            >
              {char}
            </span>
          );
        })}
        <span className="text-slate-600 ml-1 select-none">|</span>
      </div>
    </div>
  );
}, (prevProps, nextProps) => {
  return prevProps.startIndex === nextProps.startIndex &&
         prevProps.bytes === nextProps.bytes &&
         prevProps.rowIndex === nextProps.rowIndex &&
         prevProps.activeByteIndex === nextProps.activeByteIndex;
});

export default function HexEditor({ data, hoverOffset, onHoverOffset }) {
  const containerRef = useRef(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(400); // default height approximation

  // Group data into 16-byte rows
  const rows = useMemo(() => {
    if (!data || data.length === 0) return [];
    
    const result = [];
    const len = data.length;
    for (let i = 0; i < len; i += 16) {
      const chunk = data.slice(i, i + 16);
      result.push({
        startIndex: i,
        bytes: chunk
      });
    }
    return result;
  }, [data]);

  // Track container height dynamically using ResizeObserver
  useEffect(() => {
    if (containerRef.current) {
      setContainerHeight(containerRef.current.clientHeight);
      
      const observer = new ResizeObserver((entries) => {
        for (let entry of entries) {
          setContainerHeight(entry.contentRect.height);
        }
      });
      observer.observe(containerRef.current);
      return () => observer.disconnect();
    }
  }, []);

  const handleScroll = useCallback((e) => {
    setScrollTop(e.target.scrollTop);
  }, []);

  const rowHeight = 22;
  const totalRows = rows.length;
  const totalHeight = totalRows * rowHeight;

  // Render a slice of the rows with scroll margins
  const startRowIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - 5);
  const endRowIdx = Math.min(totalRows, Math.ceil((scrollTop + containerHeight) / rowHeight) + 5);

  const visibleRows = useMemo(() => {
    return rows.slice(startRowIdx, endRowIdx).map((row, idx) => {
      const actualRowIdx = startRowIdx + idx;
      return {
        ...row,
        rowIndex: actualRowIdx,
        top: actualRowIdx * rowHeight
      };
    });
  }, [rows, startRowIdx, endRowIdx]);

  // Handle automatic scrolling when hoverOffset changes
  useEffect(() => {
    if (hoverOffset === null || !containerRef.current) return;

    const rowIndex = Math.floor(hoverOffset / 16);
    const container = containerRef.current;
    
    const targetScrollTop = rowIndex * rowHeight - container.clientHeight / 2 + rowHeight / 2;
    const currentScrollTop = container.scrollTop;
    
    if (Math.abs(currentScrollTop - targetScrollTop) > 10) {
      container.scrollTo({
        top: targetScrollTop,
        behavior: 'smooth'
      });
    }
  }, [hoverOffset]);

  if (!data || data.length === 0) return null;

  // Pre-calculate active coordinates to pass only needed states to memoized HexRows
  const activeRowIndex = hoverOffset !== null ? Math.floor(hoverOffset / 16) : null;
  const activeByteIndex = hoverOffset !== null ? hoverOffset % 16 : null;

  return (
    <section className="flex flex-col h-full border border-sestina-border bg-sestina-surface/20 rounded-lg overflow-hidden font-mono" id="hex-editor">
      {/* Editor Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-sestina-border bg-neutral-950/80 select-none flex-shrink-0">
        <span className="text-[10px] text-byte-ascii tracking-widest font-bold animate-pulse">
          // MEMORY_HEX_VIEWPORT
        </span>
        <span className="text-[8px] text-sestina-text-dim uppercase tracking-wider">
          Stride: 16-byte aligned
        </span>
      </div>

      {/* Hex grid column headers */}
      <div className="flex px-3 py-1 bg-neutral-950/40 border-b border-sestina-border/30 text-[9px] text-sestina-text-dim tracking-wider font-bold select-none flex-shrink-0">
        <span className="w-16">ADDRESS</span>
        <div className="flex-1 flex justify-around pl-1 max-w-[280px]">
          <span>00</span><span>01</span><span>02</span><span>03</span>
          <span>04</span><span>05</span><span>06</span><span>07</span>
          <span className="text-slate-500">|</span>
          <span>08</span><span>09</span><span>0A</span><span>0B</span>
          <span>0C</span><span>0D</span><span>0E</span><span>0F</span>
        </div>
        <span className="w-24 text-right">ASCII_TEXT</span>
      </div>

      {/* Scrollable Hex Dump View */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto p-3 text-[10px] leading-relaxed relative bg-neutral-950/40 select-text"
      >
        <div style={{ height: `${totalHeight}px`, position: 'relative', width: '100%' }}>
          {visibleRows.map((row) => {
            const isRowHighlighted = row.rowIndex === activeRowIndex;
            const byteIndexInRow = isRowHighlighted ? activeByteIndex : null;
            
            return (
              <div
                key={row.startIndex}
                style={{
                  position: 'absolute',
                  top: `${row.top}px`,
                  left: 0,
                  right: 0,
                  height: `${rowHeight}px`
                }}
              >
                <HexRow
                  startIndex={row.startIndex}
                  bytes={row.bytes}
                  rowIndex={row.rowIndex}
                  activeByteIndex={byteIndexInRow}
                  onHoverOffset={onHoverOffset}
                />
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
