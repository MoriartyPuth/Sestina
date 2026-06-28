import { useState, useRef, useCallback } from 'react';

/**
 * DropZone — Asynchronous file ingestion hub for Sestina.
 * Accepts drag-and-drop binary files (ELF, EXE, APK, bytecode, etc.)
 * and converts them to a raw Uint8Array data stream.
 *
 * @param {Function} onFileLoad - Callback: (uint8Array, fileName, fileSize) => void
 */
export default function DropZone({ onFileLoad }) {
  const [isDragActive, setIsDragActive] = useState(false);
  const [loadedFile, setLoadedFile] = useState(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const fileInputRef = useRef(null);

  const processFile = useCallback((file) => {
    setIsProcessing(true);
    const reader = new FileReader();

    reader.onload = (event) => {
      const arrayBuffer = event.target.result;
      const uint8Array = new Uint8Array(arrayBuffer);

      setLoadedFile({
        name: file.name,
        size: file.size,
        bytes: uint8Array.length,
      });
      setIsProcessing(false);
      onFileLoad(uint8Array, file.name, file.size);
    };

    reader.onerror = () => {
      setIsProcessing(false);
      console.error('[SESTINA] FileReader error:', reader.error);
    };

    reader.readAsArrayBuffer(file);
  }, [onFileLoad]);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      processFile(files[0]);
    }
  }, [processFile]);

  const handleClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const handleFileInput = useCallback((e) => {
    const files = e.target.files;
    if (files.length > 0) {
      processFile(files[0]);
    }
  }, [processFile]);

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  // Post-load: show file metadata summary
  if (loadedFile) {
    return (
      <div className="animate-fade-in flex items-center gap-3 px-4 py-3 rounded-lg bg-sestina-surface border border-sestina-border">
        <div className="status-dot bg-byte-opcode" />
        <div className="flex-1 min-w-0">
          <p className="text-xs text-byte-ascii truncate font-medium">
            {loadedFile.name}
          </p>
          <p className="text-[10px] text-sestina-text-dim mt-0.5 tracking-wider uppercase">
            {formatFileSize(loadedFile.size)} &middot; {loadedFile.bytes.toLocaleString()} bytes loaded
          </p>
        </div>
        <button
          onClick={() => {
            setLoadedFile(null);
            if (fileInputRef.current) fileInputRef.current.value = '';
          }}
          className="text-[10px] text-sestina-text-dim hover:text-byte-nop transition-colors uppercase tracking-widest px-2 py-1 rounded border border-sestina-border hover:border-byte-nop/30"
          id="reload-binary-btn"
        >
          Reload
        </button>
      </div>
    );
  }

  return (
    <div
      id="dropzone"
      className={`
        dropzone-border rounded-xl cursor-pointer
        flex flex-col items-center justify-center
        min-h-[280px] p-8
        transition-all duration-300
        relative overflow-hidden
        ${isDragActive ? 'drag-active bg-byte-ascii/[0.03]' : 'bg-sestina-surface/50 hover:bg-sestina-surface/80'}
      `}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={handleClick}
    >
      {/* Scanline overlay */}
      <div className="scanline-overlay" />

      {/* Upload icon */}
      <div className={`mb-5 transition-transform duration-300 ${isDragActive ? 'scale-110' : ''}`}>
        <svg
          width="48"
          height="48"
          viewBox="0 0 48 48"
          fill="none"
          className={`transition-colors duration-300 ${isDragActive ? 'text-byte-ascii' : 'text-sestina-text-dim'}`}
        >
          <rect x="6" y="6" width="36" height="36" rx="4" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 3" />
          <path d="M24 16V32M16 24H32" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          <circle cx="14" cy="14" r="2" fill="currentColor" opacity="0.3" />
          <circle cx="34" cy="14" r="2" fill="currentColor" opacity="0.3" />
          <circle cx="14" cy="34" r="2" fill="currentColor" opacity="0.3" />
          <circle cx="34" cy="34" r="2" fill="currentColor" opacity="0.3" />
        </svg>
      </div>

      {/* Text */}
      {isProcessing ? (
        <div className="text-center animate-data-stream">
          <p className="text-xs text-byte-ascii tracking-[0.2em] uppercase font-medium">
            // INGESTING BINARY STREAM
          </p>
          <p className="text-[10px] text-sestina-text-dim mt-2 tracking-wider">
            Parsing ArrayBuffer → Uint8Array...
          </p>
        </div>
      ) : (
        <div className="text-center">
          <p className="text-xs text-sestina-text tracking-[0.15em] uppercase font-medium">
            {isDragActive ? '[ DROP TO INGEST ]' : 'Drop compiled binary'}
          </p>
          <p className="text-[10px] text-sestina-text-dim mt-2 tracking-wider uppercase">
            ELF &middot; EXE &middot; APK &middot; Mach-O &middot; Raw Bytecode
          </p>
          <p className="text-[10px] text-sestina-text-dim/50 mt-3 tracking-wider">
            or click to browse
          </p>
        </div>
      )}

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        className="hidden"
        onChange={handleFileInput}
        id="file-input"
      />
    </div>
  );
}
