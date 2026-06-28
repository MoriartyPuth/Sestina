# Sestina — Binary Pixel Visualizer

Sestina is a refined, low-emissive cyberpunk-themed binary visualization platform styled in the **Nocturne Dusk** theme. It translates compiled files and raw binary payloads (such as ELF binaries, APK archives, and custom VM bytecode) into structural coordinate matrices. 

By mapping raw byte streams to visual coordinate pixels, Sestina allows reverse engineers and security analysts to inspect structural layout patterns, highlight human-readable string sections, locate NOP sleds, and measure local byte entropy distributions in real-time.

---

## 🌌 What it is Used For

* **Visual Structural Profiling**: Instantly isolate binary headers, `.text` code sections, `.rodata` read-only tables, and data sections based on color-coded byte classes.
* **Malware & Packer Detection**: Locate UPX headers, structural anomalies, and high-density packed/encrypted segments using the integrated dynamic sliding entropy heatmap.
* **ASCII String Extraction**: Highlight readable metadata keys, default scanner credentials, and C2 URLs using high-contrast highlight offsets.
* **Forensic Auditing**: Audit binaries for Broken Access Control logic, 112-byte stack maps, and simulated hypervisor layouts.

---

## ⚡ Key Features

1. **Simulated Terminal Boot Screen (`SestinaBootScreen`)**:
   An animated diagnostic splash screen executing progressive startup checks (memory mapping, Bakong API handshakes, and access control scans) before mounting the main workspace.
2. **Byte-to-Pixel Classification Engine**:
   Maps the raw file buffer to color-coded matrices:
   * **NULL_PAD (`0x00`)**: Quiet, slate gray (`#262626`) representing empty space.
   * **OPCODE (Default)**: Titanium white (`#E5E5E5`) representing compiled instruction flow.
   * **ASCII_RD (`0x20-0x7E`)**: Deep amber/gold (`#D97706`) highlighting human-readable strings.
   * **NOP_BRK (`0xFF`/`0x90`)**: Crimson red (`#DC2626`) mapping breakpoints and NOP sled padding.
3. **Optimized $O(N)$ Entropy Heatmap**:
   A highly efficient sliding window calculator using precomputed lookup tables to calculate local information entropy. It identifies encryption boundaries instantly without main-thread UI lag.
4. **Interactive Loupe Magnifier**:
   A hovering reticle loupe that projects a magnified grid of hex byte definitions as you scroll the visualizer.
5. **Classic Hex Dump Viewport**:
   A virtualized scroll-synchronized hex viewer displaying side-by-side memory addresses, raw byte cells, and ASCII character conversions.

---

## 🚀 Running Sestina Locally

Sestina is split into a static React + Vite **frontend** and a Node.js Express **backend**.

### Prerequisites
Make sure you have [Node.js](https://nodejs.org/) installed.

### Step 1: Run the Backend
The backend serves preset metadata lists and streams binary file variants.

```bash
cd backend
npm install
npm run dev
```
*The backend Express server will run on `http://localhost:3001`.*

### Step 2: Run the Frontend
The frontend performs all canvas rendering and coordinate calculations.

```bash
cd ../frontend
npm install
npm run dev
```
*The frontend development server will launch on `http://localhost:5173`.*

---

## 🛡️ How to Use

1. **Select a Preset or Ingest Custom Payload**:
   * Use the **Binary Preset Laboratory** in the right sidebar to stream preconfigured files (e.g., the Mirai ELF variant or Dalvik classes.dex APK).
   * Or drag-and-drop your own raw compiled binaries directly into the visual **Ingestion Dropzone**.
2. **Explore Coordinates**:
   * Hover over the visual matrix canvas to track precise `MEM_OFFSET` coordinates and values in the live **HUD Telemetry** box.
   * Click on guided tour playback buttons to scroll directly to points of interest (e.g., C2 domains, headers, NOP slides).
3. **Toggle Visual Modes**:
   * Switch to **Byte Type** to audit class segments.
   * Switch to **Entropy Heatmap** to visualize sections of high complexity (e.g., packed segments).