# PhantomTrace — Enterprise Memory & Fileless Threat Detection

> *"Trace what others can't see."*

[![Production Frontend](https://img.shields.io/badge/Frontend-Vercel%20Production-00e5ff?style=flat-square)](https://phantom-trace-web.vercel.app/)
[![Production Backend](https://img.shields.io/badge/Backend-Render%20API-46e3b7?style=flat-square)](https://phantomtrace-web.onrender.com/api/health)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%20%2F%20Supabase-38bdf8?style=flat-square)](https://supabase.com/)
[![Windows Scanner](https://img.shields.io/badge/Scanner-Windows%20Release%201.0-818cf8?style=flat-square)](https://github.com/JaydeepChawla/PhantomTrace-Web/releases)
[![Operation Mode](https://img.shields.io/badge/Mode-100%25%20Read--Only-10b981?style=flat-square)](https://phantom-trace-web.vercel.app/#download)

PhantomTrace is an enterprise memory and fileless threat detection platform. The web console connects to the read-only Windows detection engine (`PhantomTrace_Windows_Release_1.0.exe`) to provide security operations center (SOC) analysts with telemetry triage, memory region analysis, process tree visualization, and threat alert investigation.

---

## Production Deployment Topology

```
┌────────────────────────────────────────────────────────┐
│               Windows Endpoint (Host PC)               │
│                                                        │
│  [ PhantomTrace_Windows_Release_1.0.exe ]              │
│       │  (100% Read-Only Memory & Behavior Scan)       │
│       v                                                │
│  [ scan_results.json ]                                 │
│       │                                                │
│       v  python scripts/upload_scan.py                 │
│          (HTTPS POST /api/scans/ingest + Bearer Token) │
└───────────────────────┬────────────────────────────────┘
                        │
                        v
┌────────────────────────────────────────────────────────┐
│            Render Production Backend API               │
│       https://phantomtrace-web.onrender.com            │
│       Node.js + Express + TypeScript                   │
└───────────────────────┬────────────────────────────────┘
                        │
                        v
┌────────────────────────────────────────────────────────┐
│            PostgreSQL / Supabase Database              │
│       Endpoints, Scans, Processes, Alerts, Reports     │
└───────────────────────┬────────────────────────────────┘
                        ^
                        │ Authenticated REST / Bearer Token
┌───────────────────────┴────────────────────────────────┐
│            Vercel Production Web Console               │
│       https://phantom-trace-web.vercel.app             │
│       React 19 + TypeScript + Vite                     │
└────────────────────────────────────────────────────────┘
```

---

## Quickstart: End-to-End User Flow

Follow these 6 simple steps to run an endpoint scan and review forensic results:

1. **Visit PhantomTrace Website:** Open [https://phantom-trace-web.vercel.app/](https://phantom-trace-web.vercel.app/)
2. **Download Windows Scanner:** Scroll to the **PhantomTrace for Windows** section and download `PhantomTrace_Windows_Release_1.0.exe` (or the official Release 1.0 package from [GitHub Releases](https://github.com/JaydeepChawla/PhantomTrace-Web/releases)).
3. **Run Scanner:** Open PowerShell or Command Prompt on your Windows machine and execute:
   ```powershell
   .\PhantomTrace_Windows_Release_1.0.exe --output scan_results.json
   ```
4. **Wait for Scan Completion:** The scanner performs deep, passive, read-only memory inspection and behavioral heuristic detection across all active processes.
5. **Synchronize Results:** Dispatch the generated `scan_results.json` to the cloud API:
   ```bash
   python scripts/upload_scan.py \
     --api-url https://phantomtrace-web.onrender.com \
     --token <YOUR_AUTH_TOKEN> \
     --file scan_results.json
   ```
6. **Open Dashboard & Review:** Navigate to [https://phantom-trace-web.vercel.app/dashboard](https://phantom-trace-web.vercel.app/dashboard) to inspect detected anomalies, unbacked memory segments, behavioral indicators, and threat alerts.

---

## PhantomTrace Installation Guides

Comprehensive visual installation and verification workflows are hosted directly on the [PhantomTrace Website](https://phantom-trace-web.vercel.app/):

- **Windows Agent Installation & PC Protection:** [https://phantom-trace-web.vercel.app/#download](https://phantom-trace-web.vercel.app/#download)
- **Chrome Extension Installation & Browser Protection:** [https://phantom-trace-web.vercel.app/#browser-protection](https://phantom-trace-web.vercel.app/#browser-protection)
- **PhantomTrace Web Console:** [https://phantom-trace-web.vercel.app/](https://phantom-trace-web.vercel.app/)

> **Important Note:** Visiting the website provides the visual instructions and configuration parameters; it does **not** automatically install either application. Both the Windows Agent and Chrome Extension must be downloaded, extracted, and configured independently using their verified procedures below.

### Windows Agent Installation
The Windows Agent provides passive, read-only endpoint memory and process inspection:
1. **Download Agent:** Use the official **Download Agent** button on the website at [https://phantom-trace-web.vercel.app/#download](https://phantom-trace-web.vercel.app/#download) (or the verified backend endpoint `GET /api/agent/download?installer=true`) to save `PhantomTrace_Agent_Setup.exe`. Zero Python runtime or terminal setup required.
2. **Install Agent:** Run the Authenticode SHA-256 signed installer executable (`PhantomTrace_Agent_Setup.exe`). Files are installed to `%LocalAppData%\PhantomTraceAgent`. If prompted by Windows Defender SmartScreen (*"Windows protected your PC"*), click **More info** then **Run anyway**.
3. **Start Protection:** The background agent service starts automatically on `127.0.0.1:49152`. Operational status can be verified via the local HTTP diagnostic check at `http://127.0.0.1:49152/api/status`.
4. **Connect Your PC:** In the web console ([Dashboard](https://phantom-trace-web.vercel.app/dashboard)), navigate to the **Scan My PC** panel and click **Connect This PC**. The cloud backend generates a short-lived 6-digit pairing code (`/api/devices/pair`) to enroll your workstation.
5. **Scan Your PC:** Trigger the passive forensic inspection by clicking **SCAN MY PC** in the web dashboard (or via `POST /api/scan/start` on localhost). Operates in 100% read-only mode with zero process termination and zero file alteration.
6. **Review Results:** Inspect volatile memory telemetry in [Threat Alerts](https://phantom-trace-web.vercel.app/alerts), [Processes](https://phantom-trace-web.vercel.app/processes), [Scan History](https://phantom-trace-web.vercel.app/history), and [Reports](https://phantom-trace-web.vercel.app/reports).

### Chrome Extension Installation
The Chrome Extension provides real-time web threat detection and domain policy enforcement:
1. **Get the Extension (Developer Installation — Store Publication Pending):** Official listings on the Chrome Web Store and Microsoft Edge Add-ons are currently under review. The verified extension code is distributed directly in the repository's `browser-extension/` directory.
2. **Extract / Locate Extension Files:** Ensure the `browser-extension/` folder is placed in a permanent location on your PC. The selected folder must directly contain `manifest.json`, `background.js`, `popup.html`, `popup.js`, and `icons/` (without nested directory levels). *(Note: No public ZIP distribution is hosted on CDN; use the authentic repository directory).*
3. **Open Chrome Extensions:** Open Google Chrome and enter `chrome://extensions` in the address bar (or click the **Open Chrome Extensions** button on the website guide at [https://phantom-trace-web.vercel.app/#browser-protection](https://phantom-trace-web.vercel.app/#browser-protection) to copy the internal address to your clipboard). Toggle on **Developer mode** in the upper-right corner.
4. **Load PhantomTrace:** Click **Load unpacked** in the top-left toolbar and select the permanent `browser-extension/` folder. Confirm that **PhantomTrace Web Threat Monitor (v1.0.0)** appears in your list and pin it to your toolbar.
5. **Connect to PhantomTrace:** Open the extension popup. It defaults to the production backend `https://phantomtrace-web.onrender.com`. Generate a scoped extension sync token (`pt_ext_...`) from the web console under **Domain Policies > Connect Extension** or **Settings**, paste it into **EXTENSION SYNC TOKEN**, and click **Set**.
6. **Verify Browser Protection:** Flip **Active Web Monitoring** to ON (badge displays green **ON**), confirm backend connection shows **Connected**, and click **Sync Policies**. Visited blocked domains trigger non-destructive warning interstitials (`warning.html`) with zero logging of passwords, search queries, or form data.

---

## 1. Local Development Setup

### Install Dependencies

```bash
# Frontend dependencies
npm install

# Backend dependencies
cd server
npm install
cd ..
```

---

## 2. Environment Configuration

Configuration templates are provided in `.env.example` and `server/.env.example`. Never commit real credentials to version control.

### Frontend (`.env`)
```env
# In production (Render API):
VITE_API_BASE_URL=https://phantomtrace-web.onrender.com

# In local development:
# VITE_API_BASE_URL=http://localhost:5000

# Optional: Direct binary download mirror
# VITE_WINDOWS_SCANNER_DOWNLOAD_URL=https://github.com/JaydeepChawla/PhantomTrace-Web/releases/latest/download/PhantomTrace_Windows_Release_1.0.exe
```

### Backend (`server/.env`)
```env
PORT=5000
NODE_ENV=production
CORS_ORIGIN=https://phantom-trace-web.vercel.app,http://localhost:5173

# PostgreSQL Database Connection
DATABASE_URL=postgresql://postgres:[PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres

# Scanner Ingestion & Route Authentication
PHANTOMTRACE_API_KEY=your-production-api-key
PHANTOMTRACE_OWNER_UID=phantomtrace-owner
PHANTOMTRACE_OWNER_EMAIL=owner@phantomtrace.local
PHANTOMTRACE_OWNER_NAME=PhantomTrace Analyst
```

---

## 3. Running Locally

### Development Server
```bash
# Start frontend (Vite) on http://localhost:5173
npm run dev

# Start backend (Node.js API) on http://localhost:5000
npm run server
```

### Verify Local Build
```bash
# Validate TypeScript and build frontend
npm run build

# Validate TypeScript and build backend
npm run server:build

# Lint codebase
npm run lint
```

---

## 4. Production Security & Invariants

- **100% Read-Only Windows Engine:** Zero process termination, zero memory alteration, zero file modification.
- **Forensic Evidence Preservation:** PAGE_EXECUTE_READWRITE heuristics, hollowed PE headers, and unbacked executable memory regions are preserved without disruption.
- **Threat Score Immutability:** Threat scores and threat levels are calculated strictly by the Windows detection engine and are NEVER recalculated or altered by the web platform.
- **No Browser Memory Scanning:** The browser application purely provides visualization and triage; it never accesses or scans endpoint RAM.
- **Secure CORS Isolation:** Backend rejects unauthorized cross-origin requests and permits strictly designated frontend origins.
- **Input Validation:** Route parameters, pagination limits, and large JSON payloads (>50MB) are strictly validated and sanitized.

---

## Documentation References

- [Production Deployment Guide](./PHANTOMTRACE_PHASE6_DEPLOYMENT_GUIDE.md)
- [Deployment Readiness Audit](./PHANTOMTRACE_PHASE6_DEPLOYMENT_READINESS.md)
- [Phase 5 Security & Validation Report](./PHANTOMTRACE_PHASE5_SECURITY_VALIDATION.md)
