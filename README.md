# PhantomTrace — Enterprise Memory & Fileless Threat Detection

> *"Trace what others can't see."*

[![Production Frontend](https://img.shields.io/badge/Frontend-Vercel%20Production-00e5ff?style=flat-square)](https://phantom-trace-web.vercel.app/)
[![Production Backend](https://img.shields.io/badge/Backend-Render%20API-46e3b7?style=flat-square)](https://phantomtrace-web.onrender.com/api/health)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%20%2F%20Supabase-38bdf8?style=flat-square)](https://supabase.com/)
[![Windows Scanner](https://img.shields.io/badge/Scanner-Windows%20Release%201.0-818cf8?style=flat-square)](https://github.com/JaydeepChawla/PhantomTrace-Web/releases)
[![Operation Mode](https://img.shields.io/badge/Mode-100%25%20Read--Only-10b981?style=flat-square)]()

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
