# PhantomTrace Windows Agent

Lightweight local Windows agent providing the **"Scan My PC"** one-click orchestration pipeline for PhantomTrace.

## Architecture

```
                 INTERNET
                    │
                    ▼
          PhantomTrace Website
          (https://phantom-trace-web.vercel.app)
                    │
                    │ localhost only (127.0.0.1:49152)
                    ▼
       PhantomTrace Windows Agent (Daemon)
                    │
                    ▼ (Subprocess invocation)
        PhantomTrace Windows Scanner
        (PhantomTrace_Windows_Release_1.0.exe)
                    │
                    ▼ (Passive read-only memory & process analysis)
             scan_results.json
                    │
                    ▼ (HTTPS Ingestion)
          Authenticated REST API
          (https://phantomtrace-web.onrender.com)
                    │
                    ▼
          Render + PostgreSQL
                    │
                    ▼
          PhantomTrace Dashboard
```

## Security & Privacy Model

1. **Strict Localhost Binding**: The agent listens exclusively on `127.0.0.1:49152` and never accepts connections from the local network (LAN) or public internet.
2. **Private Network Access (PNA)**: Supports Chromium Private Network Access preflights with `Access-Control-Allow-Private-Network: true`.
3. **Restricted CORS**: Binds exclusively to approved PhantomTrace origins (`https://phantom-trace-web.vercel.app` and local dev).
4. **No Arbitrary Commands**: The agent exposes only fixed, safe REST endpoints:
   - `GET /api/status`: Health and scanner availability
   - `GET /api/agent/info`: Version and platform diagnostic info
   - `POST /api/scan/start`: Triggers the verified scanner executable
   - `GET /api/scan/status`: Retrieves real-time scan progress
   - `POST /api/pair`: Device enrollment and credential management
5. **Zero Detection Changes**: The agent does not contain detection rules or memory tampering logic. It orchestrates the existing, protected `PhantomTrace_Windows_Release_1.0.exe`.
6. **100% Read-Only**: Leaves processes, files, registry, and memory completely untouched.

## Running the Agent

```powershell
cd phantomtrace-agent
python -m agent_service.main
```
