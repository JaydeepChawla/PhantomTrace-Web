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

## Background Windowless Model

The PhantomTrace Windows Agent operates as a windowless background user-session service:
- **No Console Window**: The packaged executable (`PhantomTraceAgent.exe`) runs without opening a black command prompt window on startup.
- **Single Instance Guarantee**: Automatically prevents duplicate background instances using an OS-level named mutex (`Local\PhantomTraceAgentSingleInstanceMutex`) and loopback port binding protection.
- **Diagnostic Logging**: All startup details, telemetry orchestration, and errors are continuously preserved in `%LOCALAPPDATA%\PhantomTraceAgent\phantomtrace_agent.log`.

## Service Lifecycle Management

### Starting the Agent
- **Automatic Startup**: If enabled during installation, the agent starts automatically upon Windows user login via the Startup folder shortcut (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\PhantomTrace Windows Agent.lnk`).
- **Manual Launch**: Run `PhantomTraceAgent.exe` or execute:
  ```powershell
  cd phantomtrace-agent
  python -m agent_service.main
  ```

### Checking Status
- **Web Dashboard**: Displays "PhantomTrace Agent Connected" (green badge) at `127.0.0.1:49152`.
- **Command Line**:
  ```powershell
  PhantomTraceAgent.exe --status
  # or
  python -m agent_service.main --status
  ```
- **REST Health Check**:
  ```powershell
  Invoke-RestMethod http://127.0.0.1:49152/api/status
  ```

### Stopping the Agent
- **CLI / Command Line**:
  ```powershell
  PhantomTraceAgent.exe --stop
  # or
  python -m agent_service.main --stop
  ```
- **Start Menu**: Open Windows Start Menu -> **PhantomTrace Windows Agent** -> **Stop PhantomTrace Agent**.
- **PowerShell**:
  ```powershell
  Stop-Process -Name PhantomTraceAgent -Force
  # or run the stop script:
  & "$env:LOCALAPPDATA\Programs\PhantomTrace Agent\stop_agent.ps1"
  ```
- **Task Manager**: Open Task Manager -> Processes -> End Task on `PhantomTraceAgent`.

### Disabling Automatic Startup
Users can easily disable automatic startup at any time through standard Windows controls:
1. **Windows Settings**: Go to **Settings** > **Apps** > **Startup** > Toggle off **PhantomTrace Windows Agent**.
2. **Task Manager**: Open Task Manager > **Startup apps** tab > Right-click **PhantomTrace Windows Agent** > Select **Disable**.
3. **Startup Folder**: Remove the shortcut from:
   `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\PhantomTrace Windows Agent.lnk`.

### Uninstalling the Agent
1. **Windows Settings**: Go to **Settings** > **Installed apps** (or Control Panel > Programs and Features) > Select **PhantomTrace Windows Agent** > Click **Uninstall**.
2. **Installer Uninstaller**: Run `unins000.exe` located in the application directory:
   `%LOCALAPPDATA%\Programs\PhantomTrace Agent\unins000.exe`.
3. The uninstaller automatically shuts down any running background agent process before removing installed files.

## Logs & Diagnostics

- **Log File**: `%LOCALAPPDATA%\PhantomTraceAgent\phantomtrace_agent.log`
- **Scan Telemetry**: `%LOCALAPPDATA%\PhantomTraceAgent\scan_results.json`
- **Cloud Enrollment Auth**: `%LOCALAPPDATA%\PhantomTraceAgent\cloud_auth.json`
- **Local API Security Token**: `%LOCALAPPDATA%\PhantomTraceAgent\local_token.json`
