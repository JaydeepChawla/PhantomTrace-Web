; =====================================================================
; PHANTOMTRACE AGENT SETUP - INNO SETUP SCRIPT
; =====================================================================
; Builds the single standalone Windows installer: PhantomTrace_Agent_Setup.exe
; Packages:
;   1. Standalone PhantomTrace Agent service (PyInstaller bundled runtime)
;   2. Existing untouched Windows Release 1.0 Scanner binary
;   3. Automatic background service startup (127.0.0.1:49152)
;   4. Configuration directory creation in LocalAppData
;   5. Full uninstall integration
; =====================================================================

#define MyAppName "PhantomTrace Windows Agent"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "PhantomTrace Security"
#define MyAppURL "https://phantom-trace-web.vercel.app"
#define MyAppExeName "PhantomTraceAgent.exe"

[Setup]
AppId={{D41D8CD9-8F00-B204-E980-0998ECF8427E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\PhantomTrace Agent
DisableProgramGroupPage=yes
OutputDir=..\..\dist
OutputBaseFilename=PhantomTrace_Agent_Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start PhantomTrace Agent automatically when Windows starts"; GroupDescription: "Startup Options:"

[Dirs]
Name: "{localappdata}\PhantomTraceAgent"; Flags: uninsneveruninstall
Name: "{localappdata}\PhantomTraceAgent\scans"; Flags: uninsneveruninstall
Name: "{app}\scanner"

[Files]
; Standalone Agent executable and all bundled Python runtime dependencies
Source: "..\dist\PhantomTraceAgent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Existing untouched Windows Release 1.0 Scanner binary and its runtime dependencies
Source: "D:\Phantom Trace\release\PhantomTrace_Windows_Release_1.0\PhantomTrace_Windows_Release_1.0.exe"; DestDir: "{app}\scanner"; Flags: ignoreversion
Source: "D:\Phantom Trace\release\PhantomTrace_Windows_Release_1.0\_internal\*"; DestDir: "{app}\scanner\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs
; Documentation
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: autostart

[Run]
; Automatically start the Agent service in background after installation
Filename: "{app}\{#MyAppExeName}"; Description: "Launch PhantomTrace Agent now"; Flags: nowait runhidden

[UninstallRun]
; Terminate any running Agent service prior to removing files
Filename: "taskkill.exe"; Parameters: "/F /IM {#MyAppExeName}"; Flags: runhidden; RunOnceId: "KillPhantomTraceAgent"
