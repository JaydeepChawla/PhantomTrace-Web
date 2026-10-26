; =====================================================================
; PHANTOMTRACE AGENT SETUP - INNO SETUP SCRIPT
; =====================================================================
; Builds the single standalone Windows installer: PhantomTrace_Agent_Setup.exe
; Packages:
;   1. Standalone PhantomTrace Agent service (PyInstaller bundled runtime)
;   2. Existing untouched Windows Release 1.0 Scanner binary
;   3. PhantomTrace Desktop shortcut for explicit manual launching
;   4. Start Menu shortcuts (Launch, Stop, Uninstall)
;   5. Manual launch only (Automatic startup feature removed)
;   6. Configuration directory creation in LocalAppData (Preserved on uninstall)
;   7. Full uninstall integration
; =====================================================================

#define MyAppName "PhantomTrace Windows Agent"
#define MyAppDesktopName "PhantomTrace"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "PhantomTrace Security"
#define MyAppURL "https://phantom-trace-web.vercel.app"
#define MyAppExeName "PhantomTraceAgent.exe"

#ifndef ScannerDir
  #if DirExists(SourcePath + "\..\scanner_staged")
    #define ScannerDir SourcePath + "\..\scanner_staged"
  #elif DirExists(SourcePath + "\..\phantomtrace-agent\scanner")
    #define ScannerDir SourcePath + "\..\phantomtrace-agent\scanner"
  #elif DirExists(SourcePath + "\..\release_bin")
    #define ScannerDir SourcePath + "\..\release_bin"
  #else
    #define ScannerDir SourcePath + "\..\scanner_staged"
  #endif
#endif

[Setup]
AppId={{D41D8CD9-8F00-B204-E980-0998ECF8427E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={userpf}\PhantomTrace Agent
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=PhantomTrace_Agent_Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
CloseApplications=yes
RestartApplications=no
SetupIconFile=phantomtrace.ico
UninstallDisplayIcon={app}\phantomtrace.ico
WizardImageFile=wizard.bmp
WizardSmallImageFile=wizardsmall.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Dirs]
Name: "{localappdata}\PhantomTraceAgent"; Flags: uninsneveruninstall
Name: "{localappdata}\PhantomTraceAgent\scans"; Flags: uninsneveruninstall
Name: "{app}\scanner"

[Files]
; Official PhantomTrace Application & Desktop Icon
Source: "phantomtrace.ico"; DestDir: "{app}"; Flags: ignoreversion
; Standalone Agent executable and all bundled Python runtime dependencies
Source: "..\phantomtrace-agent\dist\PhantomTraceAgent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Existing untouched Windows Release 1.0 Scanner binary and its runtime dependencies
Source: "{#ScannerDir}\PhantomTrace_Windows_Release_1.0.exe"; DestDir: "{app}\scanner"; Flags: ignoreversion
Source: "{#ScannerDir}\_internal\*"; DestDir: "{app}\scanner\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
; Documentation & Control Utilities
Source: "..\phantomtrace-agent\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\phantomtrace-agent\installer\stop_agent.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\phantomtrace-agent\installer\stop_agent.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\phantomtrace-agent\installer\uninstall_agent.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start Menu shortcuts
Name: "{autoprograms}\PhantomTrace\{#MyAppDesktopName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\phantomtrace.ico"
Name: "{autoprograms}\PhantomTrace\Stop PhantomTrace Agent"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--stop"; WorkingDir: "{app}"; IconFilename: "{app}\phantomtrace.ico"
Name: "{autoprograms}\PhantomTrace\Uninstall PhantomTrace Agent"; Filename: "{uninstallexe}"; IconFilename: "{app}\phantomtrace.ico"
; Desktop shortcut (Checked by default for manual double-click launch)
Name: "{autodesktop}\{#MyAppDesktopName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\phantomtrace.ico"; Tasks: desktopicon

[InstallDelete]
; When upgrading or reinstalling, cleanly remove legacy desktop shortcut and any unwanted automatic startup shortcuts
Type: files; Name: "{autodesktop}\{#MyAppName}.lnk"
Type: files; Name: "{userstartup}\{#MyAppDesktopName}.lnk"
Type: files; Name: "{userstartup}\{#MyAppName}.lnk"
Type: files; Name: "{userstartup}\PhantomTraceAgent.lnk"
Type: files; Name: "{commonstartup}\{#MyAppDesktopName}.lnk"
Type: files; Name: "{commonstartup}\{#MyAppName}.lnk"
Type: files; Name: "{commonstartup}\PhantomTraceAgent.lnk"

[Run]
; Never run the agent automatically upon installation.
; Manual launch via Desktop shortcut is the primary workflow.
; Optional checkbox on finish page is unchecked by default and skipped during silent install.
Filename: "{app}\{#MyAppExeName}"; Description: "Launch PhantomTrace Agent now"; Flags: nowait postinstall skipifsilent unchecked

[UninstallRun]
; Terminate any running Agent service prior to removing files
Filename: "taskkill.exe"; Parameters: "/F /IM {#MyAppExeName}"; Flags: runhidden; RunOnceId: "KillPhantomTraceAgent"
Filename: "taskkill.exe"; Parameters: "/F /IM PhantomTrace-Agent.exe"; Flags: runhidden; RunOnceId: "KillPhantomTraceAgentDash"

[UninstallDelete]
; Remove desktop and Start Menu shortcuts
Type: files; Name: "{autodesktop}\{#MyAppDesktopName}.lnk"
Type: files; Name: "{autodesktop}\{#MyAppName}.lnk"
Type: files; Name: "{userstartup}\{#MyAppDesktopName}.lnk"
Type: files; Name: "{userstartup}\{#MyAppName}.lnk"
Type: files; Name: "{userstartup}\PhantomTraceAgent.lnk"
Type: files; Name: "{commonstartup}\{#MyAppDesktopName}.lnk"
Type: files; Name: "{commonstartup}\{#MyAppName}.lnk"
Type: files; Name: "{commonstartup}\PhantomTraceAgent.lnk"
Type: filesandordirs; Name: "{autoprograms}\PhantomTrace"
Type: filesandordirs; Name: "{autoprograms}\{#MyAppName}"

[Registry]
; Clean up any registry Run entries on install/upgrade and uninstall without creating them on install
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "PhantomTrace"; Flags: dontcreatekey uninsdeletevalue deletevalue
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "PhantomTraceAgent"; Flags: dontcreatekey uninsdeletevalue deletevalue
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "PhantomTrace Windows Agent"; Flags: dontcreatekey uninsdeletevalue deletevalue
