; =====================================================================
; PHANTOMTRACE WINDOWS AGENT - INNO SETUP INSTALLER SCRIPT
; =====================================================================
; Packages the PhantomTrace Windows Agent into a standard Windows Setup EXE.
; Configures localhost service, local security token, and startup integration.
; =====================================================================

#define MyAppName "PhantomTrace Windows Agent"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "PhantomTrace Security"
#define MyAppURL "https://phantom-trace-web.vercel.app"
#define MyAppExeName "start_agent.bat"

[Setup]
AppId={{D41D8CD9-8F00-B204-E980-0998ECF8427E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={userappdata}\PhantomTraceAgent
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputBaseFilename=PhantomTrace_Agent_Installer_v1.0
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=phantomtrace.ico
UninstallDisplayIcon={app}\phantomtrace.ico
WizardImageFile=wizard.bmp
WizardSmallImageFile=wizardsmall.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "phantomtrace.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\agent_service\*"; DestDir: "{app}\agent_service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "pythonw.exe"; Parameters: "-m agent_service.main"; WorkingDir: "{app}"; IconFilename: "{app}\phantomtrace.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "pythonw.exe"; Parameters: "-m agent_service.main"; WorkingDir: "{app}"; IconFilename: "{app}\phantomtrace.ico"; Tasks: desktopicon

[InstallDelete]
Type: files; Name: "{userstartup}\{#MyAppName}.lnk"
Type: files; Name: "{userstartup}\PhantomTrace.lnk"
Type: files; Name: "{userstartup}\PhantomTraceAgent.lnk"
Type: files; Name: "{commonstartup}\{#MyAppName}.lnk"
Type: files; Name: "{commonstartup}\PhantomTrace.lnk"
Type: files; Name: "{commonstartup}\PhantomTraceAgent.lnk"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "PhantomTrace"; Flags: dontcreatekey uninsdeletevalue deletevalue
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "PhantomTraceAgent"; Flags: dontcreatekey uninsdeletevalue deletevalue
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "PhantomTrace Windows Agent"; Flags: dontcreatekey uninsdeletevalue deletevalue

[Run]
Filename: "pythonw.exe"; Parameters: "-m agent_service.main"; Description: "Launch PhantomTrace Agent now"; Flags: nowait postinstall skipifsilent unchecked
