import type { 
  ProcessItem, 
  ThreatAlert, 
  ScanOverview, 
  ScanHistoryItem, 
  ReportItem, 
  SystemSettings 
} from '../types';

export const mockOverview: ScanOverview = {
  totalProcesses: 148,
  threatAlertsCount: 6,
  criticalCount: 1,
  highCount: 2,
  mediumCount: 2,
  lowCount: 1,
  highestThreatScore: 94,
  scanTime: '2026-09-25 12:48:19 UTC',
  duration: '4.82s',
  memoryInspectedMb: 3240,
  engineVersion: 'v2.4.1-core',
  scanMode: 'Memory & Behavioral Correlation (Read-Only)',
  readOnlyEngineEnforced: true,
};

export const mockProcesses: ProcessItem[] = [
  {
    pid: 4892,
    name: 'powershell.exe',
    path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    parentPid: 3104,
    parentName: 'wscript.exe',
    commandLine: 'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAA...',
    userContext: 'NT AUTHORITY\\SYSTEM',
    threatScore: 94,
    threatLevel: 'Critical',
    application: 'Script Host',
    scoreMode: 'Correlated',
    behaviorScore: 92,
    memoryScore: 96,
    correlationSummary: 'Elevated correlation between unbacked executable memory allocation and obfuscated script invocation under anomalous parentage (wscript.exe).',
    memoryEvidenceCount: 3,
    behaviorEvidenceCount: 4,
    memoryIndicators: [
      'PAGE_EXECUTE_READWRITE allocation at non-module address',
      'Unbacked PE stub detected in private commit heap',
      'VirtualAlloc / WriteProcessMemory signature pattern'
    ],
    memoryEvidence: [
      {
        id: 'mem-4892-01',
        type: 'PAGE_EXECUTE_READWRITE Region',
        address: '0x00007FFA4B8A0000',
        size: '128 KB',
        protection: 'PAGE_EXECUTE_READWRITE',
        details: 'Memory region is not mapped to any known loaded PE image on disk. Contains shellcode bootstrap prologue (0x48 0x83 0xEC 0x28).',
        severity: 'Critical'
      },
      {
        id: 'mem-4892-02',
        type: 'Unbacked Executable Memory',
        address: '0x00007FFA4B920000',
        size: '64 KB',
        protection: 'PAGE_EXECUTE_READ',
        details: 'Allocated executable payload without backing disk binary. Memory structure resembles a reflective DLL loader header.',
        severity: 'Critical'
      },
      {
        id: 'mem-4892-03',
        type: 'PE Header Discrepancy',
        address: '0x00007FFA4B8A0040',
        size: '4 KB',
        protection: 'PAGE_READONLY',
        details: 'Erased MZ and e_lfanew DOS header signatures, indicating memory cloaking techniques commonly associated with stealth beacon injection.',
        severity: 'High'
      }
    ],
    behaviorEvidence: [
      {
        id: 'beh-4892-01',
        category: 'Process Lineage Anomaly',
        description: 'Spawned with hidden window parameter (-W Hidden) directly by Windows Script Host (wscript.exe), deviating from baseline system orchestration.',
        mitreTechnique: 'T1059.001 - Command and Scripting Interpreter: PowerShell',
        timestamp: '12:47:04 UTC',
        confidence: 'High'
      },
      {
        id: 'beh-4892-02',
        category: 'Execution Policy Bypass',
        description: 'Explicit execution bypass flag (-Exec Bypass) used in combination with Base64 encoded payload stream.',
        mitreTechnique: 'T1562.001 - Impair Defenses: Disable or Modify Tools',
        timestamp: '12:47:04 UTC',
        confidence: 'High'
      },
      {
        id: 'beh-4892-03',
        category: 'In-Memory Web Download',
        description: 'Decoded payload requests programmatic download string through System.Net.WebClient directly into memory stream.',
        mitreTechnique: 'T1105 - Ingress Tool Transfer',
        timestamp: '12:47:06 UTC',
        confidence: 'High'
      },
      {
        id: 'beh-4892-04',
        category: 'Process Injection Telemetry',
        description: 'Attempted memory querying and allocation targeting neighboring process address space.',
        mitreTechnique: 'T1055 - Process Injection',
        timestamp: '12:47:11 UTC',
        confidence: 'High'
      }
    ],
    timestamp: '2026-09-25 12:48:19 UTC',
    integrityLevel: 'System',
    startTime: '2026-09-25 12:47:02 UTC',
    responseRecommendation: {
      whyFlagged: 'High-risk memory anomalies detected: unbacked RWX memory segment holding executable shellcode, paired with suspicious parent-child process lineage (wscript.exe invoking hidden encoded PowerShell).',
      investigationSteps: [
        'Review full command line and decode the secondary Base64 payload string.',
        'Review parent process wscript.exe (PID: 3104) and identify the initiating script file or origin document.',
        'Review user context (NT AUTHORITY\\SYSTEM) to verify privilege escalation path.',
        'Review memory evidence: inspect RWX address 0x00007FFA4B8A0000 for network sockets or C2 configuration blocks.',
        'Review network activity for egress connections to external IP ranges during the 12:47 UTC timeframe.',
        'Review persistence indicators across registry Run keys, scheduled tasks, and WMI event subscriptions.',
        'Follow organizational incident-response procedures according to Section 4.2 (Endpoint Containment & Forensics).'
      ],
      mitreReferences: ['T1059.001', 'T1055.001', 'T1105', 'T1562.001'],
      containmentGuidance: 'Isolate endpoint network traffic at the firewall or switch VLAN level if external C2 is confirmed. Preserve memory snapshot before system reboot.',
      readOnlyNotice: 'The PhantomTrace Windows scanner operates in strict read-only mode to preserve forensic integrity. No processes have been terminated and no endpoint files have been modified.'
    }
  },
  {
    pid: 7216,
    name: 'svchost.exe',
    path: 'C:\\Windows\\System32\\svchost.exe',
    parentPid: 840,
    parentName: 'services.exe',
    commandLine: 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule',
    userContext: 'NT AUTHORITY\\SYSTEM',
    threatScore: 88,
    threatLevel: 'High',
    application: 'Trusted System',
    scoreMode: 'Correlated',
    behaviorScore: 78,
    memoryScore: 91,
    correlationSummary: 'Memory evidence preserved in a verified trusted system binary: detected reflective DLL hollow and unmapped executable region despite legitimate process name.',
    memoryEvidenceCount: 2,
    behaviorEvidenceCount: 2,
    memoryIndicators: [
      'Unmapped executable memory region in trusted binary',
      'Trampoline hook on ntdll!NtCreateThreadEx',
      'Thread start address points outside loaded modules'
    ],
    memoryEvidence: [
      {
        id: 'mem-7216-01',
        type: 'Unbacked Executable Memory',
        address: '0x00007FFA39120000',
        size: '256 KB',
        protection: 'PAGE_EXECUTE_READ',
        details: 'Executable segment with no corresponding filesystem DLL map in the PEB module list. Preserved as potential reflective DLL injection.',
        severity: 'High'
      },
      {
        id: 'mem-7216-02',
        type: 'Inline API Hook',
        address: '0x00007FFA5D211040',
        size: '32 B',
        protection: 'PAGE_EXECUTE_READ',
        details: 'Trampoline detected at ntdll!NtCreateThreadEx redirecting control flow to unmapped memory address 0x00007FFA39121400.',
        severity: 'High'
      }
    ],
    behaviorEvidence: [
      {
        id: 'beh-7216-01',
        category: 'Suspicious Thread Creation',
        description: 'New thread created with entry point residing in unbacked private memory rather than legitimate system DLL.',
        mitreTechnique: 'T1055.001 - Dynamic-link Library Injection',
        timestamp: '12:44:22 UTC',
        confidence: 'High'
      },
      {
        id: 'beh-7216-02',
        category: 'Anomalous Child Network Socket',
        description: 'Schedule service host initiated non-standard outbound connection on TCP port 8443.',
        mitreTechnique: 'T1071.001 - Application Layer Protocol: Web Protocols',
        timestamp: '12:45:10 UTC',
        confidence: 'Medium'
      }
    ],
    timestamp: '2026-09-25 12:48:19 UTC',
    integrityLevel: 'System',
    startTime: '2026-09-25 09:12:00 UTC',
    responseRecommendation: {
      whyFlagged: 'Preserved memory anomaly inside verified system binary: svchost.exe exhibits inline hooking of ntdll!NtCreateThreadEx and an unbacked executable segment, indicative of stealth process hollowing or thread injection.',
      investigationSteps: [
        'Review command line arguments and associated service DLL bindings (-k netsvcs).',
        'Review parent process services.exe (PID: 840) to verify service start trigger.',
        'Review user context and active security tokens for privilege abuse.',
        'Review memory evidence: dump the unmapped 256 KB buffer at 0x00007FFA39120000 for string artifacts.',
        'Review network activity for persistent outbound beacons on port 8443.',
        'Review persistence indicators in Scheduled Tasks library and TaskCache registry trees.',
        'Follow organizational incident-response procedures for suspected living-off-the-land (LotL) persistence.'
      ],
      mitreReferences: ['T1055.001', 'T1055.012', 'T1071.001'],
      containmentGuidance: 'Do not kill critical service host. Capture full process memory dump for forensic analysis before isolating the endpoint.',
      readOnlyNotice: 'The PhantomTrace Windows scanner operates in strict read-only mode to preserve forensic integrity. No processes have been terminated and no endpoint files have been modified.'
    }
  },
  {
    pid: 9140,
    name: 'rundll32.exe',
    path: 'C:\\Windows\\System32\\rundll32.exe',
    parentPid: 4892,
    parentName: 'powershell.exe',
    commandLine: 'rundll32.exe "C:\\Users\\Default\\AppData\\Local\\Temp\\update_x64.dll",#1',
    userContext: 'NT AUTHORITY\\SYSTEM',
    threatScore: 82,
    threatLevel: 'High',
    application: 'System Utility',
    scoreMode: 'Correlated',
    behaviorScore: 84,
    memoryScore: 79,
    correlationSummary: 'System execution utility invoked from temporary directory with ordinal export export syntax by high-risk PowerShell instance.',
    memoryEvidenceCount: 1,
    behaviorEvidenceCount: 3,
    memoryIndicators: [
      'Unsigned DLL loaded from AppData\\Local\\Temp',
      'PE section characteristics modified post-load'
    ],
    memoryEvidence: [
      {
        id: 'mem-9140-01',
        type: 'Modified Section Protection',
        address: '0x00007FFA21001000',
        size: '48 KB',
        protection: 'PAGE_EXECUTE_READWRITE',
        details: 'Text section memory protection transitioned from RX to RWX during execution of ordinal export #1.',
        severity: 'High'
      }
    ],
    behaviorEvidence: [
      {
        id: 'beh-9140-01',
        category: 'Unusual Child Process Inception',
        description: 'Spawned directly by suspicious PowerShell process (PID: 4892) pointing to user temporary directory.',
        mitreTechnique: 'T1218.011 - System Binary Proxy Execution: Rundll32',
        timestamp: '12:47:33 UTC',
        confidence: 'High'
      },
      {
        id: 'beh-9140-02',
        category: 'Ordinal Export Execution',
        description: 'DLL invoked via numeric ordinal (#1) without named export symbol, typical of obfuscated payloads.',
        mitreTechnique: 'T1218.011 - System Binary Proxy Execution: Rundll32',
        timestamp: '12:47:33 UTC',
        confidence: 'High'
      },
      {
        id: 'beh-9140-03',
        category: 'Disk Artifact in Staging Path',
        description: 'Target binary located within volatile user Temp directory rather than protected System32.',
        mitreTechnique: 'T1074.001 - Data Staged: Local Data Staging',
        timestamp: '12:47:33 UTC',
        confidence: 'High'
      }
    ],
    timestamp: '2026-09-25 12:48:19 UTC',
    integrityLevel: 'System',
    startTime: '2026-09-25 12:47:31 UTC',
    responseRecommendation: {
      whyFlagged: 'Rundll32 executed an unsigned payload DLL from AppData\\Local\\Temp with ordinal invocation (#1) as a child of flagged PowerShell instance.',
      investigationSteps: [
        'Review command line parameters and exact timestamp of execution.',
        'Review parent process powershell.exe (PID: 4892) to map complete attack timeline.',
        'Review user context and session logon ID.',
        'Review memory evidence: extract memory dump of update_x64.dll text section.',
        'Review network activity: verify if rundll32 initiated HTTP/DNS queries.',
        'Review persistence indicators: search registry Run keys and startup folders for reference to update_x64.dll.',
        'Follow organizational incident-response procedures for endpoint isolation.'
      ],
      mitreReferences: ['T1218.011', 'T1074.001'],
      containmentGuidance: 'Collect disk copy of update_x64.dll for static reverse engineering. Do not modify file permissions on endpoint.',
      readOnlyNotice: 'The PhantomTrace Windows scanner operates in strict read-only mode to preserve forensic integrity. No processes have been terminated and no endpoint files have been modified.'
    }
  },
  {
    pid: 10420,
    name: 'msedge.exe',
    path: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    parentPid: 1284,
    parentName: 'explorer.exe',
    commandLine: '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --type=renderer --field-trial-handle=...',
    userContext: 'DESKTOP-PTSEC\\analyst',
    threatScore: 64,
    threatLevel: 'Medium',
    application: 'Verified Third-Party',
    scoreMode: 'Memory Only',
    behaviorScore: 28,
    memoryScore: 71,
    correlationSummary: 'Memory-only detection: JIT code cache contains dynamic executable blocks with high entropy; behavioral baseline remains within normal browser boundaries.',
    memoryEvidenceCount: 1,
    behaviorEvidenceCount: 1,
    memoryIndicators: [
      'High entropy executable heap allocation (V8 JIT compilation)',
      'Dynamic executable page allocation'
    ],
    memoryEvidence: [
      {
        id: 'mem-10420-01',
        type: 'Dynamic Executable JIT Buffer',
        address: '0x00007FFA1A800000',
        size: '512 KB',
        protection: 'PAGE_EXECUTE_READ',
        details: 'Dynamic executable page allocated by browser renderer process. Shannon entropy of 7.4. Flagged for review due to non-module executable designation.',
        severity: 'Medium'
      }
    ],
    behaviorEvidence: [
      {
        id: 'beh-10420-01',
        category: 'Elevated Memory Allocation Rate',
        description: 'Renderer process allocated 12 dynamic memory blocks in rapid succession during complex web application loading.',
        timestamp: '12:46:12 UTC',
        confidence: 'Low'
      }
    ],
    timestamp: '2026-09-25 12:48:19 UTC',
    integrityLevel: 'Low',
    startTime: '2026-09-25 10:15:33 UTC',
    responseRecommendation: {
      whyFlagged: 'Elevated memory entropy detected in browser renderer dynamic heap. While common for V8 JIT code, investigation is recommended to rule out WebAssembly-based cryptomining or heap exploitation.',
      investigationSteps: [
        'Review command line to verify sandbox and renderer child tokens.',
        'Review parent process msedge.exe browser broker (PID: 1284).',
        'Review user context and active browser tab URLs from web proxy logs.',
        'Review memory evidence: check for WebAssembly compiled bytecode signatures in JIT buffers.',
        'Review network activity for high-volume WebSocket or mining pool protocol connections.',
        'Review persistence indicators: verify browser extensions and default search providers.',
        'Follow organizational incident-response procedures if malicious web source is confirmed.'
      ],
      mitreReferences: ['T1189 - Drive-by Compromise', 'T1496 - Resource Hijacking'],
      containmentGuidance: 'Investigate browser history and active domain connections before taking action.',
      readOnlyNotice: 'The PhantomTrace Windows scanner operates in strict read-only mode to preserve forensic integrity. No processes have been terminated and no endpoint files have been modified.'
    }
  },
  {
    pid: 6184,
    name: 'cmd.exe',
    path: 'C:\\Windows\\System32\\cmd.exe',
    parentPid: 4892,
    parentName: 'powershell.exe',
    commandLine: 'cmd.exe /c "whoami /priv && net group \\"Domain Admins\\" /domain"',
    userContext: 'NT AUTHORITY\\SYSTEM',
    threatScore: 68,
    threatLevel: 'Medium',
    application: 'System Utility',
    scoreMode: 'Behavior Only',
    behaviorScore: 82,
    memoryScore: 22,
    correlationSummary: 'Behavior-only detection: rapid reconnaissance commands executed under flagged parent process; memory structures match standard Windows cmd.exe image.',
    memoryEvidenceCount: 0,
    behaviorEvidenceCount: 2,
    memoryIndicators: [
      'Standard backed memory image (C:\\Windows\\System32\\cmd.exe)'
    ],
    memoryEvidence: [],
    behaviorEvidence: [
      {
        id: 'beh-6184-01',
        category: 'Privilege Enumeration',
        description: 'Execution of "whoami /priv" command to discover elevated token permissions and security rights.',
        mitreTechnique: 'T1033 - System Owner/User Discovery',
        timestamp: '12:47:45 UTC',
        confidence: 'High'
      },
      {
        id: 'beh-6184-02',
        category: 'Domain Group Discovery',
        description: 'Execution of "net group Domain Admins /domain" to enumerate privileged directory membership.',
        mitreTechnique: 'T1069.002 - Permission Groups Discovery: Domain Groups',
        timestamp: '12:47:47 UTC',
        confidence: 'High'
      }
    ],
    timestamp: '2026-09-25 12:48:19 UTC',
    integrityLevel: 'System',
    startTime: '2026-09-25 12:47:44 UTC',
    responseRecommendation: {
      whyFlagged: 'Reconnaissance commands executed in rapid sequence by cmd.exe spawned from an elevated PowerShell process.',
      investigationSteps: [
        'Review command line arguments (/c whoami /priv && net group).',
        'Review parent process powershell.exe (PID: 4892).',
        'Review user context (SYSTEM privilege execution of user discovery commands).',
        'Review memory evidence: standard image backed by disk.',
        'Review network activity: check domain controller LDAP / RPC traffic for directory queries.',
        'Review persistence indicators: verify if reconnaissance output was written to disk or redirected.',
        'Follow organizational incident-response procedures for post-exploitation discovery.'
      ],
      mitreReferences: ['T1033', 'T1069.002'],
      containmentGuidance: 'Review Active Directory audit logs for anomalous LDAP queries from this endpoint IP.',
      readOnlyNotice: 'The PhantomTrace Windows scanner operates in strict read-only mode to preserve forensic integrity. No processes have been terminated and no endpoint files have been modified.'
    }
  },
  {
    pid: 11520,
    name: 'python.exe',
    path: 'C:\\Users\\analyst\\AppData\\Local\\Programs\\Python\\Python311\\python.exe',
    parentPid: 5410,
    parentName: 'code.exe',
    commandLine: 'python.exe -m pytest tests/',
    userContext: 'DESKTOP-PTSEC\\analyst',
    threatScore: 28,
    threatLevel: 'Low',
    application: 'Verified Third-Party',
    scoreMode: 'Baseline',
    behaviorScore: 25,
    memoryScore: 30,
    correlationSummary: 'Low baseline score: execution under developer IDE with standard file system test reads; memory allocations conform to CPython runtime.',
    memoryEvidenceCount: 1,
    behaviorEvidenceCount: 0,
    memoryIndicators: [
      'CPython interpreter heap allocation'
    ],
    memoryEvidence: [
      {
        id: 'mem-11520-01',
        type: 'Private Heap Commit',
        address: '0x00007FFA08100000',
        size: '16 KB',
        protection: 'PAGE_READWRITE',
        details: 'Standard Python bytecode evaluation stack buffer. Non-executable memory page.',
        severity: 'Low'
      }
    ],
    behaviorEvidence: [],
    timestamp: '2026-09-25 12:48:19 UTC',
    integrityLevel: 'Medium',
    startTime: '2026-09-25 12:40:11 UTC',
    responseRecommendation: {
      whyFlagged: 'Routine baseline telemetry: standard Python interpreter test execution under developer environment.',
      investigationSteps: [
        'Review command line to verify test suite parameters.',
        'Review parent process VS Code process tree.',
        'Review user context (standard workstation developer session).',
        'Review memory evidence: standard read-write heap allocation.',
        'Review network activity: verify absence of external telemetry.',
        'Review persistence indicators: no persistence triggers detected.',
        'Follow organizational incident-response procedures if unauthorized scripts are executed.'
      ],
      mitreReferences: [],
      containmentGuidance: 'No action required under standard development workflow.',
      readOnlyNotice: 'The PhantomTrace Windows scanner operates in strict read-only mode to preserve forensic integrity. No processes have been terminated and no endpoint files have been modified.'
    }
  },
  {
    pid: 792,
    name: 'lsass.exe',
    path: 'C:\\Windows\\System32\\lsass.exe',
    parentPid: 648,
    parentName: 'wininit.exe',
    commandLine: 'C:\\Windows\\system32\\lsass.exe',
    userContext: 'NT AUTHORITY\\SYSTEM',
    threatScore: 18,
    threatLevel: 'Clean',
    application: 'Trusted System',
    scoreMode: 'Baseline',
    behaviorScore: 15,
    memoryScore: 20,
    correlationSummary: 'Verified secure authentication subsystem: protected process light (PPL) enabled, zero unbacked executable regions detected.',
    memoryEvidenceCount: 0,
    behaviorEvidenceCount: 0,
    memoryIndicators: [
      'Protected Process Light (PPL) enforced',
      'All code pages strictly disk-backed by validated DLLs'
    ],
    memoryEvidence: [],
    behaviorEvidence: [],
    timestamp: '2026-09-25 12:48:19 UTC',
    integrityLevel: 'System',
    startTime: '2026-09-25 08:30:15 UTC',
    responseRecommendation: {
      whyFlagged: 'Baseline inspection: critical system security component operating within normal protected parameters.',
      investigationSteps: [
        'Review command line and parent process wininit.exe.',
        'Verify PPL status and Credential Guard configuration.',
        'Review audit logs for unauthorized handle open requests (Event ID 4656/4663).'
      ],
      mitreReferences: ['T1003.001 - OS Credential Dumping: LSASS Memory'],
      containmentGuidance: 'Never kill lsass.exe (causes immediate system BSOD/reboot).',
      readOnlyNotice: 'The PhantomTrace Windows scanner operates in strict read-only mode to preserve forensic integrity.'
    }
  },
  {
    pid: 1420,
    name: 'explorer.exe',
    path: 'C:\\Windows\\explorer.exe',
    parentPid: 1204,
    parentName: 'userinit.exe',
    commandLine: 'C:\\Windows\\Explorer.EXE',
    userContext: 'DESKTOP-PTSEC\\analyst',
    threatScore: 12,
    threatLevel: 'Clean',
    application: 'Trusted System',
    scoreMode: 'Baseline',
    behaviorScore: 10,
    memoryScore: 14,
    correlationSummary: 'User desktop shell running within standard operating parameters.',
    memoryEvidenceCount: 0,
    behaviorEvidenceCount: 0,
    memoryIndicators: [
      'Legitimate Windows Shell binary signature',
      'Valid digital signature from Microsoft Windows Production PCA'
    ],
    memoryEvidence: [],
    behaviorEvidence: [],
    timestamp: '2026-09-25 12:48:19 UTC',
    integrityLevel: 'Medium',
    startTime: '2026-09-25 08:31:02 UTC',
    responseRecommendation: {
      whyFlagged: 'Normal baseline activity.',
      investigationSteps: [
        'Routine baseline inspection.'
      ],
      mitreReferences: [],
      containmentGuidance: 'None required.',
      readOnlyNotice: 'The PhantomTrace Windows scanner operates in strict read-only mode to preserve forensic integrity.'
    }
  }
];

export const mockThreatAlerts: ThreatAlert[] = [
  {
    id: 'alt-4892',
    pid: 4892,
    processName: 'powershell.exe',
    process: 'powershell.exe',
    score: 94,
    threatScore: 94,
    level: 'CRITICAL',
    threatLevel: 'Critical',
    application: 'Script Host',
    scoreMode: 'CORRELATED',
    behaviorScore: 92,
    memoryScore: 96,
    correlation: 'High (Behavior + Memory Co-occurrence)',
    memoryEvidence: {
      present: true,
      strength: 'HIGH',
      indicators: [
        'PAGE_EXECUTE_READWRITE unbacked region',
        'erased DOS header'
      ],
      details: ['PAGE_EXECUTE_READWRITE unbacked region + erased DOS header'],
      suspiciousRegions: 2,
      rwxRegions: 1,
      scanStatus: 'SCANNED',
      timestamp: '2026-09-25 12:48:19 UTC'
    },
    detectedAt: '2026-09-25 12:48:19 UTC',
    timestamp: '2026-09-25 12:48:19 UTC',
    status: 'NEW',
    title: 'Obfuscated PowerShell Execution with RWX Memory Allocation',
    description: 'Suspicious hidden window parameter with unbacked executable memory allocation.',
    recommendedActions: [
      'Inspect parent process lineage (wscript.exe)',
      'Analyze memory region contents for injected shellcode',
      'Contain host network interface pending investigation'
    ]
  },
  {
    id: 'alt-7216',
    pid: 7216,
    processName: 'svchost.exe',
    process: 'svchost.exe',
    score: 88,
    threatScore: 88,
    level: 'HIGH',
    threatLevel: 'High',
    application: 'Trusted System',
    scoreMode: 'CORRELATED',
    behaviorScore: 78,
    memoryScore: 91,
    correlation: 'Preserved in Trusted System Binary',
    memoryEvidence: {
      present: true,
      strength: 'HIGH',
      indicators: [
        'ntdll!NtCreateThreadEx hook',
        'unmapped executable section'
      ],
      details: ['ntdll!NtCreateThreadEx hook + unmapped executable section'],
      suspiciousRegions: 1,
      privateExecutableRegions: 1,
      scanStatus: 'SCANNED',
      timestamp: '2026-09-25 12:48:19 UTC'
    },
    detectedAt: '2026-09-25 12:48:19 UTC',
    timestamp: '2026-09-25 12:48:19 UTC',
    status: 'INVESTIGATING',
    title: 'Inline API Hook in System Service Host',
    description: 'Hook detected in ntdll system call with unbacked executable section.',
    recommendedActions: [
      'Verify service DLL integrity against known Windows hashes',
      'Collect thread stack backtrace'
    ]
  },
  {
    id: 'alt-9140',
    pid: 9140,
    processName: 'rundll32.exe',
    process: 'rundll32.exe',
    score: 82,
    threatScore: 82,
    level: 'HIGH',
    threatLevel: 'High',
    application: 'System Utility',
    scoreMode: 'CORRELATED',
    behaviorScore: 84,
    memoryScore: 79,
    correlation: 'Suspicious Child + Modified Section',
    memoryEvidence: {
      present: true,
      strength: 'HIGH',
      indicators: ['Temp DLL section transitioned to RWX execution'],
      details: ['Temp DLL section transitioned to RWX execution'],
      rwxRegions: 1,
      scanStatus: 'SCANNED',
      timestamp: '2026-09-25 12:48:19 UTC'
    },
    detectedAt: '2026-09-25 12:48:19 UTC',
    timestamp: '2026-09-25 12:48:19 UTC',
    status: 'NEW',
    title: 'RWX Memory Transition in rundll32',
    description: 'DLL loaded from temporary directory transitioned memory protection to RWX.',
    recommendedActions: [
      'Isolate executing binary from temporary folder',
      'Check persistence registry keys'
    ]
  },
  {
    id: 'alt-6184',
    pid: 6184,
    processName: 'cmd.exe',
    process: 'cmd.exe',
    score: 68,
    threatScore: 68,
    level: 'MEDIUM',
    threatLevel: 'Medium',
    application: 'System Utility',
    scoreMode: 'BEHAVIOR_ONLY',
    behaviorScore: 82,
    memoryScore: 22,
    correlation: 'Behavioral Reconnaissance Chain',
    memoryEvidence: {
      present: false,
      strength: 'NONE',
      indicators: [],
      details: ['Clean backed image (Behavioral trigger only)'],
      scanStatus: 'SCANNED',
      timestamp: '2026-09-25 12:48:19 UTC'
    },
    detectedAt: '2026-09-25 12:48:19 UTC',
    timestamp: '2026-09-25 12:48:19 UTC',
    status: 'NEW',
    title: 'Command Shell Reconnaissance Activity',
    description: 'Rapid sequential system discovery commands spawned under anomalous user context.',
    recommendedActions: [
      'Review executed commands in session audit log',
      'Verify administrative session origin'
    ]
  },
  {
    id: 'alt-10420',
    pid: 10420,
    processName: 'msedge.exe',
    process: 'msedge.exe',
    score: 64,
    threatScore: 64,
    level: 'MEDIUM',
    threatLevel: 'Medium',
    application: 'Verified Third-Party',
    scoreMode: 'MEMORY_ONLY',
    behaviorScore: 28,
    memoryScore: 71,
    correlation: 'Memory Anomaly (Dynamic JIT Buffer)',
    memoryEvidence: {
      present: true,
      strength: 'MEDIUM',
      indicators: ['High entropy dynamic executable heap (512 KB)'],
      details: ['High entropy dynamic executable heap (512 KB)'],
      privateExecutableRegions: 1,
      scanStatus: 'SCANNED',
      timestamp: '2026-09-25 12:48:19 UTC'
    },
    detectedAt: '2026-09-25 12:48:19 UTC',
    timestamp: '2026-09-25 12:48:19 UTC',
    status: 'DISMISSED',
    title: 'Browser JIT Code Cache High Entropy',
    description: 'Dynamic executable page allocated by browser renderer process with high Shannon entropy.',
    recommendedActions: [
      'Monitor for secondary child process creation',
      'Verify active browser tabs against corporate threat intelligence'
    ]
  },
  {
    id: 'alt-11520',
    pid: 11520,
    processName: 'python.exe',
    process: 'python.exe',
    score: 28,
    threatScore: 28,
    level: 'LOW',
    threatLevel: 'Low',
    application: 'Verified Third-Party',
    scoreMode: 'BASELINE_ADJUSTED',
    behaviorScore: 25,
    memoryScore: 30,
    correlation: 'Baseline Developer Activity',
    memoryEvidence: {
      present: false,
      strength: 'NONE',
      indicators: [],
      details: ['Standard private commit heap'],
      scanStatus: 'SCANNED',
      timestamp: '2026-09-25 12:48:19 UTC'
    },
    detectedAt: '2026-09-25 12:48:19 UTC',
    timestamp: '2026-09-25 12:48:19 UTC',
    status: 'RESOLVED',
    title: 'Developer Python Environment Routine Baseline',
    description: 'Standard local development execution matching known developer workstation profile.',
    recommendedActions: [
      'No containment required. Validated developer baseline.'
    ]
  }
];

export const mockScanHistory: ScanHistoryItem[] = [
  {
    id: 'scan-20260925-01',
    scanDate: '2026-09-25 12:48:19 UTC',
    processes: 148,
    alerts: 6,
    critical: 1,
    high: 2,
    medium: 2,
    low: 1,
    highestScore: 94,
    duration: '4.82s',
    status: 'Investigation Flags',
    engineVersion: 'v2.4.1-core'
  },
  {
    id: 'scan-20260925-02',
    scanDate: '2026-09-25 11:30:00 UTC',
    processes: 146,
    alerts: 3,
    critical: 0,
    high: 1,
    medium: 2,
    low: 0,
    highestScore: 74,
    duration: '4.65s',
    status: 'Investigation Flags',
    engineVersion: 'v2.4.1-core'
  },
  {
    id: 'scan-20260925-03',
    scanDate: '2026-09-25 10:00:14 UTC',
    processes: 144,
    alerts: 1,
    critical: 0,
    high: 0,
    medium: 1,
    low: 0,
    highestScore: 52,
    duration: '4.51s',
    status: 'Completed',
    engineVersion: 'v2.4.1-core'
  },
  {
    id: 'scan-20260925-04',
    scanDate: '2026-09-25 08:30:05 UTC',
    processes: 142,
    alerts: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    highestScore: 16,
    duration: '4.38s',
    status: 'Verified Clean',
    engineVersion: 'v2.4.1-core'
  },
  {
    id: 'scan-20260924-01',
    scanDate: '2026-09-24 22:00:00 UTC',
    processes: 140,
    alerts: 2,
    critical: 0,
    high: 1,
    medium: 1,
    low: 0,
    highestScore: 78,
    duration: '4.44s',
    status: 'Investigation Flags',
    engineVersion: 'v2.4.0-core'
  },
  {
    id: 'scan-20260924-02',
    scanDate: '2026-09-24 16:15:22 UTC',
    processes: 139,
    alerts: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    highestScore: 12,
    duration: '4.29s',
    status: 'Verified Clean',
    engineVersion: 'v2.4.0-core'
  }
];

export const mockThreatActivityTimeline = [
  { time: '08:00', totalInspected: 142, elevatedThreats: 0, avgScore: 14 },
  { time: '09:00', totalInspected: 143, elevatedThreats: 0, avgScore: 15 },
  { time: '10:00', totalInspected: 144, elevatedThreats: 1, avgScore: 22 },
  { time: '11:00', totalInspected: 145, elevatedThreats: 2, avgScore: 36 },
  { time: '12:00', totalInspected: 147, elevatedThreats: 4, avgScore: 58 },
  { time: '12:48', totalInspected: 148, elevatedThreats: 6, avgScore: 72 }
];

export const mockReports: ReportItem[] = [
  {
    id: 'rep-01',
    name: 'scan_results.json',
    type: 'json',
    size: '184.2 KB',
    lastModified: '2026-09-25 12:48:21 UTC',
    description: 'Structured JSON telemetry export from the memory & behavioral analysis engine containing serialized process metadata, memory regions, and correlation vectors.',
    recordCount: 148,
    content: JSON.stringify({
      schema_version: "2.4.0",
      product: "PhantomTrace",
      subtitle: "Memory & Fileless Threat Detection",
      engine: {
        version: "v2.4.1-core",
        architecture: "x86_64",
        read_only_enforced: true,
        execution_time_seconds: 4.82
      },
      scan_metadata: {
        timestamp: "2026-09-25T12:48:19Z",
        target_hostname: "SEC-WORKSTATION-09",
        os_version: "Windows 11 Pro 64-bit (10.0.22631)",
        total_processes_scanned: 148,
        elevated_threat_count: 6,
        highest_threat_score: 94
      },
      summary_scores: {
        critical: 1,
        high: 2,
        medium: 2,
        low: 1,
        clean: 142
      },
      alerts: [
        {
          pid: 4892,
          process: "powershell.exe",
          threat_score: 94,
          threat_level: "Critical",
          score_mode: "Correlated",
          memory_evidence_count: 3,
          behavior_evidence_count: 4,
          primary_memory_indicator: "PAGE_EXECUTE_READWRITE unbacked region at 0x00007FFA4B8A0000",
          mitre_techniques: ["T1059.001", "T1055.001", "T1105", "T1562.001"]
        },
        {
          pid: 7216,
          process: "svchost.exe",
          threat_score: 88,
          threat_level: "High",
          score_mode: "Correlated",
          memory_evidence_count: 2,
          behavior_evidence_count: 2,
          primary_memory_indicator: "Trampoline hook at ntdll!NtCreateThreadEx",
          mitre_techniques: ["T1055.001", "T1071.001"]
        },
        {
          pid: 9140,
          process: "rundll32.exe",
          threat_score: 82,
          threat_level: "High",
          score_mode: "Correlated",
          memory_evidence_count: 1,
          behavior_evidence_count: 3,
          primary_memory_indicator: "Temp DLL section transitioned to RWX",
          mitre_techniques: ["T1218.011", "T1074.001"]
        }
      ]
    }, null, 2)
  },
  {
    id: 'rep-02',
    name: 'phantomtrace_validation_report.txt',
    type: 'txt',
    size: '14.8 KB',
    lastModified: '2026-09-25 12:48:24 UTC',
    description: 'Human-readable validation and forensic audit log confirming engine read-only constraints, memory integrity verification, and diagnostic subsystem self-checks.',
    content: `================================================================================
PHANTOMTRACE THREAT DETECTION & VALIDATION AUDIT REPORT
Product: PhantomTrace - Memory & Fileless Threat Detection
Tagline: "Trace what others can't see."
Engine Version: v2.4.1-core | Build: 20260918-RELEASE
Host: SEC-WORKSTATION-09 (Windows 11 64-bit)
Timestamp: 2026-09-25 12:48:24 UTC
================================================================================

1. SAFETY & INTEGRITY ENFORCEMENT
--------------------------------------------------------------------------------
[PASS] READ_ONLY_SAFETY_CONTROLS: Active
       - Process termination handles: RESTRICTED / DISABLED
       - File modification APIs: RESTRICTED / DISABLED
       - Registry writing routines: RESTRICTED / DISABLED
       - Endpoint state perturbation: 0 mutations detected
       - Forensic baseline preservation: 100% verified

2. MEMORY SCAN SUBSYSTEM DIAGNOSTICS
--------------------------------------------------------------------------------
[PASS] VirtualQueryEx iterator initialized: 148 target process contexts
[PASS] Page protection filter: PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE
[PASS] Memory commitment inspection: 3,240 MB scanned across all active threads
[PASS] Hollowed PE header heuristic: 1 anomaly detected (PID 4892)
[PASS] Inline API hook detection: 1 trampoline detected (PID 7216)

3. BEHAVIORAL CORRELATION MATRIX
--------------------------------------------------------------------------------
Processes Evaluated: 148
Elevated Risk Flagged: 6
  - Critical Severity (Score 90-100): 1 [PID: 4892 powershell.exe]
  - High Severity     (Score 75-89):  2 [PID: 7216 svchost.exe, PID: 9140 rundll32.exe]
  - Medium Severity   (Score 50-74):  2 [PID: 6184 cmd.exe, PID: 10420 msedge.exe]
  - Low Severity      (Score 25-49):  1 [PID: 11520 python.exe]
  - Baseline / Clean  (Score 0-24):   142 processes

4. FORENSIC EVIDENCE CORRELATION SUMMARY
--------------------------------------------------------------------------------
Notice: Memory evidence is strictly preserved even when processes resolve to
trusted system binaries (e.g. svchost.exe PID 7216).
Investigation steps should adhere to standard read-only triage protocols.
No process has been terminated or modified by the PhantomTrace engine.

================================================================================
END OF VALIDATION REPORT - PHANTOMTRACE ENGINE v2.4.1-core
================================================================================`
  },
  {
    id: 'rep-03',
    name: 'alert_history.json',
    type: 'json',
    size: '42.6 KB',
    lastModified: '2026-09-25 12:48:22 UTC',
    description: 'Chronological security alert log records documenting behavioral signatures, memory indicators, and analyst triage status across consecutive scan cycles.',
    recordCount: 28,
    content: JSON.stringify({
      log_cycle_id: "cycle-20260925-0819",
      total_recorded_events: 6,
      retention_period_days: 90,
      audit_events: [
        {
          event_id: "evt-001",
          timestamp: "2026-09-25T12:47:04Z",
          pid: 4892,
          process: "powershell.exe",
          threat_score: 94,
          action_taken: "Alert Dispatched (Read-Only)",
          rule_triggered: "PT-RULE-MEM-0842 (Unbacked RWX Shellcode Allocation)",
          analyst_status: "Pending Investigation"
        },
        {
          event_id: "evt-002",
          timestamp: "2026-09-25T12:44:22Z",
          pid: 7216,
          process: "svchost.exe",
          threat_score: 88,
          action_taken: "Alert Dispatched (Read-Only)",
          rule_triggered: "PT-RULE-CORR-0210 (Trusted Binary Trampoline Injection)",
          analyst_status: "Escalated to Tier 2 Forensics"
        },
        {
          event_id: "evt-003",
          timestamp: "2026-09-25T12:47:33Z",
          pid: 9140,
          process: "rundll32.exe",
          threat_score: 82,
          action_taken: "Alert Dispatched (Read-Only)",
          rule_triggered: "PT-RULE-BEH-0199 (Temp Directory Ordinal Invocation)",
          analyst_status: "Pending Investigation"
        }
      ]
    }, null, 2)
  }
];

export const mockSettings: SystemSettings = {
  scanner: {
    scannerId: "PT-SCANNER-WIN-NODE-01",
    engineMode: "Deep Memory & Behavioral Analysis",
    pollingIntervalSeconds: 15,
    readOnlyEnforced: true,
    targetArchitecture: "Windows x86_64",
    bufferMemoryLimitMb: 4096,
    telemetryProtocol: "HTTPS REST + Secure Websocket"
  },
  api: {
    endpointUrl: "https://api.phantomtrace.security/v1/telemetry",
    apiKeyMasked: "pt_live_•••••••••••••••••••••••••7f8a",
    timeoutSeconds: 30,
    ingestionStatus: "Ready for Ingestion Stream",
    corsOrigin: "https://console.phantomtrace.security",
    version: "v1.4.2"
  },
  firebase: {
    projectId: "phantomtrace-sec-prod",
    firestoreCollection: "scan_telemetry",
    authDomain: "phantomtrace-sec-prod.firebaseapp.com",
    storageBucket: "phantomtrace-sec-prod.appspot.com",
    realtimeSync: true,
    syncStatus: "Configured (Awaiting Ingestion Pipeline)"
  },
  auth: {
    currentAnalyst: "Security Analyst (ID: SEC-8842)",
    role: "Lead Threat Responder",
    organization: "Enterprise Cyber Operations Center",
    sessionExpiry: "8 hours remaining",
    auditLoggingEnabled: true
  }
};
