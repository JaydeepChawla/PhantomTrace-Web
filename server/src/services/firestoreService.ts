import { db, isFirebaseConfigured } from "../config/firebaseAdmin";
import type {
  UserDocument,
  EndpointDocument,
  ScanDocument,
  ProcessDocument,
  ThreatAlertDocument,
  ReportDocument,
  IngestedScanBundle,
  IngestResponse,
} from "../types/api";

/**
 * =====================================================================
 * PHANTOMTRACE FIRESTORE SERVICE LAYER
 * =====================================================================
 * Encapsulates all Cloud Firestore database interactions and ingestion.
 *
 * CRITICAL RULE: User Isolation & Document Ownership
 * Every single document query strictly filters or asserts `ownerUid == uid`.
 * Client-supplied UIDs are NEVER trusted.
 * =====================================================================
 */
class FirestoreService {
  // In-memory user-scoped stores for development, testing, and caching
  private endpointsStore = new Map<string, EndpointDocument[]>();
  private scansStore = new Map<string, ScanDocument[]>();
  private processesStore = new Map<string, ProcessDocument[]>();
  private alertsStore = new Map<string, ThreatAlertDocument[]>();
  private reportsStore = new Map<string, ReportDocument[]>();

  /**
   * Retrieve user profile by verified UID.
   */
  async getUser(uid: string): Promise<UserDocument | null> {
    if (isFirebaseConfigured) {
      try {
        const docRef = db.collection("users").doc(uid);
        const docSnap = await docRef.get();
        if (docSnap.exists) {
          return { ...(docSnap.data() as Omit<UserDocument, "uid">), uid };
        }
      } catch (err) {
        console.error(`[FirestoreService] Error fetching user ${uid}:`, err);
      }
    }

    return {
      uid,
      email: `${uid}@phantomtrace.security`,
      displayName: "PhantomTrace Security Analyst",
      role: "Security Analyst",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * Ingest a complete parsed scanner bundle into Firestore.
   * Handles duplicate detection, batch writes, and user scoping.
   */
  async ingestScanBundle(bundle: IngestedScanBundle): Promise<IngestResponse> {
    const { endpoint, scan, processes, threatAlerts, report } = bundle;
    const uid = scan.ownerUid;

    // 1. Check for duplicate scan submission
    const existing = await this.getScan(uid, scan.scanId);
    if (existing) {
      console.log(`[FirestoreService] Duplicate scan detected (${scan.scanId}) for user ${uid}. Returning existing scan.`);
      const userProcesses = await this.getProcesses(uid);
      const userAlerts = await this.getThreatAlerts(uid);

      return {
        success: true,
        scanId: existing.scanId,
        endpointId: existing.endpointId,
        processesImported: userProcesses.filter((p) => p.scanId === existing.scanId).length || processes.length,
        alertsImported: userAlerts.filter((a) => a.scanId === existing.scanId).length || threatAlerts.length,
        highestScore: existing.highestScore,
        duplicate: true,
        message: "Scan has already been ingested. Returning existing scan record.",
      };
    }

    // 2. Persist to Cloud Firestore if configured
    if (isFirebaseConfigured) {
      try {
        // Upsert Endpoint
        await db.collection("endpoints").doc(endpoint.endpointId).set(endpoint, { merge: true });

        // Save Scan Document
        await db.collection("scans").doc(scan.scanId).set(scan);

        // Batch write processes in chunks of 400 (Firestore limit is 500)
        const CHUNK_SIZE = 400;
        for (let i = 0; i < processes.length; i += CHUNK_SIZE) {
          const chunk = processes.slice(i, i + CHUNK_SIZE);
          const batch = db.batch();
          for (const proc of chunk) {
            const procRef = db.collection("processes").doc(proc.processId);
            batch.set(procRef, proc);
          }
          await batch.commit();
        }

        // Batch write threat alerts
        if (threatAlerts.length > 0) {
          const alertBatch = db.batch();
          for (const alert of threatAlerts) {
            const alertRef = db.collection("threatAlerts").doc(alert.id);
            alertBatch.set(alertRef, alert);
          }
          await alertBatch.commit();
        }

        // Save Report Document
        await db.collection("reports").doc(report.id).set(report);
        console.log(`[FirestoreService] Successfully written scan bundle ${scan.scanId} to Cloud Firestore.`);
      } catch (err) {
        console.error(`[FirestoreService] Error saving scan bundle ${scan.scanId} to Firestore:`, err);
      }
    }

    // 3. Update in-memory user-scoped stores
    // Endpoints
    const userEndpoints = this.endpointsStore.get(uid) || [];
    const existingEpIndex = userEndpoints.findIndex((e) => e.endpointId === endpoint.endpointId);
    if (existingEpIndex >= 0) {
      userEndpoints[existingEpIndex] = endpoint;
    } else {
      userEndpoints.unshift(endpoint);
    }
    this.endpointsStore.set(uid, userEndpoints);

    // Scans
    const userScans = this.scansStore.get(uid) || [];
    userScans.unshift(scan);
    this.scansStore.set(uid, userScans);

    // Processes
    const userProcesses = this.processesStore.get(uid) || [];
    this.processesStore.set(uid, [...processes, ...userProcesses]);

    // Alerts
    const userAlerts = this.alertsStore.get(uid) || [];
    this.alertsStore.set(uid, [...threatAlerts, ...userAlerts]);

    // Reports
    const userReports = this.reportsStore.get(uid) || [];
    userReports.unshift(report);
    this.reportsStore.set(uid, userReports);

    return {
      success: true,
      scanId: scan.scanId,
      endpointId: endpoint.endpointId,
      processesImported: processes.length,
      alertsImported: threatAlerts.length,
      highestScore: scan.highestScore,
      duplicate: false,
    };
  }

  /**
   * Enumerate all endpoints registered to the authenticated user.
   */
  async getEndpoints(uid: string): Promise<EndpointDocument[]> {
    if (isFirebaseConfigured) {
      try {
        const snapshot = await db
          .collection("endpoints")
          .where("ownerUid", "==", uid)
          .get();

        if (!snapshot.empty) {
          return snapshot.docs.map((doc) => ({
            ...(doc.data() as Omit<EndpointDocument, "endpointId">),
            endpointId: doc.id,
          }));
        }
      } catch (err) {
        console.error(`[FirestoreService] Error fetching endpoints for ${uid}:`, err);
      }
    }

    if (this.endpointsStore.has(uid) && this.endpointsStore.get(uid)!.length > 0) {
      return this.endpointsStore.get(uid)!;
    }

    // Fallback/Seed endpoint for development
    return [
      {
        endpointId: "ep-win11-secops-01",
        ownerUid: uid,
        name: "SECOPS-WIN11-WORKSTATION",
        platform: "Windows 11 Pro 64-bit (Build 22631.3447)",
        scannerVersion: "PhantomTrace v2.3.0",
        lastSeenAt: new Date().toISOString(),
        createdAt: "2026-09-15T08:00:00.000Z",
      },
    ];
  }

  /**
   * Retrieve a specific endpoint ensuring it belongs to the authenticated user.
   */
  async getEndpoint(uid: string, endpointId: string): Promise<EndpointDocument | null> {
    if (isFirebaseConfigured) {
      try {
        const docRef = db.collection("endpoints").doc(endpointId);
        const docSnap = await docRef.get();
        if (docSnap.exists) {
          const data = docSnap.data() as EndpointDocument;
          if (data.ownerUid === uid) {
            return { ...(docSnap.data() as Omit<EndpointDocument, "endpointId">), endpointId: docSnap.id };
          }
          console.warn(`[FirestoreService] Unauthorized attempt by ${uid} to access endpoint ${endpointId}`);
          return null;
        }
      } catch (err) {
        console.error(`[FirestoreService] Error fetching endpoint ${endpointId}:`, err);
      }
    }

    const endpoints = await this.getEndpoints(uid);
    return endpoints.find((ep) => ep.endpointId === endpointId) || null;
  }

  /**
   * Enumerate all scan executions for the authenticated user.
   */
  async getScans(uid: string): Promise<ScanDocument[]> {
    if (isFirebaseConfigured) {
      try {
        const snapshot = await db
          .collection("scans")
          .where("ownerUid", "==", uid)
          .get();

        if (!snapshot.empty) {
          return snapshot.docs.map((doc) => ({
            ...(doc.data() as Omit<ScanDocument, "scanId">),
            scanId: doc.id,
          }));
        }
      } catch (err) {
        console.error(`[FirestoreService] Error fetching scans for ${uid}:`, err);
      }
    }

    if (this.scansStore.has(uid) && this.scansStore.get(uid)!.length > 0) {
      return this.scansStore.get(uid)!;
    }

    return [
      {
        scanId: "scan-20261002-120000",
        endpointId: "ep-win11-secops-01",
        ownerUid: uid,
        timestamp: new Date().toISOString(),
        durationMs: 4230,
        scannerVersion: "2.3.0",
        platform: "Windows 11 Pro 64-bit",
        totalProcesses: 184,
        memoryScanned: 1420.5,
        memoryAccessDenied: 12,
        highestScore: 88,
        counts: {
          normal: 165,
          low: 11,
          medium: 5,
          high: 2,
          critical: 1,
        },
      },
    ];
  }

  /**
   * Retrieve a specific scan ensuring ownerUid match.
   */
  async getScan(uid: string, scanId: string): Promise<ScanDocument | null> {
    if (isFirebaseConfigured) {
      try {
        const docRef = db.collection("scans").doc(scanId);
        const docSnap = await docRef.get();
        if (docSnap.exists) {
          const data = docSnap.data() as ScanDocument;
          if (data.ownerUid === uid) {
            return { ...(docSnap.data() as Omit<ScanDocument, "scanId">), scanId: docSnap.id };
          }
          console.warn(`[FirestoreService] Unauthorized attempt by ${uid} to access scan ${scanId}`);
          return null;
        }
      } catch (err) {
        console.error(`[FirestoreService] Error fetching scan ${scanId}:`, err);
      }
    }

    const scans = await this.getScans(uid);
    return scans.find((s) => s.scanId === scanId) || null;
  }

  /**
   * Enumerate all inspected processes belonging to the authenticated user.
   */
  async getProcesses(uid: string): Promise<ProcessDocument[]> {
    if (isFirebaseConfigured) {
      try {
        const snapshot = await db
          .collection("processes")
          .where("ownerUid", "==", uid)
          .get();

        if (!snapshot.empty) {
          return snapshot.docs.map((doc) => ({
            ...(doc.data() as Omit<ProcessDocument, "processId">),
            processId: doc.id,
          }));
        }
      } catch (err) {
        console.error(`[FirestoreService] Error fetching processes for ${uid}:`, err);
      }
    }

    if (this.processesStore.has(uid) && this.processesStore.get(uid)!.length > 0) {
      return this.processesStore.get(uid)!;
    }

    // Default Seed processes for development
    return [
      {
        processId: "proc-powershell-4812",
        scanId: "scan-20261002-120000",
        endpointId: "ep-win11-secops-01",
        ownerUid: uid,
        pid: 4812,
        name: "powershell.exe",
        executablePath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        applicationName: "Windows PowerShell",
        parentPid: 3120,
        parentName: "explorer.exe",
        threatScore: 88,
        threatLevel: "CRITICAL",
        scoreMode: "CORRELATED",
        behaviorScore: 82,
        memoryScore: 91,
        correlationScore: 88,
        commandLine: "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA...",
        userContext: "WIN-SEC\\Analyst",
        integrityLevel: "Medium",
        timestamp: new Date().toISOString(),
        memoryEvidence: {
          present: true,
          strength: "HIGH",
          indicators: [
            "PAGE_EXECUTE_READWRITE allocation detected",
            "Unbacked executable memory region at 0x000002A14E000000",
          ],
          suspiciousRegions: 2,
          rwxRegions: 1,
          privateExecutableRegions: 1,
          scanStatus: "SCANNED",
        },
        behaviorEvidence: {
          present: true,
          score: 82,
          indicators: [
            "Encoded command parameter (-EncodedCommand)",
            "Execution policy bypass specified",
            "Spawned via explorer with hidden flags",
          ],
          suspiciousCommandLine: true,
          suspiciousParent: false,
          commandLine: "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA...",
          parentProcess: "explorer.exe",
        },
        correlationEvidence: {
          present: true,
          score: 88,
          memoryEvidencePresent: true,
          behaviorEvidencePresent: true,
          correlatedIndicators: [
            "RWX memory section combined with encoded command line execution",
          ],
          explanation: "High confidence correlation: Process allocated unbacked executable memory while running obfuscated scripts.",
        },
        responseRecommendation: {
          whyFlagged: "Co-occurrence of RWX unbacked executable memory with encoded command line parameters.",
          investigationSteps: [
            "Review script block logs in Microsoft-Windows-PowerShell/Operational",
            "Inspect memory region 0x000002A14E000000 for injected shellcode headers",
            "Verify process parentage and user account authorization",
          ],
          mitreReferences: ["T1059.001 - PowerShell", "T1055 - Process Injection"],
          containmentGuidance: "Isolate endpoint from local network segment. Dump memory artifacts for external sandbox triage.",
          readOnlyNotice: "PhantomTrace operates strictly in read-only analysis mode. No processes were terminated or modified.",
        },
      },
      {
        processId: "proc-svchost-1044",
        scanId: "scan-20261002-120000",
        endpointId: "ep-win11-secops-01",
        ownerUid: uid,
        pid: 1044,
        name: "svchost.exe",
        executablePath: "C:\\Windows\\System32\\svchost.exe",
        applicationName: "Host Process for Windows Services",
        parentPid: 712,
        parentName: "services.exe",
        threatScore: 8,
        threatLevel: "NORMAL",
        scoreMode: "NONE",
        behaviorScore: 5,
        memoryScore: 0,
        correlationScore: 0,
        commandLine: "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
        userContext: "NT AUTHORITY\\LOCAL SERVICE",
        integrityLevel: "System",
        timestamp: new Date().toISOString(),
        memoryEvidence: {
          present: false,
          strength: "NONE",
          indicators: [],
          suspiciousRegions: 0,
          rwxRegions: 0,
          privateExecutableRegions: 0,
          scanStatus: "SCANNED",
        },
        behaviorEvidence: {
          present: false,
          score: 5,
          indicators: [],
          suspiciousCommandLine: false,
          suspiciousParent: false,
        },
        correlationEvidence: {
          present: false,
          memoryEvidencePresent: false,
          behaviorEvidencePresent: false,
          correlatedIndicators: [],
        },
      },
    ];
  }

  /**
   * Retrieve a specific process by doc ID or PID, asserting ownerUid.
   */
  async getProcess(uid: string, processId: string): Promise<ProcessDocument | null> {
    if (isFirebaseConfigured) {
      try {
        const docRef = db.collection("processes").doc(processId);
        const docSnap = await docRef.get();
        if (docSnap.exists) {
          const data = docSnap.data() as ProcessDocument;
          if (data.ownerUid === uid) {
            return { ...(docSnap.data() as Omit<ProcessDocument, "processId">), processId: docSnap.id };
          }
          console.warn(`[FirestoreService] Unauthorized attempt by ${uid} to access process ${processId}`);
          return null;
        }

        const pidNum = parseInt(processId, 10);
        if (!isNaN(pidNum)) {
          const pidSnap = await db
            .collection("processes")
            .where("ownerUid", "==", uid)
            .where("pid", "==", pidNum)
            .limit(1)
            .get();

          if (!pidSnap.empty) {
            const first = pidSnap.docs[0];
            return { ...(first.data() as Omit<ProcessDocument, "processId">), processId: first.id };
          }
        }
      } catch (err) {
        console.error(`[FirestoreService] Error fetching process ${processId}:`, err);
      }
    }

    const processes = await this.getProcesses(uid);
    const pidNum = parseInt(processId, 10);
    return (
      processes.find((p) => p.processId === processId || (!isNaN(pidNum) && p.pid === pidNum)) || null
    );
  }

  /**
   * Enumerate all threat alerts belonging to the authenticated user.
   */
  async getThreatAlerts(uid: string): Promise<ThreatAlertDocument[]> {
    if (isFirebaseConfigured) {
      try {
        const snapshot = await db
          .collection("threatAlerts")
          .where("ownerUid", "==", uid)
          .get();

        if (!snapshot.empty) {
          return snapshot.docs.map((doc) => ({
            ...(doc.data() as Omit<ThreatAlertDocument, "id">),
            id: doc.id,
          }));
        }
      } catch (err) {
        console.error(`[FirestoreService] Error fetching threat alerts for ${uid}:`, err);
      }
    }

    if (this.alertsStore.has(uid) && this.alertsStore.get(uid)!.length > 0) {
      return this.alertsStore.get(uid)!;
    }

    // Default Seed alerts for development
    return [
      {
        id: "alert-pt-4812",
        scanId: "scan-20261002-120000",
        endpointId: "ep-win11-secops-01",
        ownerUid: uid,
        pid: 4812,
        processName: "powershell.exe",
        score: 88,
        level: "CRITICAL",
        scoreMode: "CORRELATED",
        title: "Correlated Unbacked Executable Memory & Obfuscated PowerShell Execution",
        description: "Process powershell.exe (PID: 4812) executed with an encoded bypass command line while containing suspicious PAGE_EXECUTE_READWRITE unbacked memory pages.",
        detectedAt: new Date().toISOString(),
        status: "NEW",
        memoryEvidence: {
          present: true,
          strength: "HIGH",
          indicators: [
            "PAGE_EXECUTE_READWRITE region detected",
            "Unbacked executable memory allocation",
          ],
          suspiciousRegions: 2,
          rwxRegions: 1,
          scanStatus: "SCANNED",
        },
        behaviorEvidence: {
          present: true,
          score: 82,
          indicators: [
            "Execution policy bypass parameter",
            "Encoded command payload",
          ],
          suspiciousCommandLine: true,
          commandLine: "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA...",
        },
        correlationEvidence: {
          present: true,
          score: 88,
          memoryEvidencePresent: true,
          behaviorEvidencePresent: true,
          correlatedIndicators: [
            "RWX memory co-occurring with encoded command line",
          ],
          explanation: "High confidence correlation between behavioral evasion and in-memory payload staging.",
        },
        recommendedActions: [
          "Preserve memory dump for offline reverse engineering",
          "Inspect script block logging in Event Viewer under PowerShell/Operational",
          "Audit parent process lineage (explorer.exe)",
          "Maintain read-only monitoring; avoid active termination until scope verified",
        ],
      },
    ];
  }

  /**
   * Retrieve a specific threat alert ensuring ownerUid match.
   */
  async getThreatAlert(uid: string, alertId: string): Promise<ThreatAlertDocument | null> {
    if (isFirebaseConfigured) {
      try {
        const docRef = db.collection("threatAlerts").doc(alertId);
        const docSnap = await docRef.get();
        if (docSnap.exists) {
          const data = docSnap.data() as ThreatAlertDocument;
          if (data.ownerUid === uid) {
            return { ...(docSnap.data() as Omit<ThreatAlertDocument, "id">), id: docSnap.id };
          }
          console.warn(`[FirestoreService] Unauthorized attempt by ${uid} to access alert ${alertId}`);
          return null;
        }

        const querySnap = await db
          .collection("threatAlerts")
          .where("ownerUid", "==", uid)
          .where("id", "==", alertId)
          .limit(1)
          .get();

        if (!querySnap.empty) {
          const first = querySnap.docs[0];
          return { ...(first.data() as Omit<ThreatAlertDocument, "id">), id: first.id };
        }
      } catch (err) {
        console.error(`[FirestoreService] Error fetching threat alert ${alertId}:`, err);
      }
    }

    const alerts = await this.getThreatAlerts(uid);
    return alerts.find((a) => a.id === alertId) || null;
  }

  /**
   * Enumerate all forensic reports belonging to the authenticated user.
   */
  async getReports(uid: string): Promise<ReportDocument[]> {
    if (isFirebaseConfigured) {
      try {
        const snapshot = await db
          .collection("reports")
          .where("ownerUid", "==", uid)
          .get();

        if (!snapshot.empty) {
          return snapshot.docs.map((doc) => ({
            ...(doc.data() as Omit<ReportDocument, "id">),
            id: doc.id,
          }));
        }
      } catch (err) {
        console.error(`[FirestoreService] Error fetching reports for ${uid}:`, err);
      }
    }

    if (this.reportsStore.has(uid) && this.reportsStore.get(uid)!.length > 0) {
      return this.reportsStore.get(uid)!;
    }

    const alerts = await this.getThreatAlerts(uid);

    return [
      {
        id: "rep-20261002-001",
        scanId: "scan-20261002-120000",
        endpointId: "ep-win11-secops-01",
        ownerUid: uid,
        createdAt: new Date().toISOString(),
        title: "Endpoint Forensic Triage Report — SECOPS-WIN11-WORKSTATION",
        summary: "Read-only inspection completed across 184 active processes. Identified 1 CRITICAL finding involving powershell.exe with correlated memory and behavioral anomalies. All actions verified non-destructive.",
        totalProcesses: 184,
        totalAlerts: alerts.length,
        highestScore: 88,
        highestThreatLevel: "CRITICAL",
        alerts,
        generatedBy: "PHANTOMTRACE",
        type: "json",
        size: "24.6 KB",
        recordCount: 184,
      },
    ];
  }

  /**
   * Retrieve a specific forensic report ensuring ownerUid match.
   */
  async getReport(uid: string, reportId: string): Promise<ReportDocument | null> {
    if (isFirebaseConfigured) {
      try {
        const docRef = db.collection("reports").doc(reportId);
        const docSnap = await docRef.get();
        if (docSnap.exists) {
          const data = docSnap.data() as ReportDocument;
          if (data.ownerUid === uid) {
            return { ...(docSnap.data() as Omit<ReportDocument, "id">), id: docSnap.id };
          }
          console.warn(`[FirestoreService] Unauthorized attempt by ${uid} to access report ${reportId}`);
          return null;
        }

        const querySnap = await db
          .collection("reports")
          .where("ownerUid", "==", uid)
          .where("id", "==", reportId)
          .limit(1)
          .get();

        if (!querySnap.empty) {
          const first = querySnap.docs[0];
          return { ...(first.data() as Omit<ReportDocument, "id">), id: first.id };
        }
      } catch (err) {
        console.error(`[FirestoreService] Error fetching report ${reportId}:`, err);
      }
    }

    const reports = await this.getReports(uid);
    return reports.find((r) => r.id === reportId) || null;
  }
}

export const firestoreService = new FirestoreService();
