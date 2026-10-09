import { postgresPool } from "../config/postgres";
import type {
    UserDocument,
    EndpointDocument,
    DeviceDocument,
    PairingRequestDocument,
    UserSessionDocument,
    ScanDocument,
    ProcessDocument,
    ThreatAlertDocument,
    ReportDocument,
    IngestedScanBundle,
    IngestResponse,
    WebThreatEventDocument,
} from "../types/api";

class PostgresService {
    private memoryUsers: Map<string, UserDocument> = new Map();
    private memoryScans: Map<string, ScanDocument> = new Map();
    private memoryWebThreatEvents: Map<string, WebThreatEventDocument[]> = new Map();

    async getUser(uid: string): Promise<UserDocument | null> {
        try {
            const result = await postgresPool.query(
                `
          SELECT
            uid,
            email,
            display_name,
            role,
            created_at,
            updated_at
          FROM users
          WHERE uid = $1
          LIMIT 1
          `,
                [uid],
            );

            if (result.rows.length === 0) {
                return null;
            }

            const row = result.rows[0];

            return {
                uid: row.uid,
                email: row.email,
                displayName: row.display_name,
                role: row.role,
                createdAt: new Date(row.created_at).toISOString(),
                updatedAt: new Date(row.updated_at).toISOString(),
            };
        } catch {
            return this.memoryUsers.get(uid) || null;
        }
    }

    async upsertUser(user: UserDocument): Promise<void> {
        this.memoryUsers.set(user.uid, user);
        try {
            await postgresPool.query(
                `
          INSERT INTO users (
            uid,
            email,
            display_name,
            role,
            created_at,
            updated_at
          )
          VALUES ($1, $2, $3, $4, $5, $6)
          ON CONFLICT (uid)
          DO UPDATE SET
            email = EXCLUDED.email,
            display_name = EXCLUDED.display_name,
            role = EXCLUDED.role,
            updated_at = EXCLUDED.updated_at
          `,
                [
                    user.uid,
                    user.email,
                    user.displayName,
                    user.role,
                    user.createdAt,
                    user.updatedAt,
                ],
            );
        } catch {
            // in-memory fallback preserved
        }
    }

    async ingestScanBundle(
        bundle: IngestedScanBundle,
    ): Promise<IngestResponse> {
        const {
            endpoint,
            scan,
            processes,
            threatAlerts,
            report,
        } = bundle;

        const uid = scan.ownerUid;

        let client;
        try {
            client = await postgresPool.connect();
        } catch {
            this.memoryScans.set(scan.scanId, scan);
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

        try {
            await client.query("BEGIN");

            /*
             * ---------------------------------------------------------------
             * 1. Duplicate detection
             * ---------------------------------------------------------------
             */

            const existingScan = await client.query(
                `
        SELECT
          scan_id,
          endpoint_id,
          highest_score
        FROM scans
        WHERE scan_id = $1
          AND owner_uid = $2
        LIMIT 1
        `,
                [scan.scanId, uid],
            );

            if (existingScan.rows.length > 0) {
                await client.query("ROLLBACK");

                const existing = existingScan.rows[0];

                return {
                    success: true,
                    scanId: existing.scan_id,
                    endpointId: existing.endpoint_id,
                    processesImported: processes.length,
                    alertsImported: threatAlerts.length,
                    highestScore: Number(existing.highest_score),
                    duplicate: true,
                    message:
                        "Scan has already been ingested. Returning existing scan record.",
                };
            }

            /*
             * ---------------------------------------------------------------
             * 2. User record
             * ---------------------------------------------------------------
             */

            await client.query(
                `
        INSERT INTO users (
          uid,
          email,
          display_name,
          role,
          created_at,
          updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (uid)
        DO UPDATE SET
          email = EXCLUDED.email,
          display_name = EXCLUDED.display_name,
          role = EXCLUDED.role,
          updated_at = EXCLUDED.updated_at
        `,
                [
                    uid,
                    `${uid}@phantomtrace.security`,
                    "PhantomTrace Security Analyst",
                    "Security Analyst",
                    endpoint.createdAt,
                    endpoint.lastSeenAt,
                ],
            );

            /*
             * ---------------------------------------------------------------
             * 3. Endpoint
             * ---------------------------------------------------------------
             */

            await client.query(
                `
        INSERT INTO endpoints (
          endpoint_id,
          owner_uid,
          name,
          platform,
          scanner_version,
          last_seen_at,
          created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (endpoint_id)
        DO UPDATE SET
          owner_uid = EXCLUDED.owner_uid,
          name = EXCLUDED.name,
          platform = EXCLUDED.platform,
          scanner_version = EXCLUDED.scanner_version,
          last_seen_at = EXCLUDED.last_seen_at
        `,
                [
                    endpoint.endpointId,
                    endpoint.ownerUid,
                    endpoint.name,
                    endpoint.platform,
                    endpoint.scannerVersion,
                    endpoint.lastSeenAt,
                    endpoint.createdAt,
                ],
            );

            /*
             * ---------------------------------------------------------------
             * 4. Scan
             * ---------------------------------------------------------------
             */

            await client.query(
                `
        INSERT INTO scans (
          scan_id,
          endpoint_id,
          owner_uid,
          timestamp,
          duration_ms,
          scanner_version,
          platform,
          total_processes,
          memory_scanned,
          memory_access_denied,
          highest_score,
          counts
        )
        VALUES (
          $1, $2, $3, $4, $5, $6,
          $7, $8, $9, $10, $11, $12::jsonb
        )
        `,
                [
                    scan.scanId,
                    scan.endpointId,
                    scan.ownerUid,
                    scan.timestamp,
                    scan.durationMs ?? null,
                    scan.scannerVersion ?? null,
                    scan.platform ?? null,
                    scan.totalProcesses,
                    scan.memoryScanned ?? null,
                    scan.memoryAccessDenied ?? null,
                    scan.highestScore,
                    JSON.stringify(scan.counts),
                ],
            );

            /*
             * ---------------------------------------------------------------
             * 5. Processes
             *
             * Nested memory / behavior / correlation evidence is preserved
             * as JSONB.
             * ---------------------------------------------------------------
             */

            for (const process of processes) {
                await client.query(
                    `
          INSERT INTO processes (
            process_id,
            scan_id,
            endpoint_id,
            owner_uid,
            pid,
            name,
            executable_path,
            application_name,
            parent_pid,
            parent_name,
            threat_score,
            threat_level,
            score_mode,
            behavior_score,
            memory_score,
            correlation_score,
            memory_evidence,
            behavior_evidence,
            correlation_evidence,
            timestamp,
            command_line,
            user_context,
            integrity_level,
            response_recommendation
          )
          VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8,
            $9, $10, $11, $12, $13, $14, $15, $16,
            $17::jsonb, $18::jsonb, $19::jsonb,
            $20, $21, $22, $23, $24::jsonb
          )
          ON CONFLICT (process_id)
          DO UPDATE SET
            scan_id = EXCLUDED.scan_id,
            endpoint_id = EXCLUDED.endpoint_id,
            owner_uid = EXCLUDED.owner_uid,
            pid = EXCLUDED.pid,
            name = EXCLUDED.name,
            executable_path = EXCLUDED.executable_path,
            application_name = EXCLUDED.application_name,
            parent_pid = EXCLUDED.parent_pid,
            parent_name = EXCLUDED.parent_name,
            threat_score = EXCLUDED.threat_score,
            threat_level = EXCLUDED.threat_level,
            score_mode = EXCLUDED.score_mode,
            behavior_score = EXCLUDED.behavior_score,
            memory_score = EXCLUDED.memory_score,
            correlation_score = EXCLUDED.correlation_score,
            memory_evidence = EXCLUDED.memory_evidence,
            behavior_evidence = EXCLUDED.behavior_evidence,
            correlation_evidence = EXCLUDED.correlation_evidence,
            timestamp = EXCLUDED.timestamp,
            command_line = EXCLUDED.command_line,
            user_context = EXCLUDED.user_context,
            integrity_level = EXCLUDED.integrity_level,
            response_recommendation = EXCLUDED.response_recommendation
          `,
                    [
                        process.processId,
                        process.scanId,
                        process.endpointId,
                        process.ownerUid,
                        process.pid,
                        process.name,
                        process.executablePath ?? null,
                        process.applicationName ?? null,
                        process.parentPid ?? null,
                        process.parentName ?? null,
                        process.threatScore,
                        process.threatLevel,
                        process.scoreMode,
                        process.behaviorScore ?? null,
                        process.memoryScore ?? null,
                        process.correlationScore ?? null,
                        JSON.stringify(process.memoryEvidence ?? null),
                        JSON.stringify(process.behaviorEvidence ?? null),
                        JSON.stringify(process.correlationEvidence ?? null),
                        process.timestamp,
                        process.commandLine ?? null,
                        process.userContext ?? null,
                        process.integrityLevel ?? null,
                        JSON.stringify(process.responseRecommendation ?? null),
                    ],
                );
            }

            /*
             * ---------------------------------------------------------------
             * 6. Threat alerts
             * ---------------------------------------------------------------
             */

            for (const alert of threatAlerts) {
                await client.query(
                    `
          INSERT INTO threat_alerts (
            id,
            scan_id,
            endpoint_id,
            owner_uid,
            pid,
            process_name,
            score,
            level,
            score_mode,
            title,
            description,
            memory_evidence,
            behavior_evidence,
            correlation_evidence,
            detected_at,
            status,
            recommended_actions
          )
          VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9,
            $10, $11, $12::jsonb, $13::jsonb, $14::jsonb,
            $15, $16, $17::jsonb
          )
          ON CONFLICT (id)
          DO UPDATE SET
            scan_id = EXCLUDED.scan_id,
            endpoint_id = EXCLUDED.endpoint_id,
            owner_uid = EXCLUDED.owner_uid,
            pid = EXCLUDED.pid,
            process_name = EXCLUDED.process_name,
            score = EXCLUDED.score,
            level = EXCLUDED.level,
            score_mode = EXCLUDED.score_mode,
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            memory_evidence = EXCLUDED.memory_evidence,
            behavior_evidence = EXCLUDED.behavior_evidence,
            correlation_evidence = EXCLUDED.correlation_evidence,
            detected_at = EXCLUDED.detected_at,
            status = EXCLUDED.status,
            recommended_actions = EXCLUDED.recommended_actions
          `,
                    [
                        alert.id,
                        alert.scanId,
                        alert.endpointId,
                        alert.ownerUid,
                        alert.pid,
                        alert.processName,
                        alert.score,
                        alert.level,
                        alert.scoreMode,
                        alert.title ?? null,
                        alert.description ?? null,
                        JSON.stringify(alert.memoryEvidence ?? null),
                        JSON.stringify(alert.behaviorEvidence ?? null),
                        JSON.stringify(alert.correlationEvidence ?? null),
                        alert.detectedAt,
                        alert.status ?? null,
                        JSON.stringify(alert.recommendedActions ?? null),
                    ],
                );
            }

            /*
             * ---------------------------------------------------------------
             * 7. Report
             * ---------------------------------------------------------------
             */

            await client.query(
                `
        INSERT INTO reports (
          id,
          scan_id,
          endpoint_id,
          owner_uid,
          created_at,
          title,
          summary,
          total_processes,
          total_alerts,
          highest_score,
          highest_threat_level,
          alerts,
          generated_by,
          type,
          size,
          record_count
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7,
          $8, $9, $10, $11, $12::jsonb,
          $13, $14, $15, $16
        )
        ON CONFLICT (id)
        DO UPDATE SET
          scan_id = EXCLUDED.scan_id,
          endpoint_id = EXCLUDED.endpoint_id,
          owner_uid = EXCLUDED.owner_uid,
          created_at = EXCLUDED.created_at,
          title = EXCLUDED.title,
          summary = EXCLUDED.summary,
          total_processes = EXCLUDED.total_processes,
          total_alerts = EXCLUDED.total_alerts,
          highest_score = EXCLUDED.highest_score,
          highest_threat_level = EXCLUDED.highest_threat_level,
          alerts = EXCLUDED.alerts,
          generated_by = EXCLUDED.generated_by,
          type = EXCLUDED.type,
          size = EXCLUDED.size,
          record_count = EXCLUDED.record_count
        `,
                [
                    report.id,
                    report.scanId,
                    report.endpointId,
                    report.ownerUid,
                    report.createdAt,
                    report.title,
                    report.summary,
                    report.totalProcesses,
                    report.totalAlerts,
                    report.highestScore,
                    report.highestThreatLevel,
                    JSON.stringify(report.alerts),
                    report.generatedBy ?? null,
                    report.type ?? null,
                    report.size ?? null,
                    report.recordCount ?? null,
                ],
            );

            await client.query("COMMIT");

            console.log(
                `[PostgreSQL] Successfully stored scan ${scan.scanId} for user ${uid}.`,
            );

            return {
                success: true,
                scanId: scan.scanId,
                endpointId: endpoint.endpointId,
                processesImported: processes.length,
                alertsImported: threatAlerts.length,
                highestScore: scan.highestScore,
                duplicate: false,
            };
        } catch (error) {
            await client.query("ROLLBACK");

            console.error(
                `[PostgreSQL] Failed to ingest scan ${scan.scanId}:`,
                error,
            );

            throw error;
        } finally {
            client.release();
        }
    }

    async getEndpoints(uid: string): Promise<EndpointDocument[]> {
        const result = await postgresPool.query(
            `
      SELECT
        endpoint_id,
        owner_uid,
        name,
        platform,
        scanner_version,
        last_seen_at,
        created_at
      FROM endpoints
      WHERE owner_uid = $1
      ORDER BY last_seen_at DESC
      `,
            [uid],
        );

        return result.rows.map((row) => ({
            endpointId: row.endpoint_id,
            ownerUid: row.owner_uid,
            name: row.name,
            platform: row.platform,
            scannerVersion: row.scanner_version,
            lastSeenAt: new Date(row.last_seen_at).toISOString(),
            createdAt: new Date(row.created_at).toISOString(),
        }));
    }

    async getEndpoint(
        uid: string,
        endpointId: string,
    ): Promise<EndpointDocument | null> {
        const result = await postgresPool.query(
            `
      SELECT
        endpoint_id,
        owner_uid,
        name,
        platform,
        scanner_version,
        last_seen_at,
        created_at
      FROM endpoints
      WHERE endpoint_id = $1
        AND owner_uid = $2
      LIMIT 1
      `,
            [endpointId, uid],
        );

        if (result.rows.length === 0) {
            return null;
        }

        const row = result.rows[0];

        return {
            endpointId: row.endpoint_id,
            ownerUid: row.owner_uid,
            name: row.name,
            platform: row.platform,
            scannerVersion: row.scanner_version,
            lastSeenAt: new Date(row.last_seen_at).toISOString(),
            createdAt: new Date(row.created_at).toISOString(),
        };
    }

    async getScans(uid: string): Promise<ScanDocument[]> {
        try {
            const result = await postgresPool.query(
                `
          SELECT
            scan_id,
            endpoint_id,
            owner_uid,
            timestamp,
            duration_ms,
            scanner_version,
            platform,
            total_processes,
            memory_scanned,
            memory_access_denied,
            highest_score,
            counts
          FROM scans
          WHERE owner_uid = $1
          ORDER BY timestamp DESC
          `,
                [uid],
            );

            return result.rows.map((row) => ({
                scanId: row.scan_id,
                endpointId: row.endpoint_id,
                ownerUid: row.owner_uid,
                timestamp: new Date(row.timestamp).toISOString(),
                durationMs:
                    row.duration_ms !== null ? Number(row.duration_ms) : undefined,
                scannerVersion: row.scanner_version ?? undefined,
                platform: row.platform ?? undefined,
                totalProcesses: Number(row.total_processes),
                memoryScanned:
                    row.memory_scanned !== null
                        ? Number(row.memory_scanned)
                        : undefined,
                memoryAccessDenied:
                    row.memory_access_denied !== null
                        ? Number(row.memory_access_denied)
                        : undefined,
                highestScore: Number(row.highest_score),
                counts: row.counts,
            }));
        } catch {
            return Array.from(this.memoryScans.values()).filter(
                (s) => s.ownerUid === uid
            );
        }
    }

    async getScan(
        uid: string,
        scanId: string,
    ): Promise<ScanDocument | null> {
        const result = await postgresPool.query(
            `
      SELECT
        scan_id,
        endpoint_id,
        owner_uid,
        timestamp,
        duration_ms,
        scanner_version,
        platform,
        total_processes,
        memory_scanned,
        memory_access_denied,
        highest_score,
        counts
      FROM scans
      WHERE scan_id = $1
        AND owner_uid = $2
      LIMIT 1
      `,
            [scanId, uid],
        );

        if (result.rows.length === 0) {
            return null;
        }

        const row = result.rows[0];

        return {
            scanId: row.scan_id,
            endpointId: row.endpoint_id,
            ownerUid: row.owner_uid,
            timestamp: new Date(row.timestamp).toISOString(),
            durationMs:
                row.duration_ms !== null ? Number(row.duration_ms) : undefined,
            scannerVersion: row.scanner_version ?? undefined,
            platform: row.platform ?? undefined,
            totalProcesses: Number(row.total_processes),
            memoryScanned:
                row.memory_scanned !== null
                    ? Number(row.memory_scanned)
                    : undefined,
            memoryAccessDenied:
                row.memory_access_denied !== null
                    ? Number(row.memory_access_denied)
                    : undefined,
            highestScore: Number(row.highest_score),
            counts: row.counts,
        };
    }

    async getProcesses(uid: string): Promise<ProcessDocument[]> {
        const result = await postgresPool.query(
            `
      SELECT *
      FROM processes
      WHERE owner_uid = $1
      ORDER BY timestamp DESC
      `,
            [uid],
        );

        return result.rows.map((row) => this.mapProcess(row));
    }

    async getProcess(
        uid: string,
        processId: string,
    ): Promise<ProcessDocument | null> {
        const numericPid = Number(processId);

        const result = Number.isNaN(numericPid)
            ? await postgresPool.query(
                `
          SELECT *
          FROM processes
          WHERE process_id = $1
            AND owner_uid = $2
          LIMIT 1
          `,
                [processId, uid],
            )
            : await postgresPool.query(
                `
          SELECT *
          FROM processes
          WHERE owner_uid = $1
            AND (process_id = $2 OR pid = $3)
          ORDER BY timestamp DESC
          LIMIT 1
          `,
                [uid, processId, numericPid],
            );

        if (result.rows.length === 0) {
            return null;
        }

        return this.mapProcess(result.rows[0]);
    }

    private mapProcess(row: any): ProcessDocument {
        return {
            processId: row.process_id,
            scanId: row.scan_id,
            endpointId: row.endpoint_id,
            ownerUid: row.owner_uid,
            pid: Number(row.pid),
            name: row.name,
            executablePath: row.executable_path ?? undefined,
            applicationName: row.application_name ?? undefined,
            parentPid:
                row.parent_pid !== null ? Number(row.parent_pid) : undefined,
            parentName: row.parent_name ?? undefined,
            threatScore: Number(row.threat_score),
            threatLevel: row.threat_level,
            scoreMode: row.score_mode,
            behaviorScore:
                row.behavior_score !== null
                    ? Number(row.behavior_score)
                    : undefined,
            memoryScore:
                row.memory_score !== null
                    ? Number(row.memory_score)
                    : undefined,
            correlationScore:
                row.correlation_score !== null
                    ? Number(row.correlation_score)
                    : undefined,
            memoryEvidence: row.memory_evidence ?? undefined,
            behaviorEvidence: row.behavior_evidence ?? undefined,
            correlationEvidence: row.correlation_evidence ?? undefined,
            timestamp: new Date(row.timestamp).toISOString(),
            commandLine: row.command_line ?? undefined,
            userContext: row.user_context ?? undefined,
            integrityLevel: row.integrity_level ?? undefined,
            responseRecommendation:
                row.response_recommendation ?? undefined,
        };
    }

    async getThreatAlerts(uid: string): Promise<ThreatAlertDocument[]> {
        const result = await postgresPool.query(
            `
      SELECT *
      FROM threat_alerts
      WHERE owner_uid = $1
      ORDER BY detected_at DESC
      `,
            [uid],
        );

        return result.rows.map((row) => this.mapAlert(row));
    }

    async getThreatAlert(
        uid: string,
        alertId: string,
    ): Promise<ThreatAlertDocument | null> {
        const result = await postgresPool.query(
            `
      SELECT *
      FROM threat_alerts
      WHERE id = $1
        AND owner_uid = $2
      LIMIT 1
      `,
            [alertId, uid],
        );

        if (result.rows.length === 0) {
            return null;
        }

        return this.mapAlert(result.rows[0]);
    }

    private mapAlert(row: any): ThreatAlertDocument {
        return {
            id: row.id,
            scanId: row.scan_id,
            endpointId: row.endpoint_id,
            ownerUid: row.owner_uid,
            pid: Number(row.pid),
            processName: row.process_name,
            score: Number(row.score),
            level: row.level,
            scoreMode: row.score_mode,
            title: row.title ?? undefined,
            description: row.description ?? undefined,
            memoryEvidence: row.memory_evidence ?? undefined,
            behaviorEvidence: row.behavior_evidence ?? undefined,
            correlationEvidence: row.correlation_evidence ?? undefined,
            detectedAt: new Date(row.detected_at).toISOString(),
            status: row.status ?? undefined,
            recommendedActions: row.recommended_actions ?? undefined,
        };
    }

    async getReports(uid: string): Promise<ReportDocument[]> {
        const result = await postgresPool.query(
            `
      SELECT *
      FROM reports
      WHERE owner_uid = $1
      ORDER BY created_at DESC
      `,
            [uid],
        );

        return result.rows.map((row) => this.mapReport(row));
    }

    async getReport(
        uid: string,
        reportId: string,
    ): Promise<ReportDocument | null> {
        const result = await postgresPool.query(
            `
      SELECT *
      FROM reports
      WHERE id = $1
        AND owner_uid = $2
      LIMIT 1
      `,
            [reportId, uid],
        );

        if (result.rows.length === 0) {
            return null;
        }

        return this.mapReport(result.rows[0]);
    }

    private mapReport(row: any): ReportDocument {
        return {
            id: row.id,
            scanId: row.scan_id,
            endpointId: row.endpoint_id,
            ownerUid: row.owner_uid,
            createdAt: new Date(row.created_at).toISOString(),
            title: row.title,
            summary: row.summary,
            totalProcesses: Number(row.total_processes),
            totalAlerts: Number(row.total_alerts),
            highestScore: Number(row.highest_score),
            highestThreatLevel: row.highest_threat_level,
            alerts: row.alerts ?? [],
            generatedBy: row.generated_by ?? undefined,
            type: row.type ?? undefined,
            size: row.size ?? undefined,
            recordCount:
                row.record_count !== null
                    ? Number(row.record_count)
                    : undefined,
        };
    }

    /*
     * ---------------------------------------------------------------
     * Schema Initialization (Idempotent)
     * ---------------------------------------------------------------
     */
    async initDatabaseSchema(): Promise<void> {
        try {
            await postgresPool.query(`
                CREATE TABLE IF NOT EXISTS devices (
                    device_id VARCHAR(128) PRIMARY KEY,
                    owner_uid VARCHAR(128) NOT NULL,
                    device_name VARCHAR(255) NOT NULL,
                    device_token_hash VARCHAR(128) NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    revoked_at TIMESTAMPTZ
                );
                CREATE INDEX IF NOT EXISTS idx_devices_owner_uid ON devices (owner_uid);
                CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices (device_token_hash);

                CREATE TABLE IF NOT EXISTS pairing_requests (
                    pairing_id VARCHAR(128) PRIMARY KEY,
                    owner_uid VARCHAR(128) NOT NULL,
                    code VARCHAR(32) NOT NULL UNIQUE,
                    expires_at TIMESTAMPTZ NOT NULL,
                    used_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    paired_device_id VARCHAR(128)
                );
                CREATE INDEX IF NOT EXISTS idx_pairing_code ON pairing_requests (code);

                CREATE TABLE IF NOT EXISTS user_sessions (
                    token_hash VARCHAR(128) PRIMARY KEY,
                    uid VARCHAR(128) NOT NULL,
                    email VARCHAR(255),
                    display_name VARCHAR(255),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at TIMESTAMPTZ NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_user_sessions_uid ON user_sessions (uid);

                CREATE TABLE IF NOT EXISTS web_threat_events (
                    id VARCHAR(128) PRIMARY KEY,
                    owner_uid VARCHAR(128) NOT NULL,
                    device_id VARCHAR(128),
                    timestamp TIMESTAMPTZ NOT NULL,
                    domain VARCHAR(255) NOT NULL,
                    url TEXT,
                    classification VARCHAR(64) NOT NULL,
                    severity VARCHAR(32) NOT NULL,
                    score NUMERIC(5,2) NOT NULL,
                    confidence VARCHAR(32) NOT NULL,
                    detection_source VARCHAR(64) NOT NULL,
                    rule_id VARCHAR(128),
                    explanation TEXT,
                    browser VARCHAR(128),
                    notified BOOLEAN NOT NULL DEFAULT FALSE,
                    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE'
                );
                CREATE INDEX IF NOT EXISTS idx_web_threat_events_owner ON web_threat_events (owner_uid);
                CREATE INDEX IF NOT EXISTS idx_web_threat_events_timestamp ON web_threat_events (timestamp DESC);
            `);
            console.log("[PostgreSQL] Device, pairing, session, and web threat schemas verified.");
        } catch (err) {
            console.warn("[PostgreSQL] Schema auto-migration check:", (err as Error).message);
        }
    }

    // In-memory fallback registries for offline/test environments
    private memoryDevices: Map<string, DeviceDocument> = new Map();
    private memoryPairingRequests: Map<string, PairingRequestDocument> = new Map();
    private memoryUserSessions: Map<string, UserSessionDocument> = new Map();

    /*
     * ---------------------------------------------------------------
     * Device Enrollment & Credential Management
     * ---------------------------------------------------------------
     */
    async registerDevice(device: DeviceDocument): Promise<void> {
        this.memoryDevices.set(device.deviceTokenHash, device);
        try {
            await postgresPool.query(
                `
                INSERT INTO devices (
                    device_id,
                    owner_uid,
                    device_name,
                    device_token_hash,
                    created_at,
                    last_seen_at,
                    revoked_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (device_id)
                DO UPDATE SET
                    owner_uid = EXCLUDED.owner_uid,
                    device_name = EXCLUDED.device_name,
                    device_token_hash = EXCLUDED.device_token_hash,
                    last_seen_at = EXCLUDED.last_seen_at,
                    revoked_at = EXCLUDED.revoked_at
                `,
                [
                    device.deviceId,
                    device.ownerUid,
                    device.deviceName,
                    device.deviceTokenHash,
                    device.createdAt,
                    device.lastSeenAt,
                    device.revokedAt || null,
                ]
            );
        } catch (err) {
            console.warn("[PostgreSQL] Fallback to memory registry for device registration:", (err as Error).message);
        }
    }

    async getDeviceByTokenHash(tokenHash: string): Promise<DeviceDocument | null> {
        try {
            const result = await postgresPool.query(
                `
                SELECT *
                FROM devices
                WHERE device_token_hash = $1
                LIMIT 1
                `,
                [tokenHash]
            );
            if (result.rows.length > 0) {
                const row = result.rows[0];
                return {
                    deviceId: row.device_id,
                    ownerUid: row.owner_uid,
                    deviceName: row.device_name,
                    deviceTokenHash: row.device_token_hash,
                    createdAt: new Date(row.created_at).toISOString(),
                    lastSeenAt: new Date(row.last_seen_at).toISOString(),
                    revokedAt: row.revoked_at ? new Date(row.revoked_at).toISOString() : null,
                };
            }
        } catch {
            // fall back to in-memory
        }

        return this.memoryDevices.get(tokenHash) || null;
    }

    async getDevices(ownerUid: string): Promise<DeviceDocument[]> {
        try {
            const result = await postgresPool.query(
                `
                SELECT *
                FROM devices
                WHERE owner_uid = $1
                ORDER BY created_at DESC
                `,
                [ownerUid]
            );
            return result.rows.map((row) => ({
                deviceId: row.device_id,
                ownerUid: row.owner_uid,
                deviceName: row.device_name,
                deviceTokenHash: row.device_token_hash,
                createdAt: new Date(row.created_at).toISOString(),
                lastSeenAt: new Date(row.last_seen_at).toISOString(),
                revokedAt: row.revoked_at ? new Date(row.revoked_at).toISOString() : null,
            }));
        } catch {
            return Array.from(this.memoryDevices.values()).filter(
                (d) => d.ownerUid === ownerUid
            );
        }
    }

    async updateDeviceLastSeen(deviceId: string): Promise<void> {
        for (const dev of this.memoryDevices.values()) {
            if (dev.deviceId === deviceId) {
                dev.lastSeenAt = new Date().toISOString();
            }
        }
        try {
            await postgresPool.query(
                `
                UPDATE devices
                SET last_seen_at = NOW()
                WHERE device_id = $1
                `,
                [deviceId]
            );
        } catch {
            // ignore
        }
    }

    async revokeDevice(ownerUid: string, deviceId: string): Promise<boolean> {
        let found = false;
        for (const dev of this.memoryDevices.values()) {
            if (dev.deviceId === deviceId && dev.ownerUid === ownerUid) {
                dev.revokedAt = new Date().toISOString();
                found = true;
            }
        }
        try {
            const result = await postgresPool.query(
                `
                UPDATE devices
                SET revoked_at = NOW()
                WHERE device_id = $1 AND owner_uid = $2
                `,
                [deviceId, ownerUid]
            );
            return (result.rowCount ?? 0) > 0 || found;
        } catch {
            return found;
        }
    }

    /*
     * ---------------------------------------------------------------
     * Pairing Requests (Short-Lived, One-Time Codes)
     * ---------------------------------------------------------------
     */
    async createPairingRequest(pairing: PairingRequestDocument): Promise<void> {
        this.memoryPairingRequests.set(pairing.code.toUpperCase(), pairing);
        try {
            await postgresPool.query(
                `
                INSERT INTO pairing_requests (
                    pairing_id,
                    owner_uid,
                    code,
                    expires_at,
                    used_at,
                    created_at,
                    paired_device_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (pairing_id) DO NOTHING
                `,
                [
                    pairing.pairingId,
                    pairing.ownerUid,
                    pairing.code.toUpperCase(),
                    pairing.expiresAt,
                    pairing.usedAt || null,
                    pairing.createdAt,
                    pairing.pairedDeviceId || null,
                ]
            );
        } catch (err) {
            console.warn("[PostgreSQL] Fallback to memory registry for pairing request:", (err as Error).message);
        }
    }

    async getPairingRequest(code: string): Promise<PairingRequestDocument | null> {
        const cleanCode = code.toUpperCase().trim();
        try {
            const result = await postgresPool.query(
                `
                SELECT *
                FROM pairing_requests
                WHERE code = $1
                LIMIT 1
                `,
                [cleanCode]
            );
            if (result.rows.length > 0) {
                const row = result.rows[0];
                return {
                    pairingId: row.pairing_id,
                    ownerUid: row.owner_uid,
                    code: row.code,
                    expiresAt: new Date(row.expires_at).toISOString(),
                    usedAt: row.used_at ? new Date(row.used_at).toISOString() : null,
                    createdAt: new Date(row.created_at).toISOString(),
                    pairedDeviceId: row.paired_device_id,
                };
            }
        } catch {
            // fall back to memory
        }

        return this.memoryPairingRequests.get(cleanCode) || null;
    }

    async getPairingRequestById(pairingId: string): Promise<PairingRequestDocument | null> {
        try {
            const result = await postgresPool.query(
                `
                SELECT *
                FROM pairing_requests
                WHERE pairing_id = $1
                LIMIT 1
                `,
                [pairingId]
            );
            if (result.rows.length > 0) {
                const row = result.rows[0];
                return {
                    pairingId: row.pairing_id,
                    ownerUid: row.owner_uid,
                    code: row.code,
                    expiresAt: new Date(row.expires_at).toISOString(),
                    usedAt: row.used_at ? new Date(row.used_at).toISOString() : null,
                    createdAt: new Date(row.created_at).toISOString(),
                    pairedDeviceId: row.paired_device_id,
                };
            }
        } catch {
            // fall back to memory
        }

        for (const req of this.memoryPairingRequests.values()) {
            if (req.pairingId === pairingId) return req;
        }
        return null;
    }

    async markPairingRequestUsed(pairingId: string, deviceId: string): Promise<void> {
        for (const req of this.memoryPairingRequests.values()) {
            if (req.pairingId === pairingId) {
                req.usedAt = new Date().toISOString();
                req.pairedDeviceId = deviceId;
            }
        }
        try {
            await postgresPool.query(
                `
                UPDATE pairing_requests
                SET used_at = NOW(), paired_device_id = $2
                WHERE pairing_id = $1
                `,
                [pairingId, deviceId]
            );
        } catch {
            // ignore
        }
    }

    /*
     * ---------------------------------------------------------------
     * User Sessions (Web User Authentication)
     * ---------------------------------------------------------------
     */
    async createUserSession(session: UserSessionDocument): Promise<void> {
        this.memoryUserSessions.set(session.tokenHash, session);
        try {
            await postgresPool.query(
                `
                INSERT INTO user_sessions (
                    token_hash,
                    uid,
                    email,
                    display_name,
                    created_at,
                    expires_at
                )
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (token_hash) DO NOTHING
                `,
                [
                    session.tokenHash,
                    session.uid,
                    session.email || null,
                    session.displayName || null,
                    session.createdAt,
                    session.expiresAt,
                ]
            );
        } catch {
            // memory fallback
        }
    }

    async getUserSessionByTokenHash(tokenHash: string): Promise<UserSessionDocument | null> {
        try {
            const result = await postgresPool.query(
                `
                SELECT *
                FROM user_sessions
                WHERE token_hash = $1
                LIMIT 1
                `,
                [tokenHash]
            );
            if (result.rows.length > 0) {
                const row = result.rows[0];
                return {
                    tokenHash: row.token_hash,
                    uid: row.uid,
                    email: row.email,
                    displayName: row.display_name,
                    createdAt: new Date(row.created_at).toISOString(),
                    expiresAt: new Date(row.expires_at).toISOString(),
                };
            }
        } catch {
            // memory fallback
        }

        return this.memoryUserSessions.get(tokenHash) || null;
    }

    /*
     * ---------------------------------------------------------------
     * Phase 3: Web Threat Events
     * ---------------------------------------------------------------
     */
    async createWebThreatEvent(event: WebThreatEventDocument): Promise<void> {
        // Enforce in-memory retention limit (max 500 events per owner)
        const userEvents = this.memoryWebThreatEvents.get(event.ownerUid) || [];
        const filtered = userEvents.filter((e) => e.id !== event.id);
        filtered.unshift(event);
        if (filtered.length > 500) {
            filtered.pop();
        }
        this.memoryWebThreatEvents.set(event.ownerUid, filtered);

        try {
            await postgresPool.query(
                `
                INSERT INTO web_threat_events (
                    id,
                    owner_uid,
                    device_id,
                    timestamp,
                    domain,
                    url,
                    classification,
                    severity,
                    score,
                    confidence,
                    detection_source,
                    rule_id,
                    explanation,
                    browser,
                    notified,
                    status
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                ON CONFLICT (id) DO UPDATE SET
                    status = EXCLUDED.status,
                    notified = EXCLUDED.notified
                `,
                [
                    event.id,
                    event.ownerUid,
                    event.deviceId || null,
                    event.timestamp,
                    event.domain,
                    event.url || null,
                    event.classification,
                    event.severity,
                    event.score,
                    event.confidence,
                    event.detectionSource,
                    event.ruleId || null,
                    event.explanation,
                    event.browser || null,
                    event.notified ?? false,
                    event.status || "ACTIVE",
                ]
            );
        } catch {
            // in-memory fallback preserved
        }
    }

    async getWebThreatEvents(uid: string): Promise<WebThreatEventDocument[]> {
        try {
            const result = await postgresPool.query(
                `
                SELECT *
                FROM web_threat_events
                WHERE owner_uid = $1
                ORDER BY timestamp DESC
                LIMIT 200
                `,
                [uid]
            );

            if (result.rows.length > 0) {
                return result.rows.map((row) => ({
                    id: row.id,
                    ownerUid: row.owner_uid,
                    deviceId: row.device_id || undefined,
                    timestamp: new Date(row.timestamp).toISOString(),
                    domain: row.domain,
                    url: row.url || undefined,
                    classification: row.classification,
                    severity: row.severity,
                    score: Number(row.score),
                    confidence: row.confidence,
                    detectionSource: row.detection_source,
                    ruleId: row.rule_id || undefined,
                    explanation: row.explanation,
                    browser: row.browser || undefined,
                    notified: Boolean(row.notified),
                    status: row.status,
                }));
            }
        } catch {
            // memory fallback
        }

        return this.memoryWebThreatEvents.get(uid) || [];
    }

    async dismissWebThreatEvent(uid: string, eventId: string): Promise<boolean> {
        const userEvents = this.memoryWebThreatEvents.get(uid);
        let found = false;
        if (userEvents) {
            for (const ev of userEvents) {
                if (ev.id === eventId) {
                    ev.status = "DISMISSED";
                    found = true;
                }
            }
        }

        try {
            const res = await postgresPool.query(
                `
                UPDATE web_threat_events
                SET status = 'DISMISSED'
                WHERE id = $1 AND owner_uid = $2
                `,
                [eventId, uid]
            );
            if (res.rowCount && res.rowCount > 0) found = true;
        } catch {
            // fallback
        }

        return found;
    }
}


export const postgresService = new PostgresService();