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
    DomainPolicyDocument,
    UnifiedThreatAlertDocument,
    CorrelatedThreatEventDocument,
} from "../types/api";

class PostgresService {
    private memoryUsers: Map<string, UserDocument> = new Map();
    private memoryScans: Map<string, ScanDocument> = new Map();
    private memoryEndpoints: Map<string, EndpointDocument> = new Map();
    private memoryThreatAlerts: Map<string, ThreatAlertDocument> = new Map();
    private memoryProcesses: Map<string, ProcessDocument[]> = new Map();
    private memoryReports: Map<string, ReportDocument> = new Map();
    private memoryWebThreatEvents: Map<string, WebThreatEventDocument[]> = new Map();
    private memoryDomainPolicies: Map<string, DomainPolicyDocument[]> = new Map();

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
        } catch (err) {
            if (process.env.NODE_ENV === "production") {
                console.error("[PostgreSQL] Ingest rejected: database connection pool unavailable in production:", err);
                throw new Error("Database persistence failed: PostgreSQL connection pool unavailable in production");
            }
            this.memoryScans.set(scan.scanId, scan);
            this.memoryEndpoints.set(endpoint.endpointId, endpoint);
            this.memoryProcesses.set(scan.scanId, processes);
            for (const alert of threatAlerts) {
                this.memoryThreatAlerts.set(alert.id, alert);
            }
            if (report) {
                this.memoryReports.set(report.id, report);
            }
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
        try {
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
        } catch {
            return Array.from(this.memoryEndpoints.values()).filter(
                (e) => e.ownerUid === uid,
            );
        }
    }

    async getEndpoint(
        uid: string,
        endpointId: string,
    ): Promise<EndpointDocument | null> {
        try {
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
        } catch {
            const ep = this.memoryEndpoints.get(endpointId);
            return ep && ep.ownerUid === uid ? ep : null;
        }
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
        try {
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
        } catch {
            const allProcs = Array.from(this.memoryProcesses.values()).flat();
            return allProcs.filter((p) => p.ownerUid === uid);
        }
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
        try {
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
        } catch {
            return Array.from(this.memoryThreatAlerts.values()).filter(
                (a) => a.ownerUid === uid,
            );
        }
    }

    async getThreatAlert(
        uid: string,
        alertId: string,
    ): Promise<ThreatAlertDocument | null> {
        try {
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
        } catch {
            const alert = this.memoryThreatAlerts.get(alertId);
            return alert && alert.ownerUid === uid ? alert : null;
        }
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

                CREATE TABLE IF NOT EXISTS domain_policies (
                    policy_id VARCHAR(128) PRIMARY KEY,
                    owner_uid VARCHAR(128) NOT NULL,
                    domain VARCHAR(255) NOT NULL,
                    policy_type VARCHAR(32) NOT NULL,
                    reason VARCHAR(500),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT uq_owner_domain UNIQUE (owner_uid, domain)
                );
                CREATE INDEX IF NOT EXISTS idx_domain_policies_owner ON domain_policies (owner_uid);
                CREATE INDEX IF NOT EXISTS idx_domain_policies_domain ON domain_policies (domain);

                ALTER TABLE web_threat_events ADD COLUMN IF NOT EXISTS process_pid INTEGER;
                ALTER TABLE web_threat_events ADD COLUMN IF NOT EXISTS process_name VARCHAR(128);
                ALTER TABLE web_threat_events ADD COLUMN IF NOT EXISTS notes TEXT;
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
        } catch (err) {
            console.error("[PostgreSQL] Error persisting web threat event:", err);
            if (process.env.NODE_ENV === "production") {
                throw new Error("Database persistence failed for web threat event");
            }
            // in non-production/test environments, in-memory fallback preserved
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

    /*
     * ---------------------------------------------------------------
     * Phase 4: Domain Policy Management (Allowlist / Blocklist)
     * ---------------------------------------------------------------
     */
    async getDomainPolicies(uid: string): Promise<DomainPolicyDocument[]> {
        try {
            const result = await postgresPool.query(
                `
                SELECT policy_id, owner_uid, domain, policy_type, reason, created_at, updated_at
                FROM domain_policies
                WHERE owner_uid = $1
                ORDER BY created_at DESC
                `,
                [uid]
            );

            if (result.rows.length > 0) {
                return result.rows.map((row) => ({
                    policyId: row.policy_id,
                    ownerUid: row.owner_uid,
                    domain: row.domain,
                    policyType: row.policy_type as "ALLOW" | "BLOCK",
                    reason: row.reason || undefined,
                    createdAt: new Date(row.created_at).toISOString(),
                    updatedAt: new Date(row.updated_at).toISOString(),
                }));
            }
        } catch {
            // fallback to memory
        }

        return this.memoryDomainPolicies.get(uid) || [];
    }

    async upsertDomainPolicy(policy: DomainPolicyDocument): Promise<DomainPolicyDocument> {
        // Enforce memory store
        const userPolicies = this.memoryDomainPolicies.get(policy.ownerUid) || [];
        const filtered = userPolicies.filter((p) => p.domain.toLowerCase() !== policy.domain.toLowerCase());
        filtered.unshift(policy);
        this.memoryDomainPolicies.set(policy.ownerUid, filtered);

        try {
            await postgresPool.query(
                `
                INSERT INTO domain_policies (
                    policy_id, owner_uid, domain, policy_type, reason, created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (owner_uid, domain)
                DO UPDATE SET
                    policy_type = EXCLUDED.policy_type,
                    reason = EXCLUDED.reason,
                    updated_at = EXCLUDED.updated_at
                `,
                [
                    policy.policyId,
                    policy.ownerUid,
                    policy.domain.toLowerCase(),
                    policy.policyType,
                    policy.reason || null,
                    policy.createdAt,
                    policy.updatedAt,
                ]
            );
        } catch (err) {
            console.error("[PostgreSQL] Error persisting domain policy:", err);
            if (process.env.NODE_ENV === "production") {
                throw new Error("Database persistence failed for domain policy");
            }
            // in non-production/test environments, memory fallback handles operation
        }

        return policy;
    }

    async deleteDomainPolicy(uid: string, policyId: string): Promise<boolean> {
        let removed = false;
        const userPolicies = this.memoryDomainPolicies.get(uid);
        if (userPolicies) {
            const idx = userPolicies.findIndex((p) => p.policyId === policyId);
            if (idx !== -1) {
                userPolicies.splice(idx, 1);
                removed = true;
            }
        }

        try {
            const res = await postgresPool.query(
                `
                DELETE FROM domain_policies
                WHERE policy_id = $1 AND owner_uid = $2
                `,
                [policyId, uid]
            );
            if (res.rowCount && res.rowCount > 0) removed = true;
        } catch (err) {
            console.error("[PostgreSQL] Error deleting domain policy:", err);
            if (process.env.NODE_ENV === "production") {
                throw new Error("Database persistence failed for domain policy deletion");
            }
            // in non-production/test environments, memory fallback handles operation
        }

        return removed;
    }

    async findDomainPolicy(uid?: string, domain?: string): Promise<DomainPolicyDocument | null> {
        if (!domain) return null;
        const cleanDomain = domain.toLowerCase().trim();

        if (uid) {
            const userPolicies = this.memoryDomainPolicies.get(uid) || [];
            const memMatch = userPolicies.find((p) => p.domain.toLowerCase() === cleanDomain);
            if (memMatch) return memMatch;

            try {
                const res = await postgresPool.query(
                    `
                    SELECT policy_id, owner_uid, domain, policy_type, reason, created_at, updated_at
                    FROM domain_policies
                    WHERE owner_uid = $1 AND domain = $2
                    LIMIT 1
                    `,
                    [uid, cleanDomain]
                );
                if (res.rows.length > 0) {
                    const row = res.rows[0];
                    return {
                        policyId: row.policy_id,
                        ownerUid: row.owner_uid,
                        domain: row.domain,
                        policyType: row.policy_type as "ALLOW" | "BLOCK",
                        reason: row.reason || undefined,
                        createdAt: new Date(row.created_at).toISOString(),
                        updatedAt: new Date(row.updated_at).toISOString(),
                    };
                }
            } catch {
                // fallback
            }
        }

        return null;
    }

    /*
     * ---------------------------------------------------------------
     * Phase 4: Incident Triage & Event Status Workflow
     * ---------------------------------------------------------------
     */
    async updateWebThreatEventStatus(
        uid: string,
        eventId: string,
        status: "ACTIVE" | "DISMISSED" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE",
        notes?: string
    ): Promise<boolean> {
        let updated = false;
        const userEvents = this.memoryWebThreatEvents.get(uid);
        if (userEvents) {
            for (const ev of userEvents) {
                if (ev.id === eventId) {
                    ev.status = status;
                    if (notes) (ev as any).notes = notes;
                    updated = true;
                }
            }
        }

        try {
            const res = await postgresPool.query(
                `
                UPDATE web_threat_events
                SET status = $1, notes = COALESCE($2, notes)
                WHERE id = $3 AND owner_uid = $4
                `,
                [status, notes || null, eventId, uid]
            );
            if (res.rowCount && res.rowCount > 0) updated = true;
        } catch (err) {
            console.error("[PostgreSQL] Error updating web threat event status:", err);
            if (process.env.NODE_ENV === "production") {
                throw new Error("Database persistence failed for event status update");
            }
            // in non-production/test environments, memory fallback handles operation
        }

        return updated;
    }

    /*
     * ---------------------------------------------------------------
     * Phase 4: Cross-Vector Threat Correlation
     * ---------------------------------------------------------------
     */
    async getCorrelatedThreatEvents(uid: string): Promise<CorrelatedThreatEventDocument[]> {
        const webThreats = await this.getWebThreatEvents(uid);
        let browserProcesses: ProcessDocument[] = [];

        try {
            const scans = await this.getScans(uid);
            if (scans && scans.length > 0) {
                const processes = await this.getProcesses(uid);
                browserProcesses = processes.filter((p: ProcessDocument) =>
                    /^(msedge|chrome|firefox|brave|opera|iexplore|safari)\.exe$/i.test(p.name)
                );
            }
        } catch {
            // Proceed without scan processes if unavailable
        }

        return webThreats.map((wt) => {
            let matchedProcess: ProcessDocument | undefined;
            let directMatch = false;
            const bLower = (wt.browser || "").toLowerCase();

            if (bLower.includes("edge")) {
                matchedProcess = browserProcesses.find((p: ProcessDocument) => p.name.toLowerCase() === "msedge.exe");
                if (matchedProcess) directMatch = true;
            } else if (bLower.includes("chrome")) {
                matchedProcess = browserProcesses.find((p: ProcessDocument) => p.name.toLowerCase() === "chrome.exe");
                if (matchedProcess) directMatch = true;
            } else if (bLower.includes("firefox")) {
                matchedProcess = browserProcesses.find((p: ProcessDocument) => p.name.toLowerCase() === "firefox.exe");
                if (matchedProcess) directMatch = true;
            }

            if (!matchedProcess && browserProcesses.length > 0) {
                matchedProcess = browserProcesses[0];
                directMatch = false;
            }

            const hasMatch = Boolean(matchedProcess);
            const confidence: "HIGH" | "MEDIUM" | "LOW" | "NONE" = !hasMatch
                ? "NONE"
                : directMatch && (matchedProcess!.threatScore && matchedProcess!.threatScore > 20)
                ? "HIGH"
                : directMatch
                ? "MEDIUM"
                : "LOW";

            const reasonText = !hasMatch
                ? "No active browser process telemetry matched in latest endpoint scan."
                : directMatch
                ? `Heuristic correlation: Active browser process (${matchedProcess!.name}, PID ${matchedProcess!.pid}) identified in endpoint scan matching browser telemetry. Note: Temporal correlation indicates concurrent presence during scan window, not proof of process-level URL execution.`
                : `Ambient correlation: Active browser process (${matchedProcess!.name}, PID ${matchedProcess!.pid}) observed on endpoint during scan window; browser identity does not directly match telemetry source.`;

            return {
                webThreat: wt,
                correlatedProcess: matchedProcess
                    ? {
                          pid: matchedProcess.pid,
                          name: matchedProcess.name,
                          path: matchedProcess.executablePath,
                          cmdline: matchedProcess.commandLine,
                          threatScore: matchedProcess.threatScore,
                          threatLevel: matchedProcess.threatLevel,
                      }
                    : undefined,
                correlationConfidence: confidence,
                correlationReason: reasonText,
            };
        });
    }

    /*
     * ---------------------------------------------------------------
     * Phase 4: Unified Threat Alerts Stream
     * ---------------------------------------------------------------
     */
    async getUnifiedThreatAlerts(uid: string): Promise<UnifiedThreatAlertDocument[]> {
        const memoryAlerts: ThreatAlertDocument[] = [];
        try {
            const alerts = await this.getThreatAlerts(uid);
            memoryAlerts.push(...alerts);
        } catch {
            // empty if table not available
        }

        const correlatedEvents = await this.getCorrelatedThreatEvents(uid);

        const unifiedList: UnifiedThreatAlertDocument[] = [];

        // 1. Map Endpoint Memory Alerts
        for (const a of memoryAlerts) {
            unifiedList.push({
                id: a.id,
                vector: "ENDPOINT_MEMORY",
                title: a.title || `Memory Anomaly: ${a.processName} (PID ${a.pid})`,
                targetName: a.processName,
                targetDetail: `PID ${a.pid} • Risk Score ${a.score}/100`,
                level: a.level,
                score: a.score,
                status: (a.status as any) || "NEW",
                timestamp: a.detectedAt,
                indicators: [
                    ...(a.memoryEvidence?.indicators || []),
                    ...(a.behaviorEvidence?.indicators || []),
                ],
                explanation: a.description || a.correlationEvidence?.explanation,
                rawAlert: a,
            });
        }

        // 2. Map Web Threat Events
        for (const c of correlatedEvents) {
            const wt = c.webThreat;
            unifiedList.push({
                id: wt.id,
                vector: "WEB_THREAT",
                title: `Web Threat: ${wt.domain} (${wt.classification})`,
                targetName: wt.domain,
                targetDetail: c.correlatedProcess
                    ? `Browser PID ${c.correlatedProcess.pid} (${c.correlatedProcess.name})`
                    : (wt.browser || "Browser Navigation"),
                level: wt.severity,
                score: wt.score,
                status: (wt.status as any) || "ACTIVE",
                timestamp: wt.timestamp,
                indicators: [wt.classification, wt.detectionSource, wt.ruleId].filter(Boolean) as string[],
                explanation: wt.explanation,
                correlatedProcess: c.correlatedProcess
                    ? {
                          pid: c.correlatedProcess.pid,
                          name: c.correlatedProcess.name,
                          path: c.correlatedProcess.path,
                          score: c.correlatedProcess.threatScore,
                      }
                    : undefined,
                rawWebThreat: wt,
            });
        }

        // Sort by timestamp descending
        unifiedList.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        return unifiedList;
    }

    /*
     * ---------------------------------------------------------------
     * Phase 4: Unified SOC Incident Report Generation
     * ---------------------------------------------------------------
     */
    async generateUnifiedSocReport(uid: string): Promise<ReportDocument> {
        const unifiedAlerts = await this.getUnifiedThreatAlerts(uid);
        const policies = await this.getDomainPolicies(uid);
        const scans = await this.getScans(uid);
        const latestScan = scans.length > 0 ? scans[0] : null;

        const memoryCount = unifiedAlerts.filter((a) => a.vector === "ENDPOINT_MEMORY").length;
        const webCount = unifiedAlerts.filter((a) => a.vector === "WEB_THREAT").length;
        const criticalCount = unifiedAlerts.filter((a) => a.level === "CRITICAL").length;
        const highCount = unifiedAlerts.filter((a) => a.level === "HIGH").length;
        const peakScore = unifiedAlerts.length > 0 ? Math.max(...unifiedAlerts.map((a) => a.score)) : 0;
        const peakLevel = peakScore >= 75 ? "CRITICAL" : peakScore >= 50 ? "HIGH" : peakScore >= 25 ? "MEDIUM" : "NORMAL";

        const reportId = `rep-unified-${Date.now()}`;
        const timestamp = new Date().toISOString();

        const alertsBlock = unifiedAlerts.length === 0
            ? "No critical or high-severity threat incidents documented during current audit window."
            : unifiedAlerts.slice(0, 15).map((a, idx) =>
                `[Incident #${idx + 1}] [${a.vector}] ${a.title}\n  Severity:     ${a.level} (Score: ${a.score}/100)\n  Target:       ${a.targetName} (${a.targetDetail || "N/A"})\n  Status:       ${a.status}\n  Indicators:   ${a.indicators.join(", ") || "None"}\n  Summary:      ${a.explanation || "Analyzed by PhantomTrace heuristic detection engine."}`
            ).join("\n\n");

        const policiesBlock = policies.length === 0
            ? "No tenant-specific domain allowlist or blocklist rules configured."
            : policies.map((p) => `• [${p.policyType}] ${p.domain} - ${p.reason || "Enforced by SOC Administrator"} (Updated: ${p.updatedAt})`).join("\n");

        const reportContent = `
================================================================================
PHANTOMTRACE UNIFIED SOC INCIDENT & THREAT AUDIT REPORT
================================================================================
Report ID:        ${reportId}
Generated At:     ${timestamp}
Target Owner:     ${uid}
Endpoint Host:    ${latestScan?.endpointId || "Windows Endpoint"}
Peak Threat Score:${peakScore}/100 [${peakLevel}]
Platform Mode:    100% Non-Destructive Read-Only Forensic Analysis

--------------------------------------------------------------------------------
1. EXECUTIVE THREAT TELEMETRY SUMMARY
--------------------------------------------------------------------------------
Total Unified Incidents:   ${unifiedAlerts.length}
  - Endpoint Memory Alerts: ${memoryCount}
  - Web Threat Detections:  ${webCount}
Severity Distribution:
  - Critical Severity:      ${criticalCount}
  - High Severity:          ${highCount}
  - Medium / Low Severity:  ${unifiedAlerts.length - criticalCount - highCount}
Enforced Domain Policies:  ${policies.length} (Allow: ${policies.filter((p) => p.policyType === "ALLOW").length}, Block: ${policies.filter((p) => p.policyType === "BLOCK").length})

--------------------------------------------------------------------------------
2. CROSS-VECTOR CORRELATION & THREAT BREAKDOWN
--------------------------------------------------------------------------------
${alertsBlock}

--------------------------------------------------------------------------------
3. DOMAIN SECURITY POLICIES IN EFFECT
--------------------------------------------------------------------------------
${policiesBlock}

--------------------------------------------------------------------------------
4. NON-DESTRUCTIVE INCIDENT RESPONSE PROTOCOL
--------------------------------------------------------------------------------
1. Memory & Process Integrity:
   - In accordance with legal preservation standards, PhantomTrace has NOT terminated, modified,
     or quarantined any running process or memory segment.
2. Recommended Containment Steps:
   - Review correlated browser PIDs for unauthorized parent processes (e.g. cmd.exe, powershell.exe).
   - If a malicious web domain was reached, inspect memory segments of the browser instance for unbacked executable code.
   - For malicious domains, enforce an immediate BLOCK policy rule via PhantomTrace Policy Control.
   - Isolate endpoint from network access via perimeter firewall if memory injection is confirmed.

================================================================================
END OF REPORT — PHANTOMTRACE FORENSIC ENGINE RELEASE 1.0
================================================================================
`.trim();

        const reportDoc: ReportDocument = {
            id: reportId,
            scanId: latestScan?.scanId || "unified-session",
            endpointId: latestScan?.endpointId || "windows-endpoint",
            ownerUid: uid,
            createdAt: timestamp,
            title: `Unified SOC Incident Audit — ${new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}`,
            summary: `Automated cross-vector threat audit synthesizing ${memoryCount} memory telemetry alerts and ${webCount} web threat events. Peak score ${peakScore}/100 (${peakLevel}).`,
            totalProcesses: latestScan?.totalProcesses || 0,
            totalAlerts: unifiedAlerts.length,
            highestScore: peakScore,
            highestThreatLevel: peakLevel,
            alerts: (unifiedAlerts.filter(a => a.rawAlert).map(a => a.rawAlert!) as any) || [],
            generatedBy: "PHANTOMTRACE",
            type: "txt",
            size: `${(reportContent.length / 1024).toFixed(1)} KB`,
            recordCount: unifiedAlerts.length,
        };

        (reportDoc as any).content = reportContent;
        (reportDoc as any).name = `phantomtrace_soc_report_${reportId}.txt`;

        try {
            await postgresPool.query(
                `
                INSERT INTO reports (
                    id, scan_id, endpoint_id, owner_uid, created_at, title, summary,
                    total_processes, total_alerts, highest_score, highest_threat_level,
                    alerts, generated_by, type, size, record_count
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                ON CONFLICT (id) DO NOTHING
                `,
                [
                    reportDoc.id,
                    reportDoc.scanId,
                    reportDoc.endpointId,
                    reportDoc.ownerUid,
                    reportDoc.createdAt,
                    reportDoc.title,
                    reportDoc.summary,
                    reportDoc.totalProcesses,
                    reportDoc.totalAlerts,
                    reportDoc.highestScore,
                    reportDoc.highestThreatLevel,
                    JSON.stringify(reportDoc.alerts),
                    reportDoc.generatedBy,
                    reportDoc.type,
                    reportDoc.size,
                    reportDoc.recordCount,
                ]
            );
        } catch {
            // memory fallback
        }

        return reportDoc;
    }

}


export const postgresService = new PostgresService();