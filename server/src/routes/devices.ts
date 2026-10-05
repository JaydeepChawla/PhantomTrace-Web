import { Router, Response } from "express";
import crypto from "crypto";
import { authMiddleware } from "../middleware/auth";
import { postgresService } from "../services/postgresService";
import type { AuthenticatedRequest, PairingRequestDocument, DeviceDocument } from "../types/api";

export const devicesRouter = Router();

/**
 * Generates an unambiguous, cryptographically secure 8-character pairing code
 * Format: PT-XXXX-XXXX
 */
function generatePairingCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Removed ambiguous 0, O, 1, I
  const p1 = Array.from(crypto.randomBytes(4)).map((b) => chars[b % chars.length]).join("");
  const p2 = Array.from(crypto.randomBytes(4)).map((b) => chars[b % chars.length]).join("");
  return `PT-${p1}-${p2}`;
}

/**
 * POST /api/devices/pair/start
 * Authenticated website user initiates device pairing.
 * Generates a short-lived (10-minute) pairing code.
 */
devicesRouter.post("/pair/start", authMiddleware, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const ownerUid = req.ownerUid!;
    const pairingId = `pair_${crypto.randomUUID()}`;
    const code = generatePairingCode();
    const expiresInSeconds = 600; // 10 minutes
    const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString();

    const pairing: PairingRequestDocument = {
      pairingId,
      ownerUid,
      code,
      expiresAt,
      createdAt: new Date().toISOString(),
      usedAt: null,
      pairedDeviceId: null,
    };

    await postgresService.createPairingRequest(pairing);

    res.status(200).json({
      success: true,
      pairingId,
      pairingCode: code,
      expiresAt,
      expiresInSeconds,
      message: "Pairing code generated. Enter this code into your PhantomTrace Windows Agent.",
    });
  } catch (err) {
    console.error("[Devices Route] Error starting pairing:", err);
    res.status(500).json({
      error: "InternalServerError",
      message: "Failed to generate pairing code",
    });
  }
});

/**
 * GET /api/devices/pair/status
 * Polls status of an active pairing request to detect when agent completes pairing.
 */
devicesRouter.get("/pair/status", authMiddleware, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const pairingId = typeof req.query.pairingId === "string" ? req.query.pairingId : "";
    if (!pairingId) {
      res.status(400).json({ error: "MissingParameter", message: "pairingId query parameter required" });
      return;
    }

    const pairing = await postgresService.getPairingRequestById(pairingId);
    if (!pairing || pairing.ownerUid !== req.ownerUid) {
      res.status(404).json({ error: "NotFound", message: "Pairing request not found" });
      return;
    }

    const isExpired = new Date(pairing.expiresAt).getTime() < Date.now();
    const isPaired = Boolean(pairing.usedAt && pairing.pairedDeviceId);

    let status: "PENDING" | "PAIRED" | "EXPIRED" = "PENDING";
    if (isPaired) {
      status = "PAIRED";
    } else if (isExpired) {
      status = "EXPIRED";
    }

    res.status(200).json({
      pairingId: pairing.pairingId,
      code: pairing.code,
      status,
      deviceId: pairing.pairedDeviceId,
      expiresAt: pairing.expiresAt,
    });
  } catch (err) {
    console.error("[Devices Route] Error checking pairing status:", err);
    res.status(500).json({ error: "InternalServerError", message: "Failed to check pairing status" });
  }
});

/**
 * POST /api/devices/pair/complete
 * Public endpoint called by the local Windows Agent using the pairing code.
 * Issues a scoped, revocable device token (pt_dev_...) and records only its SHA-256 hash.
 */
devicesRouter.post("/pair/complete", async (req, res: Response): Promise<void> => {
  try {
    const rawCode = typeof req.body?.pairingCode === "string" ? req.body.pairingCode.trim().toUpperCase() : "";
    if (!rawCode) {
      res.status(400).json({
        error: "MissingPairingCode",
        message: "Pairing code is required",
      });
      return;
    }

    const pairing = await postgresService.getPairingRequest(rawCode);
    if (!pairing) {
      res.status(404).json({
        error: "InvalidCode",
        message: "Invalid pairing code. Please generate a new code from the dashboard.",
      });
      return;
    }

    if (new Date(pairing.expiresAt).getTime() < Date.now()) {
      res.status(400).json({
        error: "ExpiredCode",
        message: "Pairing code has expired. Please generate a new code from the dashboard.",
      });
      return;
    }

    if (pairing.usedAt) {
      res.status(409).json({
        error: "AlreadyUsed",
        message: "This pairing code has already been redeemed.",
      });
      return;
    }

    // Generate scoped device identity and high-entropy secret
    const deviceId = `dev-${crypto.randomBytes(8).toString("hex")}`;
    const rawDeviceToken = `pt_dev_${crypto.randomBytes(32).toString("hex")}`;
    const tokenHash = crypto.createHash("sha256").update(rawDeviceToken).digest("hex");

    const deviceName = typeof req.body?.deviceName === "string" && req.body.deviceName.trim()
      ? req.body.deviceName.trim()
      : "Windows PC";

    const platform = typeof req.body?.platform === "string" && req.body.platform.trim()
      ? req.body.platform.trim()
      : "Windows (x86_64)";

    // Mark pairing as used
    await postgresService.markPairingRequestUsed(pairing.pairingId, deviceId);

    // Register device in PostgreSQL
    const deviceDoc: DeviceDocument = {
      deviceId,
      ownerUid: pairing.ownerUid,
      deviceName,
      deviceTokenHash: tokenHash,
      createdAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revokedAt: null,
    };
    await postgresService.registerDevice(deviceDoc);

    console.log(`[Devices Route] Device '${deviceId}' successfully paired for user '${pairing.ownerUid}'.`);

    // Return the device credential ONCE to the agent
    res.status(200).json({
      success: true,
      deviceId,
      deviceToken: rawDeviceToken,
      ownerUid: pairing.ownerUid,
      deviceName,
      platform,
      message: "Device paired successfully. Scans can now be synchronized.",
    });
  } catch (err) {
    console.error("[Devices Route] Error completing device pairing:", err);
    res.status(500).json({
      error: "InternalServerError",
      message: "Failed to complete device pairing",
    });
  }
});

/**
 * GET /api/devices
 * Enumerate all devices registered by the authenticated user.
 */
devicesRouter.get("/", authMiddleware, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const ownerUid = req.ownerUid!;
    const devices = await postgresService.getDevices(ownerUid);

    // Sanitize response: NEVER return token hashes to client
    const sanitized = devices.map((d) => ({
      deviceId: d.deviceId,
      deviceName: d.deviceName,
      createdAt: d.createdAt,
      lastSeenAt: d.lastSeenAt,
      isRevoked: Boolean(d.revokedAt),
      revokedAt: d.revokedAt,
    }));

    res.status(200).json({ devices: sanitized });
  } catch (err) {
    console.error("[Devices Route] Error listing devices:", err);
    res.status(500).json({
      error: "InternalServerError",
      message: "Failed to enumerate devices",
    });
  }
});

/**
 * POST /api/devices/:deviceId/revoke
 * Revokes a device credential, immediately terminating upload authorization.
 */
devicesRouter.post("/:deviceId/revoke", authMiddleware, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const ownerUid = req.ownerUid!;
    const { deviceId } = req.params;

    const revoked = await postgresService.revokeDevice(ownerUid, deviceId);
    if (!revoked) {
      res.status(404).json({
        error: "NotFound",
        message: `Device '${deviceId}' not found or unauthorized`,
      });
      return;
    }

    console.log(`[Devices Route] Device '${deviceId}' revoked by owner '${ownerUid}'.`);

    res.status(200).json({
      success: true,
      deviceId,
      message: "Device revoked successfully. Cloud upload access terminated.",
    });
  } catch (err) {
    console.error("[Devices Route] Error revoking device:", err);
    res.status(500).json({
      error: "InternalServerError",
      message: "Failed to revoke device",
    });
  }
});
