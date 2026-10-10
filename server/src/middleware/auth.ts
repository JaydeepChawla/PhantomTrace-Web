import type { Response, NextFunction } from "express";
import crypto from "crypto";
import type { AuthenticatedRequest, AuthenticatedUser } from "../types/api";
import { postgresService } from "../services/postgresService";

const API_KEY = process.env.PHANTOMTRACE_API_KEY;

export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

export async function authMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Missing or malformed Authorization header. Expected Bearer token",
    });
    return;
  }

  const token = authHeader.slice("Bearer ".length).trim().replace(/^["']|["']$/g, "");

  if (!token) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Authentication token empty",
    });
    return;
  }

  // 1. Scoped Device Credential (Issued to paired Windows Agents)
  if (token.startsWith("pt_dev_")) {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const device = await postgresService.getDeviceByTokenHash(tokenHash);

    if (!device) {
      res.status(401).json({
        error: "Unauthorized",
        message: "Invalid device credential. Please re-pair your Windows PC.",
      });
      return;
    }

    if (device.revokedAt) {
      res.status(401).json({
        error: "Unauthorized",
        message: "Device access has been revoked by account owner.",
      });
      return;
    }

    // Update device activity timestamp
    void postgresService.updateDeviceLastSeen(device.deviceId);

    req.ownerUid = device.ownerUid;
    req.deviceId = device.deviceId;
    req.authType = "device";
    req.user = {
      uid: device.ownerUid,
      displayName: device.deviceName,
    };

    next();
    return;
  }

  // 2. Web User Session Token (Issued during public user registration/login)
  if (token.startsWith("pt_usr_")) {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const session = await postgresService.getUserSessionByTokenHash(tokenHash);

    if (!session || new Date(session.expiresAt).getTime() < Date.now()) {
      res.status(401).json({
        error: "Unauthorized",
        message: "Invalid or expired user session.",
      });
      return;
    }

    req.ownerUid = session.uid;
    req.authType = "user";
    req.user = {
      uid: session.uid,
      email: session.email,
      displayName: session.displayName,
    };

    next();
    return;
  }

  // 3. Master Owner API Key (Existing Administrative / SOC Ingestion)
  if (API_KEY && safeEqual(token, API_KEY)) {
    const ownerUid =
      process.env.PHANTOMTRACE_OWNER_UID?.trim() || "phantomtrace-owner";

    const user: AuthenticatedUser = {
      uid: ownerUid,
      email: process.env.PHANTOMTRACE_OWNER_EMAIL?.trim() || "owner@phantomtrace.local",
      displayName:
        process.env.PHANTOMTRACE_OWNER_NAME?.trim() || "PhantomTrace Owner",
    };

    req.ownerUid = user.uid;
    req.authType = "owner";
    req.user = user;

    next();
    return;
  }

  // 4. Non-production development analyst tokens (Test suite compatibility)
  if (process.env.NODE_ENV !== "production" && token.startsWith("dev-")) {
    const uid = `uid-${token}`;
    req.ownerUid = uid;
    req.authType = "user";
    req.user = {
      uid,
      displayName: `Development Analyst (${token})`,
      email: `${token}@phantomtrace.local`,
    };

    next();
    return;
  }

  res.status(401).json({
    error: "Unauthorized",
    message: "Invalid authentication token",
  });
}
