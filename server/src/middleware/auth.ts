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

  // 2. Web User Session Token
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

    if ((session as any).revokedAt) {
      res.status(401).json({
        error: "Unauthorized",
        message: "User session has been revoked.",
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

  // 3. Scoped Browser Extension Token (Least-Privilege Scoped Access)
  if (token.startsWith("pt_ext_")) {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const session = await postgresService.getUserSessionByTokenHash(tokenHash);

    if (!session) {
      res.status(401).json({
        error: "Unauthorized",
        message: "Invalid extension credential.",
      });
      return;
    }

    if (new Date(session.expiresAt).getTime() < Date.now()) {
      res.status(401).json({
        error: "Unauthorized",
        message: "Extension credential has expired.",
      });
      return;
    }

    if ((session as any).revokedAt) {
      res.status(401).json({
        error: "Unauthorized",
        message: "Extension credential has been revoked.",
      });
      return;
    }

    // Least-privilege authorization: extension tokens may only access web-threat monitor endpoints
    const cleanPath = (req.originalUrl || req.baseUrl || req.path || "").split("?")[0];
    if (!cleanPath.startsWith("/api/web-threats")) {
      res.status(403).json({
        error: "Forbidden",
        message: "Extension credentials have restricted scope and are only authorized for Web Threat Monitor operations.",
      });
      return;
    }

    // Preserve least privilege within /api/web-threats:
    // Extensions may sync policies (GET /policies), report detected threats (POST /events),
    // query reputation (POST /check), and inspect events (GET /events).
    // Mutating security policies (POST/DELETE /policies) or triaging events (POST/PATCH /status, /dismiss)
    // requires an authenticated user or owner session.
    const isPolicyMutation =
      (req.method === "POST" || req.method === "DELETE") && cleanPath.includes("/policies");
    const isIncidentTriage =
      (req.method === "POST" || req.method === "PATCH") &&
      (cleanPath.includes("/status") || cleanPath.includes("/dismiss"));

    if (isPolicyMutation || isIncidentTriage) {
      res.status(403).json({
        error: "Forbidden",
        message: "Extension credentials cannot modify security policies or triage incidents. User authentication required.",
      });
      return;
    }

    req.ownerUid = session.uid;
    req.authType = "extension";
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

/**
 * Resolves owner UID from Bearer token if valid, otherwise returns null.
 */
export async function resolveOwnerUidFromToken(token: string): Promise<string | null> {
  if (!token) return null;
  const cleanToken = token.trim().replace(/^["']|["']$/g, "");
  if (!cleanToken) return null;

  // 1. Scoped Device Credential (pt_dev_)
  if (cleanToken.startsWith("pt_dev_")) {
    const tokenHash = crypto.createHash("sha256").update(cleanToken).digest("hex");
    const device = await postgresService.getDeviceByTokenHash(tokenHash);
    if (!device || device.revokedAt) return null;
    return device.ownerUid;
  }

  // 2. Web User Session Token or Scoped Extension Token
  if (cleanToken.startsWith("pt_usr_") || cleanToken.startsWith("pt_ext_")) {
    const tokenHash = crypto.createHash("sha256").update(cleanToken).digest("hex");
    const session = await postgresService.getUserSessionByTokenHash(tokenHash);
    if (!session || new Date(session.expiresAt).getTime() < Date.now()) return null;
    if ((session as any).revokedAt) return null;
    return session.uid;
  }

  // 3. Master Owner API Key
  if (API_KEY && safeEqual(cleanToken, API_KEY)) {
    return process.env.PHANTOMTRACE_OWNER_UID?.trim() || "phantomtrace-owner";
  }

  // 4. Non-production development analyst tokens
  if (process.env.NODE_ENV !== "production" && cleanToken.startsWith("dev-")) {
    return `uid-${cleanToken}`;
  }

  return null;
}
