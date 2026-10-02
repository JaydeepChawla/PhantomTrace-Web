import type { Response, NextFunction } from "express";
import type { AuthenticatedRequest, AuthenticatedUser } from "../types/api";

const API_KEY = process.env.PHANTOMTRACE_API_KEY;

function safeEqual(a: string, b: string): boolean {
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

  const token = authHeader.slice("Bearer ".length).trim();

  if (!token) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Authentication token empty",
    });
    return;
  }

  if (!API_KEY) {
    console.error("[Auth Middleware] PHANTOMTRACE_API_KEY is not configured.");
    res.status(503).json({
      error: "ServiceUnavailable",
      message: "Authentication service is not configured",
    });
    return;
  }

  if (!safeEqual(token, API_KEY)) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Invalid authentication token",
    });
    return;
  }

  const ownerUid =
    process.env.PHANTOMTRACE_OWNER_UID?.trim() || "phantomtrace-owner";

  const user: AuthenticatedUser = {
    uid: ownerUid,
    email: process.env.PHANTOMTRACE_OWNER_EMAIL?.trim() || "owner@phantomtrace.local",
    displayName:
      process.env.PHANTOMTRACE_OWNER_NAME?.trim() || "PhantomTrace Owner",
  };

  req.ownerUid = user.uid;
  req.user = user;

  next();
}
