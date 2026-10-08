import { Router, Request, Response } from "express";
import fs from "fs";
import path from "path";
import { Readable } from "stream";
import { pipeline } from "stream/promises";

export const agentRouter = Router();

// Approved release asset URL (GitHub Releases)
const GITHUB_RELEASE_ASSET_URL =
  process.env.PHANTOMTRACE_AGENT_RELEASE_URL ||
  "https://github.com/JaydeepChawla/PhantomTrace-Web/releases/download/v1.0.0/PhantomTrace-Agent.exe";

// Candidate local filesystem paths
const LOCAL_CANDIDATE_PATHS = [
  path.resolve(__dirname, "../../../release_bin/PhantomTrace-Agent.exe"),
  path.resolve(__dirname, "../../../dist/PhantomTrace-Agent.exe"),
  path.resolve(__dirname, "../../../public/downloads/PhantomTrace-Agent.exe"),
  path.resolve(__dirname, "../../downloads/PhantomTrace-Agent.exe"),
];

/**
 * GET /api/agent/download
 * Downloads the approved PhantomTrace Windows Agent executable (PhantomTrace-Agent.exe).
 *
 * Constraints:
 * - Query parameters (e.g. ?file=...) are strictly rejected.
 * - Only the approved PhantomTrace-Agent.exe binary is provided.
 * - Zero exposure of server filesystem paths, GitHub credentials, or secrets.
 * - Fallback error: "Unable to download the PhantomTrace Agent. Please try again."
 */
agentRouter.get("/download", async (req: Request, res: Response) => {
  // Reject arbitrary file parameter attempts
  if (req.query.file) {
    return res.status(400).json({
      error: {
        code: "INVALID_REQUEST",
        message: "Arbitrary file downloads are prohibited.",
      },
    });
  }

  // Check for installer requested via query flag
  if (req.query.installer === "true") {
    const installerPaths = [
      path.resolve(__dirname, "../../../dist/PhantomTrace_Agent_Setup.exe"),
      path.resolve(__dirname, "../../../public/downloads/PhantomTrace_Agent_Setup.exe"),
      path.resolve(__dirname, "../../../public/PhantomTrace_Agent_Setup.exe"),
      path.resolve(__dirname, "../../downloads/PhantomTrace_Agent_Setup.exe"),
    ];
    for (const candidatePath of installerPaths) {
      if (fs.existsSync(candidatePath)) {
        try {
          const stat = fs.statSync(candidatePath);
          res.setHeader("Content-Disposition", 'attachment; filename="PhantomTrace_Agent_Setup.exe"');
          res.setHeader("Content-Type", "application/octet-stream");
          res.setHeader("Content-Length", stat.size.toString());
          const stream = fs.createReadStream(candidatePath);
          return stream.pipe(res);
        } catch {
          // Fall through
        }
      }
    }
  }

  // 1. Check local candidates first
  for (const candidatePath of LOCAL_CANDIDATE_PATHS) {
    if (fs.existsSync(candidatePath)) {
      try {
        const stat = fs.statSync(candidatePath);
        res.setHeader("Content-Disposition", 'attachment; filename="PhantomTrace-Agent.exe"');
        res.setHeader("Content-Type", "application/octet-stream");
        res.setHeader("Content-Length", stat.size.toString());
        const stream = fs.createReadStream(candidatePath);
        return stream.pipe(res);
      } catch {
        // Fall through to remote asset
      }
    }
  }

  // 2. Fetch and stream from approved GitHub Release asset
  try {
    const response = await fetch(GITHUB_RELEASE_ASSET_URL, {
      redirect: "follow",
      headers: {
        "User-Agent": "PhantomTrace-Backend/1.0",
      },
    });

    if (!response.ok || !response.body) {
      return res.status(503).json({
        error: {
          code: "AGENT_UNAVAILABLE",
          message: "Unable to download the PhantomTrace Agent. Please try again.",
        },
      });
    }

    res.setHeader("Content-Disposition", 'attachment; filename="PhantomTrace-Agent.exe"');
    res.setHeader("Content-Type", "application/octet-stream");
    const contentLength = response.headers.get("content-length");
    if (contentLength) {
      res.setHeader("Content-Length", contentLength);
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const nodeStream = Readable.fromWeb(response.body as any);
    await pipeline(nodeStream, res);
  } catch {
    if (!res.headersSent) {
      res.status(503).json({
        error: {
          code: "AGENT_UNAVAILABLE",
          message: "Unable to download the PhantomTrace Agent. Please try again.",
        },
      });
    }
  }
});
