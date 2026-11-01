import { Router, Request, Response } from "express";
import fs from "fs";
import path from "path";
import { Readable } from "stream";
import { pipeline } from "stream/promises";

export const agentRouter = Router();

// Approved release asset URLs (GitHub Releases)
const GITHUB_AGENT_RELEASE_ASSET_URL =
  process.env.PHANTOMTRACE_AGENT_RELEASE_URL ||
  "https://github.com/JaydeepChawla/PhantomTrace-Web/releases/download/v1.0.0/PhantomTrace-Agent.exe";

const GITHUB_INSTALLER_RELEASE_ASSET_URL =
  process.env.PHANTOMTRACE_INSTALLER_RELEASE_URL ||
  "https://github.com/JaydeepChawla/PhantomTrace-Web/releases/download/v1.0.0/PhantomTrace_Agent_Setup.exe";

// Candidate local filesystem paths
const LOCAL_AGENT_PATHS = [
  path.resolve(__dirname, "../../../release_bin/PhantomTrace-Agent.exe"),
  path.resolve(__dirname, "../../../dist/PhantomTrace-Agent.exe"),
  path.resolve(__dirname, "../../../public/downloads/PhantomTrace-Agent.exe"),
  path.resolve(__dirname, "../../downloads/PhantomTrace-Agent.exe"),
];

const LOCAL_INSTALLER_PATHS = [
  path.resolve(__dirname, "../../../dist/PhantomTrace_Agent_Setup.exe"),
  path.resolve(__dirname, "../../../public/downloads/PhantomTrace_Agent_Setup.exe"),
  path.resolve(__dirname, "../../../public/PhantomTrace_Agent_Setup.exe"),
  path.resolve(__dirname, "../../downloads/PhantomTrace_Agent_Setup.exe"),
];

/**
 * Helper to stream remote release assets safely with proper headers
 */
async function streamRemoteAsset(
  url: string,
  downloadFilename: string,
  res: Response
): Promise<void> {
  try {
    const response = await fetch(url, {
      redirect: "follow",
      headers: {
        "User-Agent": "PhantomTrace-Backend/1.0",
      },
    });

    if (!response.ok || !response.body) {
      if (!res.headersSent) {
        res.status(503).json({
          error: {
            code: "AGENT_UNAVAILABLE",
            message: "Unable to download the PhantomTrace Agent. Please try again.",
          },
        });
      }
      return;
    }

    res.setHeader("Content-Disposition", `attachment; filename="${downloadFilename}"`);
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
}

/**
 * GET /api/agent/download
 * Downloads the approved PhantomTrace Windows Agent or Inno Setup Installer.
 *
 * Query options:
 * - ?installer=true: Serves PhantomTrace_Agent_Setup.exe
 * - default: Serves PhantomTrace-Agent.exe
 *
 * Constraints:
 * - Arbitrary file query parameters (e.g. ?file=...) are strictly rejected.
 * - Only verified release deliverables are provided.
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

  // Branch 1: Inno Setup Installer deliverable
  if (req.query.installer === "true") {
    for (const candidatePath of LOCAL_INSTALLER_PATHS) {
      if (fs.existsSync(candidatePath)) {
        try {
          const stat = fs.statSync(candidatePath);
          res.setHeader("Content-Disposition", 'attachment; filename="PhantomTrace_Agent_Setup.exe"');
          res.setHeader("Content-Type", "application/octet-stream");
          res.setHeader("Content-Length", stat.size.toString());
          const stream = fs.createReadStream(candidatePath);
          return stream.pipe(res);
        } catch {
          // Fall through to remote asset
        }
      }
    }

    // Remote GitHub Release stream for installer
    return streamRemoteAsset(
      GITHUB_INSTALLER_RELEASE_ASSET_URL,
      "PhantomTrace_Agent_Setup.exe",
      res
    );
  }

  // Branch 2: Standalone Agent binary deliverable
  for (const candidatePath of LOCAL_AGENT_PATHS) {
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

  // Remote GitHub Release stream for agent
  return streamRemoteAsset(
    GITHUB_AGENT_RELEASE_ASSET_URL,
    "PhantomTrace-Agent.exe",
    res
  );
});
