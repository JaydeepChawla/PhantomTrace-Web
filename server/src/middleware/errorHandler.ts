import type { Request, Response, NextFunction } from "express";

/**
 * Global Express Error Handling Middleware.
 * Prevents server crashes and formats error responses safely without leaking secrets or stack traces.
 */
export function errorHandler(
  err: any,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  // Check for body-parser payload limit exceeded (413 Payload Too Large)
  if (err.type === "entity.too.large" || err.status === 413 || err.statusCode === 413) {
    res.status(413).json({
      error: {
        code: "PAYLOAD_TOO_LARGE",
        message: "Scan payload exceeds the maximum allowable request size limit.",
      },
    });
    return;
  }

  // Check for body-parser malformed JSON syntax error (400 Bad Request)
  if (err.type === "entity.parse.failed" || (err instanceof SyntaxError && "body" in err)) {
    res.status(400).json({
      error: {
        code: "INVALID_JSON",
        message: "Malformed JSON payload in request body.",
      },
    });
    return;
  }

  // CORS rejection
  if (err.message === "CORS_NOT_ALLOWED") {
    res.status(403).json({
      error: {
        code: "CORS_FORBIDDEN",
        message: "Cross-Origin request blocked by CORS policy.",
      },
    });
    return;
  }

  const statusCode = typeof err.status === "number" ? err.status : typeof err.statusCode === "number" ? err.statusCode : 500;
  const code = err.code || (statusCode >= 500 ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST");
  const message = statusCode >= 500 ? "An unexpected internal server error occurred." : err.message || "Invalid request.";

  console.error(`[Error Handler] ${statusCode} (${code}) - ${err.message || message}`);

  res.status(statusCode).json({
    error: {
      code,
      message,
    },
  });
}
