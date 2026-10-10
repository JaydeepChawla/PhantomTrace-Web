import express from "express";
import cors from "cors";
import { healthRouter } from "./routes/health";
import { authRouter } from "./routes/auth";
import { devicesRouter } from "./routes/devices";
import { usersRouter } from "./routes/users";
import { endpointsRouter } from "./routes/endpoints";
import { scansRouter } from "./routes/scans";
import { processesRouter } from "./routes/processes";
import { alertsRouter } from "./routes/alerts";
import { reportsRouter } from "./routes/reports";
import { agentRouter } from "./routes/agent";
import { webThreatsRouter } from "./routes/webThreats";
import { dashboardRouter } from "./routes/dashboard";
import { errorHandler } from "./middleware/errorHandler";

export const app = express();

// Disable express identification header
app.disable("x-powered-by");

// Enterprise API Security Headers Middleware
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

// Security and Cross-Origin Resource Sharing (CORS)
const defaultAllowedOrigins = [
  "https://phantom-trace-web.vercel.app",
  "http://localhost:5173",
  "http://localhost:3000",
  "http://127.0.0.1:5173",
];

const rawOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map((o) => o.trim())
  : defaultAllowedOrigins;

// Normalize origins by stripping trailing slashes for resilient matching
const allowedOrigins = rawOrigins.map((o) => o.replace(/\/+$/, ""));

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. mobile apps, curl, scanner, or server-to-server)
      if (!origin) {
        callback(null, true);
        return;
      }
      const cleanOrigin = origin.replace(/\/+$/, "");
      if (
        allowedOrigins.includes(cleanOrigin) ||
        cleanOrigin.startsWith("chrome-extension://") ||
        cleanOrigin.startsWith("edge-extension://") ||
        cleanOrigin.startsWith("moz-extension://")
      ) {
        callback(null, true);
      } else {
        callback(new Error("CORS_NOT_ALLOWED"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Endpoint-Id", "X-Scan-Timestamp"],
  })
);

// Body Parsing Middleware (50mb to accommodate real endpoint memory telemetry)
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// API Routes
app.use("/api/health", healthRouter);
app.use("/api/auth", authRouter);
app.use("/api/devices", devicesRouter);
app.use("/api/users", usersRouter);
app.use("/api/endpoints", endpointsRouter);
app.use("/api/scans", scansRouter);
app.use("/api/processes", processesRouter);
app.use("/api/alerts", alertsRouter);
app.use("/api/reports", reportsRouter);
app.use("/api/agent", agentRouter);
app.use("/api/web-threats", webThreatsRouter);
app.use("/api/dashboard", dashboardRouter);

// Root informational endpoint
app.get("/", (_req, res) => {
  res.json({
    name: "PhantomTrace Web API",
    version: "1.0.0",
    docs: "/api/health",
  });
});

// Fallback 404 Handler for Unrecognized API Routes
app.use((req, res) => {
  res.status(404).json({
    error: {
      code: "NOT_FOUND",
      message: `Cannot ${req.method} ${req.originalUrl}`,
    },
  });
});

// Global Error Handler Middleware
app.use(errorHandler);
