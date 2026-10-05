import dotenv from "dotenv";
dotenv.config();

import { app } from "./app";
import { postgresService } from "./services/postgresService";

const PORT = parseInt(process.env.PORT || "5000", 10);

const server = app.listen(PORT, async () => {
  console.log(`====================================================`);
  console.log(` PhantomTrace Security API v1.0.0`);
  console.log(` Server listening at http://localhost:${PORT}`);
  console.log(` Health check available at http://localhost:${PORT}/api/health`);
  console.log(` Mode: ${process.env.NODE_ENV || "development"}`);
  console.log(`====================================================`);

  // Initialize device and pairing tables in PostgreSQL
  try {
    await postgresService.initDatabaseSchema();
  } catch (err) {
    console.warn("[Server] Database schema init note:", (err as Error).message);
  }
});

// Graceful termination handling
process.on("SIGTERM", () => {
  console.log("[Server] Received SIGTERM, shutting down gracefully...");
  server.close(() => {
    console.log("[Server] Process terminated.");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("[Server] Received SIGINT, shutting down gracefully...");
  server.close(() => {
    console.log("[Server] Process terminated.");
    process.exit(0);
  });
});
