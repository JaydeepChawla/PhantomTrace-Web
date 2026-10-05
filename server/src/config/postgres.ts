import { Pool } from "pg";

const databaseUrl =
    process.env.DATABASE_URL || "postgresql://mock:mock@localhost:5432/mock";

if (!process.env.DATABASE_URL && process.env.NODE_ENV === "production") {
    throw new Error("DATABASE_URL is not configured.");
}

export const postgresPool = new Pool({
    connectionString: databaseUrl,
    ssl: process.env.DATABASE_URL
        ? {
              rejectUnauthorized: false,
          }
        : undefined,
});

postgresPool.on("error", (err) => {
    if (process.env.DATABASE_URL) {
        console.error("[PostgreSQL] Unexpected pool error:", err);
    }
});

export async function testPostgresConnection(): Promise<void> {
    const client = await postgresPool.connect();

    try {
        await client.query("SELECT 1");
        console.log("[PostgreSQL] Connection successful.");
    } finally {
        client.release();
    }
}