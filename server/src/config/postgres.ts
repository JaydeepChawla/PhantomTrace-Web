import { Pool } from "pg";

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
    throw new Error("DATABASE_URL is not configured.");
}

export const postgresPool = new Pool({
    connectionString: databaseUrl,
    ssl: {
        rejectUnauthorized: false,
    },
});

postgresPool.on("error", (err) => {
    console.error("[PostgreSQL] Unexpected pool error:", err);
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