import admin from "firebase-admin";

/**
 * =====================================================================
 * PHANTOMTRACE BACKEND — FIREBASE ADMIN SDK CONFIGURATION
 * =====================================================================
 * Strictly backend-only. Never expose credentials to frontend/browser.
 *
 * Reads service account credentials from environment variables:
 * - FIREBASE_PROJECT_ID
 * - FIREBASE_CLIENT_EMAIL
 * - FIREBASE_PRIVATE_KEY (unescaping \n)
 *
 * Alternatively supports GOOGLE_APPLICATION_CREDENTIALS file path.
 * =====================================================================
 */

const projectId = process.env.FIREBASE_PROJECT_ID;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const rawPrivateKey = process.env.FIREBASE_PRIVATE_KEY;
const privateKey = rawPrivateKey ? rawPrivateKey.replace(/\\n/g, "\n") : undefined;

let isConfigured = false;

if (admin.apps.length === 0) {
  if (projectId && clientEmail && privateKey) {
    try {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId,
          clientEmail,
          privateKey,
        }),
      });
      isConfigured = true;
      console.log(`[Firebase Admin] Successfully initialized with project: ${projectId}`);
    } catch (err) {
      console.error("[Firebase Admin] Failed to initialize with provided service account credentials:", err);
      admin.initializeApp({ projectId: projectId || "phantomtrace-local" });
    }
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    try {
      admin.initializeApp({
        credential: admin.credential.applicationDefault(),
      });
      isConfigured = true;
      console.log("[Firebase Admin] Successfully initialized with Application Default Credentials");
    } catch (err) {
      console.error("[Firebase Admin] Failed to initialize with Application Default Credentials:", err);
      admin.initializeApp({ projectId: "phantomtrace-local" });
    }
  } else {
    // Development fallback when credentials are not yet populated in .env
    console.warn(
      "[Firebase Admin] NOTICE: Running in development mode without live service account credentials. " +
      "Provide FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY in server/.env for production."
    );
    admin.initializeApp({
      projectId: projectId || "phantomtrace-security-dev",
    });
  }
}

export const firebaseAdmin = admin;
export const auth = admin.auth();
export const db = admin.firestore();
export const isFirebaseConfigured = isConfigured;
