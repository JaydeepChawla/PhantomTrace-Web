# PhantomTrace — Enterprise Detection & Triage Web Platform

> *"Trace what others can't see."*

PhantomTrace is an enterprise memory and behavioral detection platform. The web console connects to the read-only Windows detection engine (`PhantomTrace_Windows_Release_1.0.exe`) to provide security operations center (SOC) analysts with telemetry triage, memory region analysis, process tree visualization, and threat alert investigation.

---

## Architecture Overview

```
Windows PhantomTrace Scanner (Read-Only)
                 |
                 | HTTPS POST /api/scans/ingest (Bearer Token)
                 v
      PhantomTrace Node.js API (Express)
                 |
                 v
   Firebase Authentication & Cloud Firestore
                 |
                 v
React + TypeScript Web Dashboard (Vercel)
```

---

## 1. Install Dependencies

### Frontend & Project Root
```bash
npm install
```

### Backend API Server
```bash
cd server
npm install
cd ..
```

---

## 2. Configure Environment Variables

Never commit real credentials to version control. Configuration templates are provided.

### Frontend (`.env`)
Create `.env` in the project root:
```env
# URL of your deployed Node.js backend
VITE_API_BASE_URL=http://localhost:5000
```
In production, point `VITE_API_BASE_URL` to your live API domain (e.g. `https://api.phantomtrace.security`).

### Backend (`server/.env`)
Create `server/.env`:
```env
PORT=5000
NODE_ENV=development
CORS_ORIGIN=http://localhost:5173

# Firebase Admin Service Account Credentials
FIREBASE_PROJECT_ID=YOUR_FIREBASE_PROJECT_ID
FIREBASE_CLIENT_EMAIL=firebase-adminsdk@YOUR_FIREBASE_PROJECT_ID.iam.gserviceaccount.com
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
```

---

## 3. Start Frontend

```bash
npm run dev
```
The React dashboard will be accessible at: `http://localhost:5173`

---

## 4. Start Backend

```bash
cd server
npm run dev
```
The API server will listen on `http://localhost:5000`. Health check endpoint: `GET /api/health`.

---

## 5. Run Production Build

Verify that both frontend and backend compile without errors:

### Frontend Production Build
```bash
npx tsc --noEmit
npm run build
```
Generates production bundle in `dist/`.

### Backend Production Build
```bash
cd server
npm run build
```
Compiles TypeScript into `server/dist/`.

---

## 6. Deploy Frontend to Vercel

1. Import the repository into your [Vercel](https://vercel.com) account.
2. Ensure the framework preset is **Vite**.
3. Under **Environment Variables**, set:
   ```env
   VITE_API_BASE_URL=https://YOUR_API_DOMAIN
   ```
4. Deploy. The included `vercel.json` automatically configures SPA route rewrites to `/index.html` to prevent 404s on browser refresh.

---

## 7. Deploy Backend

Deploy the `server/` directory to a Node.js hosting platform (such as Render, Railway, Fly.io, or Google Cloud Run):
- **Root Directory:** `server`
- **Build Command:** `npm install && npm run build`
- **Start Command:** `npm start`
- Configure environment variables: `PORT`, `NODE_ENV=production`, `CORS_ORIGIN=https://YOUR_VERCEL_DOMAIN`, and Firebase Admin keys.

---

## 8. Configure Firebase

1. Create a project in [Firebase Console](https://console.firebase.google.com/).
2. Enable **Authentication** and **Cloud Firestore**.
3. Deploy security rules from `firestore.rules`.
4. Generate a Service Account key under **Project Settings** > **Service accounts** and copy credentials to the backend environment variables.
5. **Security Guarantee:** Firebase Admin credentials are strictly backend-only and never exposed to the browser.

---

## 9. Configure Windows Scanner Ingestion

The Windows detection engine (`PhantomTrace_Windows_Release_1.0.exe`) is **100% READ-ONLY** and generates `scan_results.json`.

To transmit results to the cloud API without modifying the scanner:

### Python Dispatcher (Standard Library)
```bash
python scripts/upload_scan.py \
  --api-url https://YOUR_API_DOMAIN \
  --token YOUR_FIREBASE_TOKEN \
  --file scan_results.json
```

### Node.js Dispatcher
```bash
node scripts/upload_scan.mjs https://YOUR_API_DOMAIN YOUR_FIREBASE_TOKEN scan_results.json
```

---

## Security & Safety Invariants

- **Read-Only Engine:** Zero process termination, zero memory modification, zero file deletion.
- **Evidence Integrity:** RWX allocations, memory indicators, and behavioral flags are preserved without modification.
- **Threat Score Immutability:** Threat scores are calculated exclusively by the Windows engine and are NEVER recalculated or altered by the web platform.
- **Tenant Isolation:** Ingested scans are cryptographically bound to the authenticated `ownerUid`.

---

## Documentation

- [Deployment Readiness Audit](./PHANTOMTRACE_PHASE6_DEPLOYMENT_READINESS.md)
- [Production Deployment Guide](./PHANTOMTRACE_PHASE6_DEPLOYMENT_GUIDE.md)
- [Phase 5 Security & Validation Report](./PHANTOMTRACE_PHASE5_SECURITY_VALIDATION.md)
