# PhantomTrace — Production Deployment Guide (Phase 6)

**Target System:** PhantomTrace Enterprise Detection & Triage Platform  
**Architecture:** Windows Scanner (Read-Only) -> Node.js Express API -> Firebase Firestore -> React/TypeScript Dashboard on Vercel  
**Security Posture:** Strictly Read-Only. Zero process termination, zero memory alteration, zero automated file deletion.

---

## Table of Contents

- [A. GitHub Setup](#a-github-setup)
- [B. Vercel Frontend Setup](#b-vercel-frontend-setup)
- [C. Backend Deployment Requirements](#c-backend-deployment-requirements)
- [D. Firebase Configuration](#d-firebase-configuration)
- [E. Environment Variables Reference](#e-environment-variables-reference)
- [F. Production API URL Configuration](#f-production-api-url-configuration)
- [G. Windows Scanner Integration](#g-windows-scanner-integration)
- [H. Testing & Verification Checklist](#h-testing--verification-checklist)
- [I. Rollback & Disaster Recovery Considerations](#i-rollback--disaster-recovery-considerations)
- [J. Final Production Architecture Diagram](#j-final-production-architecture-diagram)

---

## A. GitHub Setup

### 1. Repository Hygiene & Secret Check
Before pushing to GitHub, verify that all sensitive files and build artifacts are strictly ignored:
- Ensure `.gitignore` contains rules for `.env`, `node_modules/`, `dist/`, `server/dist/`, `*.pem`, `*.key`, and `serviceAccountKey.json`.
- Run a scan for uncommitted secrets or sensitive scan fixtures:
  ```bash
  git status
  ```
- Verify that only template files (`.env.example`, `server/.env.example`) are tracked.

### 2. Pushing to GitHub
```bash
git add .
git commit -m "feat(phase6): prepare phantomtrace for production deployment"
git branch -M main
git remote add origin https://github.com/YOUR_ORGANIZATION/PhantomTrace-Web.git
git push -u origin main
```

---

## B. Vercel Frontend Setup

### 1. Connect Repository
1. Log in to [Vercel Dashboard](https://vercel.com).
2. Click **Add New Project** and select your GitHub repository (`PhantomTrace-Web`).

### 2. Configure Build & Output Settings
- **Framework Preset:** `Vite`
- **Root Directory:** `./` (Repository root)
- **Build Command:** `npm run build`
- **Output Directory:** `dist`
- **Install Command:** `npm install`

### 3. SPA Route Configuration (`vercel.json`)
The repository includes `vercel.json` in the root directory:
```json
{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```
*Purpose:* Ensures deep routes such as `/dashboard`, `/alerts`, `/processes`, `/processes/:pid`, `/scan-history`, `/reports`, and `/settings` resolve to `index.html` without 404 errors on browser refresh.

### 4. Deploy Frontend
Click **Deploy**. Once complete, Vercel will assign a production domain (e.g., `https://phantomtrace.vercel.app`).

---

## C. Backend Deployment Requirements

The Node.js Express API (`server/`) must be deployed to a modern Node.js hosting platform (such as Render, Railway, Fly.io, AWS App Runner, or Google Cloud Run).

### 1. Hosting Specifications
- **Node.js Version:** `18.x`, `20.x`, or `22.x`
- **Memory Allocation:** Minimum 512 MB (1 GB recommended for handling concurrent 20MB+ scan payloads)
- **CPU:** 1 vCPU
- **Build Command:** `npm run build` (inside `server/`)
- **Start Command:** `npm start` (which runs `node dist/index.js`)

### 2. Example: Render.com Web Service
1. Create a **New Web Service** pointing to the repository.
2. Set **Root Directory:** `server`
3. Set **Build Command:** `npm install && npm run build`
4. Set **Start Command:** `npm start`
5. Configure Environment Variables (see Section E).

---

## D. Firebase Configuration

### 1. Create Firebase Project
1. Navigate to the [Firebase Console](https://console.firebase.google.com/).
2. Create a new project: `YOUR_FIREBASE_PROJECT_ID`.
3. Enable **Authentication** (Email/Password or Google Sign-In as required).
4. Enable **Cloud Firestore** in Production mode.

### 2. Deploy Firestore Security Rules
Deploy the following rules (also available in `firestore.rules`):
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    match /endpoints/{endpointId} {
      allow read, write: if request.auth != null && resource.data.ownerUid == request.auth.uid;
    }
    match /scans/{scanId} {
      allow read: if request.auth != null && resource.data.ownerUid == request.auth.uid;
      allow create: if request.auth != null && request.resource.data.ownerUid == request.auth.uid;
    }
    match /processes/{processId} {
      allow read: if request.auth != null && resource.data.ownerUid == request.auth.uid;
      allow create: if request.auth != null && request.resource.data.ownerUid == request.auth.uid;
    }
    match /alerts/{alertId} {
      allow read: if request.auth != null && resource.data.ownerUid == request.auth.uid;
      allow write: if request.auth != null && resource.data.ownerUid == request.auth.uid;
    }
    match /reports/{reportId} {
      allow read: if request.auth != null && resource.data.ownerUid == request.auth.uid;
      allow write: if request.auth != null && resource.data.ownerUid == request.auth.uid;
    }
  }
}
```

### 3. Generate Service Account Key (Backend Only)
1. In Firebase Console, go to **Project Settings** > **Service accounts**.
2. Click **Generate new private key** and download the JSON.
3. Extract `project_id`, `client_email`, and `private_key` to configure backend environment variables.
4. **CRITICAL:** Never store or commit this JSON file in Git or frontend source directories.

---

## E. Environment Variables Reference

### Frontend Environment Variables (Vercel)
Add under Vercel Project Settings > Environment Variables:

| Variable | Description | Example / Default |
| :--- | :--- | :--- |
| `VITE_API_BASE_URL` | Base URL of deployed PhantomTrace API | `https://api.phantomtrace.security` |

### Backend Environment Variables (Hosting Provider)
Add under your backend service settings:

| Variable | Description | Example / Value |
| :--- | :--- | :--- |
| `PORT` | HTTP port for server listener | `5000` (or host assigned) |
| `NODE_ENV` | Runtime environment mode | `production` |
| `CORS_ORIGIN` | Allowed frontend origin(s) | `https://phantomtrace.vercel.app` |
| `FIREBASE_PROJECT_ID` | Google Cloud / Firebase project ID | `YOUR_FIREBASE_PROJECT_ID` |
| `FIREBASE_CLIENT_EMAIL`| Service account email | `firebase-adminsdk@YOUR_PROJECT.iam.gserviceaccount.com` |
| `FIREBASE_PRIVATE_KEY` | Service account RSA private key | `"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"` |

---

## F. Production API URL Configuration

The React frontend utilizes `ApiDataService` (`src/services/apiDataService.ts`), which automatically resolves API requests:
- If `VITE_API_BASE_URL` is configured (e.g. `https://api.phantomtrace.security`), all requests are dispatched to:
  `https://api.phantomtrace.security/api/<route>`
- Normalization automatically removes trailing slashes and ensures single `/api` prefixing.
- If the remote API is unreachable, the dashboard automatically provides non-destructive fallback to `LocalDataService` so analysts are never left with broken UI views.

---

## G. Windows Scanner Integration

### 1. Architecture & Scanner Immutability
- The existing Windows scanner executable `PhantomTrace_Windows_Release_1.0.exe` is **READ-ONLY**.
- **DO NOT** modify the Python detection engine, memory scanner, behavioral rules, or scoring weights.
- The scanner produces `scan_results.json` upon completion of an endpoint audit.

### 2. Transport Layer (`scripts/upload_scan.py`)
To integrate endpoint scans with the production cloud API without altering the core detection binary, use the standalone dispatcher provided in `scripts/upload_scan.py`:

```bash
# Python 3 standard library (no pip dependencies required)
python scripts/upload_scan.py \
  --api-url https://api.phantomtrace.security \
  --token YOUR_FIREBASE_ID_TOKEN \
  --file scan_results.json
```

Or via Node.js runtime:
```bash
node scripts/upload_scan.mjs https://api.phantomtrace.security YOUR_FIREBASE_ID_TOKEN scan_results.json
```

### 3. Windows Scheduled Task / Automation Example
To run automated periodic scanning and cloud ingestion via Windows PowerShell:
```powershell
# 1. Execute read-only scanner
.\PhantomTrace_Windows_Release_1.0.exe --output scan_results.json

# 2. Dispatch to cloud API via HTTPS
python .\scripts\upload_scan.py --api-url "https://api.phantomtrace.security" --token "$ENV:PT_TOKEN" --file "scan_results.json"
```

---

## H. Testing & Verification Checklist

Complete this checklist prior to production promotion:

- [x] **TypeScript Validation:** `npx tsc --noEmit` exits with status `0` (Zero errors).
- [x] **Frontend Build:** `npm run build` succeeds cleanly, producing optimized `dist/` bundle.
- [x] **Backend Build:** `npm run build` (in `server/`) compiles TypeScript to `dist/`.
- [x] **API Healthcheck:** `GET /api/health` returns `{"status":"ok","service":"PhantomTrace API"}`.
- [x] **Unauthenticated Access:** Unauthenticated requests to `/api/scans` or `/api/alerts` return `401 Unauthorized`.
- [x] **Authorized Access:** Authenticated requests return tenant-isolated telemetry with HTTP `200`.
- [x] **Payload Ingestion:** Transmitting a multi-megabyte `scan_results.json` succeeds and returns scan and endpoint IDs.
- [x] **Duplicate Protection:** Resubmitting an identical scan produces `duplicate: true` without data corruption.
- [x] **Evidence Preservation:** Memory indicators (`EXECUTABLE_WRITABLE_MEMORY`), threat scores, and process telemetry match scanner output exactly.
- [x] **Threat Score Integrity:** Threat scores are NEVER altered or recalculated by web platform.
- [x] **SPA Routing:** Browser reload on `/dashboard`, `/alerts`, `/processes`, `/scan-history`, `/reports`, `/settings` succeeds without 404s.
- [x] **Dynamic Clock:** Top-right system clock continuously updates with local time.

---

## I. Rollback & Disaster Recovery Considerations

1. **Frontend Rollback (Vercel):**
   - Vercel retains immutable deployment URLs for every commit.
   - To roll back instantly: Go to **Vercel Dashboard** > **Deployments** > Select previous stable deployment > Click **Instant Rollback**.
2. **Backend Rollback:**
   - In your backend hosting provider (e.g. Render/Railway), select the previous successful release and redeploy.
   - The API is stateless; rollback does not alter data previously stored in Cloud Firestore.
3. **Database Safeguards (Cloud Firestore):**
   - All scan entries are immutable forensic snapshots.
   - Point-in-time recovery (PITR) can be enabled in Google Cloud Console for continuous disaster recovery.

---

## J. Final Production Architecture Diagram

```
+-------------------------------------------------------------+
|                  HOST WINDOWS ENDPOINT                      |
|                                                             |
|  [ PhantomTrace_Windows_Release_1.0.exe ]                   |
|  - Memory Scanner (VirtualQueryEx, ReadProcessMemory)       |
|  - Behavioral Engine (Process Tree, Parent-Child)           |
|  - Threat Scoring Engine (Strictly Read-Only)               |
|                           |                                 |
|                           v                                 |
|                 [ scan_results.json ]                       |
|                           |                                 |
|                           v                                 |
|             [ scripts/upload_scan.py ]                      |
+-------------------------------------------------------------+
                            |
                            | HTTPS POST /api/scans/ingest
                            | Header: Authorization Bearer <Token>
                            v
+-------------------------------------------------------------+
|               PRODUCTION BACKEND API HOST                   |
|         (Render / Railway / GCP Cloud Run / Fly.io)         |
|                                                             |
|  [ Express Node.js Engine (server/dist/index.js) ]          |
|  - Security Headers: nosniff, DENY, xss-protection         |
|  - Body Parser: 50MB telemetry limit                        |
|  - Authentication: Firebase Admin SDK verifyIdToken()       |
|  - Ingestion Validator: Schema, duplicate SHA-256 check     |
|  - Multi-tenant Firestore Service                           |
+-------------------------------------------------------------+
                            |
                 +----------+----------+
                 |                     |
                 v                     v
+-----------------------------+  +-----------------------------+
|   FIREBASE AUTHENTICATION   |  |   GOOGLE CLOUD FIRESTORE    |
| - Identity verification     |  | - scans                     |
| - Secure token issuance     |  | - endpoints                 |
|                             |  | - processes                 |
|                             |  | - alerts                    |
|                             |  | - reports                   |
+-----------------------------+  +-----------------------------+
                                               ^
                                               | REST Queries
                                               v
+-------------------------------------------------------------+
|                      VERCEL HOSTING                         |
|                                                             |
|  [ React + TypeScript Web Dashboard ]                       |
|  - Static CDN edge delivery                                 |
|  - SPA rewrites (/dashboard, /alerts, /processes)           |
|  - Dynamic SOC Clock (Intl.DateTimeFormat)                  |
|  - ApiDataService connecting via VITE_API_BASE_URL          |
|  - Comprehensive Threat Investigation & Forensic Views      |
|  - 100% Read-Only Security Analyst Console                  |
+-------------------------------------------------------------+
```
