# Complete Deployment & Hosting Guide for TrustProof-Cloud

This guide provides step-by-step instructions to host and deploy the complete **TrustProof-Cloud** risk-adaptive ML inference system.

---

## 1. Prerequisites & Repository Setup

Ensure your latest code is committed and pushed to your GitHub repository:
- **Repository**: `https://github.com/nagasumukh01/Cloud_Project.git`
- **Main Branch**: `main`

If you make any local changes, push them to GitHub with:
```bash
git add .
git commit -m "update: deployment configuration"
git push origin main
```

---

## 2. Option A — Render Deployment (Recommended)

Render offers free hosting with native support for `render.yaml` Blueprint configurations.

### Method 1: Render Blueprint (Zero Manual Configuration)

1. Go to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** in the top-right corner and select **Blueprint**.
3. Connect your GitHub repository (`nagasumukh01/Cloud_Project`).
4. Render will automatically read `render.yaml` and configure:
   - **Environment**: Python 3.11+
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn services.api.main:app --host 0.0.0.0 --port $PORT`
5. Click **Apply**. Render will build and launch your service.

### Method 2: Manual Web Service Setup

If creating a direct Web Service on Render:
1. Click **New +** → **Web Service**.
2. Select repository `nagasumukh01/Cloud_Project`.
3. Fill in the deployment details:
   - **Name**: `trustproof-cloud-api`
   - **Language**: Python 3
   - **Region**: Select your nearest region
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn services.api.main:app --host 0.0.0.0 --port $PORT`
4. Expand **Environment Variables** and add:
   - `TPC_ENV` = `production`
   - `TPC_REQUIRE_AUTH` = `false` *(or `true` if you pass `TPC_API_KEY`)*
   - `TPC_DATA_DIR` = `./data`
5. Click **Create Web Service**.

---

## 3. Option B — Railway / Dokku / Heroku Deployment

Since the repository includes a `Procfile`, Railway and Heroku detect the start command automatically.

1. Log in to [Railway.app](https://railway.app).
2. Click **New Project** → **Deploy from GitHub repo**.
3. Select `nagasumukh01/Cloud_Project`.
4. Railway auto-detects `Procfile` and builds the Python app.
5. In **Variables**, add:
   - `TPC_ENV` = `production`
   - `TPC_REQUIRE_AUTH` = `false`
6. Click **Deploy**.

---

## 4. Option C — Self-Hosted VPS or Docker Compose

For persistent 24/7 hosting on Ubuntu / Debian / Fedora / Windows VPS:

### Step 1: Clone the repository
```bash
git clone https://github.com/nagasumukh01/Cloud_Project.git trustproof-cloud
cd trustproof-cloud
```

### Step 2: Build & Launch with Docker Compose
```bash
docker compose up -d --build
```

### Step 3: Verify the Running Container
```bash
curl http://localhost:8000/health
```

To view live container logs:
```bash
docker compose logs -f api
```

---

## 5. Verifying & Testing Your Live Deployment

Once deployed (e.g. at `https://cloud-project-3bw5.onrender.com`), verify your endpoints:

### A. Health & System Status
```bash
curl https://cloud-project-3bw5.onrender.com/health
```
Expected output:
```json
{"status":"ok","service":"api-gateway","version":"0.2.0-m2","workers_active":4,"database":true}
```

### B. Interactive API Documentation
Open in your web browser:
```
https://cloud-project-3bw5.onrender.com/docs
```

### C. Execute an Inference Task via CURL
```bash
curl -X POST "https://cloud-project-3bw5.onrender.com/tasks" \
     -H "Content-Type: application/json" \
     -d '{"features": [0.0, 0.0, 5.0, 13.0, 9.0, 1.0, 0.0, 0.0, 0.0, 0.0, 13.0, 15.0, 10.0, 15.0, 5.0, 0.0, 0.0, 3.0, 15.0, 2.0, 0.0, 11.0, 8.0, 0.0, 0.0, 4.0, 12.0, 0.0, 0.0, 8.0, 8.0, 0.0, 0.0, 5.0, 8.0, 0.0, 0.0, 9.0, 8.0, 0.0, 0.0, 4.0, 11.0, 0.0, 1.0, 12.0, 7.0, 0.0, 0.0, 2.0, 14.0, 5.0, 10.0, 12.0, 0.0, 0.0, 0.0, 0.0, 6.0, 13.0, 10.0, 0.0, 0.0, 0.0], "sensitivity": "high"}'
```

---

## Summary of Key Deployment Files in Repository

| File | Description |
|---|---|
| [`render.yaml`](file:///c:/Users/Lenovo/Downloads/workspace-01a0db79-d88e-7adf-9a75-d0bd726f8494/trustproof-cloud/render.yaml) | Render Blueprint configuration for 1-click cloud deployment |
| [`Procfile`](file:///c:/Users/Lenovo/Downloads/workspace-01a0db79-d88e-7adf-9a75-d0bd726f8494/trustproof-cloud/Procfile) | Web process definition for Railway / Heroku / Dokku |
| [`Dockerfile`](file:///c:/Users/Lenovo/Downloads/workspace-01a0db79-d88e-7adf-9a75-d0bd726f8494/trustproof-cloud/Dockerfile) | Standalone CPU-optimized container image |
| [`docker-compose.yml`](file:///c:/Users/Lenovo/Downloads/workspace-01a0db79-d88e-7adf-9a75-d0bd726f8494/trustproof-cloud/docker-compose.yml) | Multi-container stack (API + Redis + MinIO) |
