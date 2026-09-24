# SIH26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

A passive network monitoring system. It demonstrates: unidirectional flow data collection, preprocessing, ML classification on metadata without decryption, real-time volumetric alerting, and persistent reporting.

## Architecture

```
Browser  →  Nginx (port 8080)  →  Node.js API (port 3000)  →  PostgreSQL
                                         ↑
                              Named Docker volume (data persists)
```

## Quick Start (Docker Compose — recommended)

```bash
# 1. Clone
git clone https://github.com/habeebc84-create/cloud-exicution.git
cd cloud-exicution

# 2. Set up environment
cp .env.example .env

# 3. Start all services (frontend + backend API + PostgreSQL)
docker-compose up -d --build

# 4. Open in browser
http://localhost:8080
```

Data is stored in a **named Docker volume** (`cloudguard_pgdata`) and survives container restarts.

## Run frontend only (no database)

```bash
docker build -t cloudguard-ai .
docker run --rm -p 8080:80 cloudguard-ai
```

The app automatically detects whether the backend is available and falls back to standalone (in-memory) mode.

## Useful commands

```bash
# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Stop and DELETE all data
docker-compose down -v

# Restart only the backend
docker-compose restart backend

# Check service status
docker-compose ps
```

## Push images to Docker Hub

```bash
docker tag cloudguard-frontend your-username/cloudguard-frontend:latest
docker tag cloudguard-backend  your-username/cloudguard-backend:latest
docker push your-username/cloudguard-frontend:latest
docker push your-username/cloudguard-backend:latest
```

## REST API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/health | Health check |
| GET | /api/events | List threat events |
| POST | /api/events | Save a threat event |
| GET | /api/alerts | List all alerts |
| POST | /api/alerts | Create an alert |
| PATCH | /api/alerts/:id/resolve | Resolve an alert |
| GET | /api/reports | List reports |
| POST | /api/reports | Save a report |
| GET | /api/audit | List audit log entries |
| GET | /api/stats | Dashboard stats summary |

## Features

- Security overview dashboard and threat activity chart
- Live event stream persisted to PostgreSQL
- ML scan results with model switching (Random Forest, SVM, XGBoost, Isolation Forest)
- Alert filtering and incident resolution (synced to DB)
- Downloadable JSON report (also saved to DB)
- Audit log with full history
- Graceful standalone fallback when backend is offline
