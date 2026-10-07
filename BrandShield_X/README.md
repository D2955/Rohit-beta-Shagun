# BrandShield X
**See the threat. Understand the threat. Stop the spread.**

BrandShield X is a hackathon-ready digital risk protection foundation for reviewing possible social-profile, mobile-app and domain impersonation. It includes a React/JavaScript dashboard, FastAPI backend, tenant-scoped SQLite persistence for local demos, explainable heuristic risk scoring, JWT authentication, Brand Twin onboarding, campaign grouping, CSV ingestion/export, audit records, and a reproducible threat simulation.

> **Important scope note:** this is a working MVP, not a fully production-hardened enterprise system. It uses synthetic demo records and user-provided metadata. It does not connect to live social networks, app stores, DNS reputation services, external LLMs, or vision models. Scores are decision-support signals, not proof of malicious intent. Review evidence before taking action.

## Features
- Landing / welcome page and secure sign-in UI
- JWT authentication, organization-scoped records, and role field
- Digital Brand Twin with aliases, domains, official social/app references and SHA-256 identity fingerprint
- Threat discovery and explainable heuristic scoring: identity, domain, social-language and app signals
- Separate risk and confidence values; LOW/MEDIUM/HIGH/CRITICAL severity
- Threat list, search, severity filter, status workflow, detail drawer and read-only investigation recommendations
- Campaign correlation using explicit campaign keys
- CSV ingestion (max 2 MB, up to 500 rows) and CSV export
- Database-grounded rules-based copilot (not a generative LLM)
- Audit log, security headers, rate limits, request IDs, input schemas, and organization filtering in backend queries
- API docs at `/docs`, unit tests, Dockerfile, compose file and seed script
- Responsive SOC-style UI with reduced-motion support

## Architecture
- Frontend: React 18 + Vite + JavaScript/JSX + Recharts + Lucide
- Backend: Python FastAPI + Pydantic + SQLAlchemy
- Local database: SQLite (`backend/brandshield.db`)
- Production database path: configure `DATABASE_URL` for PostgreSQL
- Authentication: signed JWT bearer token
- Scoring: transparent local heuristic rules with evidence IDs
- Future integration points: approved social/app APIs, domain intelligence feeds, OCR/vision/embedding providers, PostgreSQL + pgvector, Redis/Celery, S3-compatible evidence storage

## Quick start (Mac/Linux)
Open two terminal windows.

### 1. Backend
```bash
cd BrandShield_X/backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp ../.env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
API: http://127.0.0.1:8000  
Interactive docs: http://127.0.0.1:8000/docs  
Health: http://127.0.0.1:8000/api/health

### 2. Frontend
```bash
cd BrandShield_X/frontend
npm install
npm run dev
```
Open http://localhost:5173

### Demo login
- Email: `demo@brandshield.local`
- Password: `DemoPass123!`

The demo organization and seed data are created automatically on backend startup. Change demo credentials and secrets before any public deployment. For first run, if database seed already exists and you want a clean reset, stop the server and delete `backend/brandshield.db`.

## Environment variables
See `.env.example`. The local app defaults to SQLite. For deployment, use a managed PostgreSQL database and set `DATABASE_URL`, `JWT_SECRET`, `CORS_ORIGINS`, and `DEMO_MODE=false`. Never commit a real `.env`.

## API endpoints
- `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`
- `GET/POST /api/brands`
- `GET /api/dashboard/summary`
- `GET /api/threats`, `GET /api/threats/{id}`, `PATCH /api/threats/{id}/status`
- `POST /api/assets/analyze`, `POST /api/assets/import`
- `POST /api/threats/{id}/investigate`
- `GET /api/campaigns`, `POST /api/copilot/query`
- `GET /api/audit-logs`, `GET /api/reports/threats.csv`
- `GET /api/health`

## Tests
```bash
cd backend
pytest -q
```

## Docker Compose
```bash
docker compose up --build
```
The compose file starts PostgreSQL, API and Vite frontend. For the simple demo, the backend can run on SQLite without Docker.

## Security checklist before production
- Replace JWT secret with a high-entropy secret from a secrets manager
- Use HTTPS and strict production CORS
- Use managed PostgreSQL, backups, least-privilege DB credentials and migrations
- Add refresh-token rotation, MFA/OIDC, account recovery and full RBAC enforcement
- Add malware scanning/quarantine and private object storage before enabling uploads of evidence binaries
- Add CSRF controls if using cookie auth; do not store long-lived tokens in browser localStorage for a sensitive production deployment
- Add immutable evidence storage / append-only chain of custody
- Add monitoring, dependency scanning, secret scanning and security tests
- Integrate only authorized platform APIs and licensed threat-intelligence feeds
- Require human approval for any external response or takedown

## Known limitations
- Demo threat timeline chart is illustrative; severity donut uses database values.
- Campaign grouping uses seeded/shared campaign identifiers rather than ML correlation.
- Investigation and copilot are rules/database-based, not LLM/RAG.
- No image embeddings, OCR, logo similarity, PDF export, live connectors, Redis worker, object storage, or PostgreSQL pgvector implementation is enabled yet.
- Local SQLite is not appropriate for multi-instance production deployment.
