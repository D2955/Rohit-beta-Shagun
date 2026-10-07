# BrandShield X architecture

```mermaid
flowchart LR
  U[Analyst] --> UI[React + Vite UI]
  UI -->|JWT REST| API[FastAPI]
  API --> AUTH[Authentication and tenant scope]
  API --> RISK[Explainable risk engine]
  API --> DB[(SQLite local / PostgreSQL deployment)]
  RISK --> SIG[Signal + evidence references]
  DB --> DASH[Dashboard and threat workflow]
  DB --> COP[Rules-based database copilot]
  FEED[CSV / user-provided metadata] --> API
  FUTURE[Authorized platform APIs / licensed feeds] -. future connector interface .-> API
```

## Trust boundaries

- Browser is untrusted; backend checks token and scopes database queries by organization.
- Submitted URLs/descriptions are treated as data. This MVP does not fetch arbitrary URLs.
- CSV is size-limited and parsed as data; uploaded files are not executed.
- Threat scoring is heuristic and creates evidence references for each matched rule.
- External reporting, takedown and other response actions are intentionally not automated.

