# Threat model summary

| Threat | Mitigation in MVP | Residual gap |
|---|---|---|
| Unauthorized API access | JWT bearer authentication | No MFA/refresh rotation |
| Cross-tenant data leakage | Organization filter on core queries | Add PostgreSQL RLS and tenant tests |
| Brute force | Per-IP auth rate limits | Add account lockout and centralized rate limiting |
| Malicious CSV | Size bound, strict fields, never execute | Add robust schema/encoding test suite |
| Stored XSS | React text rendering and no raw HTML rendering | Add CSP and full output review |
| Secret exposure | `.env.example`, `.gitignore` | Rotate secrets and use secret manager |
| Fabricated AI claims | Local heuristic/rules-only assessments | Add RAG citations only when actual sources exist |
| Unauthorized external response | No external response connector | Keep human approval mandatory |
