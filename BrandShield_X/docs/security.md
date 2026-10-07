# Security notes and threat model

## Implemented in this MVP
- JWT bearer authentication and bcrypt password hashing
- Organization IDs on core records and organization-scoped reads/updates
- Pydantic request validation and bounded strings
- Login/register rate limits
- Security response headers and explicit CORS origins
- Audit events for authentication, brand creation, analysis, imports, status changes and investigation
- CSV extension check, 2 MB size limit, UTF-8 decoding and maximum 500 records
- No arbitrary URL fetching, shell execution, external takedown or uploaded-file execution
- Synthetic demo data clearly described as demo data

## Not yet production-ready
- Demo credentials and default JWT secret must not be used in public deployments
- Browser token is stored in localStorage for hackathon convenience; consider secure HttpOnly cookies or an OIDC client
- No refresh-token rotation, MFA, password reset, full role permission matrix, CSRF strategy for cookie sessions, or account lockout
- No database migrations, backup automation, encryption-at-rest configuration, object storage, malware scanner or immutable evidence store
- Docker compose uses a local development password unless overridden
- CORS and secret settings must be configured for the deployed origins
- Database tenant isolation is enforced in API query filters, not PostgreSQL RLS
- Seed data is synthetic; no live feeds are enabled

## Production recommendations
Use a secrets manager, managed PostgreSQL with backups, HTTPS, least privilege, SAST/dependency scanning, MFA/OIDC, centralized logs, alerting, retention/deletion controls, and independent security review. Human approval is required before any external response.
