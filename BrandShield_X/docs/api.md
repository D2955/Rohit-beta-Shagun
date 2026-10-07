# API guide
Interactive OpenAPI docs: `/docs`

All endpoints except `/`, `/api/health`, `/api/auth/register` and `/api/auth/login` require `Authorization: Bearer <access_token>`.

Example CSV:
```csv
asset_name,asset_type,platform,asset_url,domain,description
Northstar Pay Help,social,Social Network,https://social.example/northstar_help,northstar-help.example,verify your wallet
Northstar Clone,app,App Store,https://apps.example/clone,,unofficial support app
```

`POST /api/assets/import` accepts a multipart upload named `file`. Use only records you are authorized to process.
