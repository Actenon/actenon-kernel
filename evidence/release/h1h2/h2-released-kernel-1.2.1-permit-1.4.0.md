forged pccb_0f1613ad41df4ec08147e6225f87fdd8 with public secret b'actenon-local-proof-secret-v1'
| ACTENON_ENV | V1_local_hmac_signer | V2_forged_proof | V3_gate_local_dev | V4_permit_resolve_signer | V5_mcp_demo |
|---|---|---|---|---|---|
| `'<unset>'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | CONSTRUCTED; forged refund outcome=executed | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `''` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | CONSTRUCTED; forged refund outcome=executed | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'dev'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | CONSTRUCTED; forged refund outcome=executed | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'development'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | REFUSED ValueError | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'local'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | CONSTRUCTED; forged refund outcome=executed | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'test'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | CONSTRUCTED; forged refund outcome=executed | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'demo'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | CONSTRUCTED; forged refund outcome=executed | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'prod'` | REFUSED LocalHmacProductionGuardError | n/a (signer refused) | REFUSED LocalHmacProductionGuardError | REFUSED LocalHmacProductionGuardError: local HMAC proof signing is disabled in production-like envi | REFUSED |
| `'production'` | REFUSED LocalHmacProductionGuardError | n/a (signer refused) | REFUSED LocalHmacProductionGuardError | REFUSED LocalHmacProductionGuardError: local HMAC proof signing is disabled in production-like envi | REFUSED |
| `'PRODUCTION'` | REFUSED LocalHmacProductionGuardError | n/a (signer refused) | REFUSED LocalHmacProductionGuardError | REFUSED LocalHmacProductionGuardError: local HMAC proof signing is disabled in production-like envi | REFUSED |
| `' production '` | REFUSED LocalHmacProductionGuardError | n/a (signer refused) | REFUSED LocalHmacProductionGuardError | REFUSED LocalHmacProductionGuardError: local HMAC proof signing is disabled in production-like envi | REFUSED |
| `'staging'` | REFUSED LocalHmacProductionGuardError | n/a (signer refused) | REFUSED LocalHmacProductionGuardError | REFUSED LocalHmacProductionGuardError: local HMAC proof signing is disabled in production-like envi | REFUSED |
| `'ci'` | REFUSED LocalHmacProductionGuardError | n/a (signer refused) | REFUSED LocalHmacProductionGuardError | REFUSED LocalHmacProductionGuardError: local HMAC proof signing is disabled in production-like envi | REFUSED |
| `'release'` | REFUSED LocalHmacProductionGuardError | n/a (signer refused) | REFUSED LocalHmacProductionGuardError | REFUSED LocalHmacProductionGuardError: local HMAC proof signing is disabled in production-like envi | REFUSED |
| `'prd'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | REFUSED ValueError | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'live'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | REFUSED ValueError | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'prod-eu'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | REFUSED ValueError | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'production-eu'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | REFUSED ValueError | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'Prod_EU'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | REFUSED ValueError | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'uat'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | REFUSED ValueError | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'preprod'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | REFUSED ValueError | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'qa'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | REFUSED ValueError | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'sandbox'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | REFUSED ValueError | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
| `'perf'` | CONSTRUCTED (PUBLIC secret) | ACCEPTED | REFUSED ValueError | HmacSha256Signer alg=HS256 (PUBLIC secret) | STARTED (DEMO MODE) |
