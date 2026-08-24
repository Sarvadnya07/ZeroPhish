# ZeroPhish — Staging Deployment Architecture

## Overview
The ZeroPhish staging environment provides a replica of the production detection stack with complete network, database, Redis, and storage isolation.

```
                              External Client
                                    │
                                    ▼ (TCP / HTTP)
                     ┌─────────────────────────────┐
                     │ ZeroPhish Staging API       │
                     │ (Port 8000, ENV=staging)    │
                     └──────────────┬──────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
       ┌────────────────────────┐      ┌────────────────────────┐
       │ Staging SQLite / DB    │      │ Staging Redis (DB 1)   │
       │ (staging_zerophish.db) │      │ (redis:6379/1)         │
       └────────────────────────┘      └────────────────────────┘
```

## Component Isolation
1. **Network Boundary:** The external client communicates via TCP socket (`http://127.0.0.1:8000` or `https://staging.zerophish.internal`) without in-process Python imports.
2. **Database Isolation:** Staging persists to `staging_zerophish.db` (never connecting to production storage).
3. **Cache & Queues:** Redis DB namespace index 1 is reserved exclusively for staging.
4. **Cascade Shadow:** Evaluates traffic at a 10% observational sample rate without affecting user-visible scan responses.
