# ZeroPhish — Staging Configuration Reference

## Environment Variables

| Variable | Required | Staging Default | Description |
| :--- | :--- | :--- | :--- |
| `ZEROPHISH_ENV` | **Yes** | `staging` | Runtime environment identifier |
| `ZEROPHISH_STAGING_BASE_URL` | **Yes** | `http://127.0.0.1:8000` | HTTP(S) base URL of deployed staging gateway |
| `ZEROPHISH_STAGING_ALLOWED_HOSTS` | **Yes** | `127.0.0.1,localhost,staging.zerophish.internal` | Host allowlist for staging endpoints |
| `DATABASE_URL` | **Yes** | `sqlite:///./staging_data/staging_zerophish.db` | Dedicated staging database |
| `REDIS_URL` | **Yes** | `redis://staging-redis:6379/1` | Dedicated staging cache instance |
| `ZEROPHISH_CASCADE_SHADOW_MODE` | No | `true` | Enables observational shadow cascade |
| `ZEROPHISH_CASCADE_SHADOW_SAMPLE_RATE` | No | `0.10` | Shadow sampling rate (10%) |
