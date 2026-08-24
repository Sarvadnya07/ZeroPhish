# ZeroPhish — Master Authentication & Login Security Architecture

## 1. Authentication Architecture & Overview

ZeroPhish implements a multi-tier, zero-trust authentication and access-control architecture supporting both interactive web dashboard users (via HttpOnly session cookies with CSRF defense) and programmatic API / Chrome extension clients (via Bearer token authorization headers).

```
+---------------------------+       +---------------------------------------------+
| Interactive Web Dashboard | ----> | HttpOnly SameSite Cookie (`zp_session`)     | --+
+---------------------------+       +---------------------------------------------+   |
                                                                                      |
                                                                                      v
+---------------------------+       +---------------------------------------------+  FastAPI Gateway (`/auth/*`)
| Chrome Sentinel Extension | ----> | Authorization: Bearer <token>               | --> Role-Based Auth Middleware
+---------------------------+       +---------------------------------------------+   | (Admin, Analyst, User, ReadOnly)
                                                                                      |
                                                                                      v
+---------------------------+       +---------------------------------------------+   |
| External API Clients      | ----> | Programmatic API Key / Bearer Tokens        | --+
+---------------------------+       +---------------------------------------------+
```

---

## 2. Token Lifecycle & Session Management

- **Token Generation:** Generated via cryptographically secure randomness (`secrets.token_urlsafe(48)`), providing 288 bits of entropy.
- **Token Storage & Validation:** Managed through repository abstractions (`InMemoryUserRepository` for testing, `SQLUserRepository` with relational indexing in production).
- **Time-to-Live (TTL):** Configurable via `AUTH_TOKEN_TTL` (default: 86,400 seconds / 24 hours). Expired tokens fail validation immediately and are lazily collected.
- **Logout & Revocation:** `POST /auth/logout` explicitly removes the token record from the token store and clears the `zp_session` HttpOnly cookie on the client response.

---

## 3. Password Security & Hashing

- **Hashing Algorithm:** PBKDF2-HMAC-SHA256 with **260,000 iterations** and a **16-byte cryptographically random salt** (`secrets.token_hex(16)`).
- **Constant-Time Verification:** Password comparison uses `secrets.compare_digest` to prevent timing attacks.
- **Production Guard:** Seeded administrative passwords reject known weak or default passwords (`ZeroPhish@Admin1`, `admin`, `password`, `123456`, `changeme`) at startup when `ENV=production`.
- **Password Policy:** Enforces minimum 8 characters and maximum 128 characters across user registration and password updates.

---

## 4. Multi-Factor Authentication (MFA / TOTP)

- **Standard Compliance:** TOTP RFC 6238 compliant via `pyotp`.
- **Seed Generation:** Generates 160-bit cryptographically secure Base32 secrets with standard `otpauth://totp/...` URI configuration for authenticator applications.
- **Fail-Closed Verification:** If `pyotp` is unavailable, MFA verification fails closed with a critical audit log rather than allowing permissive bypass.
- **Rate Limiting:** `/auth/mfa/verify` is strictly rate-limited (5 requests/minute) to prevent brute-forcing 6-digit codes.

---

## 5. Role-Based Access Control (RBAC) & Privilege Escalation Defenses

ZeroPhish defines four distinct user roles:
1. `UserRole.ADMIN` — Full administrative control, user management, webhook deletion, and global policies.
2. `UserRole.ANALYST` — Security incident investigation, threat feed analytics, and false positive reviews.
3. `UserRole.USER` — Scan submission, personal scan history, awareness training, and password management.
4. `UserRole.READONLY` — Read-only observation of public telemetry feeds and awareness lessons.

### Hardened Defenses:
- **Self-Registration Enforcement:** Public `POST /auth/register` strictly forces `role = UserRole.USER` regardless of any client-supplied role in the payload.
- **Self-Service Boundaries:** `PATCH /auth/me` only allows users to edit their own `full_name`. User roles and account status can only be modified by authorized administrators via `/admin/users/{id}`.
- **Independent Backend Authorization:** Every private endpoint independently enforces `require_auth` and `require_role(...)` dependencies regardless of frontend state.

---

## 6. Rate Limiting & Anti-Brute Force Protection

All authentication endpoints are guarded by SlowAPI rate limiters:
- `POST /auth/login`: **5 attempts / minute**
- `POST /auth/register`: **3 registrations / minute**
- `POST /auth/mfa/verify`: **5 attempts / minute**
- `POST /auth/password/change`: **5 attempts / minute**

---

## 7. CSRF & Cross-Origin Protections

- **Cookie Security:** The `zp_session` cookie is issued with `HttpOnly = True`, `SameSite = "lax"`, and `Secure = True` in production environments.
- **CSRF Origin Verification:** When state-changing HTTP methods (`POST`, `PUT`, `DELETE`, `PATCH`) are authenticated via session cookies, `Backend/auth/middleware.py` validates incoming `Origin` and `Referer` headers against `ALLOWED_ORIGINS` to prevent Cross-Site Request Forgery.
- **CORS Configuration:** Explicit allowed origins configured via `ALLOWED_ORIGINS` (wildcards prohibited with credentialed requests).
