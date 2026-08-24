# ZeroPhish — Clerk Identity & Access Architecture

## 1. Authentication Architecture & Overview

ZeroPhish utilizes **Clerk** as the sole identity and authentication authority across all interfaces (Web Dashboard, Chrome Extension, Programmatic API). ZeroPhish delegates user credential lifecycle, authentication factors, MFA, passwords, and sessions to Clerk, while retaining full server-side ownership of application RBAC roles, resource authorization, user provisioning, and audit logging.

```
                              CLERK IDENTITY PROVIDER
                            (Authentication Authority)
                                         │
                                         │ Clerk Session Token (JWT)
                   ┌─────────────────────┴─────────────────────┐
                   ▼                                           ▼
          Next.js Web Dashboard                       Chrome Extension
         (@clerk/nextjs / React)                  (Clerk Session Integration)
                   │                                           │
                   └─────────────────────┬─────────────────────┘
                                         │ Authorization: Bearer <clerk_token>
                                         ▼
                               ZeroPhish FastAPI Gateway
                              (Clerk JWT / JWKS Verifier)
                                         │
                                         ▼
                             Server-Side Authorization
                              (RBAC: Admin, Analyst, User)
                                         │
                                         ▼
                              Application Services
```

---

## 2. Token Lifecycle & Verification

- **Token Format:** Signed JWT issued by Clerk containing standard claims (`sub` = Clerk User ID, `iss`, `exp`, `nbf`, `azp`).
- **Verification Engine (`Backend/auth/clerk.py`):**
  - Uses `CLERK_JWT_KEY` (PEM-encoded RSA/ECDSA public key) for networkless, low-latency cryptographic signature validation.
  - Validates `exp` (expiration), `nbf` (not before), `iss` (issuer), and authorized parties (`azp` allowlist matching configured origins).
- **Logout & Revocation:** Handled directly by Clerk SDK session termination. After sign-out, tokens expire or are rejected by the backend.

---

## 3. Application User Mapping & RBAC

- **Principle of Least Privilege:** When a verified Clerk user reaches ZeroPhish for the first time, an internal profile is safely auto-provisioned with the default role `UserRole.USER`.
- **Application Roles:**
  - `admin`: Full administrative access to user role management, global policies, and analytics.
  - `analyst`: Access to incident management, triage, investigation, and threat intelligence.
  - `user`: Access to personal scans, security awareness training, and threat reporting.
  - `readonly`: Read-only telemetry access.
- **Admin Role Assignment:** Assigned securely server-side via `PATCH /admin/users/{user_id}` or through environment bootstrap `CLERK_ADMIN_USER_IDS` / `ADMIN_EMAIL`.

---

## 4. Web Dashboard & Extension Integration

- **Web Dashboard:** Powered by `@clerk/nextjs` `<ClerkProvider>` with custom cyber-defense dark theme, `<SignIn />`, `<SignUp />`, and route protection.
- **Chrome Extension:** Synchronizes with Clerk session tokens to attach `Authorization: Bearer <token>` to all scan dispatches (`POST /gateway/scan` and `POST /vision/analyze`).

---

## 5. Security & Audit Logging

- **Safe Logging:** Structured audit events (`AUTH_LOGIN_SUCCESS`, `AUTH_LOGOUT`, `AUTHZ_DENIED`, `USER_PROVISIONED`) are logged to the `security.*` namespace without ever recording tokens or private claims.
- **CSRF Defense:** Strict origin and referer verification on cookie-bearing requests.
