# ZEUS Multi-Worker Architecture Specification & Deployment Manual

Refactored distributed architecture separating the monolithic ZEUS panel into four decoupled services with clear boundaries and fail-closed security.

---

## 🏛️ Architecture & Service Boundaries

```
                    ┌────────────────────────────────────────┐
                    │          Client (Browser / App)        │
                    └───────────────────┬────────────────────┘
                                        │
                           [Secret Route Gate /ggg]
                                        │
                   ┌────────────────────▼────────────────────┐
                   │                WORKER A                 │
                   │          Management Panel ONLY          │
                   │   - HTML / Persian UI & Admin Auth      │
                   │   - Cryptographic Random Session Tokens │
                   │   - Secret Route Gate Filter (404 Gate) │
                   │   - Displays Worker D Subscription URLs │
                   │   - Dynamic Admin Settings Panel        │
                   └──────────┬──────────────────┬───────────┘
                              │                  │
                   Internal   │                  │ Internal
                   RPC / API  │                  │ RPC / API
                              │                  │
             ┌────────────────┘                  └──────────────────┐
             ▼                                                      ▼
  ┌─────────────────────┐                                ┌──────────────────────┐
  │      WORKER B       │◄───────────────────────────────┤       WORKER D       │
  │  Database Service   │  Authenticated User Lookup &   │  Connection & Proxy  │
  │     (ONLY D1)       │     Traffic Batch Flushes      │        Engine        │
  │                     │                                │                      │
  │ - Users & Settings  │                                │ - Heavy WebSockets   │
  │ - Traffic Auditing  │                                │ - VLESS / Trojan / SS│
  │ - Idempotent Schema │                                │ - Outbound TCP / DoH │
  │ - Fail-Closed Auth  │                                │ - Subscription Feeds │
  └─────────────────────┘                                └──────────┬───────────┘
                                                                    │
                                                Cache & IP Lookups  │
                                                                    ▼
                                                         ┌──────────────────────┐
                                                         │       WORKER C       │
                                                         │  Repository & Cache  │
                                                         │     (ONLY KV)        │
                                                         │                      │
                                                         │ - ips.txt & VIP-list │
                                                         │ - In-Memory + KV TTL │
                                                         │ - Fallback Mirrors   │
                                                         │ - Fail-Closed Auth   │
                                                         └──────────────────────┘
```

---

## 1. Service Responsibilities Matrix

| Service | Directory | Responsibilities | Forbidden Operations |
|---|---|---|---|
| **Worker A** | `workers/worker-a/` | Management UI, Login/Logout, Cryptographic Sessions, Secret Route Gate, displays subscription URLs, server-side RPC to B/C/D. | **NO** protocol parsing, **NO** proxy sockets/`connect()`, **NO** D1 binding, **NO** GitHub raw fetching, **NO** subscription content generation. |
| **Worker B** | `workers/worker-b/` | **SOLE** owner of D1 database, user management, quota counters, safe schema migrations, session storage, fail-closed auth. | **NO** proxy traffic handling, **NO** public unauthenticated endpoints (except `/health`). |
| **Worker C** | `workers/worker-c/` | **SOLE** repository/cache service, KV storage (`FILE_CACHE_KV`), clean IP parsing (`ips.txt`), proxy test offloader, fail-closed auth. | **NO** D1 database access, **NO** proxy connection handling. |
| **Worker D** | `workers/worker-d/` | **SOLE** connection engine, VLESS / Trojan / Shadowsocks WebSocket streaming, direct TCP sockets (`cloudflare:sockets`), SOCKS5/HTTP chaining, **SOLE** owner of subscription feeds (`/sub/`, `/feed/`, `/yaml/`). | **NO** admin dashboard UI, **NO** direct D1 binding (calls Worker B for users & traffic). |

---

## 2. Cloudflare Bindings & Environment Variables

### Worker A (`workers/worker-a/wrangler.toml`)
- **[vars]**:
  - `SECRET_ROUTE_GATE = "ggg"` (Secret path prefix or query parameter)
  - `DB_SERVICE_URL = "https://worker-b-db.<YOUR-ACCOUNT>.workers.dev"`
  - `CACHE_SERVICE_URL = "https://worker-c-cache.<YOUR-ACCOUNT>.workers.dev"`
  - `PROXY_SERVICE_URL = "https://worker-d-proxy.<YOUR-ACCOUNT>.workers.dev"`
- **Cloudflare Secrets** (`wrangler secret put`):
  - `INTERNAL_AUTH_TOKEN`: Shared secret token for inter-worker authentication.
- **Bindings**: None required (Service bindings `DB_SERVICE`, `CACHE_SERVICE`, `PROXY_SERVICE` optional if deployed in the same account).

### Worker B (`workers/worker-b/wrangler.toml`)
- **Bindings**:
  - `[[d1_databases]]`: `binding = "DB"`, `database_name = "zeus-db"`, `database_id = "<YOUR_D1_DATABASE_ID>"`
- **Cloudflare Secrets**:
  - `INTERNAL_AUTH_TOKEN`: Shared secret token. Must match Worker A and Worker D.
- **Triggers**:
  - `crons = ["0 * * * *"]`: Hourly scheduled auto-reset for volume/request quotas.

### Worker C (`workers/worker-c/wrangler.toml`)
- **Bindings**:
  - `[[kv_namespaces]]`: `binding = "FILE_CACHE_KV"`, `id = "<YOUR_KV_NAMESPACE_ID>"`
- **[vars]**:
  - `UPSTREAM_MIRRORS = "https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main,https://fesavswgvswgvswgfvasw.hxxyrukih4kvmeawzmdmug2eh5uwtcmt.workers.dev"`
- **Cloudflare Secrets**:
  - `INTERNAL_AUTH_TOKEN`: Shared secret token.

### Worker D (`workers/worker-d/wrangler.toml`)
- **[vars]**:
  - `DB_SERVICE_URL = "https://worker-b-db.<YOUR-ACCOUNT>.workers.dev"`
  - `CACHE_SERVICE_URL = "https://worker-c-cache.<YOUR-ACCOUNT>.workers.dev"`
- **Cloudflare Secrets**:
  - `INTERNAL_AUTH_TOKEN`: Shared secret token.
- **Compatibility Flags**:
  - `compatibility_flags = ["nodejs_compat"]`

---

## 3. Safe Database Schema Migration

Worker B features an idempotent migration system. It executes `PRAGMA table_info(users)` and uses `ALTER TABLE users ADD COLUMN ...` only for missing columns.
It **never** runs `DROP TABLE users` or `DROP TABLE settings`.

If an older database exists containing legacy columns like:
- `total_gb`: Kept intact and mapped to `limit_gb = COALESCE(limit_gb, total_gb)`.
- `password`: Kept intact.
- `expire_at`: Kept intact.

---

## 4. Deployment Instructions

### Step 1: Deploy Worker B (Database Service)
```bash
cd workers/worker-b
wrangler d1 create zeus-db
# Insert the returned database_id into workers/worker-b/wrangler.toml

wrangler secret put INTERNAL_AUTH_TOKEN
# Enter your random 32+ character secret token

wrangler deploy
```
Copy Worker B's URL (e.g., `https://worker-b-db.example.workers.dev`).

### Step 2: Deploy Worker C (Repository & Cache)
```bash
cd workers/worker-c
wrangler kv:namespace create "FILE_CACHE_KV"
# Insert the returned namespace id into workers/worker-c/wrangler.toml

wrangler secret put INTERNAL_AUTH_TOKEN
# Enter the exact same secret token

wrangler deploy
```
Copy Worker C's URL (e.g., `https://worker-c-cache.example.workers.dev`).

### Step 3: Deploy Worker D (Connection & Proxy Engine)
```bash
cd workers/worker-d
# Set DB_SERVICE_URL and CACHE_SERVICE_URL in workers/worker-d/wrangler.toml

wrangler secret put INTERNAL_AUTH_TOKEN
# Enter the exact same secret token

wrangler deploy
```
Copy Worker D's URL (e.g., `https://worker-d-proxy.example.workers.dev`).

### Step 4: Deploy Worker A (Management Panel)
```bash
cd workers/worker-a
# Set DB_SERVICE_URL, CACHE_SERVICE_URL, and PROXY_SERVICE_URL in workers/worker-a/wrangler.toml

wrangler secret put INTERNAL_AUTH_TOKEN
# Enter the exact same secret token

wrangler deploy
```

---

## 5. Security & Session Guarantees

1. **Fail-Closed Policy**: If `INTERNAL_AUTH_TOKEN` is missing or empty, Worker B, C, and D strictly reject internal requests with HTTP 403.
2. **Timing-Safe Equal**: All internal token checks and password verifications use constant-time character comparisons to prevent timing attacks.
3. **Session Tokens**: Replaced password hash session cookies with 256-bit cryptographically random tokens stored in D1's `sessions` table. Sent via `HttpOnly`, `Secure`, `SameSite=Lax` cookies.
4. **Secret Route Gate**: Access to admin routes on Worker A requires the secret path prefix (e.g., `/ggg/panel`) or query parameter (`?gate=ggg`). Unauthorized scanners receive an immediate 404 "Nothing to see here" without consuming D1 reads.
5. **Authoritative Dynamic Configuration**: Worker A provides a dedicated Admin Settings section to update `db_service_url`, `cache_service_url`, `proxy_service_url`, and `secret_route_gate` dynamically in Worker B's database without code redeployments.
