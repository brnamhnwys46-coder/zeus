# Distributed Multi-Worker Architecture for Cloudflare Workers Proxy Panel

This architecture decomposes a monolithic Cloudflare Worker into **4 decoupled, secure, and horizontally scalable Workers** that can be deployed across different Cloudflare accounts.

---

## 🏛️ System Topology

```
                  ┌────────────────────────────────────────┐
                  │          Client (Browser / App)        │
                  └───────────────────┬────────────────────┘
                                      │
                         [Secret Route Gate /ggg]
                                      │
                 ┌────────────────────▼────────────────────┐
                 │                WORKER A                 │
                 │          Main Panel & Gateway           │
                 │   - HTML / UI & Admin Authentication    │
                 │   - Secret Route Gate Filter (404 Gate) │
                 │   - Subscriptions Generator (Feed/YAML) │
                 │   - Dynamic Settings Configuration UI   │
                 └──────────┬──────────┬───────────┬───────┘
                            │          │           │
                 Internal   │          │           │ WebSocket Proxy
                 RPC / API  │          │           │ Forwarding
                            │          │           │
           ┌────────────────┘          │           └─────────────────┐
           ▼                           ▼                             ▼
┌─────────────────────┐   ┌──────────────────────┐   ┌───────────────────────┐
│      WORKER B       │   │       WORKER C       │   │       WORKER D        │
│  Database Service   │   │ Repository & Cache   │   │ Connection & Proxy    │
│  (Cloudflare D1)    │   │   (Cloudflare KV)    │   │       Handler         │
│                     │   │                      │   │                       │
│ - Users & Settings  │   │ - ips.txt & VIP-list │   │ - Heavy WebSocket TCP │
│ - Traffic Auditing  │   │ - In-Memory + KV TTL │   │ - VLESS / Trojan / SS │
│ - Auto Quota Reset  │   │ - Fallback Mirrors   │   │ - Direct Sockets / DOH│
└─────────────────────┘   └──────────────────────┘   └───────────────────────┘
```

---

## 📦 Workers Summary

| Worker | Directory | Primary Role | Cloudflare Bindings |
|---|---|---|---|
| **Worker A** | `workers/worker-a/` | Gateway, Panel UI, Secret Route Gate, Subscriptions | Environment Variables (`DB_SERVICE_URL`, `CACHE_SERVICE_URL`, `PROXY_SERVICE_URL`, `SECRET_ROUTE_GATE`) |
| **Worker B** | `workers/worker-b/` | Database Service (CRUD, Traffic Logs, Auth, Auto-reset) | `DB` (D1 Database), Cron Trigger |
| **Worker C** | `workers/worker-c/` | Repository & File Cache, Clean IP Generator, Ping Tester | `FILE_CACHE_KV` (KV Namespace) |
| **Worker D** | `workers/worker-d/` | High-Throughput Proxy Handler (VLESS, Trojan, SS, TCP Sockets) | `cloudflare:sockets`, `nodejs_compat` |

---

## 🚀 Step-by-Step Deployment Guide

### 1. Deploy Worker B (Database Service - Cloudflare D1)

Deploy on Account #1 or dedicated database account:

```bash
cd workers/worker-b

# 1. Create the D1 Database
wrangler d1 create zeus-db

# 2. Copy the database_id from terminal output and paste into wrangler.toml:
# [[d1_databases]]
# binding = "DB"
# database_name = "zeus-db"
# database_id = "YOUR_DATABASE_ID_HERE"

# 3. Set the shared secret token
wrangler secret put INTERNAL_AUTH_TOKEN
# Enter your random secret token (e.g., a 32-character string)

# 4. Deploy Worker B
wrangler deploy
```

Note Worker B's URL (e.g. `https://worker-b-db.YOUR-ACCOUNT.workers.dev`).

---

### 2. Deploy Worker C (Repository & File Cache - Cloudflare KV)

Deploy on Account #2 or dedicated cache account:

```bash
cd workers/worker-c

# 1. Create the KV Namespace
wrangler kv:namespace create "FILE_CACHE_KV"

# 2. Copy the id from terminal output and paste into wrangler.toml:
# [[kv_namespaces]]
# binding = "FILE_CACHE_KV"
# id = "YOUR_KV_NAMESPACE_ID_HERE"

# 3. Set the shared secret token (same as Worker B)
wrangler secret put INTERNAL_AUTH_TOKEN

# 4. Deploy Worker C
wrangler deploy
```

Note Worker C's URL (e.g. `https://worker-c-cache.YOUR-ACCOUNT.workers.dev`).

---

### 3. Deploy Worker D (Connection & Proxy Handler)

Deploy on Account #3 (high compute quota account):

```bash
cd workers/worker-d

# 1. Set the shared secret token
wrangler secret put INTERNAL_AUTH_TOKEN

# 2. Set Worker B and Worker C URLs in wrangler.toml or via vars:
# DB_SERVICE_URL = "https://worker-b-db.YOUR-ACCOUNT.workers.dev"
# CACHE_SERVICE_URL = "https://worker-c-cache.YOUR-ACCOUNT.workers.dev"

# 3. Deploy Worker D
wrangler deploy
```

Note Worker D's URL (e.g. `https://worker-d-proxy.YOUR-ACCOUNT.workers.dev`).

---

### 4. Deploy Worker A (Main Gateway & Panel)

Deploy on Account #4 (or your primary custom domain):

```bash
cd workers/worker-a

# 1. Configure wrangler.toml:
# SECRET_ROUTE_GATE = "ggg"
# INTERNAL_AUTH_TOKEN = "YOUR_SHARED_SECRET_TOKEN"
# DB_SERVICE_URL = "https://worker-b-db.YOUR-ACCOUNT.workers.dev"
# CACHE_SERVICE_URL = "https://worker-c-cache.YOUR-ACCOUNT.workers.dev"
# PROXY_SERVICE_URL = "https://worker-d-proxy.YOUR-ACCOUNT.workers.dev"

# 2. Set the secret token
wrangler secret put INTERNAL_AUTH_TOKEN

# 3. Deploy Worker A
wrangler deploy
```

---

## 🔒 Secret Route Gate Usage

The Secret Route Gate protects your panel from web crawlers, scans, and unauthorized reconnaissance.

- If `SECRET_ROUTE_GATE = "ggg"` is configured:
  - Visiting `https://your-domain.com/panel` directly returns:
    ```
    404 Not Found: Nothing to see here
    ```
  - Visiting `https://your-domain.com/ggg/panel` or `https://your-domain.com/panel?gate=ggg` unlocks access and sets a secure `panel_gate` cookie for the session.
- Public client links (`/sub/:username`, `/feed/:username`, `/yaml/:username`, `/status/:username`) remain operational for proxy clients without exposing the secret gate.

---

## ⚙️ Dynamic Configuration in Admin Settings

Inside Worker A's Web Dashboard:
1. Click **⚙️ تنظیمات ورکرها (Worker Endpoints & Gate Settings)**.
2. You can dynamically modify:
   - Worker B Database Endpoint URL
   - Worker C Cache Endpoint URL
   - Worker D Proxy Engine Endpoint URL
   - Secret Route Gate key
3. Click **تست اتصال ورکرها (Test Endpoints)** to inspect live millisecond latencies to all 3 upstream services.
4. Changes are saved directly in Worker B's persistent `settings` table without requiring any code redeployments!
