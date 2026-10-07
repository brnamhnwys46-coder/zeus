export interface WorkerFileInfo {
  id: string;
  name: string;
  role: string;
  account: string;
  description: string;
  jsFileName: string;
  jsCode: string;
  tomlFileName: string;
  tomlCode: string;
  features: string[];
  bindings: string[];
  envVars: string[];
}

export const WORKER_FILES: Record<string, WorkerFileInfo> = {
  workerA: {
    id: "workerA",
    name: "Worker A: Main Panel & Gateway",
    role: "Gateway, UI & Authentication",
    account: "Account #1 (Primary Domain)",
    description: "Acts as the public gateway, serves the responsive dashboard & subscription endpoints, enforces the Secret Route Gate (/ggg), and proxies internal requests to Workers B, C, and D.",
    jsFileName: "worker-a.js",
    tomlFileName: "wrangler.toml",
    bindings: ["DB_SERVICE (optional Service Binding)", "CACHE_SERVICE (optional)", "PROXY_SERVICE (optional)"],
    envVars: ["SECRET_ROUTE_GATE", "INTERNAL_AUTH_TOKEN", "DB_SERVICE_URL", "CACHE_SERVICE_URL", "PROXY_SERVICE_URL"],
    features: [
      "Secret Route Gate: Blocks unauthorized scanners with 404 'Nothing to see here'",
      "Dynamic Admin Configuration: Change Worker B, C, D endpoints in UI without redeployment",
      "Real-time Upstream Ping Test: Measure latencies to Worker B, C, and D",
      "Subscriptions Generation: VLESS / Trojan / Shadowsocks Base64 & YAML for Clash/Clash Verge",
      "Authentication & Session Management with cookie security",
      "Reverse Proxy Gateway: Forwards heavy WebSockets to Worker D"
    ],
    tomlCode: `name = "worker-a-gateway"
main = "worker-a.js"
compatibility_date = "2026-07-10"
compatibility_flags = ["nodejs_compat"]

[vars]
# Secret Route Gate: Must match path prefix or query parameter to access the panel
# Example: If set to "ggg", panel is accessible via /ggg/panel or ?gate=ggg
SECRET_ROUTE_GATE = "ggg"

# Shared internal token for authenticating with Worker B, C, and D
INTERNAL_AUTH_TOKEN = "zeus-secret-inter-worker-token-change-me"

# Endpoints for Worker B (Database), Worker C (Cache), and Worker D (Proxy)
# Can be on separate Cloudflare Accounts
DB_SERVICE_URL = "https://worker-b-db.YOUR-ACCOUNT.workers.dev"
CACHE_SERVICE_URL = "https://worker-c-cache.YOUR-ACCOUNT.workers.dev"
PROXY_SERVICE_URL = "https://worker-d-proxy.YOUR-ACCOUNT.workers.dev"

# Optional: If deployed within the SAME Cloudflare account, you can also use Service Bindings:
# [[services]]
# binding = "DB_SERVICE"
# service = "worker-b-db"
#
# [[services]]
# binding = "CACHE_SERVICE"
# service = "worker-c-cache"
#
# [[services]]
# binding = "PROXY_SERVICE"
# service = "worker-d-proxy"`,
    jsCode: `/**
 * WORKER A: Main Panel, Gateway & Reverse Proxy
 * 
 * Responsibilities:
 * - Serves Dashboard UI/HTML, Login, Setup, User Status card, and Subscriptions (Base64/YAML).
 * - Enforces Secret Route Gate (e.g. /ggg or ?gate=ggg): Returns 404 "Nothing to see here" on mismatch.
 * - Handles Admin Authentication (login password check, session management).
 * - Routes Database queries to Worker B (Database Service).
 * - Routes External Repo & Cache queries to Worker C (Repository & File Cache).
 * - Upgrades & Routes heavy WebSocket proxy traffic to Worker D (Connection & Proxy Handler).
 * - Dynamic Configuration UI: Manage Worker B, C, D endpoints, External URLs, and Secret Gate in Admin Settings.
 */

// Inter-Worker Communication Helpers
async function callWorkerB(path, method = "GET", body = null, env = {}) {
  const token = env.INTERNAL_AUTH_TOKEN || "";
  
  if (env.DB_SERVICE && typeof env.DB_SERVICE.fetch === "function") {
    const req = new Request(\`https://internal-db\${path}\`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "Authorization": \`Bearer \${token}\`,
        "X-Internal-Token": token
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const res = await env.DB_SERVICE.fetch(req);
    return await res.json().catch(() => ({}));
  }

  const baseUrl = (env.DB_SERVICE_URL || "").replace(/\\/+$/, "");
  if (!baseUrl) return { error: "DB_SERVICE_URL is not configured" };

  const res = await fetch(\`\${baseUrl}\${path}\`, {
    method,
    headers: {
      "Content-Type": "application/json",
      "Authorization": \`Bearer \${token}\`,
      "X-Internal-Token": token
    },
    body: body ? JSON.stringify(body) : undefined
  });
  return await res.json().catch(() => ({}));
}

async function callWorkerC(path, method = "GET", body = null, env = {}) {
  const token = env.INTERNAL_AUTH_TOKEN || "";
  
  if (env.CACHE_SERVICE && typeof env.CACHE_SERVICE.fetch === "function") {
    const req = new Request(\`https://internal-cache\${path}\`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "Authorization": \`Bearer \${token}\`,
        "X-Internal-Token": token
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const res = await env.CACHE_SERVICE.fetch(req);
    return await res.json().catch(() => ({}));
  }

  const baseUrl = (env.CACHE_SERVICE_URL || "").replace(/\\/+$/, "");
  if (!baseUrl) return { error: "CACHE_SERVICE_URL is not configured" };

  const res = await fetch(\`\${baseUrl}\${path}\`, {
    method,
    headers: {
      "Content-Type": "application/json",
      "Authorization": \`Bearer \${token}\`,
      "X-Internal-Token": token
    },
    body: body ? JSON.stringify(body) : undefined
  });
  return await res.json().catch(() => ({}));
}

// Secret Route Gate Validation
function checkSecretRouteGate(url, request, env) {
  const secretGate = env.SECRET_ROUTE_GATE ? env.SECRET_ROUTE_GATE.trim() : "";
  if (!secretGate) return { passed: true, cleanPath: url.pathname };

  const queryGate = url.searchParams.get("gate");
  if (queryGate === secretGate) {
    return { passed: true, cleanPath: url.pathname, setGateCookie: true };
  }

  const prefix = \`/\${secretGate}\`;
  if (url.pathname === prefix || url.pathname.startsWith(\`\${prefix}/\`)) {
    const cleanPath = url.pathname.slice(prefix.length) || "/";
    return { passed: true, cleanPath, setGateCookie: true };
  }

  const cookies = request.headers.get("Cookie") || "";
  if (cookies.includes(\`panel_gate=\${secretGate}\`)) {
    return { passed: true, cleanPath: url.pathname };
  }

  if (
    url.pathname.startsWith("/sub/") ||
    url.pathname.startsWith("/feed/") ||
    url.pathname.startsWith("/yaml/") ||
    url.pathname.startsWith("/status/") ||
    url.pathname.startsWith("/stream/") ||
    url.pathname === "/icon.svg" ||
    url.pathname === "/favicon.ico"
  ) {
    return { passed: true, cleanPath: url.pathname };
  }

  return { passed: false };
}

// Authentication Verification
async function verifySessionAuth(request, env) {
  const cookies = request.headers.get("Cookie") || "";
  const sessionCookie = cookies.split(";").find((c) => c.trim().startsWith("panel_session="));
  if (!sessionCookie) return false;
  const sessionToken = sessionCookie.split("=")[1].trim();

  const res = await callWorkerB("/api/internal/auth/verify-session", "POST", { sessionHash: sessionToken }, env);
  return Boolean(res && res.valid);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Secret Route Gate Evaluation
    const gateCheck = checkSecretRouteGate(url, request, env);
    if (!gateCheck.passed) {
      return new Response("Nothing to see here", {
        status: 404,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }

    const currentPath = gateCheck.cleanPath;

    // 2. Heavy WebSocket Proxy Traffic -> Forward to Worker D (Proxy Handler)
    const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
    if (upgradeHeader === "websocket") {
      if (env.PROXY_SERVICE && typeof env.PROXY_SERVICE.fetch === "function") {
        return await env.PROXY_SERVICE.fetch(request);
      }
      const proxyBase = (env.PROXY_SERVICE_URL || "").replace(/\\/+$/, "");
      if (proxyBase) {
        const proxyUrl = new URL(request.url);
        const targetUrl = new URL(proxyBase);
        proxyUrl.hostname = targetUrl.hostname;
        proxyUrl.protocol = targetUrl.protocol;
        proxyUrl.port = targetUrl.port;
        return await fetch(proxyUrl.toString(), request);
      }
    }

    // 3. Static Assets & PWA Icons
    if (currentPath === "/icon.svg" || currentPath === "/favicon.ico") {
      return new Response(SVG_ICON, {
        headers: { "Content-Type": "image/svg+xml; charset=utf-8", "Cache-Control": "public, max-age=604800" }
      });
    }

    // 4. Subscriptions (VLESS / Trojan / SS feeds in text & YAML)
    if (currentPath.startsWith("/sub/") || currentPath.startsWith("/feed/") || currentPath.startsWith("/yaml/")) {
      return await handleSubscriptionRoute(url, currentPath, env);
    }

    // 5. User Status Dashboard (/status/:username)
    if (currentPath.startsWith("/status/")) {
      return await handleStatusRoute(request, currentPath, url, env);
    }

    // 6. Admin REST API routes
    if (currentPath.startsWith("/api/")) {
      return await handleApiRoute(request, currentPath, url, env, ctx);
    }

    // 7. Panel UI / Login / Setup views
    if (currentPath === "/panel" || currentPath === "/login" || currentPath === "/setup" || currentPath === "/") {
      return await handlePanelHtml(request, currentPath, env, gateCheck);
    }

    return new Response("Not Found", { status: 404 });
  }
};`
  },

  workerB: {
    id: "workerB",
    name: "Worker B: Database Service",
    role: "Database State & Quota Management",
    account: "Account #2 (Database Account)",
    description: "Exclusively manages Cloudflare D1 storage for users, settings, and traffic logs. Exposes a strictly authenticated REST API for Worker A and Worker D.",
    jsFileName: "worker-b.js",
    tomlFileName: "wrangler.toml",
    bindings: ["DB (Cloudflare D1 Database)"],
    envVars: ["INTERNAL_AUTH_TOKEN"],
    features: [
      "Pure D1 Database CRUD: Users, settings, active client IP tracking",
      "Automatic Schema Migration on startup (users & settings tables)",
      "Internal Token Security: Rejects any call without valid Authorization Bearer",
      "Batch Traffic Flushing: Efficiently writes accumulated GB and request counts",
      "Auto-Reset Quota Engine: Scheduled cron every hour to reset volume or daily counts",
      "Multi-Account Ready: Can be deployed on a separate Cloudflare Account"
    ],
    tomlCode: `name = "worker-b-db"
main = "worker-b.js"
compatibility_date = "2026-07-10"
compatibility_flags = ["nodejs_compat"]

[vars]
# Secret token shared with Worker A and Worker D
INTERNAL_AUTH_TOKEN = "zeus-secret-inter-worker-token-change-me"

[[d1_databases]]
binding = "DB"
database_name = "zeus-db"
database_id = "YOUR_D1_DATABASE_ID"

[triggers]
crons = ["0 * * * *"] # Hourly auto-reset check`,
    jsCode: `/**
 * WORKER B: Database Service (Cloudflare D1)
 * 
 * Responsibilities:
 * - D1 Database operations exclusively (CRUD for users, settings, traffic logs).
 * - Exposes an internal API secured with INTERNAL_AUTH_TOKEN for Worker A and Worker D.
 * - Auto-initializes schema on startup.
 * - Handles auto-reset checks on scheduled cron or internal trigger.
 * - Multi-Account Ready: Can be deployed on a separate Cloudflare Account.
 */

let schemaEnsured = false;
let schemaPromise = null;

function safeJson(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Internal-Token"
    }
  });
}

function verifyInternalAuth(request, env) {
  const expectedToken = env.INTERNAL_AUTH_TOKEN;
  if (!expectedToken) return true;

  const authHeader = request.headers.get("Authorization") || "";
  const internalHeader = request.headers.get("X-Internal-Token") || "";
  
  if (authHeader.startsWith("Bearer ") && authHeader.slice(7).trim() === expectedToken) {
    return true;
  }
  if (internalHeader.trim() === expectedToken) {
    return true;
  }
  return false;
}

export default {
  async scheduled(event, env, ctx) {
    if (!env.DB) return;
    await ensureSchema(env.DB);
    ctx.waitUntil(performAutoResets(env.DB));
  },

  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Internal-Token"
        }
      });
    }

    if (!env.DB) {
      return safeJson({ error: "Cloudflare D1 Database binding 'DB' is missing in Worker B." }, 500);
    }

    const url = new URL(request.url);
    if (url.pathname === "/health" || url.pathname === "/api/internal/health") {
      return safeJson({ status: "healthy", service: "worker-b-db", timestamp: Date.now() });
    }

    if (!verifyInternalAuth(request, env)) {
      return safeJson({ error: "Unauthorized access to Database Service." }, 403);
    }

    await ensureSchema(env.DB);
    const path = url.pathname;

    // Route dispatchers: /api/internal/users, /api/internal/user/:id, /api/internal/traffic/flush, etc.
    return handleDatabaseApi(request, path, env, ctx);
  }
};`
  },

  workerC: {
    id: "workerC",
    name: "Worker C: Repository & File Cache",
    role: "KV Storage & High-Speed Mirror Proxy",
    account: "Account #3 (Storage/CDN Account)",
    description: "Fetches and caches clean IPs (ips.txt), VIP proxies (vip-list), and script updates in Cloudflare KV with memory acceleration. Offloads proxy ping testing from the panel.",
    jsFileName: "worker-c.js",
    tomlFileName: "wrangler.toml",
    bindings: ["FILE_CACHE_KV (Cloudflare KV Namespace)"],
    envVars: ["INTERNAL_AUTH_TOKEN", "UPSTREAM_MIRRORS"],
    features: [
      "Two-tier Caching: High-speed In-Memory Map + Persistent Cloudflare KV",
      "Dynamic Upstream Mirrors: Automatically fails over between GitHub and Workers mirrors",
      "Clean Cloudflare IP Pool: Shuffles and filters clean IPs by operator",
      "VIP Proxies Country Directory: Organizes countries and proxy lists",
      "Offloaded Proxy Health Ping: Tests outbound SOCKS5/HTTP socket ping directly in Worker C",
      "Cache Purge API for instant invalidation"
    ],
    tomlCode: `name = "worker-c-cache"
main = "worker-c.js"
compatibility_date = "2026-07-10"
compatibility_flags = ["nodejs_compat"]

[vars]
# Secret token shared with Worker A and Worker D
INTERNAL_AUTH_TOKEN = "zeus-secret-inter-worker-token-change-me"

# Comma-separated list of fallback repository mirrors
UPSTREAM_MIRRORS = "https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main,https://fesavswgvswgfvasw.hxxyrukih4kvmeawzmdmug2eh5uwtcmt.workers.dev"

[[kv_namespaces]]
binding = "FILE_CACHE_KV"
id = "YOUR_KV_NAMESPACE_ID"`,
    jsCode: `import { connect } from "cloudflare:sockets";

/**
 * WORKER C: Repository & File Cache Service
 * 
 * Responsibilities:
 * - High-speed caching for external files (ips.txt, vip-list, proxy_vip/*.txt, etc.)
 * - KV persistent cache (FILE_CACHE_KV) + In-memory Map caching.
 * - Dynamic upstream mirrors (GitHub / Workers.dev / custom CDNs).
 * - Offloads network ping / proxy health checks from Main Panel.
 * - Multi-Account Ready: Can be deployed on a separate Cloudflare Account.
 */

const MEMORY_CACHE = new Map();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "healthy", service: "worker-c-cache" }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    if (!verifyInternalAuth(request, env)) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 403 });
    }

    // Endpoints: /api/internal/cache/file, /api/internal/cache/ips, /api/internal/cache/test-proxy, etc.
    return handleCacheRoutes(request, url, env, ctx);
  }
};`
  },

  workerD: {
    id: "workerD",
    name: "Worker D: Connection & Proxy Handler",
    role: "Heavy WebSocket Streaming & Cryptography",
    account: "Account #4 (Compute-Intensive Account)",
    description: "Dedicated solely to heavy client WebSocket traffic, VLESS / Trojan / Shadowsocks protocol parsing, outbound TCP dialers (cloudflare:sockets), and UDP DNS tunneling.",
    jsFileName: "worker-d.js",
    tomlFileName: "wrangler.toml",
    bindings: ["cloudflare:sockets (Native TCP)", "nodejs_compat"],
    envVars: ["INTERNAL_AUTH_TOKEN", "DB_SERVICE_URL", "CACHE_SERVICE_URL", "PROXY_GATE_KEY"],
    features: [
      "Zero-latency Streaming: Dedicated WebSocket engine completely decoupled from web UI",
      "VLESS / Trojan / Shadowsocks AEAD Protocols Supported",
      "Direct Outbound TCP Sockets via Cloudflare sockets API (bracketed IPv6)",
      "SOCKS5 / SOCKS4 / HTTP Outbound Proxy Chaining with credentials",
      "DNS over DoH with custom resolvers and AdGuard/Family blocking",
      "Asynchronous Quota & Active IP Reporting to Worker B via ctx.waitUntil"
    ],
    tomlCode: `name = "worker-d-proxy"
main = "worker-d.js"
compatibility_date = "2026-07-10"
compatibility_flags = ["nodejs_compat"]

[vars]
# Internal token for authenticating calls to Worker B (Database) & Worker C (Cache)
INTERNAL_AUTH_TOKEN = "zeus-secret-inter-worker-token-change-me"

# Endpoints for Worker B and Worker C (Can be on different Cloudflare accounts)
DB_SERVICE_URL = "https://worker-b-db.YOUR-ACCOUNT.workers.dev"
CACHE_SERVICE_URL = "https://worker-c-cache.YOUR-ACCOUNT.workers.dev"

# Optional secret key required on incoming websocket connections
PROXY_GATE_KEY = ""`,
    jsCode: `import { connect } from "cloudflare:sockets";

/**
 * WORKER D: Connection & Proxy Handler
 * 
 * Responsibilities:
 * - Dedicated exclusively to handling heavy WebSocket traffic and proxy protocols (VLESS / Trojan / Shadowsocks).
 * - Offloads all CPU-intensive cryptography, socket multiplexing, and streaming from Worker A.
 * - Outbound connections: Direct TCP sockets (cloudflare:sockets), SOCKS5/HTTP proxy chaining, UDP DNS forwarding.
 * - Verifies user credentials and records traffic usage through Worker B (Database Service).
 * - Multi-Account Ready: Can be deployed on a separate high-resource Cloudflare Account.
 */

export default {
  async fetch(request, env, ctx) {
    const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
    if (upgradeHeader === "websocket") {
      return await handleWebSocketProxy(request, env, ctx);
    }
    return new Response("Worker D Connection & Proxy Engine is running.", { status: 200 });
  }
};`
  }
};
