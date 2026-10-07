import workerAJscode from "../../workers/worker-a/worker-a.js?raw";
import workerATomlcode from "../../workers/worker-a/wrangler.toml?raw";
import workerBJscode from "../../workers/worker-b/worker-b.js?raw";
import workerBTomlcode from "../../workers/worker-b/wrangler.toml?raw";
import workerCJscode from "../../workers/worker-c/worker-c.js?raw";
import workerCTomlcode from "../../workers/worker-c/wrangler.toml?raw";
import workerDJscode from "../../workers/worker-d/worker-d.js?raw";
import workerDTomlcode from "../../workers/worker-d/wrangler.toml?raw";

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
    name: "Worker A: Management Panel & Gateway",
    role: "Administration & Display Layer ONLY",
    account: "Account #1 (Management/Panel Domain)",
    description: "Serves the dashboard UI/HTML, login, session management with random tokens, user status, and worker diagnostics. Does NOT parse proxy protocols, does NOT proxy WebSockets, does NOT access D1, does NOT fetch GitHub. Displays Worker D subscription links.",
    jsFileName: "worker-a.js",
    tomlFileName: "wrangler.toml",
    bindings: ["DB_SERVICE (optional Service Binding)", "CACHE_SERVICE (optional)", "PROXY_SERVICE (optional)"],
    envVars: ["SECRET_ROUTE_GATE", "INTERNAL_AUTH_TOKEN (Secret)", "DB_SERVICE_URL", "CACHE_SERVICE_URL", "PROXY_SERVICE_URL"],
    features: [
      "Panel & Display ONLY: Strictly decoupled from proxy and connection engine",
      "Secret Route Gate: Rejects scanners with 404 'Nothing to see here'",
      "Cryptographically Random Session Tokens (no password hash leakage)",
      "Dynamic Configuration UI: Authoritative config from Worker B with runtime override",
      "Authenticated diagnostics testing Worker B, C, and D endpoints",
      "Worker D Subscription Link Display & Clipboard Copy"
    ],
    tomlCode: workerATomlcode,
    jsCode: workerAJscode
  },

  workerB: {
    id: "workerB",
    name: "Worker B: Database Service",
    role: "Sole Owner of Cloudflare D1 Database",
    account: "Account #2 (Database Account)",
    description: "The ONLY service that accesses D1 directly. Handles user management, traffic counters, quota limits, expiry, and safe schema migrations. Fails closed if INTERNAL_AUTH_TOKEN is missing.",
    jsFileName: "worker-b.js",
    tomlFileName: "wrangler.toml",
    bindings: ["DB (Cloudflare D1 Database)"],
    envVars: ["INTERNAL_AUTH_TOKEN (Secret)"],
    features: [
      "Sole D1 Client: Worker A and Worker D communicate via authenticated internal RPC",
      "Fail-Closed Security: Strictly rejects any call if INTERNAL_AUTH_TOKEN is missing or invalid",
      "Safe Idempotent Migrations: Uses PRAGMA table_info; never drops users or settings tables",
      "Preserves legacy columns (total_gb, password, expire_at) with backward-compatibility",
      "Cryptographic Sessions: Generates 256-bit random session tokens in D1 sessions table",
      "Batch Traffic Flush & Auto-reset hourly cron trigger"
    ],
    tomlCode: workerBTomlcode,
    jsCode: workerBJscode
  },

  workerC: {
    id: "workerC",
    name: "Worker C: Repository & File Cache Service",
    role: "KV Storage & High-Speed Mirror Proxy",
    account: "Account #3 (Storage/CDN Account)",
    description: "Fetches and caches clean IPs (ips.txt), VIP proxies (vip-list), and proxy lists in Cloudflare KV and memory. Fails closed if internal token is missing.",
    jsFileName: "worker-c.js",
    tomlFileName: "wrangler.toml",
    bindings: ["FILE_CACHE_KV (Cloudflare KV Namespace)"],
    envVars: ["INTERNAL_AUTH_TOKEN (Secret)", "UPSTREAM_MIRRORS"],
    features: [
      "Sole External Repo Client: Worker A never touches GitHub or raw files",
      "Two-tier Caching: In-memory Map + Persistent Cloudflare KV",
      "Configurable Upstream Mirrors with automatic failover",
      "Clean Cloudflare IP Pool: Shuffles and filters clean IPs by operator",
      "VIP Proxies Country Directory and health testing offloader",
      "Fail-Closed Authentication for all internal cache endpoints"
    ],
    tomlCode: workerCTomlcode,
    jsCode: workerCJscode
  },

  workerD: {
    id: "workerD",
    name: "Worker D: Connection & Proxy Engine",
    role: "Proxy Protocols & Subscription Service",
    account: "Account #4 (High Compute Proxy Account)",
    description: "Dedicated solely to heavy client WebSocket traffic, VLESS / Trojan / Shadowsocks protocols, direct TCP sockets, outbound proxies, and subscription generation (/sub/, /feed/, /yaml/).",
    jsFileName: "worker-d.js",
    tomlFileName: "wrangler.toml",
    bindings: ["cloudflare:sockets (Native TCP)", "nodejs_compat"],
    envVars: ["INTERNAL_AUTH_TOKEN (Secret)", "DB_SERVICE_URL", "CACHE_SERVICE_URL"],
    features: [
      "Complete, Unsimplified Connection Engine: VLESS, Trojan (SHA-224), Shadowsocks (AEAD)",
      "Native TCP Sockets: Direct dialing via cloudflare:sockets and bracketed IPv6",
      "Upstream Proxy Chaining: SOCKS5, SOCKS4, HTTP CONNECT with authentication",
      "DoH DNS Tunneling with AdGuard and Family parental filtering",
      "Streaming Pipeline: BYOB reader, backpressure, upstream queue bundling",
      "Sole Owner of Subscription Feeds: /sub/:username, /feed/:username, /yaml/:username",
      "Asynchronous Quota & Active IP Reporting to Worker B via ctx.waitUntil"
    ],
    tomlCode: workerDTomlcode,
    jsCode: workerDJscode
  }
};
