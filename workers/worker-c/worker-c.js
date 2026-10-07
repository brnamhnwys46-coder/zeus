import { connect } from "cloudflare:sockets";

/**
 * WORKER C: Repository & File Cache Service
 * 
 * Handles:
 * - External file caching (ips.txt, vip-list, proxy_vip/*.txt, proxy/*.txt)
 * - Cloudflare KV storage (FILE_CACHE_KV) with memory cache acceleration
 * - Upstream mirrors with automatic fallback (GitHub, Workers mirrors)
 * - Offloaded outbound proxy socket health testing
 * 
 * Security:
 * - Fails closed if INTERNAL_AUTH_TOKEN is missing or invalid.
 * - Constant-time token verification.
 * - Server-side only; does not expose internal endpoints to the browser.
 */

const MEMORY_CACHE = new Map();
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

function safeJson(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

function verifyInternalAuth(request, env) {
  const expectedToken = env.INTERNAL_AUTH_TOKEN;
  // FAIL CLOSED: if token is missing or empty, deny access immediately
  if (!expectedToken || typeof expectedToken !== "string" || expectedToken.trim() === "") {
    return false;
  }

  const authHeader = request.headers.get("Authorization") || "";
  const internalHeader = request.headers.get("X-Internal-Token") || "";

  let providedToken = "";
  if (authHeader.startsWith("Bearer ")) {
    providedToken = authHeader.slice(7).trim();
  } else if (internalHeader) {
    providedToken = internalHeader.trim();
  }

  if (!providedToken) return false;
  return timingSafeEqual(providedToken, expectedToken.trim());
}

function getUpstreamUrls(filePath, env) {
  const rawMirrors = env.UPSTREAM_MIRRORS || "https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main,https://fesavswgvswgfvasw.hxxyrukih4kvmeawzmdmug2eh5uwtcmt.workers.dev";
  const mirrors = rawMirrors.split(",").map(m => m.trim().replace(/\/+$/, "")).filter(Boolean);
  const cleanPath = filePath.startsWith("/") ? filePath.slice(1) : filePath;
  const ghPath = cleanPath.includes("?") ? cleanPath.substring(0, cleanPath.indexOf("?")) : cleanPath;

  return mirrors.map(mirror => {
    if (mirror.includes("githubusercontent.com")) {
      return `${mirror}/${ghPath}`;
    }
    return `${mirror}/${cleanPath}`;
  });
}

async function fetchFromUpstream(filePath, env) {
  const urls = getUpstreamUrls(filePath, env);

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 7000);

      const res = await Promise.any(
        urls.map(url =>
          fetch(url, {
            signal: controller.signal,
            headers: { "User-Agent": "Mozilla/5.0 (Cloudflare-Worker-C; ZeusArchitecture)" }
          }).then(response => {
            if (!response.ok) throw new Error(`HTTP ${response.status} from ${url}`);
            return response;
          })
        )
      );

      clearTimeout(timeoutId);
      return res;
    } catch (_) {}
    if (attempt === 0) await new Promise(r => setTimeout(r, 500));
  }
  return null;
}

async function getCachedFile(filePath, env, ttlSeconds = 3600) {
  const now = Date.now();
  const cacheKey = `file:${filePath}`;

  // 1. Hot Memory Cache
  const memCached = MEMORY_CACHE.get(cacheKey);
  if (memCached && (now - memCached.timestamp < ttlSeconds * 1000)) {
    return { data: memCached.data, source: "memory" };
  }

  // 2. Persistent KV Cache
  if (env.FILE_CACHE_KV) {
    try {
      const kvData = await env.FILE_CACHE_KV.get(cacheKey, filePath.includes("vip-list") ? "json" : "text");
      if (kvData) {
        MEMORY_CACHE.set(cacheKey, { data: kvData, timestamp: now });
        return { data: kvData, source: "kv" };
      }
    } catch (_) {}
  }

  // 3. Fallback to Upstream Mirrors
  const upstreamRes = await fetchFromUpstream(filePath, env);
  if (upstreamRes && upstreamRes.ok) {
    const isJson = filePath.includes("vip-list");
    const data = isJson ? await upstreamRes.json() : await upstreamRes.text();

    MEMORY_CACHE.set(cacheKey, { data, timestamp: now });

    if (env.FILE_CACHE_KV) {
      env.FILE_CACHE_KV.put(
        cacheKey,
        isJson ? JSON.stringify(data) : data,
        { expirationTtl: Math.max(60, ttlSeconds) }
      ).catch(() => {});
    }

    return { data, source: "upstream" };
  }

  // 4. Stale fallback if available
  if (memCached && memCached.data) {
    return { data: memCached.data, source: "memory_stale" };
  }

  return null;
}

// Socket helpers for testing proxies
function bracketIPv6(host) {
  return typeof host === "string" && host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function parseProxyConfig(proxyStr, defaultPort = 1080) {
  let user = "", pass = "", host = "", port = defaultPort;
  let auth = false, remain = proxyStr;
  if (remain.includes("@")) {
    const atIdx = remain.lastIndexOf("@");
    const authPart = remain.substring(0, atIdx);
    remain = remain.substring(atIdx + 1);
    const colonIdx = authPart.indexOf(":");
    if (colonIdx !== -1) {
      user = authPart.substring(0, colonIdx);
      pass = authPart.substring(colonIdx + 1);
    } else {
      user = authPart;
    }
    auth = true;
  }
  if (remain.startsWith("[")) {
    const closeIdx = remain.indexOf("]");
    if (closeIdx !== -1) {
      host = remain.substring(1, closeIdx);
      if (remain.length > closeIdx + 1 && remain[closeIdx + 1] === ":") {
        port = parseInt(remain.substring(closeIdx + 2)) || defaultPort;
      }
    }
  } else {
    const lastColon = remain.lastIndexOf(":");
    if (lastColon !== -1 && remain.indexOf(":") === lastColon) {
      host = remain.substring(0, lastColon);
      port = parseInt(remain.substring(lastColon + 1)) || defaultPort;
    } else {
      host = remain;
    }
  }
  return { user, pass, host, port, auth };
}

async function testOutboundSocket(proxyStr, targetHost = "1.1.1.1", targetPort = 80) {
  const { host, port } = parseProxyConfig(proxyStr, 1080);
  const startT = Date.now();
  const socket = connect({ hostname: bracketIPv6(host), port });
  await Promise.race([
    socket.opened,
    new Promise((_, reject) => setTimeout(() => reject(new Error("Connection timeout")), 4000))
  ]);
  const ping = Date.now() - startT;
  try { socket.close(); } catch (_) {}
  return { success: true, ping, country: "UN" };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Public Health Check
    if (url.pathname === "/health" || url.pathname === "/api/internal/health") {
      return safeJson({
        status: "healthy",
        service: "worker-c-cache",
        hasKV: Boolean(env.FILE_CACHE_KV),
        memoryCacheSize: MEMORY_CACHE.size,
        timestamp: Date.now()
      });
    }

    // Strict Internal Authentication (FAIL CLOSED)
    if (!verifyInternalAuth(request, env)) {
      return safeJson({ success: false, error: "Forbidden: Invalid or missing internal authentication token." }, 403);
    }

    const path = url.pathname;

    try {
      // 1. Get Cached Repository File
      if (path === "/api/internal/cache/file" && request.method === "GET") {
        const filePath = url.searchParams.get("path");
        const ttl = parseInt(url.searchParams.get("ttl") || "3600");
        if (!filePath) return safeJson({ success: false, error: "Missing 'path' query parameter." }, 400);

        const result = await getCachedFile(filePath, env, ttl);
        if (!result) return safeJson({ success: false, error: `File not found: ${filePath}` }, 404);

        return safeJson({
          success: true,
          path: filePath,
          source: result.source,
          data: result.data
        });
      }

      // 2. Get Clean Cloudflare IPs (Operator Filtered & Shuffled)
      if (path === "/api/internal/cache/ips" && request.method === "GET") {
        let count = parseInt(url.searchParams.get("count") || "20");
        if (isNaN(count) || count < 1) count = 20;

        const result = await getCachedFile("ips.txt", env, 86400);
        let ips = [];
        if (result && result.data && typeof result.data === "string") {
          ips = result.data.split("\n")
            .map(l => l.trim())
            .filter(l => l.length > 0 && !l.includes("#") && !l.startsWith("[source") && !l.includes("----------"));
        }

        const shuffled = ips.slice();
        for (let i = shuffled.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }

        const selected = shuffled.slice(0, count);
        return safeJson({
          success: true,
          count: selected.length,
          totalAvailable: ips.length,
          ips: selected,
          rawLines: selected.join("\n")
        });
      }

      // 3. Get VIP Country Directory
      if (path === "/api/internal/cache/vip-countries" && request.method === "GET") {
        const result = await getCachedFile("vip-list", env, 3600);
        let countries = ["DE", "US", "GB", "NL", "FR", "TR"];
        if (result && Array.isArray(result.data)) {
          countries = result.data
            .filter(f => f && f.name && f.name.endsWith(".txt"))
            .map(f => f.name.replace(".txt", "").toUpperCase());
        }
        return safeJson({ success: true, countries });
      }

      // 4. Outbound Proxy Health Check
      if (path === "/api/internal/cache/test-proxy" && request.method === "POST") {
        const { proxy } = await request.json().catch(() => ({}));
        if (!proxy) return safeJson({ success: false, error: "Missing proxy parameter." }, 400);

        if (proxy === "direct") {
          const startT = Date.now();
          try {
            const controller = new AbortController();
            const tid = setTimeout(() => controller.abort(), 3000);
            await fetch("https://cp.cloudflare.com/generate_204", { method: "HEAD", signal: controller.signal });
            clearTimeout(tid);
            return safeJson({ success: true, ping: Date.now() - startT, country: "UN" });
          } catch (_) {
            return safeJson({ success: false, error: "Direct internet test failed." });
          }
        }

        try {
          const res = await testOutboundSocket(proxy);
          return safeJson(res);
        } catch (e) {
          return safeJson({ success: false, error: e.message || "Proxy test failed." });
        }
      }

      // 5. Purge Cache
      if (path === "/api/internal/cache/purge" && request.method === "POST") {
        MEMORY_CACHE.clear();
        return safeJson({ success: true, message: "In-memory cache purged successfully." });
      }

      return safeJson({ success: false, error: "Not Found in Cache Service." }, 404);
    } catch (err) {
      return safeJson({ success: false, error: "Cache Service error: " + err.message }, 500);
    }
  }
};
