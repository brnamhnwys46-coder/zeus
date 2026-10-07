import { connect } from "cloudflare:sockets";

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
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

function safeJson(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Internal-Token, X-Upstream-Mirrors"
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

function getUpstreamUrls(filePath, env, request) {
  const customHeader = request.headers.get("X-Upstream-Mirrors");
  const rawMirrors = customHeader || env.UPSTREAM_MIRRORS || "https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main,https://fesavswgvswgfvasw.hxxyrukih4kvmeawzmdmug2eh5uwtcmt.workers.dev";
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

async function fetchFromUpstream(filePath, env, request) {
  const urls = getUpstreamUrls(filePath, env, request);

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
    } catch (e) {}
    if (attempt === 0) await new Promise(r => setTimeout(r, 600));
  }
  return null;
}

async function getCachedFile(filePath, env, request, ttlSeconds = 3600) {
  const now = Date.now();
  const cacheKey = `file:${filePath}`;

  // 1. In-memory hot cache
  const memCached = MEMORY_CACHE.get(cacheKey);
  if (memCached && (now - memCached.timestamp < ttlSeconds * 1000)) {
    return { data: memCached.data, source: "memory" };
  }

  // 2. Cloudflare KV cache
  if (env.FILE_CACHE_KV) {
    try {
      const kvData = await env.FILE_CACHE_KV.get(cacheKey, filePath.includes("vip-list") ? "json" : "text");
      if (kvData) {
        MEMORY_CACHE.set(cacheKey, { data: kvData, timestamp: now });
        return { data: kvData, source: "kv" };
      }
    } catch (e) {}
  }

  // 3. Fallback to upstream mirrors
  const upstreamRes = await fetchFromUpstream(filePath, env, request);
  if (upstreamRes && upstreamRes.ok) {
    const isJson = filePath.includes("vip-list");
    const data = isJson ? await upstreamRes.json() : await upstreamRes.text();

    // Store in memory
    MEMORY_CACHE.set(cacheKey, { data, timestamp: now });

    // Store in KV asynchronously
    if (env.FILE_CACHE_KV) {
      try {
        await env.FILE_CACHE_KV.put(
          cacheKey, 
          isJson ? JSON.stringify(data) : data, 
          { expirationTtl: Math.max(60, ttlSeconds) }
        );
      } catch (e) {}
    }

    return { data, source: "upstream" };
  }

  // Fallback to expired memory cache if available
  if (memCached && memCached.data) {
    return { data: memCached.data, source: "memory_stale" };
  }

  return null;
}

// Socket / Proxy connection helpers for test-proxy offloading
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

async function connectSocks5(socksStr, destAddr, destPort, initialData) {
  const { user, pass, host, port, auth } = parseProxyConfig(socksStr, 1080);
  const socket = connect({ hostname: bracketIPv6(host), port });
  await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 4000))]);
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  try {
    if (auth) {
      await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
    } else {
      await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
    }
    let res = await reader.read();
    if (res.done || !res.value || res.value[0] !== 0x05) throw new Error("Invalid socks5 response");
    if (res.value[1] === 0x02) {
      const uEnc = TEXT_ENCODER.encode(user);
      const pEnc = TEXT_ENCODER.encode(pass);
      const authReq = new Uint8Array(1 + 1 + uEnc.length + 1 + pEnc.length);
      authReq[0] = 0x01; authReq[1] = uEnc.length;
      authReq.set(uEnc, 2); authReq[2 + uEnc.length] = pEnc.length;
      authReq.set(pEnc, 3 + uEnc.length);
      await writer.write(authReq);
      let authRes = await reader.read();
      if (authRes.done || !authRes.value || authRes.value[1] !== 0x00) throw new Error("Proxy auth failed");
    }
    const enc = TEXT_ENCODER.encode(destAddr);
    const req = new Uint8Array(4 + 1 + enc.length + 2);
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03; req[4] = enc.length;
    req.set(enc, 5);
    const portOffset = 5 + enc.length;
    req[portOffset] = (destPort >> 8) & 0xff; req[portOffset + 1] = destPort & 0xff;
    await writer.write(req);
    let connRes = await reader.read();
    if (connRes.done || !connRes.value || connRes.value[1] !== 0x00) throw new Error("Socks5 connect rejected");
    if (initialData) await writer.write(initialData);
    writer.releaseLock();
    reader.releaseLock();
    return socket;
  } catch (e) {
    try { writer.releaseLock(); } catch (_) {}
    try { reader.releaseLock(); } catch (_) {}
    try { socket.close(); } catch (_) {}
    throw e;
  }
}

async function connectHttpProxy(proxyStr, destAddr, destPort, initialData) {
  const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 80);
  const socket = connect({ hostname: bracketIPv6(host), port });
  await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 4000))]);
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  try {
    const safeDest = destAddr.includes(":") ? `[${destAddr}]` : destAddr;
    let req = `CONNECT ${safeDest}:${destPort} HTTP/1.1\r\nHost: ${safeDest}:${destPort}\r\n`;
    if (auth) req += `Proxy-Authorization: Basic ${btoa(`${user}:${pass}`)}\r\n`;
    req += "\r\n";
    await writer.write(TEXT_ENCODER.encode(req));
    const res = await reader.read();
    if (res.done || !res.value) throw new Error("HTTP proxy closed");
    const resStr = TEXT_DECODER.decode(res.value);
    if (!resStr.includes("200")) throw new Error("HTTP proxy reject");
    if (initialData) await writer.write(initialData);
    writer.releaseLock();
    reader.releaseLock();
    return socket;
  } catch (e) {
    try { writer.releaseLock(); } catch (_) {}
    try { reader.releaseLock(); } catch (_) {}
    try { socket.close(); } catch (_) {}
    throw e;
  }
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Internal-Token, X-Upstream-Mirrors"
        }
      });
    }

    const url = new URL(request.url);
    if (url.pathname === "/health" || url.pathname === "/api/internal/health") {
      return safeJson({ 
        status: "healthy", 
        service: "worker-c-cache", 
        hasKV: Boolean(env.FILE_CACHE_KV), 
        memoryKeys: MEMORY_CACHE.size,
        timestamp: Date.now() 
      });
    }

    // Authenticate internal caller
    if (!verifyInternalAuth(request, env)) {
      return safeJson({ error: "Unauthorized access to Cache Service." }, 403);
    }

    const path = url.pathname;

    try {
      // 1. GET GENERIC CACHED FILE
      if (path === "/api/internal/cache/file" && request.method === "GET") {
        const filePath = url.searchParams.get("path");
        const ttl = parseInt(url.searchParams.get("ttl") || "3600");
        if (!filePath) return safeJson({ error: "Missing 'path' parameter" }, 400);

        const result = await getCachedFile(filePath, env, request, ttl);
        if (!result) return safeJson({ error: `File not found: ${filePath}` }, 404);

        return safeJson({
          path: filePath,
          source: result.source,
          data: result.data
        });
      }

      // 2. GET CLEAN CLOUDFLARE IPS (Shuffled, Operator Filtered)
      if (path === "/api/internal/cache/ips" && request.method === "GET") {
        const operator = url.searchParams.get("operator") || "all";
        let count = parseInt(url.searchParams.get("count") || "20");
        if (isNaN(count) || count < 1) count = 20;

        const result = await getCachedFile("ips.txt", env, request, 86400);
        let ips = [];
        if (result && result.data && typeof result.data === "string") {
          ips = result.data.split("\n")
            .map(l => l.trim())
            .filter(l => l.length > 0 && !l.includes("#") && !l.startsWith("[source") && !l.includes("----------"));
        }

        // Shuffle IPs
        const shuffled = ips.slice();
        for (let i = shuffled.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }

        const selected = shuffled.slice(0, count);
        return safeJson({
          count: selected.length,
          totalAvailable: ips.length,
          ips: selected,
          rawLines: selected.join("\n")
        });
      }

      // 3. GET VIP PROXY COUNTRIES & LIST
      if (path === "/api/internal/cache/vip-countries" && request.method === "GET") {
        const result = await getCachedFile("vip-list", env, request, 3600);
        let countries = ["DE", "US", "GB", "NL", "FR", "TR"];
        if (result && Array.isArray(result.data)) {
          countries = result.data
            .filter(f => f && f.name && f.name.endsWith(".txt"))
            .map(f => f.name.replace(".txt", "").toUpperCase());
        }
        return safeJson({ countries });
      }

      // 4. TEST PROXY HEALTH (Offloaded from Worker A)
      if (path === "/api/internal/cache/test-proxy" && request.method === "POST") {
        const { proxy, skip_country } = await request.json().catch(() => ({}));
        if (!proxy) return safeJson({ error: "Missing proxy parameter" }, 400);

        if (proxy === "direct") {
          const startT = Date.now();
          try {
            const controller = new AbortController();
            const tid = setTimeout(() => controller.abort(), 3000);
            await fetch("https://cp.cloudflare.com/generate_204", { method: "HEAD", signal: controller.signal });
            clearTimeout(tid);
            return safeJson({ success: true, ping: Date.now() - startT, country: "UN" });
          } catch (e) {
            return safeJson({ error: "Direct connection failed" });
          }
        }

        const startTime = Date.now();
        const targetHost = skip_country ? "1.1.1.1" : "ip-api.com";
        const reqPath = skip_country ? "/" : "/json/?fields=countryCode";
        const payload = TEXT_ENCODER.encode(`GET ${reqPath} HTTP/1.1\r\nHost: ${targetHost}\r\nConnection: close\r\n\r\n`);

        let sock = null;
        try {
          const isHttp = proxy.toLowerCase().startsWith("http://") || proxy.toLowerCase().startsWith("https://");
          const cleanStr = proxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");

          if (isHttp) {
            sock = await connectHttpProxy(cleanStr, targetHost, 80, payload);
          } else {
            sock = await connectSocks5(cleanStr, targetHost, 80, payload);
          }

          const reader = sock.readable.getReader();
          let resStr = "";
          const timeoutId = setTimeout(() => { try { sock.close(); } catch (_) {} }, 5000);
          try {
            while (true) {
              const res = await reader.read();
              if (res.done || !res.value) break;
              resStr += TEXT_DECODER.decode(res.value, { stream: true });
              if (skip_country && resStr.includes("HTTP/1.")) break;
              if (resStr.includes("countryCode")) break;
            }
          } finally {
            clearTimeout(timeoutId);
            try { sock.close(); } catch (_) {}
          }

          const ping = Date.now() - startTime;
          let country = "UN";
          const jsonMatch = resStr.match(/\{[^}]*"countryCode"\s*:\s*"([^"]+)"[^}]*\}/);
          if (jsonMatch && jsonMatch[1]) country = jsonMatch[1];

          return safeJson({ success: true, ping, country });
        } catch (e) {
          return safeJson({ error: e.message || "Connection failed" }, 200);
        }
      }

      // 5. PURGE CACHE
      if (path === "/api/internal/cache/purge" && request.method === "POST") {
        MEMORY_CACHE.clear();
        return safeJson({ success: true, message: "In-memory cache purged" });
      }

      return safeJson({ error: "Not Found in Cache Service" }, 404);
    } catch (err) {
      return safeJson({ error: "Cache Service error: " + err.message }, 500);
    }
  }
};
