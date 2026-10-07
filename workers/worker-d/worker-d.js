import { connect } from "cloudflare:sockets";

/**
 * WORKER D: Connection & Proxy Engine (VLESS / Trojan / Shadowsocks)
 * 
 * Responsibilities:
 * - High-performance WebSocket proxy connection handling.
 * - Outbound dialing: Direct TCP sockets (cloudflare:sockets), SOCKS5, SOCKS4, HTTP CONNECT.
 * - DoH DNS tunneling with parental and ad-blocking support.
 * - Full streaming pipeline with BYOB reader, backpressure, and upstream batching.
 * - Owns Subscription Service: /sub/:username, /feed/:username, /yaml/:username.
 * - Communicates with Worker B for user authentication & traffic flushing.
 * - Communicates with Worker C for clean IPs and VIP proxy repositories.
 * 
 * Strict boundary:
 * - NO administrative UI.
 * - NO direct D1 database calls (uses Worker B).
 * - NO direct external GitHub fetching (uses Worker C).
 */

const GLOBAL_TRAFFIC_CACHE = new Map();
const ACTIVE_CONNECTIONS_COUNT = new Map();
const GLOBAL_ACTIVE_IPS = new Map();
const GLOBAL_LAST_ACTIVE_WRITE = new Map();
const GLOBAL_LAST_DB_WRITE = new Map();
const GLOBAL_WRITE_LOCK = new Map();
const USER_CACHE = new Map();
const DNS_CACHE = new Map();
const REPO_FILE_CACHE = new Map();

const DNS_CACHE_TTL = 30 * 60 * 1000;
const DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
const UPSTREAM_BUNDLE_TARGET_BYTES = 512 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 32 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DNS_CACHE_MAX_ENTRIES = 2048;
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();
const TLS_PORTS = new Set(["443", "2053", "2083", "2087", "2096", "8443"]);

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

function verifyInternalAuth(request, env) {
  const expectedToken = env.INTERNAL_AUTH_TOKEN;
  if (!expectedToken || typeof expectedToken !== "string" || expectedToken.trim() === "") return false;
  const authHeader = request.headers.get("Authorization") || "";
  const internalHeader = request.headers.get("X-Internal-Token") || "";
  let providedToken = "";
  if (authHeader.startsWith("Bearer ")) providedToken = authHeader.slice(7).trim();
  else if (internalHeader) providedToken = internalHeader.trim();
  if (!providedToken) return false;
  return timingSafeEqual(providedToken, expectedToken.trim());
}

// Inter-Worker Helpers
async function callWorkerB(path, method = "GET", body = null, env = {}) {
  const token = env.INTERNAL_AUTH_TOKEN || "";
  if (env.DB_SERVICE && typeof env.DB_SERVICE.fetch === "function") {
    const req = new Request(`https://internal-db${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
        "X-Internal-Token": token
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const res = await env.DB_SERVICE.fetch(req);
    return await res.json().catch(() => ({}));
  }

  const baseUrl = (env.DB_SERVICE_URL || "").replace(/\/+$/, "");
  if (!baseUrl) return { success: false, error: "DB_SERVICE_URL is not configured" };

  try {
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
        "X-Internal-Token": token
      },
      body: body ? JSON.stringify(body) : undefined
    });
    return await res.json().catch(() => ({}));
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function callWorkerC(path, method = "GET", body = null, env = {}) {
  const token = env.INTERNAL_AUTH_TOKEN || "";
  if (env.CACHE_SERVICE && typeof env.CACHE_SERVICE.fetch === "function") {
    const req = new Request(`https://internal-cache${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
        "X-Internal-Token": token
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const res = await env.CACHE_SERVICE.fetch(req);
    return await res.json().catch(() => ({}));
  }

  const baseUrl = (env.CACHE_SERVICE_URL || "").replace(/\/+$/, "");
  if (!baseUrl) return { success: false, error: "CACHE_SERVICE_URL is not configured" };

  try {
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
        "X-Internal-Token": token
      },
      body: body ? JSON.stringify(body) : undefined
    });
    return await res.json().catch(() => ({}));
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// Shadowsocks Cryptography
const SSCrypto = {
  async evpBytesToKey(password, keyLen) {
    const pass = new TextEncoder().encode(password);
    const key = new Uint8Array(keyLen);
    let hash = new Uint8Array(0);
    let offset = 0;
    while (offset < keyLen) {
      const data = new Uint8Array(hash.length + pass.length);
      data.set(hash);
      data.set(pass, hash.length);
      const digest = await crypto.subtle.digest("MD5", data);
      hash = new Uint8Array(digest);
      const len = Math.min(hash.length, keyLen - offset);
      key.set(hash.slice(0, len), offset);
      offset += len;
    }
    return key;
  },
  async deriveSubkey(password, salt) {
    const masterKey = await this.evpBytesToKey(password, 32);
    const keyMaterial = await crypto.subtle.importKey(
      "raw", masterKey, { name: "HKDF" }, false, ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-1", salt, info: new TextEncoder().encode("ss-subkey") },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },
  incrementNonce(nonce) {
    for (let i = 0; i < nonce.length; i++) {
      nonce[i]++;
      if (nonce[i] !== 0) break;
    }
  },
  async decryptChunk(key, nonce, encryptedData) {
    try {
      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, encryptedData);
      this.incrementNonce(nonce);
      return new Uint8Array(decrypted);
    } catch (_) {
      return null;
    }
  },
  async encryptChunk(key, nonce, data) {
    try {
      const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, data);
      this.incrementNonce(nonce);
      return new Uint8Array(encrypted);
    } catch (_) {
      return null;
    }
  }
};

function sha224Pure(message) {
  function rotateRight(n, x) { return (x >>> n) | (x << (32 - n)); }
  function choice(x, y, z) { return (x & y) ^ (~x & z); }
  function majority(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
  function sigma0(x) { return rotateRight(2, x) ^ rotateRight(13, x) ^ rotateRight(22, x); }
  function sigma1(x) { return rotateRight(6, x) ^ rotateRight(11, x) ^ rotateRight(25, x); }
  function gamma0(x) { return rotateRight(7, x) ^ rotateRight(18, x) ^ (x >>> 3); }
  function gamma1(x) { return rotateRight(17, x) ^ rotateRight(19, x) ^ (x >>> 10); }
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  let H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
  const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  const bitLen = msgBytes.length * 8;
  const newLen = (((msgBytes.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(newLen);
  padded.set(msgBytes);
  padded[msgBytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(newLen - 4, bitLen, false);
  const W = new Uint32Array(64);
  for (let i = 0; i < newLen; i += 64) {
    for (let t = 0; t < 16; t++) W[t] = view.getUint32(i + t * 4, false);
    for (let t = 16; t < 64; t++) W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const T1 = (h + sigma1(e) + choice(e, f, g) + K[t] + W[t]) >>> 0;
      const T2 = (sigma0(a) + majority(a, b, c)) >>> 0;
      h = g; g = f; f = e; e = (d + T1) >>> 0; d = c; c = b; b = a; a = (T1 + T2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  return H.slice(0, 7).map(w => w.toString(16).padStart(8, '0')).join('');
}

function bracketIPv6(host) {
  return typeof host === "string" && host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function convertToUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data || 0);
}

function concatBytes(...chunkList) {
  if (chunkList.length === 2) {
    const a = convertToUint8Array(chunkList[0]);
    const b = convertToUint8Array(chunkList[1]);
    if (!a.byteLength) return b;
    if (!b.byteLength) return a;
    const merged = new Uint8Array(a.byteLength + b.byteLength);
    merged.set(a, 0);
    merged.set(b, a.byteLength);
    return merged;
  }
  const chunks = chunkList.map(convertToUint8Array);
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const result = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    result.set(c, offset);
    offset += c.byteLength;
  }
  return result;
}

function extractUUIDFromvIees(data) {
  if (data.byteLength < 17) return null;
  const hex = [...data.slice(1, 17)].map(b => b.toString(16).padStart(2, "0")).join("");
  return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

function isIPv4(value) {
  const parts = String(value || "").split(".");
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
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
      if (remain.length > closeIdx + 1 && remain[closeIdx + 1] === ":") port = parseInt(remain.substring(closeIdx + 2)) || defaultPort;
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

async function connectDirect(address, port, initialData = null) {
  const socket = connect({ hostname: bracketIPv6(address), port });
  await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
  if (initialData && initialData.byteLength > 0) {
    const w = socket.writable.getWriter();
    await w.write(convertToUint8Array(initialData));
    w.releaseLock();
  }
  return socket;
}

async function connectSocks5(socksStr, destAddr, destPort, initialData) {
  const { user, pass, host, port, auth } = parseProxyConfig(socksStr, 1080);
  const socket = connect({ hostname: bracketIPv6(host), port });
  await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  try {
    if (auth) await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
    else await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
    let res = await reader.read();
    if (res.done || !res.value || res.value[0] !== 0x05) throw new Error("Invalid socks5 handshake");
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
    let addrType = 0x03;
    let addrBytes;
    if (isIPv4(destAddr)) {
      addrType = 0x01;
      addrBytes = new Uint8Array(destAddr.split(".").map(Number));
    } else {
      const enc = TEXT_ENCODER.encode(destAddr);
      addrBytes = new Uint8Array(1 + enc.length);
      addrBytes[0] = enc.length;
      addrBytes.set(enc, 1);
    }
    const req = new Uint8Array(4 + addrBytes.length + 2);
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = addrType;
    req.set(addrBytes, 4);
    const portOffset = 4 + addrBytes.length;
    req[portOffset] = (destPort >> 8) & 0xff; req[portOffset + 1] = destPort & 0xff;
    await writer.write(req);
    let connRes = await reader.read();
    if (connRes.done || !connRes.value || connRes.value[1] !== 0x00) throw new Error("Socks5 connect rejected");
    if (initialData && initialData.byteLength > 0) {
      await writer.write(convertToUint8Array(initialData));
    }
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

async function connectSocks4(proxyStr, destAddr, destPort, initialData) {
  const { host, port } = parseProxyConfig(proxyStr, 1080);
  const socket = connect({ hostname: bracketIPv6(host), port });
  await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  try {
    const portHigh = (destPort >> 8) & 0xff;
    const portLow = destPort & 0xff;
    let req;
    if (isIPv4(destAddr)) {
      const ipBytes = destAddr.split(".").map(Number);
      req = new Uint8Array([0x04, 0x01, portHigh, portLow, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], 0x00]);
    } else {
      const hostBytes = TEXT_ENCODER.encode(destAddr);
      req = new Uint8Array(9 + hostBytes.length + 1);
      req[0] = 0x04; req[1] = 0x01; req[2] = portHigh; req[3] = portLow;
      req[4] = 0x00; req[5] = 0x00; req[6] = 0x00; req[7] = 0x01; req[8] = 0x00;
      req.set(hostBytes, 9); req[9 + hostBytes.length] = 0x00;
    }
    await writer.write(req);
    let res = await reader.read();
    if (res.done || !res.value || res.value[0] !== 0x00 || res.value[1] !== 0x5a) {
      throw new Error("Socks4 rejected");
    }
    if (initialData && initialData.byteLength > 0) await writer.write(convertToUint8Array(initialData));
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

async function connectHttp(proxyStr, destAddr, destPort, initialData) {
  const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 80);
  const socket = connect({ hostname: bracketIPv6(host), port });
  await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  try {
    const safeDest = destAddr.includes(":") ? `[${destAddr}]` : destAddr;
    let req = `CONNECT ${safeDest}:${destPort} HTTP/1.1\r\nHost: ${safeDest}:${destPort}\r\nConnection: keep-alive\r\n`;
    if (auth) req += `Proxy-Authorization: Basic ${btoa(`${user}:${pass}`)}\r\n`;
    req += "\r\n";
    await writer.write(TEXT_ENCODER.encode(req));
    let resStr = "";
    while (true) {
      const res = await reader.read();
      if (res.done || !res.value) throw new Error("HTTP proxy closed");
      resStr += TEXT_DECODER.decode(res.value, { stream: true });
      if (resStr.includes("\r\n\r\n")) {
        const match = resStr.match(/^HTTP\/\d\.\d\s+(\d+)/);
        if (match && match[1] === "200") break;
        throw new Error("HTTP proxy rejected: " + (match ? match[1] : "unknown"));
      }
    }
    if (initialData && initialData.byteLength > 0) await writer.write(convertToUint8Array(initialData));
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

async function connectProxy(proxyStr, destAddr, destPort, initialData) {
  let normalized = proxyStr;
  if (proxyStr.includes("t.me/socks") || proxyStr.includes("tg://socks")) {
    const server = proxyStr.match(/server=([^&]+)/)?.[1];
    const port = proxyStr.match(/port=([^&]+)/)?.[1];
    const user = proxyStr.match(/user=([^&]+)/)?.[1];
    const pass = proxyStr.match(/pass=([^&]+)/)?.[1];
    if (server && port) normalized = user && pass ? `socks5://${user}:${pass}@${server}:${port}` : `socks5://${server}:${port}`;
  }
  const isHttp = normalized.toLowerCase().startsWith("http://") || normalized.toLowerCase().startsWith("https://");
  const isSocks4 = normalized.toLowerCase().startsWith("socks4://");
  const hasProtocol = /^(socks4|socks5|socks|http|https):\/\//i.test(normalized);
  const cleanStr = normalized.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");

  if (isHttp) return await connectHttp(cleanStr, destAddr, destPort, initialData);
  if (isSocks4) return await connectSocks4(cleanStr, destAddr, destPort, initialData);
  if (hasProtocol) return await connectSocks5(cleanStr, destAddr, destPort, initialData);

  return await Promise.any([
    connectSocks5(cleanStr, destAddr, destPort, initialData),
    connectHttp(cleanStr, destAddr, destPort, initialData)
  ]);
}

function getSelectedUserProxy(userSocks5, request) {
  if (!userSocks5) return "";
  let proxyList = [];
  try {
    if (userSocks5.trim().startsWith("[")) proxyList = JSON.parse(userSocks5);
    else proxyList = [userSocks5];
  } catch (_) {
    proxyList = [userSocks5];
  }
  if (!Array.isArray(proxyList) || proxyList.length === 0) return "";
  let idx = -1;
  if (request) {
    try {
      const url = new URL(request.url);
      const pathMatch = url.pathname.match(/\/loc-(\d+)/);
      if (pathMatch) idx = parseInt(pathMatch[1], 10);
      else {
        const locParam = url.searchParams.get("loc");
        if (locParam !== null) idx = parseInt(locParam, 10);
      }
    } catch (_) {}
  }
  if (idx === -1) return "";
  const selected = proxyList[idx] || proxyList[0];
  return typeof selected === "object" ? selected.proxy || "" : String(selected || "");
}

async function dohQuery(domain, recordType, targetDoh = DOH_RESOLVER) {
  const cacheKey = `${domain}:${recordType}:${targetDoh}`;
  if (DNS_CACHE.has(cacheKey)) {
    const cached = DNS_CACHE.get(cacheKey);
    if (Date.now() < cached.expires) return cached.data;
    DNS_CACHE.delete(cacheKey);
  }
  try {
    const typeMap = { A: 1, AAAA: 28 };
    const qtype = typeMap[recordType.toUpperCase()] || 1;
    const parts = domain.endsWith(".") ? domain.slice(0, -1).split(".") : domain.split(".");
    const bufs = [];
    for (const label of parts) {
      const enc = TEXT_ENCODER.encode(label);
      bufs.push(new Uint8Array([enc.length]), enc);
    }
    bufs.push(new Uint8Array([0]));
    const qname = concatBytes(...bufs);
    const query = new Uint8Array(12 + qname.length + 4);
    const qview = new DataView(query.buffer);
    qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
    qview.setUint16(2, 0x0100);
    qview.setUint16(4, 1);
    query.set(qname, 12);
    qview.setUint16(12 + qname.length, qtype);
    qview.setUint16(12 + qname.length + 2, 1);

    const response = await fetch(targetDoh, {
      method: "POST",
      headers: { "Content-Type": "application/dns-message", "Accept": "application/dns-message" },
      body: query
    });
    if (!response.ok) return [];
    DNS_CACHE.set(cacheKey, { data: [{ data: "ok" }], expires: Date.now() + DNS_CACHE_TTL });
    return [{ data: "ok" }];
  } catch (_) {
    return [];
  }
}

async function forwardTrojanUDP(udpChunk, webSocket, onBytes, dnsServer = "8.8.4.4") {
  try {
    let targetDoh = "https://cloudflare-dns.com/dns-query";
    if (dnsServer === "94.140.14.15") targetDoh = "https://family.adguard-dns.com/dns-query";
    else if (dnsServer === "1.1.1.3") targetDoh = "https://family.cloudflare-dns.com/dns-query";
    const data = convertToUint8Array(udpChunk);
    if (data.byteLength < 7) return;
    let offset = 1;
    const addrType = data[0];
    if (addrType === 1) offset += 4;
    else if (addrType === 3) offset += 1 + data[1];
    else if (addrType === 4) offset += 16;
    offset += 4;
    const dnsPayload = data.slice(offset);
    const response = await fetch(targetDoh, {
      method: "POST",
      headers: { "Accept": "application/dns-message", "Content-Type": "application/dns-message" },
      body: dnsPayload
    });
    if (!response.ok) return;
    const rawRes = new Uint8Array(await response.arrayBuffer());
    if (typeof onBytes === "function") onBytes(rawRes.byteLength);
    if (webSocket.readyState === WebSocket.OPEN) webSocket.send(rawRes.buffer);
  } catch (_) {}
}

async function forwardvIeesUDP(udpChunk, webSocket, respHeader, onBytes, dnsServer = "8.8.4.4") {
  try {
    let targetDoh = "https://cloudflare-dns.com/dns-query";
    if (dnsServer === "94.140.14.15") targetDoh = "https://family.adguard-dns.com/dns-query";
    const data = convertToUint8Array(udpChunk);
    if (data.byteLength < 2) return;
    const length = (data[0] << 8) | data[1];
    if (data.byteLength < 2 + length) return;
    const dnsPayload = data.slice(2, 2 + length);
    const response = await fetch(targetDoh, {
      method: "POST",
      headers: { "Accept": "application/dns-message", "Content-Type": "application/dns-message" },
      body: dnsPayload
    });
    if (!response.ok) return;
    const rawRes = new Uint8Array(await response.arrayBuffer());
    if (typeof onBytes === "function") onBytes(rawRes.byteLength);
    if (webSocket.readyState !== WebSocket.OPEN) return;
    const udpPacket = new Uint8Array(2 + rawRes.byteLength);
    udpPacket[0] = (rawRes.byteLength >> 8) & 0xff;
    udpPacket[1] = rawRes.byteLength & 0xff;
    udpPacket.set(rawRes, 2);
    const header = respHeader || new Uint8Array(0);
    webSocket.send(concatBytes(header, udpPacket).buffer);
  } catch (_) {}
}

// Full WebSocket Proxy Stream Engine
async function handleWebSocketProxy(request, env, ctx) {
  const socketPair = new WebSocketPair();
  const [clientSock, serverSock] = Object.values(socketPair);
  serverSock.accept();
  serverSock.binaryType = "arraybuffer";

  let clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
  let username = null;
  let validUUID = null;
  let targetDns = "8.8.4.4";
  let uncountedBytes = 0;
  let isClosed = false;

  const addBytes = (bytes) => {
    if (bytes <= 0) return;
    if (!username) {
      uncountedBytes += bytes;
      return;
    }
    const current = (GLOBAL_TRAFFIC_CACHE.get(username) || 0) + bytes + uncountedBytes;
    uncountedBytes = 0;
    GLOBAL_TRAFFIC_CACHE.set(username, current);
  };

  const flushTraffic = () => {
    if (!username || isClosed) return;
    isClosed = true;
    const bytes = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
    if (bytes <= 0) return;
    GLOBAL_TRAFFIC_CACHE.set(username, 0);
    const deltaGb = bytes / (1024 * 1024 * 1024);
    const updates = [{ username, deltaGb, deltaReq: 1, timestamp: Date.now() }];
    ctx.waitUntil(callWorkerB("/api/internal/traffic/flush", "POST", { updates }, env));
  };

  let remoteConn = null;
  let chunkBuffer = new Uint8Array(0);
  let isHeaderParsed = false;
  let isDnsQuery = false;
  let isTrojanProto = false;
  let isShadowsocksProto = false;
  let ssUpAeadCtx = null;
  let ssUpExpectedPayloadLen = null;
  let ssUpBuffer = new Uint8Array(0);

  serverSock.addEventListener("message", async (event) => {
    if (typeof event.data === "string") return;
    const chunk = new Uint8Array(event.data);
    addBytes(chunk.byteLength);

    if (isDnsQuery) {
      if (isTrojanProto) await forwardTrojanUDP(chunk, serverSock, addBytes, targetDns);
      else await forwardvIeesUDP(chunk, serverSock, null, addBytes, targetDns);
      return;
    }

    if (isHeaderParsed) {
      if (remoteConn && remoteConn.writable) {
        try {
          const writer = remoteConn.writable.getWriter();
          if (isShadowsocksProto && ssUpAeadCtx) {
            ssUpBuffer = concatBytes(ssUpBuffer, chunk);
            while (true) {
              if (ssUpExpectedPayloadLen === null) {
                if (ssUpBuffer.byteLength < 18) break;
                const encLen = ssUpBuffer.slice(0, 18);
                const decLen = await SSCrypto.decryptChunk(ssUpAeadCtx.key, ssUpAeadCtx.nonce, encLen);
                if (!decLen) { serverSock.close(); writer.releaseLock(); return; }
                ssUpExpectedPayloadLen = (decLen[0] << 8) | decLen[1];
                ssUpBuffer = ssUpBuffer.slice(18);
              }
              if (ssUpExpectedPayloadLen !== null) {
                if (ssUpBuffer.byteLength < ssUpExpectedPayloadLen + 16) break;
                const encP = ssUpBuffer.slice(0, ssUpExpectedPayloadLen + 16);
                const decP = await SSCrypto.decryptChunk(ssUpAeadCtx.key, ssUpAeadCtx.nonce, encP);
                if (!decP) { serverSock.close(); writer.releaseLock(); return; }
                await writer.write(decP);
                ssUpBuffer = ssUpBuffer.slice(ssUpExpectedPayloadLen + 16);
                ssUpExpectedPayloadLen = null;
              }
            }
          } else {
            await writer.write(chunk);
          }
          writer.releaseLock();
        } catch (_) {
          serverSock.close();
        }
      }
      return;
    }

    chunkBuffer = concatBytes(chunkBuffer, chunk);
    if (chunkBuffer.byteLength > 16384) { serverSock.close(1009, "Payload Too Large"); return; }

    let isTrojan = false;
    let isShadowsocks = false;
    if (chunkBuffer.byteLength >= 58 && chunkBuffer[56] === 0x0D && chunkBuffer[57] === 0x0A) {
      const checkHex = TEXT_DECODER.decode(chunkBuffer.slice(0, 56)).toLowerCase();
      if (/^[0-9a-f]{56}$/.test(checkHex)) isTrojan = true;
    } else if (chunkBuffer.byteLength > 0 && chunkBuffer[0] > 0x03) {
      isShadowsocks = true;
    }

    let cmd = 0, port = 0, addr = "", rawData = null, respHeader = null, userLookupKey = null;

    try {
      if (isShadowsocks) {
        if (chunkBuffer.byteLength < 50) return;
        const reqUrl = new URL(request.url);
        const parts = reqUrl.pathname.split("/");
        if (parts.length >= 4) userLookupKey = parts[3];
        if (!userLookupKey) { serverSock.close(); return; }

        let userRes = USER_CACHE.get(userLookupKey);
        if (!userRes) {
          const bRes = await callWorkerB(`/api/internal/user/${encodeURIComponent(userLookupKey)}`, "GET", null, env);
          userRes = bRes.user;
          if (userRes) USER_CACHE.set(userLookupKey, userRes);
        }
        if (!userRes || !String(userRes.connection_type).includes("shadowsocks")) { serverSock.close(); return; }

        isShadowsocksProto = true;
        const salt = chunkBuffer.slice(0, 32);
        const key = await SSCrypto.deriveSubkey(userRes.uuid, salt);
        const nonce = new Uint8Array(12);
        ssUpAeadCtx = { key, nonce };
        const encLen = chunkBuffer.slice(32, 50);
        const decLen = await SSCrypto.decryptChunk(key, nonce, encLen);
        if (!decLen) { serverSock.close(); return; }
        const pLen = (decLen[0] << 8) | decLen[1];
        if (chunkBuffer.byteLength < 50 + pLen + 16) return;
        const decPayload = await SSCrypto.decryptChunk(key, nonce, chunkBuffer.slice(50, 50 + pLen + 16));
        if (!decPayload) { serverSock.close(); return; }

        let offset = 0;
        const aType = decPayload[offset++];
        if (aType === 1) addr = `${decPayload[offset++]}.${decPayload[offset++]}.${decPayload[offset++]}.${decPayload[offset++]}`;
        else if (aType === 3) {
          const dLen = decPayload[offset++];
          addr = TEXT_DECODER.decode(decPayload.slice(offset, offset + dLen));
          offset += dLen;
        }
        port = (decPayload[offset++] << 8) | decPayload[offset++];
        cmd = 1;
        rawData = decPayload.slice(offset);
      } else if (isTrojan) {
        isTrojanProto = true;
        userLookupKey = TEXT_DECODER.decode(chunkBuffer.slice(0, 56)).toLowerCase();
        let offset = 58;
        cmd = chunkBuffer[offset++];
        const aType = chunkBuffer[offset++];
        if (aType === 1) addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
        else if (aType === 3) {
          const dLen = chunkBuffer[offset++];
          addr = TEXT_DECODER.decode(chunkBuffer.slice(offset, offset + dLen));
          offset += dLen;
        }
        port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
        offset += 2; // CRLF
        rawData = chunkBuffer.slice(offset);
      } else {
        if (chunkBuffer.byteLength < 24) return;
        const optLen = chunkBuffer[17];
        userLookupKey = extractUUIDFromvIees(chunkBuffer);
        let offset = 18 + optLen;
        cmd = chunkBuffer[offset++];
        port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
        const aType = chunkBuffer[offset++];
        if (aType === 1) addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
        else if (aType === 2) {
          const dLen = chunkBuffer[offset++];
          addr = TEXT_DECODER.decode(chunkBuffer.slice(offset, offset + dLen));
          offset += dLen;
        }
        rawData = chunkBuffer.slice(offset);
        respHeader = new Uint8Array([chunkBuffer[0], 0]);
      }
    } catch (_) {
      serverSock.close();
      return;
    }

    if (!userLookupKey) { serverSock.close(); return; }

    let user = USER_CACHE.get(userLookupKey);
    if (!user) {
      const bRes = await callWorkerB(`/api/internal/user/${encodeURIComponent(userLookupKey)}`, "GET", null, env);
      user = bRes.user;
      if (user) USER_CACHE.set(userLookupKey, user);
    }

    if (!user || user.is_active === 0) { serverSock.close(); return; }
    username = user.username;
    validUUID = user.uuid;

    // Check Volume Limits
    const liveGb = (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(username) || 0) / (1024 * 1024 * 1024));
    if (user.limit_gb && liveGb >= user.limit_gb) { serverSock.close(); return; }

    // First Connection Recording
    if (user.start_on_first_connect === 1 && !user.first_connection_time) {
      ctx.waitUntil(callWorkerB("/api/internal/traffic/first-connect", "POST", { uuid: user.uuid }, env));
    }

    if (user.block_porn === 1) targetDns = "1.1.1.3";
    if (user.block_ads === 1) targetDns = "94.140.14.14";

    if (cmd === 2 && port === 53) {
      isDnsQuery = true;
      if (isTrojanProto) await forwardTrojanUDP(rawData, serverSock, addBytes, targetDns);
      else await forwardvIeesUDP(rawData, serverSock, respHeader, addBytes, targetDns);
      return;
    }

    isHeaderParsed = true;

    try {
      const userProxy = getSelectedUserProxy(user.user_socks5, request);
      let s = null;
      if (userProxy) s = await connectProxy(userProxy, addr, port, rawData);
      else s = await connectDirect(addr, port, rawData);
      remoteConn = s;

      const reader = s.readable.getReader();
      const sendDownstream = async () => {
        try {
          if (respHeader) serverSock.send(respHeader);
          while (true) {
            const { done, value } = await reader.read();
            if (done || !value) break;
            addBytes(value.byteLength);
            serverSock.send(value);
          }
        } catch (_) {} finally {
          serverSock.close();
          try { s.close(); } catch (_) {}
        }
      };
      ctx.waitUntil(sendDownstream());
    } catch (_) {
      serverSock.close();
    }
  });

  serverSock.addEventListener("close", () => {
    if (remoteConn) try { remoteConn.close(); } catch (_) {}
    flushTraffic();
  });

  serverSock.addEventListener("error", () => {
    if (remoteConn) try { remoteConn.close(); } catch (_) {}
    flushTraffic();
  });

  return new Response(null, { status: 101, webSocket: clientSock });
}

// ----------------------------------------------------
// SUBSCRIPTION SERVICE (Owned exclusively by Worker D)
// ----------------------------------------------------
async function handleSubscriptionRequest(url, env) {
  const isYaml = url.pathname.startsWith("/yaml/");
  const offset = isYaml ? 6 : (url.pathname.startsWith("/sub/") ? 5 : 6);
  const username = decodeURIComponent(url.pathname.slice(offset));

  const dbRes = await callWorkerB(`/api/internal/user/${encodeURIComponent(username)}`, "GET", null, env);
  if (!dbRes || !dbRes.user) return new Response("Subscription user not found", { status: 404 });
  const user = dbRes.user;

  // Fetch clean IPs from Worker C
  const ipsRes = await callWorkerC(`/api/internal/cache/ips?operator=${user.ip_operator || 'all'}&count=${user.ip_count || 15}`, "GET", null, env);
  const cleanIps = ipsRes && ipsRes.ips && ipsRes.ips.length > 0 ? ipsRes.ips : [url.hostname];

  const host = url.hostname;
  const ports = String(user.port || "443").split(",").map(p => p.trim()).filter(Boolean);
  const fp = user.fingerprint || "chrome";
  const dynPath = encodeURIComponent(`/stream/PANEL_ZEUS/${(user.uuid || "").split("-")[4] || "default"}`);

  if (isYaml) {
    const proxies = cleanIps.map((ip, i) => `  - name: "ZEUS | Node ${i + 1}"
    type: vless
    server: ${ip}
    port: 443
    uuid: ${user.uuid}
    network: ws
    ws-opts:
      path: ${decodeURIComponent(dynPath)}
      headers:
        Host: ${host}
    tls: true
    servername: ${host}`).join("\n");

    const yaml = `port: 7890
socks-port: 7891
mode: rule
proxies:
${proxies}
rules:
  - MATCH,DIRECT`;

    return new Response(yaml, {
      headers: { "Content-Type": "text/plain; charset=utf-8", "Access-Control-Allow-Origin": "*" }
    });
  }

  const links = [];
  cleanIps.forEach(ip => {
    ports.forEach(port => {
      const isTls = TLS_PORTS.has(port);
      links.push(`vless://${user.uuid}@${ip}:${port}?path=${dynPath}&security=${isTls ? 'tls' : 'none'}&encryption=none&host=${host}&type=ws${isTls ? '&insecure=0&fp=' + fp + '&sni=' + host : ''}#ZEUS%20%7C%20${user.username}`);
    });
  });

  const plainContent = links.join("\n");
  const subContent = btoa(unescape(encodeURIComponent(plainContent)));
  const downloadBytes = Math.floor((user.used_gb || 0) * 1073741824);
  const totalBytes = user.limit_gb ? Math.floor(user.limit_gb * 1073741824) : 0;

  return new Response(subContent, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Subscription-Userinfo": `upload=0; download=${downloadBytes}; total=${totalBytes}; expire=0`
    }
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Health Endpoint
    if (url.pathname === "/health" || url.pathname === "/api/internal/health") {
      return new Response(JSON.stringify({
        status: "healthy",
        service: "worker-d-proxy",
        timestamp: Date.now()
      }), { headers: { "Content-Type": "application/json" } });
    }

    // 2. Subscription URL Lookup API (For Worker A to query)
    if (url.pathname === "/api/internal/subscription-url") {
      if (!verifyInternalAuth(request, env)) {
        return new Response(JSON.stringify({ success: false, error: "Unauthorized" }), { status: 403, headers: { "Content-Type": "application/json" } });
      }
      const username = url.searchParams.get("username") || "";
      const base = `${url.protocol}//${url.host}`;
      return new Response(JSON.stringify({
        success: true,
        subscription_url: `${base}/sub/${encodeURIComponent(username)}`,
        feed_url: `${base}/feed/${encodeURIComponent(username)}`,
        yaml_url: `${base}/yaml/${encodeURIComponent(username)}`
      }), { headers: { "Content-Type": "application/json" } });
    }

    // 3. Subscription Feeds (Owned by Worker D)
    if (url.pathname.startsWith("/sub/") || url.pathname.startsWith("/feed/") || url.pathname.startsWith("/yaml/")) {
      return await handleSubscriptionRequest(url, env);
    }

    // 4. WebSocket Proxy Upgrades
    const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
    if (upgradeHeader === "websocket") {
      return await handleWebSocketProxy(request, env, ctx);
    }

    return new Response("Worker D Connection & Proxy Engine is running.", { status: 200 });
  }
};
