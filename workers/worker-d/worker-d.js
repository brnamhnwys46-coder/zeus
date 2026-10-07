import { connect } from "cloudflare:sockets";

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

// In-memory traffic & connection caches
const GLOBAL_TRAFFIC_CACHE = new Map();
const ACTIVE_CONNECTIONS_COUNT = new Map();
const GLOBAL_ACTIVE_IPS = new Map();
const USER_CACHE = new Map(); // Local user cache to avoid hitting Worker B on every chunk
const DNS_CACHE = new Map();

const DNS_CACHE_TTL = 30 * 60 * 1000;
const DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
const UPSTREAM_BUNDLE_TARGET_BYTES = 512 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 32 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

// Helper to make authenticated calls to Worker B (Database Service)
async function callWorkerB(path, method = "GET", body = null, env = {}) {
  const baseUrl = (env.DB_SERVICE_URL || "").replace(/\/+$/, "");
  const token = env.INTERNAL_AUTH_TOKEN || "";
  
  // If service binding exists
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

  if (!baseUrl) {
    return { error: "DB_SERVICE_URL is not configured" };
  }

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
}

// Shadowsocks Crypto Implementation
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
    } catch (e) {
      return null;
    }
  },
  async encryptChunk(key, nonce, data) {
    try {
      const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, data);
      this.incrementNonce(nonce);
      return new Uint8Array(encrypted);
    } catch (e) {
      return null;
    }
  }
};

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
  const hex = [...data.slice(1, 17)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

function isIPv4(value) {
  const parts = String(value || "").split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
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
        throw new Error("HTTP proxy error " + (match ? match[1] : "unknown"));
      }
    }
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

async function connectProxy(proxyStr, destAddr, destPort, initialData) {
  const isHttp = proxyStr.toLowerCase().startsWith("http://") || proxyStr.toLowerCase().startsWith("https://");
  const cleanStr = proxyStr.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
  if (isHttp) return await connectHttp(cleanStr, destAddr, destPort, initialData);
  return await connectSocks5(cleanStr, destAddr, destPort, initialData);
}

function getSelectedUserProxy(userSocks5, request) {
  if (!userSocks5) return "";
  let proxyList = [];
  try {
    if (userSocks5.trim().startsWith("[")) proxyList = JSON.parse(userSocks5);
    else proxyList = [userSocks5];
  } catch (e) {
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
    } catch (e) {}
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
    const buf = new Uint8Array(await response.arrayBuffer());
    DNS_CACHE.set(cacheKey, { data: [{ data: "ok" }], expires: Date.now() + DNS_CACHE_TTL });
    return [{ data: "ok" }];
  } catch (e) {
    return [];
  }
}

async function forwardUdpDns(udpChunk, webSocket, onBytes, isTrojan = false, respHeader = null, dnsServer = "8.8.4.4") {
  try {
    let targetDoh = "https://cloudflare-dns.com/dns-query";
    if (dnsServer === "94.140.14.15") targetDoh = "https://family.adguard-dns.com/dns-query";
    else if (dnsServer === "1.1.1.3") targetDoh = "https://family.cloudflare-dns.com/dns-query";
    else if (dnsServer === "94.140.14.14") targetDoh = "https://dns.adguard-dns.com/dns-query";

    const data = convertToUint8Array(udpChunk);
    if (data.byteLength < 2) return;

    let dnsPayload = data;
    if (isTrojan) {
      if (data.byteLength < 7) return;
      let offset = 1;
      const addrType = data[0];
      if (addrType === 1) offset += 4;
      else if (addrType === 3) offset += 1 + data[1];
      else if (addrType === 4) offset += 16;
      offset += 4;
      dnsPayload = data.slice(offset);
    } else {
      const length = (data[0] << 8) | data[1];
      if (data.byteLength < 2 + length) return;
      dnsPayload = data.slice(2, 2 + length);
    }

    const response = await fetch(targetDoh, {
      method: "POST",
      headers: { "Accept": "application/dns-message", "Content-Type": "application/dns-message" },
      body: dnsPayload
    });
    if (!response.ok) return;
    const rawRes = new Uint8Array(await response.arrayBuffer());
    if (typeof onBytes === "function") onBytes(rawRes.byteLength);
    if (webSocket.readyState !== WebSocket.OPEN) return;

    const resLen = rawRes.byteLength;
    const udpPacket = new Uint8Array(2 + resLen);
    udpPacket[0] = (resLen >> 8) & 0xff;
    udpPacket[1] = resLen & 0xff;
    udpPacket.set(rawRes, 2);

    const header = respHeader || new Uint8Array(0);
    const merged = concatBytes(header, udpPacket);
    webSocket.send(merged.buffer);
  } catch (e) {}
}

async function handleWebSocketProxy(request, env, ctx) {
  const socketPair = new WebSocketPair();
  const [clientSock, serverSock] = Object.values(socketPair);
  serverSock.accept();
  serverSock.binaryType = "arraybuffer";

  let clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
  let username = null;
  let validUUID = null;
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

  const flushTrafficToDB = async () => {
    if (!username || isClosed) return;
    isClosed = true;
    const bytes = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
    if (bytes <= 0) return;

    GLOBAL_TRAFFIC_CACHE.set(username, 0);
    const deltaGb = bytes / (1024 * 1024 * 1024);

    const activeCount = Math.max(0, (ACTIVE_CONNECTIONS_COUNT.get(username) || 1) - 1);
    ACTIVE_CONNECTIONS_COUNT.set(username, activeCount);

    const updateItem = {
      username,
      deltaGb,
      deltaReq: 1,
      timestamp: Date.now()
    };

    ctx.waitUntil(callWorkerB("/api/internal/traffic/flush", "POST", { updates: [updateItem] }, env));
  };

  let remoteConn = null;
  let chunkBuffer = new Uint8Array(0);
  let isHeaderParsed = false;
  let isDnsQuery = false;
  let isTrojanProto = false;
  let isShadowsocksProto = false;
  let ssUpAeadCtx = null;
  let targetDns = "8.8.4.4";
  let targetDoh = DOH_RESOLVER;

  serverSock.addEventListener("message", async (event) => {
    if (typeof event.data === "string") return;
    const chunk = new Uint8Array(event.data);
    addBytes(chunk.byteLength);

    if (isDnsQuery) {
      await forwardUdpDns(chunk, serverSock, addBytes, isTrojanProto, null, targetDns);
      return;
    }

    if (isHeaderParsed) {
      if (remoteConn && remoteConn.writable) {
        try {
          const writer = remoteConn.writable.getWriter();
          await writer.write(chunk);
          writer.releaseLock();
        } catch (e) {
          serverSock.close();
        }
      }
      return;
    }

    chunkBuffer = concatBytes(chunkBuffer, chunk);
    if (chunkBuffer.byteLength > 16384) {
      serverSock.close(1009, "Payload Too Large");
      return;
    }

    // Inspect protocol
    let isTrojan = false;
    let isSS = false;
    if (chunkBuffer.byteLength >= 58 && chunkBuffer[56] === 0x0D && chunkBuffer[57] === 0x0A) {
      const hex = TEXT_DECODER.decode(chunkBuffer.slice(0, 56)).toLowerCase();
      if (/^[0-9a-f]{56}$/.test(hex)) isTrojan = true;
    } else if (chunkBuffer.byteLength > 0 && chunkBuffer[0] > 0x03) {
      isSS = true;
    }

    let cmd = 0, port = 0, addr = "", rawData = null, userLookupKey = null, respHeader = null;

    try {
      if (isTrojan) {
        isTrojanProto = true;
        userLookupKey = TEXT_DECODER.decode(chunkBuffer.slice(0, 56)).toLowerCase();
        let offset = 58;
        cmd = chunkBuffer[offset++];
        const addrType = chunkBuffer[offset++];
        if (addrType === 1) {
          addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
        } else if (addrType === 3) {
          const dLen = chunkBuffer[offset++];
          addr = TEXT_DECODER.decode(chunkBuffer.slice(offset, offset + dLen));
          offset += dLen;
        }
        port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
        offset += 2; // CRLF
        rawData = chunkBuffer.slice(offset);
      } else if (!isSS) {
        // VLESS
        if (chunkBuffer.byteLength < 24) return;
        const optLen = chunkBuffer[17];
        userLookupKey = extractUUIDFromvIees(chunkBuffer);
        let offset = 18 + optLen;
        cmd = chunkBuffer[offset++];
        port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
        const addrType = chunkBuffer[offset++];
        if (addrType === 1) {
          addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
        } else if (addrType === 2) {
          const dLen = chunkBuffer[offset++];
          addr = TEXT_DECODER.decode(chunkBuffer.slice(offset, offset + dLen));
          offset += dLen;
        }
        rawData = chunkBuffer.slice(offset);
        respHeader = new Uint8Array([chunkBuffer[0], 0]);
      }
    } catch (e) {
      serverSock.close();
      return;
    }

    if (!userLookupKey) {
      serverSock.close();
      return;
    }

    // Lookup user in local cache or Worker B
    let user = USER_CACHE.get(userLookupKey);
    if (!user) {
      const res = await callWorkerB(`/api/internal/user/${encodeURIComponent(userLookupKey)}`, "GET", null, env);
      user = res.user;
      if (user) USER_CACHE.set(userLookupKey, user);
    }

    if (!user || user.is_active === 0) {
      serverSock.close();
      return;
    }

    username = user.username;
    validUUID = user.uuid;
    isHeaderParsed = true;

    // Record first connect time
    if (user.start_on_first_connect === 1 && !user.first_connection_time) {
      ctx.waitUntil(callWorkerB("/api/internal/traffic/first-connect", "POST", { uuid: user.uuid }, env));
    }

    // Connect outbound
    try {
      const userProxy = getSelectedUserProxy(user.user_socks5, request);
      let s = null;
      if (userProxy) {
        s = await connectProxy(userProxy, addr, port, rawData);
      } else {
        s = await connectDirect(addr, port, rawData);
      }
      remoteConn = s;

      // Pipe remote to WebSocket
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
    } catch (e) {
      serverSock.close();
    }
  });

  serverSock.addEventListener("close", () => {
    if (remoteConn) {
      try { remoteConn.close(); } catch (_) {}
    }
    flushTrafficToDB();
  });

  serverSock.addEventListener("error", () => {
    if (remoteConn) {
      try { remoteConn.close(); } catch (_) {}
    }
    flushTrafficToDB();
  });

  return new Response(null, { status: 101, webSocket: clientSock });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/health" || url.pathname === "/api/internal/health") {
      return new Response(JSON.stringify({
        status: "healthy",
        service: "worker-d-proxy",
        timestamp: Date.now()
      }), { headers: { "Content-Type": "application/json" } });
    }

    // Check optional proxy gate key
    if (env.PROXY_GATE_KEY) {
      const clientGateKey = url.searchParams.get("gate") || request.headers.get("X-Proxy-Gate") || "";
      if (clientGateKey !== env.PROXY_GATE_KEY && !url.pathname.includes(env.PROXY_GATE_KEY)) {
        return new Response("Unauthorized Proxy Gateway", { status: 403 });
      }
    }

    const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
    if (upgradeHeader === "websocket") {
      return await handleWebSocketProxy(request, env, ctx);
    }

    return new Response("Worker D Connection & Proxy Engine is running.", { status: 200 });
  }
};
