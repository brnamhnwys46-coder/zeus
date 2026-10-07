/**
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
let cachedPanelPassword = null;

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
  // Allow if Service Binding call or matching secret token
  const expectedToken = env.INTERNAL_AUTH_TOKEN;
  if (!expectedToken) return true; // development fallback if not set

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

async function readJsonBody(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body : {};
  } catch (e) {
    return {};
  }
}

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

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
  let H = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
  ];
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
    for (let t = 0; t < 16; t++) {
      W[t] = view.getUint32(i + t * 4, false);
    }
    for (let t = 16; t < 64; t++) {
      W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const T1 = (h + sigma1(e) + choice(e, f, g) + K[t] + W[t]) >>> 0;
      const T2 = (sigma0(a) + majority(a, b, c)) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + T1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (T1 + T2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }
  return H.slice(0, 7).map(w => w.toString(16).padStart(8, '0')).join('');
}

async function ensureSchema(db) {
  if (schemaEnsured) return;
  if (schemaPromise) {
    await schemaPromise;
    return;
  }
  schemaPromise = (async () => {
    try {
      await db.prepare(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        uuid TEXT, 
        limit_gb REAL, 
        expiry_days INTEGER, 
        ips TEXT, 
        connection_type TEXT, 
        tls TEXT, 
        port INTEGER, 
        used_gb REAL DEFAULT 0, 
        is_active INTEGER DEFAULT 1, 
        last_active INTEGER, 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`).run();
    } catch (e) {}

    try {
      await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
    } catch (e) {}

    try {
      const { results } = await db.prepare("PRAGMA table_info(users)").all();
      const existingCols = new Set((results || []).map((r) => r.name));
      const colsToAdd = [
        { name: "advanced_frag", def: "TEXT DEFAULT NULL" },
        { name: "cipher_suites", def: "TEXT DEFAULT NULL" },
        { name: "tls_mask", def: "TEXT DEFAULT NULL" },
        { name: "is_active", def: "INTEGER DEFAULT 1" },
        { name: "last_active", def: "INTEGER" },
        { name: "fingerprint", def: "TEXT DEFAULT 'chrome'" },
        { name: "max_connections", def: "INTEGER" },
        { name: "limit_req", def: "INTEGER" },
        { name: "used_req", def: "INTEGER DEFAULT 0" },
        { name: "ip_limit", def: "INTEGER DEFAULT NULL" },
        { name: "active_ips", def: "TEXT DEFAULT NULL" },
        { name: "block_porn", def: "INTEGER DEFAULT 0" },
        { name: "block_ads", def: "INTEGER DEFAULT 0" },
        { name: "frag_len", def: "TEXT DEFAULT '200-3000'" },
        { name: "frag_int", def: "TEXT DEFAULT '1-2'" },
        { name: "lifetime_used_gb", def: "REAL DEFAULT 0" },
        { name: "user_proxy_ip", def: "TEXT DEFAULT NULL" },
        { name: "user_proxy_iata", def: "TEXT DEFAULT NULL" },
        { name: "user_socks5", def: "TEXT DEFAULT NULL" },
        { name: "auto_reset_vol_days", def: "INTEGER DEFAULT 0" },
        { name: "auto_reset_req_days", def: "INTEGER DEFAULT 0" },
        { name: "last_reset_vol_time", def: "INTEGER DEFAULT 0" },
        { name: "last_reset_req_time", def: "INTEGER DEFAULT 0" },
        { name: "auto_rotate_ip", def: "INTEGER DEFAULT 1" },
        { name: "rotate_time", def: "INTEGER DEFAULT 0" },
        { name: "ip_operator", def: "TEXT DEFAULT 'all'" },
        { name: "ip_count", def: "INTEGER DEFAULT 15" },
        { name: "last_rotate_time", def: "INTEGER DEFAULT 0" },
        { name: "auto_rotate_user_proxy", def: "INTEGER DEFAULT 0" },
        { name: "start_on_first_connect", def: "INTEGER DEFAULT 0" },
        { name: "first_connection_time", def: "INTEGER DEFAULT NULL" },
        { name: "trojan_hash", def: "TEXT DEFAULT NULL" },
        { name: "enable_direct", def: "INTEGER DEFAULT 1" },
      ];
      for (const col of colsToAdd) {
        if (!existingCols.has(col.name)) {
          try {
            await db.prepare(`ALTER TABLE users ADD COLUMN ${col.name} ${col.def}`).run();
          } catch (colErr) {}
        }
      }
    } catch (e) {}

    try {
      await db.prepare("UPDATE users SET ip_limit = max_connections WHERE ip_limit IS NULL AND max_connections IS NOT NULL").run();
      await db.prepare("UPDATE users SET lifetime_used_gb = used_gb WHERE lifetime_used_gb = 0 OR lifetime_used_gb IS NULL").run();
    } catch (e) {}
  })();
  await schemaPromise;
  schemaEnsured = true;
}

async function performAutoResets(db) {
  const now = Date.now();
  const todayUtc = Math.floor(now / 86400000) * 86400000;
  try {
    await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_auto_reset_check', ?)").bind(String(now)).run();
    await db.prepare(`UPDATE users SET used_gb = 0, is_active = 1, last_reset_vol_time = ? WHERE auto_reset_vol_days > 0 AND ? >= (last_reset_vol_time + (auto_reset_vol_days * 86400000))`).bind(todayUtc, todayUtc).run();
    await db.prepare(`UPDATE users SET used_req = 0, is_active = 1, last_reset_req_time = ? WHERE auto_reset_req_days > 0 AND ? >= (last_reset_req_time + (auto_reset_req_days * 86400000))`).bind(todayUtc, todayUtc).run();
    return { success: true, timestamp: now };
  } catch (e) {
    return { success: false, error: e.message };
  }
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

    // Health check endpoint (can be public or internal)
    const url = new URL(request.url);
    if (url.pathname === "/health" || url.pathname === "/api/internal/health") {
      return safeJson({ status: "healthy", service: "worker-b-db", timestamp: Date.now() });
    }

    // Authenticate internal caller
    if (!verifyInternalAuth(request, env)) {
      return safeJson({ error: "Unauthorized access to Database Service." }, 403);
    }

    await ensureSchema(env.DB);

    const path = url.pathname;

    try {
      // 1. GET ALL USERS
      if (path === "/api/internal/users" && request.method === "GET") {
        const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
        
        let deletedGb = 0;
        try {
          const delRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'deleted_users_gb'").first();
          if (delRow) deletedGb = parseFloat(delRow.value) || 0;
        } catch (e) {}

        return safeJson({
          users: results || [],
          serverTime: Date.now(),
          deletedGb
        });
      }

      // 2. CREATE NEW USER
      if (path === "/api/internal/users" && request.method === "POST") {
        const body = await readJsonBody(request);
        const {
          username, uuid, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint,
          ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads,
          frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata,
          user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days,
          auto_rotate_ip, rotate_time, ip_operator, ip_count, auto_rotate_user_proxy,
          start_on_first_connect, enable_direct, connection_type, protocols
        } = body;

        if (!username) return safeJson({ error: "Username is required" }, 400);

        const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
        if (existing) return safeJson({ error: "User already exists" }, 400);

        let finalUuid = uuid;
        if (!finalUuid) {
          const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(6)))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          finalUuid = `50414e45-4c5f-5a45-5553-${randomHex}`;
        }

        let finalConnType = "vless";
        if (protocols && Array.isArray(protocols) && protocols.length > 0) {
          finalConnType = protocols.join(",");
        } else if (connection_type) {
          finalConnType = connection_type;
        }

        const trojanHash = sha224Pure(finalUuid);
        const todayUtc = Math.floor(Date.now() / 86400000) * 86400000;
        const nowTime = Date.now();

        await env.DB.prepare(`INSERT INTO users (
          username, uuid, limit_gb, expiry_days, limit_req, ips, connection_type, tls, port, fingerprint,
          max_connections, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads,
          frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata, user_socks5,
          user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, last_reset_vol_time, last_reset_req_time,
          auto_rotate_ip, rotate_time, ip_operator, ip_count, last_rotate_time, auto_rotate_user_proxy,
          start_on_first_connect, first_connection_time, trojan_hash, enable_direct
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
          .bind(
            username, finalUuid, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null,
            limit_req ? parseInt(limit_req) : null, ips || null, finalConnType, tls, port, fingerprint || "chrome",
            ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, parseFloat(used_gb) || 0,
            parseInt(used_req) || 0, created_at || new Date().toISOString(), is_active !== undefined ? parseInt(is_active) : 1,
            block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000",
            frag_int !== undefined ? frag_int : "1-2", advanced_frag || null, cipher_suites || null,
            tls_mask || null, user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null,
            auto_reset_vol_days ? parseInt(auto_reset_vol_days) : 0, auto_reset_req_days ? parseInt(auto_reset_req_days) : 0,
            todayUtc, todayUtc, auto_rotate_ip || 0, rotate_time || 0, ip_operator || "all", ip_count || 20,
            nowTime, auto_rotate_user_proxy ? 1 : 0, start_on_first_connect ? 1 : 0, null, trojanHash,
            enable_direct !== undefined ? (enable_direct ? 1 : 0) : 1
          ).run();

        return safeJson({ success: true, uuid: finalUuid, username });
      }

      // 3. GET SINGLE USER BY USERNAME / UUID / TROJAN_HASH (High-Speed Lookup for Worker D & Subs)
      if (path.startsWith("/api/internal/user/") && request.method === "GET") {
        const lookupKey = decodeURIComponent(path.slice("/api/internal/user/".length));
        if (!lookupKey) return safeJson({ error: "Missing lookup key" }, 400);

        let user = await env.DB.prepare(
          "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ? OR trojan_hash = ?"
        ).bind(lookupKey, lookupKey, lookupKey).first();

        // Fallback search by UUID suffix or trojan hash compute
        if (!user && lookupKey.length === 56) {
          const { results } = await env.DB.prepare("SELECT * FROM users WHERE is_active = 1").all();
          if (results) {
            user = results.find(u => u.uuid && sha224Pure(u.uuid) === lookupKey);
            if (user) {
              ctx.waitUntil(env.DB.prepare("UPDATE users SET trojan_hash = ? WHERE id = ?").bind(lookupKey, user.id).run());
            }
          }
        } else if (!user && lookupKey.length === 12) {
          // UUID suffix match
          user = await env.DB.prepare("SELECT * FROM users WHERE uuid LIKE ? AND is_active = 1").bind("%" + lookupKey).first();
        }

        if (!user) return safeJson({ error: "User not found" }, 404);
        return safeJson({ user });
      }

      // 4. UPDATE USER
      if (path.startsWith("/api/internal/users/") && request.method === "PUT") {
        const targetUsername = decodeURIComponent(path.slice("/api/internal/users/".length));
        const body = await readJsonBody(request);

        if (body.toggle_only !== undefined) {
          await env.DB.prepare("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE username = ?")
            .bind(targetUsername).run();
          return safeJson({ success: true });
        }

        if (body.reset_action !== undefined) {
          if (body.reset_action === "volume") {
            await env.DB.prepare("UPDATE users SET used_gb = 0, is_active = 1 WHERE username = ?").bind(targetUsername).run();
          } else if (body.reset_action === "req") {
            await env.DB.prepare("UPDATE users SET used_req = 0, is_active = 1 WHERE username = ?").bind(targetUsername).run();
          } else if (body.reset_action === "time") {
            await env.DB.prepare("UPDATE users SET created_at = CURRENT_TIMESTAMP, first_connection_time = NULL, is_active = 1 WHERE username = ?").bind(targetUsername).run();
          }
          return safeJson({ success: true });
        }

        const {
          username: new_username, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint,
          ip_limit, block_porn, block_ads, frag_len, frag_int, advanced_frag, cipher_suites,
          tls_mask, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days,
          auto_reset_req_days, auto_rotate_ip, rotate_time, ip_operator, ip_count,
          auto_rotate_user_proxy, start_on_first_connect, enable_direct, connection_type, protocols
        } = body;

        let finalConnType = undefined;
        if (protocols && Array.isArray(protocols) && protocols.length > 0) {
          finalConnType = protocols.join(",");
        } else if (connection_type) {
          finalConnType = connection_type;
        }

        const existingUser = await env.DB.prepare("SELECT uuid FROM users WHERE username = ?").bind(targetUsername).first();
        const trojanHash = existingUser && existingUser.uuid ? sha224Pure(existingUser.uuid) : null;

        await env.DB.prepare(`UPDATE users SET 
          username = ?, limit_gb = ?, expiry_days = ?, limit_req = ?, ips = ?, tls = ?, port = ?, 
          fingerprint = ?, max_connections = ?, ip_limit = ?, block_porn = ?, block_ads = ?, 
          frag_len = ?, frag_int = ?, advanced_frag = ?, cipher_suites = ?, tls_mask = ?, 
          user_proxy_iata = ?, user_socks5 = ?, user_proxy_ip = ?, auto_reset_vol_days = ?, 
          auto_reset_req_days = ?, auto_rotate_ip = ?, rotate_time = ?, ip_operator = ?, 
          ip_count = ?, auto_rotate_user_proxy = ?, start_on_first_connect = ?, enable_direct = ?, 
          connection_type = CASE WHEN ? IS NOT NULL THEN ? ELSE connection_type END, 
          trojan_hash = COALESCE(trojan_hash, ?) 
          WHERE username = ?`)
          .bind(
            new_username || targetUsername, limit_gb ? parseFloat(limit_gb) : null,
            expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null,
            ips || null, tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null,
            ip_limit ? parseInt(ip_limit) : null, block_porn ? 1 : 0, block_ads ? 1 : 0,
            frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2",
            advanced_frag || null, cipher_suites || null, tls_mask || null, user_proxy_iata || null,
            user_socks5 || null, user_proxy_ip || null, auto_reset_vol_days ? parseInt(auto_reset_vol_days) : 0,
            auto_reset_req_days ? parseInt(auto_reset_req_days) : 0, auto_rotate_ip || 0, rotate_time || 0,
            ip_operator || "all", ip_count || 20, auto_rotate_user_proxy ? 1 : 0,
            start_on_first_connect ? 1 : 0, enable_direct !== undefined ? (enable_direct ? 1 : 0) : 1,
            finalConnType !== undefined ? finalConnType : null, finalConnType !== undefined ? finalConnType : null,
            trojanHash, targetUsername
          ).run();

        return safeJson({ success: true });
      }

      // 5. DELETE USER
      if (path.startsWith("/api/internal/users/") && request.method === "DELETE") {
        const targetUsername = decodeURIComponent(path.slice("/api/internal/users/".length));
        try {
          const userToDelete = await env.DB.prepare("SELECT lifetime_used_gb, used_gb FROM users WHERE username = ?").bind(targetUsername).first();
          if (userToDelete) {
            const gbToKeep = userToDelete.lifetime_used_gb || userToDelete.used_gb || 0;
            if (gbToKeep > 0) {
              await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('deleted_users_gb', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS REAL) + ?").bind(String(gbToKeep), String(gbToKeep)).run();
            }
          }
        } catch (e) {}

        await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(targetUsername).run();
        return safeJson({ success: true });
      }

      // 6. TRAFFIC FLUSH (Called by Worker A or Worker D)
      if (path === "/api/internal/traffic/flush" && request.method === "POST") {
        const body = await readJsonBody(request);
        const { updates } = body; // Array of { username, deltaGb, deltaReq, activeIps, timestamp }
        if (Array.isArray(updates)) {
          for (const item of updates) {
            const { username, deltaGb = 0, deltaReq = 0, activeIps, timestamp = Date.now() } = item;
            if (!username) continue;
            try {
              if (activeIps) {
                await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ?, last_active = ?, active_ips = ? WHERE username = ?")
                  .bind(deltaGb, deltaGb, deltaReq, timestamp, activeIps, username).run();
              } else {
                await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ?, last_active = ? WHERE username = ?")
                  .bind(deltaGb, deltaGb, deltaReq, timestamp, username).run();
              }
            } catch (err) {}
          }
        }
        return safeJson({ success: true });
      }

      // 7. RECORD FIRST CONNECTION TIME
      if (path === "/api/internal/traffic/first-connect" && request.method === "POST") {
        const { uuid, timestamp = Date.now() } = await readJsonBody(request);
        if (uuid) {
          await env.DB.prepare("UPDATE users SET first_connection_time = ? WHERE uuid = ? AND first_connection_time IS NULL")
            .bind(timestamp, uuid).run();
        }
        return safeJson({ success: true });
      }

      // 8. SETTINGS CRUD
      if (path === "/api/internal/settings" && request.method === "GET") {
        const { results } = await env.DB.prepare("SELECT * FROM settings").all();
        const settingsObj = {};
        if (results) {
          results.forEach((r) => {
            if (r.key !== "cf_token" && r.key !== "panel_password") settingsObj[r.key] = r.value;
          });
        }
        return safeJson({ settings: settingsObj });
      }

      if (path === "/api/internal/settings" && request.method === "POST") {
        const body = await readJsonBody(request);
        if (body.settings && typeof body.settings === "object") {
          for (const [k, v] of Object.entries(body.settings)) {
            await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(k, String(v)).run();
          }
        }
        return safeJson({ success: true });
      }

      // 9. AUTH VERIFICATION & PASSWORD MANAGEMENT
      if (path === "/api/internal/auth/has-password" && request.method === "GET") {
        const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
        return safeJson({ hasPassword: Boolean(row && row.value) });
      }

      if (path === "/api/internal/auth/verify-password" && request.method === "POST") {
        const { password } = await readJsonBody(request);
        const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
        if (!row || !row.value) return safeJson({ success: true, isSetup: false }); // No password set yet

        const hashed = await sha256(password || "");
        if (row.value === hashed) {
          return safeJson({ success: true, hash: hashed });
        }
        return safeJson({ success: false, error: "Invalid password" }, 401);
      }

      if (path === "/api/internal/auth/verify-session" && request.method === "POST") {
        const { sessionHash } = await readJsonBody(request);
        const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
        if (!row || !row.value) return safeJson({ valid: true }); // No password protection active
        return safeJson({ valid: row.value === sessionHash });
      }

      if (path === "/api/internal/auth/set-password" && request.method === "POST") {
        const { password } = await readJsonBody(request);
        if (!password || password.length < 4) {
          return safeJson({ error: "Password must be at least 4 characters" }, 400);
        }
        const hashed = await sha256(password);
        await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(hashed).run();
        return safeJson({ success: true, hash: hashed });
      }

      if (path === "/api/internal/auth/remove-password" && request.method === "POST") {
        await env.DB.prepare("DELETE FROM settings WHERE key = 'panel_password'").run();
        return safeJson({ success: true });
      }

      // 10. MANUAL TRIGGER FOR AUTO-RESET
      if (path === "/api/internal/maintenance/auto-reset" && request.method === "POST") {
        const res = await performAutoResets(env.DB);
        return safeJson(res);
      }

      return safeJson({ error: "Not Found in Database Service" }, 404);
    } catch (err) {
      let msg = err.message || "";
      if (msg.toLowerCase().includes("d1") && (msg.toLowerCase().includes("limit") || msg.toLowerCase().includes("exceeded"))) {
        return safeJson({ error: "D1 Database daily quota exceeded" }, 503);
      }
      return safeJson({ error: "Database Service error: " + msg }, 500);
    }
  }
};
