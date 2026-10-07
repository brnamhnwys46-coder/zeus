/**
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
  if (!baseUrl) return { error: "DB_SERVICE_URL is not configured" };

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
  if (!baseUrl) return { error: "CACHE_SERVICE_URL is not configured" };

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

// Secret Route Gate Validation
function checkSecretRouteGate(url, request, env) {
  const secretGate = env.SECRET_ROUTE_GATE ? env.SECRET_ROUTE_GATE.trim() : "";
  if (!secretGate) return { passed: true, cleanPath: url.pathname };

  const queryGate = url.searchParams.get("gate");
  if (queryGate === secretGate) {
    return { passed: true, cleanPath: url.pathname, setGateCookie: true };
  }

  // Check path prefix e.g. /ggg/panel or /ggg
  const prefix = `/${secretGate}`;
  if (url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)) {
    const cleanPath = url.pathname.slice(prefix.length) || "/";
    return { passed: true, cleanPath, setGateCookie: true };
  }

  // Check gate session cookie
  const cookies = request.headers.get("Cookie") || "";
  if (cookies.includes(`panel_gate=${secretGate}`)) {
    return { passed: true, cleanPath: url.pathname };
  }

  // Allow public subscription feeds and user status paths without the secret admin gate
  if (
    url.pathname.startsWith("/sub/") ||
    url.pathname.startsWith("/feed/") ||
    url.pathname.startsWith("/yaml/") ||
    url.pathname.startsWith("/status/") ||
    url.pathname.startsWith("/stream/") ||
    url.pathname === "/icon.svg" ||
    url.pathname === "/favicon.ico" ||
    url.pathname === "/manifest.json" ||
    url.pathname === "/sw.js"
  ) {
    return { passed: true, cleanPath: url.pathname };
  }

  return { passed: false };
}

// Authentication Helpers
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
      const proxyBase = (env.PROXY_SERVICE_URL || "").replace(/\/+$/, "");
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
};

// --- SUB-HANDLERS ---

async function handleSubscriptionRoute(url, pathname, env) {
  const isYaml = pathname.startsWith("/yaml/");
  const offset = isYaml ? 6 : (pathname.startsWith("/sub/") ? 5 : 6);
  const username = decodeURIComponent(pathname.slice(offset));

  const dbRes = await callWorkerB(`/api/internal/user/${encodeURIComponent(username)}`, "GET", null, env);
  if (!dbRes || !dbRes.user) {
    return new Response("Subscription user not found", { status: 404 });
  }
  const user = dbRes.user;

  // Fetch clean IPs from Worker C
  const ipsRes = await callWorkerC(`/api/internal/cache/ips?operator=${user.ip_operator || 'all'}&count=${user.ip_count || 15}`, "GET", null, env);
  const cleanIps = ipsRes && ipsRes.ips && ipsRes.ips.length > 0 ? ipsRes.ips : [url.hostname];

  if (isYaml) {
    return generateYamlSubscription(user, cleanIps, url.hostname);
  }
  return generateTextSubscription(user, cleanIps, url.hostname);
}

function generateTextSubscription(user, cleanIps, host) {
  const ports = String(user.port || "443").split(",").map(p => p.trim()).filter(Boolean);
  const fp = user.fingerprint || "chrome";
  const dynPath = encodeURIComponent(`/stream/PANEL_ZEUS/${(user.uuid || "").split("-")[4] || "default"}`);
  const links = [];

  const connType = String(user.connection_type || "vless").toLowerCase();
  const enableVless = connType.includes("vless") || (!connType.includes("trojan") && !connType.includes("shadowsocks"));
  const enableTrojan = connType.includes("trojan");
  const enableSS = connType.includes("shadowsocks");

  cleanIps.forEach((ip) => {
    ports.forEach((portStr) => {
      const isTls = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
      const tlsVal = isTls ? "tls" : "none";
      const tlsParams = isTls ? `&insecure=0&fp=${fp}&sni=${host}` : "";

      if (enableVless) {
        links.push(`vless://${user.uuid}@${ip}:${portStr}?path=${dynPath}&security=${tlsVal}&encryption=none&host=${host}&type=ws${tlsParams}#ZEUS%20%7C%20${user.username}`);
      }
      if (enableTrojan) {
        links.push(`trojan://${user.uuid}@${ip}:${portStr}?path=${dynPath}&security=${tlsVal}&host=${host}&type=ws${tlsParams}#ZEUS%20Trojan%20%7C%20${user.username}`);
      }
      if (enableSS) {
        const methodPass = btoa(`aes-256-gcm:${user.uuid}`);
        const pluginStr = encodeURIComponent(`v2ray-plugin;mode=websocket;host=${host};path=${decodeURIComponent(dynPath)}${isTls ? ';tls' : ''}`);
        links.push(`ss://${methodPass}@${ip}:${portStr}/?plugin=${pluginStr}#ZEUS%20SS%20%7C%20${user.username}`);
      }
    });
  });

  const plainContent = "# ZEUS Distributed Subscription Feed\n" + links.join("\n");
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

function generateYamlSubscription(user, cleanIps, host) {
  const ports = String(user.port || "443").split(",").map(p => p.trim()).filter(Boolean);
  const dynPath = `/stream/PANEL_ZEUS/${(user.uuid || "").split("-")[4] || "default"}`;
  const proxies = [];

  cleanIps.forEach((ip, idx) => {
    ports.forEach((portStr) => {
      const isTls = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
      proxies.push(`  - name: "ZEUS | Node ${idx + 1} (${portStr})"
    type: vless
    server: ${ip}
    port: ${portStr}
    uuid: ${user.uuid}
    network: ws
    ws-opts:
      path: ${dynPath}
      headers:
        Host: ${host}
    tls: ${isTls}
    servername: ${host}`);
    });
  });

  const yaml = `port: 7890
socks-port: 7891
mode: rule
log-level: info
proxies:
${proxies.join("\n")}
proxy-groups:
  - name: "PROXIES"
    type: select
    proxies:
${proxies.map((_, i) => `      - "ZEUS | Node ${i + 1}"`).join("\n")}
rules:
  - MATCH,PROXIES`;

  return new Response(yaml, {
    headers: { "Content-Type": "text/plain; charset=utf-8", "Access-Control-Allow-Origin": "*" }
  });
}

async function handleStatusRoute(request, pathname, url, env) {
  const username = decodeURIComponent(pathname.slice("/status/".length));
  const dbRes = await callWorkerB(`/api/internal/user/${encodeURIComponent(username)}`, "GET", null, env);
  if (!dbRes || !dbRes.user) return new Response("User not found", { status: 404 });

  const html = STATUS_HTML_TEMPLATE.replace("/* {{USER_DATA_PLACEHOLDER}} */", `window.statusUser = ${JSON.stringify(dbRes.user)};`);
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handlePanelHtml(request, pathname, env, gateCheck) {
  const authRes = await callWorkerB("/api/internal/auth/has-password", "GET", null, env);
  const hasPassword = Boolean(authRes && authRes.hasPassword);

  if (!hasPassword) {
    return new Response(SETUP_HTML_TEMPLATE, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  const isAuthed = await verifySessionAuth(request, env);
  if (!isAuthed) {
    return new Response(LOGIN_HTML_TEMPLATE, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  const headers = new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store, no-cache, must-revalidate"
  });

  if (gateCheck.setGateCookie && env.SECRET_ROUTE_GATE) {
    headers.set("Set-Cookie", `panel_gate=${env.SECRET_ROUTE_GATE}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`);
  }

  return new Response(PANEL_HTML_TEMPLATE, { headers });
}

async function handleApiRoute(request, pathname, url, env, ctx) {
  // 1. Auth routes (Login, Setup, Logout)
  if (pathname === "/api/login" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const res = await callWorkerB("/api/internal/auth/verify-password", "POST", { password: body.password }, env);
    if (res && res.success) {
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": `panel_session=${res.hash}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000`
        }
      });
    }
    return new Response(JSON.stringify({ error: "رمز عبور اشتباه است" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }

  if (pathname === "/api/setup-password" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const res = await callWorkerB("/api/internal/auth/set-password", "POST", { password: body.password }, env);
    if (res && res.success) {
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": `panel_session=${res.hash}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000`
        }
      });
    }
    return new Response(JSON.stringify({ error: res.error || "خطا در تنظیم رمز" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }

  if (pathname === "/api/logout" && request.method === "POST") {
    return new Response(JSON.stringify({ success: true }), {
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax"
      }
    });
  }

  // Require login session for subsequent endpoints
  const isAuthed = await verifySessionAuth(request, env);
  if (!isAuthed && pathname !== "/api/test-proxy") {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }

  // 2. Multi-Worker Architecture Configuration & Diagnostics
  if (pathname === "/api/settings/endpoints") {
    if (request.method === "GET") {
      const dbSettings = await callWorkerB("/api/internal/settings", "GET", null, env);
      const s = (dbSettings && dbSettings.settings) || {};
      return new Response(JSON.stringify({
        db_service_url: s.db_service_url || env.DB_SERVICE_URL || "",
        cache_service_url: s.cache_service_url || env.CACHE_SERVICE_URL || "",
        proxy_service_url: s.proxy_service_url || env.PROXY_SERVICE_URL || "",
        secret_route_gate: s.secret_route_gate || env.SECRET_ROUTE_GATE || "",
        has_internal_token: Boolean(env.INTERNAL_AUTH_TOKEN)
      }), { headers: { "Content-Type": "application/json" } });
    }
    if (request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      await callWorkerB("/api/internal/settings", "POST", { settings: body.settings }, env);
      return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
    }
  }

  if (pathname === "/api/settings/test-endpoints" && request.method === "POST") {
    // Tests connection to Worker B, C, D
    const tests = {};
    const t0 = Date.now();
    try {
      const bRes = await callWorkerB("/health", "GET", null, env);
      tests.worker_b = { status: bRes.status === "healthy" ? "ok" : "err", ping: Date.now() - t0 };
    } catch (e) { tests.worker_b = { status: "fail", error: e.message }; }

    const t1 = Date.now();
    try {
      const cRes = await callWorkerC("/health", "GET", null, env);
      tests.worker_c = { status: cRes.status === "healthy" ? "ok" : "err", ping: Date.now() - t1 };
    } catch (e) { tests.worker_c = { status: "fail", error: e.message }; }

    const t2 = Date.now();
    try {
      const dUrl = (env.PROXY_SERVICE_URL || "").replace(/\/+$/, "");
      if (dUrl) {
        const dRes = await fetch(`${dUrl}/health`);
        tests.worker_d = { status: dRes.ok ? "ok" : "err", ping: Date.now() - t2 };
      } else {
        tests.worker_d = { status: "not_configured" };
      }
    } catch (e) { tests.worker_d = { status: "fail", error: e.message }; }

    return new Response(JSON.stringify({ success: true, tests }), { headers: { "Content-Type": "application/json" } });
  }

  // 3. Delegate User Operations to Worker B
  if (pathname.startsWith("/api/users")) {
    const relativePath = pathname.replace("/api/users", "/api/internal/users");
    const body = request.method !== "GET" ? await request.json().catch(() => ({})) : null;
    const res = await callWorkerB(relativePath, request.method, body, env);
    return new Response(JSON.stringify(res), { headers: { "Content-Type": "application/json" } });
  }

  // 4. Delegate Proxy Testing & Repo Files to Worker C
  if (pathname === "/api/test-proxy") {
    const body = await request.json().catch(() => ({}));
    const res = await callWorkerC("/api/internal/cache/test-proxy", "POST", body, env);
    return new Response(JSON.stringify(res), { headers: { "Content-Type": "application/json" } });
  }

  // 5. General Settings
  if (pathname === "/api/settings/bulk") {
    if (request.method === "GET") {
      const res = await callWorkerB("/api/internal/settings", "GET", null, env);
      return new Response(JSON.stringify((res && res.settings) || {}), { headers: { "Content-Type": "application/json" } });
    }
    const body = await request.json().catch(() => ({}));
    const res = await callWorkerB("/api/internal/settings", "POST", body, env);
    return new Response(JSON.stringify(res), { headers: { "Content-Type": "application/json" } });
  }

  return new Response(JSON.stringify({ error: "Endpoint not found" }), { status: 404, headers: { "Content-Type": "application/json" } });
}

// UI TEMPLATES & SVG ASSETS
const SVG_ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512"><rect width="512" height="512" rx="128" fill="#000"/><path d="M256 64L128 288h128l-32 160 160-224H256l32-160z" fill="#38bdf8"/></svg>`;

const SETUP_HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
  <meta charset="UTF-8"><title>تعریف رمز پنل زئوس</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-white min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-6 text-center">
    <h2 class="text-xl font-bold text-blue-400 mb-2">راه‌اندازی اولیه پنل</h2>
    <p class="text-xs text-slate-400 mb-6">رمز عبور مدیریت پنل را وارد کنید.</p>
    <form onsubmit="setup(event)" class="space-y-4">
      <input type="password" id="p1" placeholder="رمز عبور" class="w-full p-2.5 bg-slate-950 border border-slate-700 rounded-lg text-center" required minlength="4">
      <input type="password" id="p2" placeholder="تکرار رمز عبور" class="w-full p-2.5 bg-slate-950 border border-slate-700 rounded-lg text-center" required minlength="4">
      <button type="submit" class="w-full py-2.5 bg-blue-600 hover:bg-blue-500 rounded-lg font-bold">ثبت و ورود</button>
    </form>
  </div>
  <script>
    async function setup(e){
      e.preventDefault();
      const p1 = document.getElementById('p1').value;
      const p2 = document.getElementById('p2').value;
      if(p1 !== p2) return alert('رمزها مطابقت ندارند');
      const res = await fetch('/api/setup-password', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:p1})});
      if(res.ok) window.location.reload();
      else alert('خطا در ثبت');
    }
  </script>
</body>
</html>`;

const LOGIN_HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
  <meta charset="UTF-8"><title>ورود به پنل زئوس</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-white min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-6 text-center">
    <h2 class="text-xl font-bold text-blue-400 mb-4">⚡ ورود به پنل مدیریت</h2>
    <form onsubmit="login(event)" class="space-y-4">
      <input type="password" id="pwd" placeholder="رمز عبور" class="w-full p-2.5 bg-slate-950 border border-slate-700 rounded-lg text-center" required>
      <button type="submit" class="w-full py-2.5 bg-blue-600 hover:bg-blue-500 rounded-lg font-bold">ورود به پنل</button>
    </form>
  </div>
  <script>
    async function login(e){
      e.preventDefault();
      const pwd = document.getElementById('pwd').value;
      const res = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pwd})});
      if(res.ok) window.location.reload();
      else alert('رمز عبور اشتباه است');
    }
  </script>
</body>
</html>`;

const PANEL_HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
  <meta charset="UTF-8"><title>⚡ ZEUS Panel (Distributed Architecture)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" />
  <style>body{font-family:'Vazirmatn',sans-serif;}</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <header class="border-b border-slate-800 bg-slate-900/80 px-6 py-4 flex justify-between items-center backdrop-blur">
    <div class="flex items-center gap-3">
      <span class="text-2xl">⚡</span>
      <h1 class="font-bold text-lg">پنل توزیع‌شده زئوس (4-Worker Architecture)</h1>
    </div>
    <div class="flex items-center gap-3">
      <button onclick="toggleSettingsModal(true)" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs font-bold">⚙️ تنظیمات ورکرها</button>
      <button onclick="logout()" class="px-3 py-1.5 bg-red-900/30 hover:bg-red-900/50 text-red-400 border border-red-800 rounded-lg text-xs font-bold">خروج</button>
    </div>
  </header>

  <main class="max-w-6xl mx-auto p-6 space-y-6">
    <!-- Architecture Status Bar -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
        <div><div class="text-xs text-slate-400">Worker A</div><div class="font-bold text-blue-400">Gateway & UI</div></div>
        <span class="w-3 h-3 rounded-full bg-green-500 animate-pulse"></span>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
        <div><div class="text-xs text-slate-400">Worker B</div><div class="font-bold text-purple-400">D1 Database</div></div>
        <span id="stat-b" class="text-xs text-slate-400">چک وضعیت...</span>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
        <div><div class="text-xs text-slate-400">Worker C</div><div class="font-bold text-amber-400">KV & File Cache</div></div>
        <span id="stat-c" class="text-xs text-slate-400">چک وضعیت...</span>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
        <div><div class="text-xs text-slate-400">Worker D</div><div class="font-bold text-emerald-400">Proxy Engine</div></div>
        <span id="stat-d" class="text-xs text-slate-400">چک وضعیت...</span>
      </div>
    </div>

    <!-- Users Section -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6">
      <div class="flex justify-between items-center mb-6">
        <h2 class="text-lg font-bold">مدیریت کاربران</h2>
        <button onclick="createUserPrompt()" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-xl text-xs font-bold shadow-lg">+ ایجاد کاربر جدید</button>
      </div>
      <div id="users-list" class="space-y-3"><div class="text-center text-slate-500 py-8">در حال دریافت لیست کاربران از Worker B...</div></div>
    </div>
  </main>

  <!-- Multi-Worker Dynamic Settings Modal -->
  <div id="settings-modal" class="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4 hidden">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-4">
      <div class="flex justify-between items-center border-b border-slate-800 pb-3">
        <h3 class="font-bold text-sm text-blue-400">⚙️ تنظیمات داینامیک ورکرها و گیت مخفی</h3>
        <button onclick="toggleSettingsModal(false)" class="text-slate-400 hover:text-white">✕</button>
      </div>
      <div class="space-y-3 text-xs">
        <div>
          <label class="block text-slate-400 mb-1">Secret Route Gate (مسیر مخفی ورود)</label>
          <input type="text" id="cfg-gate" placeholder="مثال: ggg" class="w-full p-2 bg-slate-950 border border-slate-800 rounded font-mono">
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Worker B Endpoint (دیتابیس D1)</label>
          <input type="text" id="cfg-db" placeholder="https://worker-b-db.domain.workers.dev" class="w-full p-2 bg-slate-950 border border-slate-800 rounded font-mono" dir="ltr">
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Worker C Endpoint (کش فایل و مخزن)</label>
          <input type="text" id="cfg-cache" placeholder="https://worker-c-cache.domain.workers.dev" class="w-full p-2 bg-slate-950 border border-slate-800 rounded font-mono" dir="ltr">
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Worker D Endpoint (موتور پروکسی وب‌سوکت)</label>
          <input type="text" id="cfg-proxy" placeholder="https://worker-d-proxy.domain.workers.dev" class="w-full p-2 bg-slate-950 border border-slate-800 rounded font-mono" dir="ltr">
        </div>
        <div class="pt-2 flex gap-2">
          <button onclick="testEndpoints()" class="w-1/2 py-2 bg-slate-800 hover:bg-slate-700 rounded font-bold">تست اتصال ورکرها</button>
          <button onclick="saveEndpoints()" class="w-1/2 py-2 bg-green-600 hover:bg-green-500 rounded font-bold">ذخیره تنظیمات</button>
        </div>
      </div>
    </div>
  </div>

  <script>
    function toggleSettingsModal(show){ document.getElementById('settings-modal').classList.toggle('hidden', !show); }
    async function loadEndpoints(){
      const res = await fetch('/api/settings/endpoints');
      const data = await res.json();
      document.getElementById('cfg-gate').value = data.secret_route_gate || '';
      document.getElementById('cfg-db').value = data.db_service_url || '';
      document.getElementById('cfg-cache').value = data.cache_service_url || '';
      document.getElementById('cfg-proxy').value = data.proxy_service_url || '';
    }
    async function saveEndpoints(){
      const payload = {
        settings: {
          secret_route_gate: document.getElementById('cfg-gate').value,
          db_service_url: document.getElementById('cfg-db').value,
          cache_service_url: document.getElementById('cfg-cache').value,
          proxy_service_url: document.getElementById('cfg-proxy').value
        }
      };
      await fetch('/api/settings/endpoints', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
      alert('تنظیمات با موفقیت در دیتابیس Worker B ذخیره شد.');
      toggleSettingsModal(false);
      testEndpoints();
    }
    async function testEndpoints(){
      const res = await fetch('/api/settings/test-endpoints', {method:'POST'});
      const data = await res.json();
      if(data.tests){
        document.getElementById('stat-b').innerText = data.tests.worker_b?.status === 'ok' ? data.tests.worker_b.ping + 'ms ✅' : 'خطا ❌';
        document.getElementById('stat-c').innerText = data.tests.worker_c?.status === 'ok' ? data.tests.worker_c.ping + 'ms ✅' : 'خطا ❌';
        document.getElementById('stat-d').innerText = data.tests.worker_d?.status === 'ok' ? data.tests.worker_d.ping + 'ms ✅' : 'قطع ❌';
      }
    }
    async function loadUsers(){
      const res = await fetch('/api/users');
      const data = await res.json();
      const list = document.getElementById('users-list');
      if(!data.users || data.users.length === 0){
        list.innerHTML = '<div class="text-center text-slate-500 py-6">کاربری یافت نشد.</div>';
        return;
      }
      list.innerHTML = data.users.map(u => \`
        <div class="flex items-center justify-between p-3.5 bg-slate-950 border border-slate-800 rounded-xl">
          <div class="flex items-center gap-3">
            <span class="w-2.5 h-2.5 rounded-full \${u.is_active ? 'bg-green-500' : 'bg-red-500'}"></span>
            <span class="font-bold text-sm">\${u.username}</span>
            <span class="text-xs text-slate-500">\${(u.used_gb || 0).toFixed(2)} GB / \${u.limit_gb || '∞'} GB</span>
          </div>
          <div class="flex items-center gap-2">
            <button onclick="navigator.clipboard.writeText(window.location.origin + '/sub/' + '\${u.username}').then(()=>alert('لینک ساب کپی شد'))" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-xs rounded">کپی ساب</button>
            <button onclick="deleteUser('\${u.username}')" class="px-2.5 py-1 bg-red-950 text-red-400 hover:bg-red-900 text-xs rounded">حذف</button>
          </div>
        </div>
      \`).join('');
    }
    async function createUserPrompt(){
      const username = prompt('نام کاربری جدید:');
      if(!username) return;
      await fetch('/api/users', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ username, limit_gb: 50, expiry_days: 30 })
      });
      loadUsers();
    }
    async function deleteUser(u){
      if(!confirm('حذف کاربر ' + u + '؟')) return;
      await fetch('/api/users/' + encodeURIComponent(u), {method: 'DELETE'});
      loadUsers();
    }
    async function logout(){
      await fetch('/api/logout', {method: 'POST'});
      window.location.reload();
    }
    loadEndpoints();
    testEndpoints();
    loadUsers();
  </script>
</body>
</html>`;

const STATUS_HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
  <meta charset="UTF-8"><title>وضعیت اشتراک کاربر</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-white min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-6 text-center space-y-4">
    <h2 class="text-xl font-bold text-blue-400">وضعیت سرویس زئوس</h2>
    <div id="user-info" class="p-4 bg-slate-950 rounded-xl space-y-2 text-sm text-slate-300"></div>
    <div class="flex gap-2">
      <button onclick="copySub()" class="w-full py-2 bg-blue-600 rounded-lg text-xs font-bold">کپی لینک اتصال (Subscription)</button>
    </div>
  </div>
  <script>
    /* {{USER_DATA_PLACEHOLDER}} */
    if(window.statusUser){
      document.getElementById('user-info').innerHTML = \`
        <div>کاربر: <b>\${window.statusUser.username}</b></div>
        <div>وضعیت: <b>\${window.statusUser.is_active ? 'فعال ✅' : 'مسدود ❌'}</b></div>
        <div>حجم مصرفی: <b>\${(window.statusUser.used_gb || 0).toFixed(2)} GB / \${window.statusUser.limit_gb || 'نامحدود'}</b></div>
      \`;
    }
    function copySub(){
      const sub = window.location.origin + '/sub/' + encodeURIComponent(window.statusUser.username);
      navigator.clipboard.writeText(sub).then(()=>alert('لینک ساب با موفقیت کپی شد.'));
    }
  </script>
</body>
</html>`;
