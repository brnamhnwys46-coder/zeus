/**
 * WORKER A: Management Panel & Administration Layer (ZEUS)
 * 
 * Strict Role: Administration & Display ONLY.
 * - Login, initial setup, session management (cryptographically random session tokens).
 * - Admin dashboard, user management UI, worker health/diagnostics display.
 * - Dynamic configuration UI for Worker B, C, D endpoints and Secret Route Gate.
 * - Subscription URL display & copy (subscriptions generated and served by Worker D).
 * - User status inspection page.
 * 
 * Strict Boundaries:
 * - NO VLESS / Trojan / Shadowsocks protocol parsing.
 * - NO WebSocket proxying or raw connection forwarding.
 * - NO TCP socket dialing (connect()).
 * - NO direct D1 access (delegated to Worker B).
 * - NO direct GitHub / external repo fetches (delegated to Worker C).
 * - NO exposure of INTERNAL_AUTH_TOKEN to browser JavaScript or JSON responses.
 */

function safeJson(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function normalizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return "";
  const trimmed = rawUrl.trim();
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return "";
    return `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/+$/, "")}`;
  } catch (_) {
    return "";
  }
}

// Authoritative configuration loader: Reads bootstrap env, then overrides with Worker B settings
async function getEffectiveConfig(env) {
  let dbUrl = normalizeUrl(env.DB_SERVICE_URL);
  let cacheUrl = normalizeUrl(env.CACHE_SERVICE_URL);
  let proxyUrl = normalizeUrl(env.PROXY_SERVICE_URL);
  let secretGate = (env.SECRET_ROUTE_GATE || "").trim();

  // Try to load dynamic overrides from Worker B if accessible
  try {
    const res = await callWorkerB("/api/internal/settings", "GET", null, env, dbUrl);
    if (res && res.success && res.settings) {
      if (res.settings.db_service_url) dbUrl = normalizeUrl(res.settings.db_service_url) || dbUrl;
      if (res.settings.cache_service_url) cacheUrl = normalizeUrl(res.settings.cache_service_url) || cacheUrl;
      if (res.settings.proxy_service_url) proxyUrl = normalizeUrl(res.settings.proxy_service_url) || proxyUrl;
      if (res.settings.secret_route_gate !== undefined) secretGate = res.settings.secret_route_gate.trim();
    }
  } catch (_) {}

  return { dbUrl, cacheUrl, proxyUrl, secretGate };
}

// Inter-Worker RPC Clients
async function callWorkerB(path, method = "GET", body = null, env = {}, overrideUrl = null) {
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

  const baseUrl = overrideUrl || normalizeUrl(env.DB_SERVICE_URL);
  if (!baseUrl) return { success: false, error: "Database service URL is not configured." };

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
    return { success: false, error: "Worker B unreachable: " + err.message };
  }
}

async function callWorkerC(path, method = "GET", body = null, env = {}, overrideUrl = null) {
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

  const baseUrl = overrideUrl || normalizeUrl(env.CACHE_SERVICE_URL);
  if (!baseUrl) return { success: false, error: "Cache service URL is not configured." };

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
    return { success: false, error: "Worker C unreachable: " + err.message };
  }
}

async function callWorkerD(path, method = "GET", body = null, env = {}, overrideUrl = null) {
  const token = env.INTERNAL_AUTH_TOKEN || "";
  if (env.PROXY_SERVICE && typeof env.PROXY_SERVICE.fetch === "function") {
    const req = new Request(`https://internal-proxy${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
        "X-Internal-Token": token
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const res = await env.PROXY_SERVICE.fetch(req);
    return await res.json().catch(() => ({}));
  }

  const baseUrl = overrideUrl || normalizeUrl(env.PROXY_SERVICE_URL);
  if (!baseUrl) return { success: false, error: "Connection/Proxy service URL is not configured." };

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
    return { success: false, error: "Worker D unreachable: " + err.message };
  }
}

// Secret Route Gate Validation
function checkSecretRouteGate(url, request, secretGate) {
  if (!secretGate) return { passed: true, cleanPath: url.pathname };

  const queryGate = url.searchParams.get("gate");
  if (queryGate === secretGate) {
    return { passed: true, cleanPath: url.pathname, setGateCookie: true };
  }

  const prefix = `/${secretGate}`;
  if (url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)) {
    const cleanPath = url.pathname.slice(prefix.length) || "/";
    return { passed: true, cleanPath, setGateCookie: true };
  }

  const cookies = request.headers.get("Cookie") || "";
  if (cookies.includes(`panel_gate=${secretGate}`)) {
    return { passed: true, cleanPath: url.pathname };
  }

  // Public asset and user status paths
  if (
    url.pathname.startsWith("/status/") ||
    url.pathname === "/icon.svg" ||
    url.pathname === "/favicon.ico"
  ) {
    return { passed: true, cleanPath: url.pathname };
  }

  return { passed: false };
}

// Session Validation using Cryptographically Random Tokens (delegated to Worker B)
async function verifySessionAuth(request, env) {
  const cookies = request.headers.get("Cookie") || "";
  const match = cookies.split(";").find(c => c.trim().startsWith("panel_session="));
  if (!match) return false;
  const sessionToken = match.split("=")[1].trim();

  const res = await callWorkerB("/api/internal/auth/verify-session", "POST", { sessionToken }, env);
  return Boolean(res && res.valid);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Health Endpoint
    if (url.pathname === "/health" || url.pathname === "/api/internal/health") {
      return safeJson({
        status: "healthy",
        service: "worker-a-panel",
        timestamp: Date.now()
      });
    }

    // Load effective configuration
    const config = await getEffectiveConfig(env);

    // 2. Secret Route Gate
    const gateCheck = checkSecretRouteGate(url, request, config.secretGate);
    if (!gateCheck.passed) {
      return new Response("Nothing to see here", {
        status: 404,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }

    const currentPath = gateCheck.cleanPath;

    // 3. Static Assets
    if (currentPath === "/icon.svg" || currentPath === "/favicon.ico") {
      return new Response(SVG_ICON, {
        headers: { "Content-Type": "image/svg+xml; charset=utf-8", "Cache-Control": "public, max-age=604800" }
      });
    }

    // 4. User Status Display (/status/:username)
    if (currentPath.startsWith("/status/")) {
      return await handleStatusRoute(currentPath, config, env);
    }

    // 5. Admin API Routes
    if (currentPath.startsWith("/api/")) {
      return await handleAdminApi(request, currentPath, config, env, ctx);
    }

    // 6. Panel / Login / Setup HTML Views
    if (currentPath === "/panel" || currentPath === "/login" || currentPath === "/setup" || currentPath === "/") {
      return await handlePanelHtml(request, currentPath, config, env, gateCheck);
    }

    return new Response("Not Found", { status: 404 });
  }
};

// --- HANDLERS ---

async function handleStatusRoute(pathname, config, env) {
  const username = decodeURIComponent(pathname.slice("/status/".length));
  const userRes = await callWorkerB(`/api/internal/user/${encodeURIComponent(username)}`, "GET", null, env);
  if (!userRes || !userRes.user) {
    return new Response("کاربر یافت نشد", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } });
  }

  // Get subscription URL from Worker D
  const proxyBase = config.proxyUrl || "https://worker-d.example.com";
  const subscriptionUrl = `${proxyBase}/sub/${encodeURIComponent(username)}`;

  const html = STATUS_HTML_TEMPLATE
    .replace("/* {{USER_DATA_PLACEHOLDER}} */", `window.statusUser = ${JSON.stringify(userRes.user)}; window.subscriptionUrl = "${subscriptionUrl}";`);

  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handlePanelHtml(request, pathname, config, env, gateCheck) {
  const hasPwdRes = await callWorkerB("/api/internal/auth/has-password", "GET", null, env);
  const hasPassword = Boolean(hasPwdRes && hasPwdRes.hasPassword);

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

  if (gateCheck.setGateCookie && config.secretGate) {
    headers.set("Set-Cookie", `panel_gate=${config.secretGate}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`);
  }

  return new Response(PANEL_HTML_TEMPLATE, { headers });
}

async function handleAdminApi(request, pathname, config, env, ctx) {
  // Setup password endpoint
  if (pathname === "/api/setup-password" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const res = await callWorkerB("/api/internal/auth/set-password", "POST", { password: body.password }, env);
    if (res && res.success && res.sessionToken) {
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": `panel_session=${res.sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
        }
      });
    }
    return safeJson({ success: false, error: res.error || "خطا در تنظیم رمز" }, 400);
  }

  // Login endpoint
  if (pathname === "/api/login" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const res = await callWorkerB("/api/internal/auth/verify-password", "POST", { password: body.password }, env);
    if (res && res.success && res.sessionToken) {
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": `panel_session=${res.sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
        }
      });
    }
    return safeJson({ success: false, error: res.error || "رمز عبور اشتباه است." }, 401);
  }

  // Logout endpoint
  if (pathname === "/api/logout" && request.method === "POST") {
    const cookies = request.headers.get("Cookie") || "";
    const match = cookies.split(";").find(c => c.trim().startsWith("panel_session="));
    if (match) {
      const sessionToken = match.split("=")[1].trim();
      ctx.waitUntil(callWorkerB("/api/internal/auth/destroy-session", "POST", { sessionToken }, env));
    }
    return new Response(JSON.stringify({ success: true }), {
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax"
      }
    });
  }

  // Authenticate session for all subsequent admin endpoints
  const isAuthed = await verifySessionAuth(request, env);
  if (!isAuthed) {
    return safeJson({ success: false, error: "Unauthorized session." }, 401);
  }

  // 1. Dynamic Endpoints & Diagnostics
  if (pathname === "/api/settings/endpoints") {
    if (request.method === "GET") {
      return safeJson({
        success: true,
        db_service_url: config.dbUrl,
        cache_service_url: config.cacheUrl,
        proxy_service_url: config.proxyUrl,
        secret_route_gate: config.secretGate
      });
    }
    if (request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const newSettings = {};
      if (body.db_service_url !== undefined) newSettings.db_service_url = normalizeUrl(body.db_service_url);
      if (body.cache_service_url !== undefined) newSettings.cache_service_url = normalizeUrl(body.cache_service_url);
      if (body.proxy_service_url !== undefined) newSettings.proxy_service_url = normalizeUrl(body.proxy_service_url);
      if (body.secret_route_gate !== undefined) newSettings.secret_route_gate = String(body.secret_route_gate).trim();

      const saveRes = await callWorkerB("/api/internal/settings", "POST", { settings: newSettings }, env);
      return safeJson(saveRes);
    }
  }

  // Authenticated Diagnostics & Latency Test
  if (pathname === "/api/settings/test-endpoints" && request.method === "POST") {
    const tests = {};

    // Worker B test (authenticated)
    const t0 = Date.now();
    const bRes = await callWorkerB("/health", "GET", null, env);
    tests.worker_b = {
      status: bRes.status === "healthy" ? "healthy" : "error",
      ping: Date.now() - t0,
      service: bRes.service || "worker-b-db"
    };

    // Worker C test (authenticated)
    const t1 = Date.now();
    const cRes = await callWorkerC("/health", "GET", null, env);
    tests.worker_c = {
      status: cRes.status === "healthy" ? "healthy" : "error",
      ping: Date.now() - t1,
      service: cRes.service || "worker-c-cache"
    };

    // Worker D test (authenticated)
    const t2 = Date.now();
    const dRes = await callWorkerD("/health", "GET", null, env);
    tests.worker_d = {
      status: dRes.status === "healthy" ? "healthy" : "error",
      ping: Date.now() - t2,
      service: dRes.service || "worker-d-proxy"
    };

    return safeJson({ success: true, tests });
  }

  // 2. User Operations (Delegated to Worker B)
  if (pathname.startsWith("/api/users")) {
    const subPath = pathname.replace("/api/users", "/api/internal/users");
    const body = request.method !== "GET" ? await request.json().catch(() => ({})) : null;
    const res = await callWorkerB(subPath, request.method, body, env);

    // If listing users, enrich with Worker D subscription URL
    if (request.method === "GET" && res.users) {
      const proxyBase = config.proxyUrl || "https://worker-d.example.com";
      res.users = res.users.map(u => ({
        ...u,
        subscription_url: `${proxyBase}/sub/${encodeURIComponent(u.username)}`,
        yaml_url: `${proxyBase}/yaml/${encodeURIComponent(u.username)}`
      }));
    }

    return safeJson(res);
  }

  // 3. Proxy Testing (Delegated to Worker C)
  if (pathname === "/api/test-proxy" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const res = await callWorkerC("/api/internal/cache/test-proxy", "POST", body, env);
    return safeJson(res);
  }

  // 4. General Settings (Delegated to Worker B)
  if (pathname === "/api/settings/bulk") {
    if (request.method === "GET") {
      const res = await callWorkerB("/api/internal/settings", "GET", null, env);
      return safeJson(res.settings || {});
    }
    const body = await request.json().catch(() => ({}));
    const res = await callWorkerB("/api/internal/settings", "POST", body, env);
    return safeJson(res);
  }

  return safeJson({ success: false, error: "Endpoint not found in Panel API." }, 404);
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
    <h2 class="text-xl font-bold text-blue-400 mb-4">⚡ ورود به پنل مدیریت (Worker A)</h2>
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
  <meta charset="UTF-8"><title>⚡ ZEUS Panel (Distributed 4-Worker)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" />
  <style>body{font-family:'Vazirmatn',sans-serif;}</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <header class="border-b border-slate-800 bg-slate-900/80 px-6 py-4 flex justify-between items-center backdrop-blur">
    <div class="flex items-center gap-3">
      <span class="text-2xl">⚡</span>
      <h1 class="font-bold text-lg">پنل مدیریت زئوس (Worker A: Management Layer)</h1>
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
        <div><div class="text-xs text-slate-400">Worker A</div><div class="font-bold text-blue-400">Management Panel</div></div>
        <span class="w-3 h-3 rounded-full bg-green-500 animate-pulse"></span>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
        <div><div class="text-xs text-slate-400">Worker B</div><div class="font-bold text-purple-400">D1 Database</div></div>
        <span id="stat-b" class="text-xs text-slate-400">بررسی وضعیت...</span>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
        <div><div class="text-xs text-slate-400">Worker C</div><div class="font-bold text-amber-400">KV & File Cache</div></div>
        <span id="stat-c" class="text-xs text-slate-400">بررسی وضعیت...</span>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
        <div><div class="text-xs text-slate-400">Worker D</div><div class="font-bold text-emerald-400">Connection Engine</div></div>
        <span id="stat-d" class="text-xs text-slate-400">بررسی وضعیت...</span>
      </div>
    </div>

    <!-- Users Section -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6">
      <div class="flex justify-between items-center mb-6">
        <h2 class="text-lg font-bold">مدیریت کاربران</h2>
        <button onclick="createUserPrompt()" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-xl text-xs font-bold shadow-lg">+ ایجاد کاربر جدید</button>
      </div>
      <div id="users-list" class="space-y-3"><div class="text-center text-slate-500 py-8">در حال دریافت کاربران از Worker B...</div></div>
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
          <label class="block text-slate-400 mb-1">Worker D Endpoint (موتور پروکسی و ساب)</label>
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
        secret_route_gate: document.getElementById('cfg-gate').value,
        db_service_url: document.getElementById('cfg-db').value,
        cache_service_url: document.getElementById('cfg-cache').value,
        proxy_service_url: document.getElementById('cfg-proxy').value
      };
      await fetch('/api/settings/endpoints', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
      alert('تنظیمات با موفقیت ذخیره شد.');
      toggleSettingsModal(false);
      testEndpoints();
    }
    async function testEndpoints(){
      const res = await fetch('/api/settings/test-endpoints', {method:'POST'});
      const data = await res.json();
      if(data.tests){
        document.getElementById('stat-b').innerText = data.tests.worker_b?.status === 'healthy' ? data.tests.worker_b.ping + 'ms ✅' : 'خطا ❌';
        document.getElementById('stat-c').innerText = data.tests.worker_c?.status === 'healthy' ? data.tests.worker_c.ping + 'ms ✅' : 'خطا ❌';
        document.getElementById('stat-d').innerText = data.tests.worker_d?.status === 'healthy' ? data.tests.worker_d.ping + 'ms ✅' : 'خطا ❌';
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
            <button onclick="navigator.clipboard.writeText('\${u.subscription_url}').then(()=>alert('لینک ساب کپی شد: ' + '\${u.subscription_url}'))" class="px-2.5 py-1 bg-blue-900/30 text-blue-400 hover:bg-blue-900/50 text-xs rounded border border-blue-800 font-bold">کپی ساب Worker D</button>
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
      <button onclick="copySub()" class="w-full py-2 bg-blue-600 rounded-lg text-xs font-bold">کپی لینک اتصال (سرویس Worker D)</button>
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
      if(window.subscriptionUrl){
        navigator.clipboard.writeText(window.subscriptionUrl).then(()=>alert('لینک ساب کپی شد: ' + window.subscriptionUrl));
      }
    }
  </script>
</body>
</html>`;
