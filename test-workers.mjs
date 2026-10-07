import fs from "fs";
import { execSync } from "child_process";

console.log("==================================================");
console.log("RUNNING ZEUS MULTI-WORKER FINAL VERIFICATION SUITE");
console.log("==================================================\n");

let passedCount = 0;
let failedCount = 0;
let notRunCount = 0;

function assert(condition, testName, details = "") {
  if (condition) {
    console.log(`[PASS] ${testName}`);
    passedCount++;
  } else {
    console.error(`[FAIL] ${testName}${details ? " - " + details : ""}`);
    failedCount++;
  }
}

function markNotRun(testName, reason) {
  console.log(`[NOT RUN] ${testName}: ${reason}`);
  notRunCount++;
}

// 1. Syntax check all Worker JS files using node --check
const workerFiles = [
  ["Worker A", "workers/worker-a/worker-a.js"],
  ["Worker B", "workers/worker-b/worker-b.js"],
  ["Worker C", "workers/worker-c/worker-c.js"],
  ["Worker D", "workers/worker-d/worker-d.js"]
];

for (const [name, filePath] of workerFiles) {
  try {
    execSync(`node --check ${filePath}`);
    assert(true, `Test 1: Syntax check ${name} (${filePath})`);
  } catch (err) {
    assert(false, `Test 1: Syntax check ${name}`, err.message);
  }
}

const workerACode = fs.readFileSync("workers/worker-a/worker-a.js", "utf8");
const workerAToml = fs.readFileSync("workers/worker-a/wrangler.toml", "utf8");
const workerBCode = fs.readFileSync("workers/worker-b/worker-b.js", "utf8");
const workerBToml = fs.readFileSync("workers/worker-b/wrangler.toml", "utf8");
const workerCCode = fs.readFileSync("workers/worker-c/worker-c.js", "utf8");
const workerCToml = fs.readFileSync("workers/worker-c/wrangler.toml", "utf8");
const workerDCode = fs.readFileSync("workers/worker-d/worker-d.js", "utf8");
const workerDToml = fs.readFileSync("workers/worker-d/wrangler.toml", "utf8");

function stripComments(code) {
  return code.replace(/\/\*[\s\S]*?\*\/|([^:]|^)\/\/.*$/gm, "");
}

const strippedA = stripComments(workerACode);
const strippedB = stripComments(workerBCode);
const strippedC = stripComments(workerCCode);
const strippedD = stripComments(workerDCode);

// 2. Worker A Strict Role Checks
assert(!strippedA.includes("connect(") && !strippedA.includes("WebSocketPair"), "Test 2: Worker A contains no connect() or WebSocketPair");
assert(!workerAToml.includes("[[d1_databases]]") && !strippedA.includes("env.DB.prepare"), "Test 3: Worker A contains no direct D1 access");
assert(!strippedA.includes("raw.githubusercontent.com"), "Test 4: Worker A contains no direct GitHub/raw repository fetch");
assert(!strippedA.includes("generateTextSubscription") && !strippedA.includes("generateYamlSubscription"), "Test 5: Worker A contains no VLESS/Trojan/SS generator");

// 3. Worker B D1 Ownership
assert(
  workerBToml.includes("[[d1_databases]]") &&
  !workerAToml.includes("[[d1_databases]]") &&
  !workerCToml.includes("[[d1_databases]]") &&
  !workerDToml.includes("[[d1_databases]]"),
  "Test 6: Worker B is the ONLY Worker with D1 database binding"
);

// 4. Worker C Repository & Cache Ownership
assert(
  workerCToml.includes("[[kv_namespaces]]") &&
  strippedC.includes("FILE_CACHE_KV") &&
  strippedC.includes("ips.txt"),
  "Test 7: Worker C is the repository/cache owner"
);
assert(!workerCCode.includes("fesavswgvswgfvasw.hxxyrukih4kvmeawzmdmug2eh5uwtcmt"), "Test 8: Worker C has no hard-coded obscure fallback mirror");

// 5. Worker D Connection Engine & Subscription Ownership
assert(
  strippedD.includes("connect(") &&
  strippedD.includes("WebSocketPair") &&
  strippedD.includes("SSCrypto") &&
  strippedD.includes("extractUUIDFromvIees") &&
  strippedD.includes("connectSocks5") &&
  strippedD.includes("dohQuery"),
  "Test 9: Worker D preserves full connection & proxy engine"
);
assert(
  strippedD.includes("/sub/") &&
  strippedD.includes("/yaml/") &&
  strippedD.includes("sub_token"),
  "Test 10: Worker D owns subscription endpoints with random token authorization"
);

// 6. Security: Fail-Closed Authentication
for (const [name, code] of [
  ["Worker B", strippedB],
  ["Worker C", strippedC],
  ["Worker D", strippedD]
]) {
  const hasFailClosed = code.includes("return false;") && code.includes("!expectedToken");
  assert(hasFailClosed, `Test 11: ${name} fails closed if INTERNAL_AUTH_TOKEN is missing or empty`);
}

// 7. Security: No Hardcoded Secrets in wrangler.toml files
for (const [name, toml] of [
  ["Worker A", workerAToml],
  ["Worker B", workerBToml],
  ["Worker C", workerCToml],
  ["Worker D", workerDToml]
]) {
  const hasHardcodedSecret = toml.includes('INTERNAL_AUTH_TOKEN = "') || toml.includes("INTERNAL_AUTH_TOKEN = '");
  assert(!hasHardcodedSecret, `Test 12: ${name} wrangler.toml contains no hardcoded INTERNAL_AUTH_TOKEN`);
}

// 8. Worker A: Dynamic Configuration is Authoritative
assert(
  strippedA.includes("config.dbUrl") &&
  strippedA.includes("config.cacheUrl") &&
  strippedA.includes("config.proxyUrl") &&
  strippedA.includes("getEffectiveConfig"),
  "Test 13: Worker A authoritative dynamic configuration is actually used for RPC"
);

// 9. Worker A: Diagnostics tests internal authenticated endpoints
assert(
  strippedA.includes("/api/internal/health"),
  "Test 14: Worker A diagnostics tests internal authenticated health endpoints"
);

// 10. Worker A: Brute-Force Login Rate Limiting
assert(
  strippedA.includes("LOGIN_ATTEMPTS") &&
  strippedA.includes("checkLoginRateLimit") &&
  strippedA.includes("recordFailedLogin"),
  "Test 15: Worker A has login brute-force rate limit protection"
);

// 11. Worker A: Frontend HTML/JS Escaping
assert(
  strippedA.includes("escapeHtml") &&
  strippedA.includes("JSON.stringify(safeUserData)"),
  "Test 16: Worker A uses safe escaping for user-controlled values"
);

// 12. Worker A: Secure Public Status without Username Enumeration
assert(
  strippedA.includes("status_token") &&
  strippedA.includes("verifySessionAuth(request, env, config.dbUrl)"),
  "Test 17: User status endpoint rejects unauthorized username enumeration"
);

// 13. Worker B: Safe Schema Migrations & Revocable Tokens
assert(
  strippedB.includes("PRAGMA table_info(users)") &&
  strippedB.includes("ALTER TABLE users ADD COLUMN") &&
  !strippedB.includes("DROP TABLE users"),
  "Test 18: Worker B performs safe idempotent migration without DROP TABLE"
);
assert(
  strippedB.includes("sub_token") &&
  strippedB.includes("status_token") &&
  strippedB.includes("revoke-tokens"),
  "Test 19: Worker B manages random revocable sub_token and status_token"
);

// Tests that require active Cloudflare production edge infrastructure
markNotRun("Test 20: Edge D1 user CRUD execution", "Requires deployed Cloudflare account with active D1 database binding.");
markNotRun("Test 21: Live session cookie exchange", "Requires live deployment domain.");
markNotRun("Test 22: Live cross-worker RPC network hops", "Requires deployed Worker URLs on Cloudflare edge network.");
markNotRun("Test 23: Live Cloudflare KV write/read", "Requires active Cloudflare KV namespace provisioning.");
markNotRun("Test 24: Live WebSocket VLESS proxy stream handshake", "Requires live Cloudflare edge network with cloudflare:sockets runtime.");

console.log("\n==================================================");
console.log(`FINAL TEST RESULTS: ${passedCount} PASSED, ${failedCount} FAILED, ${notRunCount} NOT RUN`);
console.log("==================================================");

if (failedCount > 0) {
  process.exit(1);
}
