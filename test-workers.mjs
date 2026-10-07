import fs from "fs";
import { execSync } from "child_process";

console.log("==================================================");
console.log("RUNNING ZEUS MULTI-WORKER ARCHITECTURE VERIFICATION TEST SUITE");
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

// Strip comments for code pattern assertions
function stripComments(code) {
  return code.replace(/\/\*[\s\S]*?\*\/|([^:]|^)\/\/.*$/gm, "");
}

const strippedA = stripComments(workerACode);
const strippedB = stripComments(workerBCode);
const strippedC = stripComments(workerCCode);
const strippedD = stripComments(workerDCode);

// 2. Verify Worker A contains no proxy socket / connection implementation
assert(!strippedA.includes("connect(") && !strippedA.includes("WebSocketPair"), "Test 6: Verify Worker A contains no proxy socket implementation");
assert(!workerAToml.includes("[[d1_databases]]"), "Test 7: Verify Worker A contains no D1 binding");
assert(!strippedA.includes("raw.githubusercontent.com"), "Test 8: Verify Worker A contains no direct GitHub/raw repository fetch");
assert(!strippedA.includes("generateTextSubscription") && !strippedA.includes("generateYamlSubscription"), "Test 9: Verify Worker A contains no VLESS/Trojan/SS generation");

// 5. Verify no hardcoded INTERNAL_AUTH_TOKEN in wrangler.toml files
for (const [name, toml] of [
  ["Worker A", workerAToml],
  ["Worker B", workerBToml],
  ["Worker C", workerCToml],
  ["Worker D", workerDToml]
]) {
  const hasHardcodedSecret = toml.includes('INTERNAL_AUTH_TOKEN = "') || toml.includes("INTERNAL_AUTH_TOKEN = '");
  assert(!hasHardcodedSecret, `Test 5: Verify ${name} wrangler.toml has no hardcoded INTERNAL_AUTH_TOKEN`);
}

// 10. Verify Worker D contains the full connection engine
assert(
  strippedD.includes("connect(") &&
  strippedD.includes("WebSocketPair") &&
  strippedD.includes("SSCrypto") &&
  strippedD.includes("extractUUIDFromvIees") &&
  strippedD.includes("connectSocks5") &&
  strippedD.includes("dohQuery"),
  "Test 10: Verify Worker D contains full connection & proxy engine"
);

// 11. Verify Worker B is the ONLY worker with D1 binding
assert(
  workerBToml.includes("[[d1_databases]]") &&
  !workerAToml.includes("[[d1_databases]]") &&
  !workerCToml.includes("[[d1_databases]]") &&
  !workerDToml.includes("[[d1_databases]]"),
  "Test 11: Verify Worker B is the only Worker directly using D1"
);

// 12. Verify Worker C is the repository/cache service with KV
assert(
  workerCToml.includes("[[kv_namespaces]]") &&
  strippedC.includes("FILE_CACHE_KV") &&
  strippedC.includes("ips.txt"),
  "Test 12: Verify Worker C is the repository/cache service"
);

// 13 & 14. Verify missing INTERNAL_AUTH_TOKEN causes authentication failure (Fail closed)
for (const [name, code] of [
  ["Worker B", strippedB],
  ["Worker C", strippedC],
  ["Worker D", strippedD]
]) {
  const hasFailClosed = code.includes("return false;") && code.includes("!expectedToken");
  assert(hasFailClosed, `Test 13/14: Verify ${name} fail-closed authentication`);
}

// 15. Verify database migration safety
assert(
  strippedB.includes("PRAGMA table_info(users)") &&
  strippedB.includes("ALTER TABLE users ADD COLUMN") &&
  !strippedB.includes("DROP TABLE users"),
  "Test 15: Verify database schema migrates safely without DROP TABLE"
);

// 18. Verify Worker D owns subscription feeds
assert(
  strippedD.includes("/sub/") &&
  strippedD.includes("/yaml/") &&
  strippedD.includes("handleSubscriptionRequest"),
  "Test 18: Verify Worker D owns subscription endpoints (/sub/, /yaml/)"
);

// 24. Verify health endpoints exist across all 4 workers
for (const [name, code] of [
  ["Worker A", strippedA],
  ["Worker B", strippedB],
  ["Worker C", strippedC],
  ["Worker D", strippedD]
]) {
  assert(code.includes("/health"), `Test 24: Verify ${name} has /health endpoint`);
}

// 26. Verify no browser response contains INTERNAL_AUTH_TOKEN
assert(!strippedA.includes("INTERNAL_AUTH_TOKEN: env.INTERNAL_AUTH_TOKEN") && !strippedA.includes("internal_auth_token:"), "Test 26: Verify no browser response contains INTERNAL_AUTH_TOKEN");

// Tests that require actual live Cloudflare deployment infrastructure:
markNotRun("Test 16: Live Cloudflare D1 User CRUD execution", "Requires live Cloudflare account with provisioned D1 database credentials.");
markNotRun("Test 17: Live Browser Cookie Session Exchange", "Requires live deployment domain.");
markNotRun("Test 19-22: Live Inter-Worker Network RPC", "Requires deployed Worker URLs on Cloudflare edge network.");
markNotRun("Test 23: Live Cloudflare KV write/read", "Requires active Cloudflare KV namespace provisioning.");
markNotRun("Test 25: Live WebSocket VLESS proxy stream handshake", "Requires live Cloudflare edge network with cloudflare:sockets runtime.");

console.log("\n==================================================");
console.log(`TEST RESULTS SUMMARY: ${passedCount} PASSED, ${failedCount} FAILED, ${notRunCount} NOT RUN`);
console.log("==================================================");

if (failedCount > 0) {
  process.exit(1);
}
