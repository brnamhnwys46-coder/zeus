import React, { useState } from "react";
import {
  Server,
  Database,
  Layers,
  Shield,
  Radio,
  FileCode,
  Download,
  Copy,
  Check,
  ExternalLink,
  Cpu,
  Zap,
  Terminal,
  Settings,
  RefreshCw,
  Lock,
  ArrowRight,
  Globe,
  Activity,
  Archive
} from "lucide-react";
import JSZip from "jszip";
import { WORKER_FILES } from "./data/workerFiles";

export default function App() {
  const [activeTab, setActiveTab] = useState<"architecture" | "code" | "simulator" | "deploy">("architecture");
  const [selectedWorkerId, setSelectedWorkerId] = useState<string>("workerA");
  const [codeViewType, setCodeViewType] = useState<"js" | "toml">("js");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Simulator State
  const [simPath, setSimPath] = useState<string>("/ggg/panel");
  const [simGateKey, setSimGateKey] = useState<string>("ggg");
  const [simResult, setSimResult] = useState<{
    status: number;
    title: string;
    description: string;
    passed: boolean;
    workerFlow: string[];
  } | null>(null);

  const selectedWorker = WORKER_FILES[selectedWorkerId];

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDownloadFile = (fileName: string, content: string) => {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadAllZip = async () => {
    const zip = new JSZip();

    // Worker A
    const folderA = zip.folder("worker-a");
    folderA?.file("worker-a.js", WORKER_FILES.workerA.jsCode);
    folderA?.file("wrangler.toml", WORKER_FILES.workerA.tomlCode);

    // Worker B
    const folderB = zip.folder("worker-b");
    folderB?.file("worker-b.js", WORKER_FILES.workerB.jsCode);
    folderB?.file("wrangler.toml", WORKER_FILES.workerB.tomlCode);

    // Worker C
    const folderC = zip.folder("worker-c");
    folderC?.file("worker-c.js", WORKER_FILES.workerC.jsCode);
    folderC?.file("wrangler.toml", WORKER_FILES.workerC.tomlCode);

    // Worker D
    const folderD = zip.folder("worker-d");
    folderD?.file("worker-d.js", WORKER_FILES.workerD.jsCode);
    folderD?.file("wrangler.toml", WORKER_FILES.workerD.tomlCode);

    // README
    zip.file("README.md", `# Cloudflare Distributed 4-Worker Architecture\n\nSee deployment instructions inside each worker folder.`);

    const blob = await zip.generateAsync({ type: "blob" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "cloudflare-4-workers-architecture.zip";
    link.click();
    URL.revokeObjectURL(url);
  };

  const runSimulation = (path = simPath, gateKey = simGateKey) => {
    const cleanPath = path.trim();
    const cleanGate = gateKey.trim();

    // Check public routes
    if (
      cleanPath.startsWith("/sub/") ||
      cleanPath.startsWith("/feed/") ||
      cleanPath.startsWith("/yaml/") ||
      cleanPath.startsWith("/status/") ||
      cleanPath.startsWith("/stream/")
    ) {
      if (cleanPath.startsWith("/stream/")) {
        setSimResult({
          status: 101,
          title: "101 Switching Protocols (WebSocket Accepted)",
          description: "Incoming proxy connection bypassed the secret gate (client connection), authenticated user via Worker B, and established direct TCP stream in Worker D.",
          passed: true,
          workerFlow: ["Client", "Worker A Gateway", "Worker D Proxy Handler", "Worker B User Check", "Outbound Socket"]
        });
      } else {
        setSimResult({
          status: 200,
          title: "200 OK (Public Subscription Feed)",
          description: "Client subscription feed is delivered without exposing the secret admin gate. Clean IPs retrieved from Worker C and user quotas from Worker B.",
          passed: true,
          workerFlow: ["Client", "Worker A Gateway", "Worker B Database", "Worker C Clean IPs Cache", "Response Output"]
        });
      }
      return;
    }

    // Check if path or query matches gate
    const hasGatePrefix = cleanPath === `/${cleanGate}` || cleanPath.startsWith(`/${cleanGate}/`);
    const hasGateQuery = cleanPath.includes(`gate=${cleanGate}`);

    if (cleanGate && (hasGatePrefix || hasGateQuery)) {
      setSimResult({
        status: 200,
        title: "200 OK (Secret Gate Verified)",
        description: `Access granted! Secret key "${cleanGate}" was recognized. Secure 'panel_gate' cookie generated and dashboard UI dispatched.`,
        passed: true,
        workerFlow: ["Admin Browser", "Secret Gate Check", "Worker A Gateway", "Worker B Auth Check", "Dashboard Render"]
      });
    } else {
      setSimResult({
        status: 404,
        title: "404 Not Found (Secret Gate Blocked)",
        description: "Nothing to see here. Unauthenticated crawler or scanner blocked immediately before consuming D1 database reads or proxy memory.",
        passed: false,
        workerFlow: ["Scanner / Unknown Request", "Secret Gate Filter", "Immediate 404 Discard"]
      });
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      {/* Top Navbar */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-4 sm:px-8 py-3.5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-cyan-400 p-0.5 shadow-lg shadow-blue-500/20 flex items-center justify-center">
            <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
              <Zap className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-black text-base tracking-tight text-white">Cloudflare Multi-Worker Architect</h1>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-500/10 text-cyan-400 border border-cyan-500/30">
                Distributed 4-Worker Architecture
              </span>
            </div>
            <p className="text-xs text-slate-400">Refactoring Monolithic Proxy Panels into Isolated Services</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveTab("architecture")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 ${
              activeTab === "architecture"
                ? "bg-blue-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>معماری و توپولوژی</span>
          </button>
          <button
            onClick={() => setActiveTab("code")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 ${
              activeTab === "code"
                ? "bg-blue-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>کدهای آماده (Code Studio)</span>
          </button>
          <button
            onClick={() => {
              setActiveTab("simulator");
              if (!simResult) runSimulation();
            }}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 ${
              activeTab === "simulator"
                ? "bg-blue-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>شبیه‌ساز گیت مخفی & RPC</span>
          </button>
          <button
            onClick={() => setActiveTab("deploy")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 ${
              activeTab === "deploy"
                ? "bg-blue-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>راهنمای دیپلوی چند اکانت</span>
          </button>
        </div>

        <button
          onClick={handleDownloadAllZip}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-bold transition shadow-lg shadow-emerald-600/20"
        >
          <Archive className="w-4 h-4" />
          <span>دانلود پکیج کامل (ZIP)</span>
        </button>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* TAB 1: ARCHITECTURE TOPOLOGY */}
        {activeTab === "architecture" && (
          <div className="space-y-6">
            {/* Value Proposition Hero */}
            <div className="bg-gradient-to-b from-slate-900 to-slate-900/60 border border-slate-800 rounded-3xl p-6 sm:p-8 relative overflow-hidden">
              <div className="absolute top-0 right-0 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl pointer-events-none" />
              <div className="relative z-10 max-w-3xl space-y-3">
                <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Shield className="w-4 h-4" />
                  چرا معماری توزیع‌شده چند ورکر (Multi-Worker, Multi-Account)؟
                </span>
                <h2 className="text-2xl sm:text-3xl font-black text-white leading-tight">
                  جداسازی قطعی فشار CPU، دیتابیس D1، و مدیریت ترافیک WebSocket سنگین
                </h2>
                <p className="text-sm text-slate-300 leading-relaxed text-justify">
                  در معماری یکپارچه (Monolithic)، تمام درخواست‌های پنل ادمین، ساب‌اسکریپشن‌ها، استریم‌های رمزنگاری شده VLESS/Trojan/Shadowsocks و کوئری‌های دیتابیس D1 همگی بر روی یک ورکر اجرا می‌شدند که منجر به مصرف سریع سهمیه روزانه D1 (Daily Rows Limit)، محدودیت CPU time کلودفلر، و ریسک‌های امنیتی می‌شد. با تفکیک سیستم به ۴ ورکر، هر سرویس روی اکانت یا ساب‌دامین مستقل با سهمیه اختصاصی و ایزولاسیون کامل قرار می‌گیرد.
                </p>
              </div>

              {/* Stat Counters */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-8 pt-6 border-t border-slate-800">
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80">
                  <div className="text-xs text-slate-400">تعداد ورکرها</div>
                  <div className="text-xl font-black text-cyan-400 mt-1">۴ ورکر مستقل</div>
                </div>
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80">
                  <div className="text-xs text-slate-400">ایزولاسیون اکانت‌ها</div>
                  <div className="text-xl font-black text-emerald-400 mt-1">Multi-Account</div>
                </div>
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80">
                  <div className="text-xs text-slate-400">دروازه امنیتی ادمین</div>
                  <div className="text-xl font-black text-purple-400 mt-1">Secret Route Gate</div>
                </div>
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80">
                  <div className="text-xs text-slate-400">کانفیگ داینامیک</div>
                  <div className="text-xl font-black text-amber-400 mt-1">Zero-Redeploy</div>
                </div>
              </div>
            </div>

            {/* Interactive Flow Diagram */}
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 sm:p-8 space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <Activity className="w-5 h-5 text-cyan-400" />
                    <span>دیاگرام تعاملی توزیع بار و ارتباطات بین ورکرها</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">روی هر ورکر کلیک کنید تا مشخصات و وظایف آن را بررسی نمایید.</p>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="flex items-center gap-1 text-slate-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-blue-500" /> ورکر فعال
                  </span>
                  <span className="flex items-center gap-1 text-slate-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> ارتباط ایمن
                  </span>
                </div>
              </div>

              {/* Grid of 4 Workers */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {Object.values(WORKER_FILES).map((w) => {
                  const isSelected = selectedWorkerId === w.id;
                  return (
                    <div
                      key={w.id}
                      onClick={() => setSelectedWorkerId(w.id)}
                      className={`cursor-pointer p-5 rounded-2xl border transition-all duration-300 relative flex flex-col justify-between ${
                        isSelected
                          ? "bg-slate-850 border-cyan-500 shadow-xl shadow-cyan-500/10 ring-1 ring-cyan-500/50"
                          : "bg-slate-950/70 border-slate-800 hover:border-slate-700 hover:bg-slate-900/60"
                      }`}
                    >
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 text-cyan-400 flex items-center justify-center font-bold text-xs">
                            {w.id.replace("worker", "W-")}
                          </span>
                          <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
                            {w.account}
                          </span>
                        </div>
                        <div>
                          <h4 className="font-bold text-sm text-white">{w.name}</h4>
                          <span className="text-xs text-cyan-400 font-medium block mt-0.5">{w.role}</span>
                        </div>
                        <p className="text-xs text-slate-400 leading-relaxed text-justify line-clamp-3">
                          {w.description}
                        </p>
                      </div>

                      <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                        <span>{w.jsFileName}</span>
                        <span className="text-cyan-400 font-bold flex items-center gap-1">
                          مشاهده سورس <ArrowRight className="w-3.5 h-3.5" />
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Selected Worker Deep Dive Card */}
              <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-xl bg-blue-600/20 border border-blue-500/30 text-cyan-400 flex items-center justify-center">
                      <Server className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="font-bold text-base text-white">{selectedWorker.name}</h4>
                      <p className="text-xs text-slate-400">{selectedWorker.account} • {selectedWorker.jsFileName}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        setActiveTab("code");
                        setCodeViewType("js");
                      }}
                      className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition flex items-center gap-1.5"
                    >
                      <FileCode className="w-3.5 h-3.5" />
                      <span>مشاهده کد کامل در Code Studio</span>
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                  <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
                    <span className="text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5" /> قابلیت‌ها و مسئولیت‌ها
                    </span>
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {selectedWorker.features.map((f, i) => (
                        <li key={i} className="flex items-start gap-1.5">
                          <span className="text-cyan-400 font-bold">•</span>
                          <span>{f}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
                    <span className="text-xs font-bold text-purple-400 flex items-center gap-1.5">
                      <Database className="w-3.5 h-3.5" /> بایندینگ‌ها (Bindings)
                    </span>
                    <ul className="space-y-1.5 text-xs text-slate-300 font-mono">
                      {selectedWorker.bindings.map((b, i) => (
                        <li key={i} className="flex items-center gap-1.5 bg-slate-950 px-2 py-1 rounded border border-slate-800">
                          <Check className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                          <span className="truncate">{b}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
                    <span className="text-xs font-bold text-amber-400 flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5" /> متغیرهای محیطی (Env Vars & Secrets)
                    </span>
                    <ul className="space-y-1.5 text-xs text-slate-300 font-mono">
                      {selectedWorker.envVars.map((v, i) => (
                        <li key={i} className="flex items-center gap-1.5 bg-slate-950 px-2 py-1 rounded border border-slate-800">
                          <span className="text-amber-400 text-[10px] font-bold">ENV</span>
                          <span className="truncate">{v}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </div>

            {/* Architecture Comparison Table */}
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 sm:p-8 space-y-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-emerald-400" />
                <span>مقایسه ساختاری: ورکر یکپارچه قدیمی در مقابل معماری ۴ ورکر</span>
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-right text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-3 px-4 font-bold">شاخص</th>
                      <th className="py-3 px-4 font-bold text-red-400">ورکر یکپارچه قبلی (Monolithic)</th>
                      <th className="py-3 px-4 font-bold text-emerald-400">معماری ۴ ورکر جدید (Distributed)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    <tr>
                      <td className="py-3 px-4 font-bold text-white">سهمیه دیتابیس D1</td>
                      <td className="py-3 px-4 text-red-300">تمام ترافیک، پینگ‌ها و لودها مستقیماً سهمیه محدود D1 را پر می‌کرد.</td>
                      <td className="py-3 px-4 text-emerald-300">D1 به ورکر B محدود شده، ترافیک‌ها در مموری بافر شده و فقط در دوره‌های منظم فلاش می‌شوند.</td>
                    </tr>
                    <tr>
                      <td className="py-3 px-4 font-bold text-white">امنیت مسیر ادمین</td>
                      <td className="py-3 px-4 text-red-300">مسیر /panel باز بود و بات‌ها و اسکنرها به راحتی پنل را پیدا می‌کردند.</td>
                      <td className="py-3 px-4 text-emerald-300">دروازه مخفی (Secret Route Gate) تمام درخواست‌های غریبه را با خطای 404 ریجکت می‌کند.</td>
                    </tr>
                    <tr>
                      <td className="py-3 px-4 font-bold text-white">فشار CPU وب‌سوکت</td>
                      <td className="py-3 px-4 text-red-300">فشار رمزنگاری سنگین VLESS و SS رابط وب را کند می‌کرد.</td>
                      <td className="py-3 px-4 text-emerald-300">ورکر D به تنهایی استریم‌ها و رمزنگاری را روی اکانت با منابع بالا مدیریت می‌کند.</td>
                    </tr>
                    <tr>
                      <td className="py-3 px-4 font-bold text-white">تنظیمات اندپوینت‌ها</td>
                      <td className="py-3 px-4 text-red-300">آدرس‌ها هاردکد شده بود؛ با هر تغییر نیاز به ادیت سورس و دیپلوی مجدد بود.</td>
                      <td className="py-3 px-4 text-emerald-300">بخش Admin Settings در پنل اجازه تغییر آدرس ورکرها و توکن‌ها بدون دیپلوی را می‌دهد.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: CODE STUDIO */}
        {activeTab === "code" && (
          <div className="space-y-6">
            {/* Worker Selector Pills */}
            <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900 p-3 rounded-2xl border border-slate-800">
              <div className="flex flex-wrap items-center gap-2">
                {Object.values(WORKER_FILES).map((w) => (
                  <button
                    key={w.id}
                    onClick={() => setSelectedWorkerId(w.id)}
                    className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
                      selectedWorkerId === w.id
                        ? "bg-blue-600 text-white shadow-md shadow-blue-500/20"
                        : "bg-slate-950 text-slate-400 hover:text-white border border-slate-800"
                    }`}
                  >
                    <span>{w.id.replace("worker", "Worker ")}</span>
                    <span className="text-[10px] opacity-75 font-normal">({w.role.split(",")[0]})</span>
                  </button>
                ))}
              </div>

              {/* View Type Toggle (JavaScript vs Wrangler.toml) */}
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
                <button
                  onClick={() => setCodeViewType("js")}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                    codeViewType === "js" ? "bg-slate-800 text-cyan-400" : "text-slate-400 hover:text-white"
                  }`}
                >
                  {selectedWorker.jsFileName}
                </button>
                <button
                  onClick={() => setCodeViewType("toml")}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                    codeViewType === "toml" ? "bg-slate-800 text-cyan-400" : "text-slate-400 hover:text-white"
                  }`}
                >
                  {selectedWorker.tomlFileName}
                </button>
              </div>
            </div>

            {/* Code Viewer Panel */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl flex flex-col">
              <div className="px-5 py-3.5 bg-slate-950 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <div className="flex items-center gap-1.5">
                    <span className="w-3 h-3 rounded-full bg-red-500/60" />
                    <span className="w-3 h-3 rounded-full bg-amber-500/60" />
                    <span className="w-3 h-3 rounded-full bg-emerald-500/60" />
                  </div>
                  <span className="text-xs font-mono font-bold text-slate-300">
                    {codeViewType === "js" ? selectedWorker.jsFileName : selectedWorker.tomlFileName}
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 font-mono">
                    {codeViewType === "js" ? "ES Module" : "Wrangler TOML"}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() =>
                      handleCopy(
                        codeViewType === "js" ? selectedWorker.jsCode : selectedWorker.tomlCode,
                        `${selectedWorker.id}-${codeViewType}`
                      )
                    }
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-bold text-slate-200 transition"
                  >
                    {copiedKey === `${selectedWorker.id}-${codeViewType}` ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">کپی شد!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>کپی کد</span>
                      </>
                    )}
                  </button>

                  <button
                    onClick={() =>
                      handleDownloadFile(
                        codeViewType === "js" ? selectedWorker.jsFileName : selectedWorker.tomlFileName,
                        codeViewType === "js" ? selectedWorker.jsCode : selectedWorker.tomlCode
                      )
                    }
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition shadow-sm"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>دانلود فایل</span>
                  </button>
                </div>
              </div>

              {/* Code Content */}
              <div className="p-4 overflow-x-auto max-h-[600px] overflow-y-auto bg-slate-950 font-mono text-xs leading-relaxed text-slate-200" dir="ltr">
                <pre>
                  <code>{codeViewType === "js" ? selectedWorker.jsCode : selectedWorker.tomlCode}</code>
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: SECRET ROUTE GATE & RPC SIMULATOR */}
        {activeTab === "simulator" && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 sm:p-8 space-y-6">
              <div>
                <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Shield className="w-4 h-4" /> تست زنده سناریوهای دروازه امنیتی (Secret Route Gate)
                </span>
                <h2 className="text-xl sm:text-2xl font-black text-white mt-1">
                  شبیه‌ساز رفتار Gateway در مواجهه با اسکنرها و درخواست‌های مجاز
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  در کادر زیر آدرس‌های مختلف را امتحان کنید تا تفاوت رفتار ورکر هنگام ارسال مسیر مخفی (Secret Route) با حالت عادی را مشاهده فرمایید.
                </p>
              </div>

              {/* Test Sandbox Input */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-slate-950 p-4 rounded-2xl border border-slate-800">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400">کلید مخفی گیت (SECRET_ROUTE_GATE)</label>
                  <input
                    type="text"
                    value={simGateKey}
                    onChange={(e) => setSimGateKey(e.target.value)}
                    placeholder="مثال: ggg"
                    className="w-full p-2.5 bg-slate-900 border border-slate-700 rounded-xl font-mono text-xs text-white"
                  />
                </div>
                <div className="md:col-span-2 space-y-1">
                  <label className="text-xs font-bold text-slate-400">مسیر درخواستی کلاینت (Requested URL Path)</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={simPath}
                      onChange={(e) => setSimPath(e.target.value)}
                      placeholder="/ggg/panel یا /panel یا /sub/user1"
                      className="flex-1 p-2.5 bg-slate-900 border border-slate-700 rounded-xl font-mono text-xs text-white"
                    />
                    <button
                      onClick={() => runSimulation()}
                      className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold transition flex items-center gap-1.5"
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                      <span>ارسال درخواست</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Quick Preset Buttons */}
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-slate-400 font-bold">تست‌های سریع:</span>
                <button
                  onClick={() => {
                    setSimPath("/panel");
                    runSimulation("/panel");
                  }}
                  className="px-2.5 py-1 rounded-lg bg-red-950/40 text-red-400 border border-red-900 hover:bg-red-900/60 transition"
                >
                  ❌ اسکنر بدون گیت (/panel)
                </button>
                <button
                  onClick={() => {
                    setSimPath(`/${simGateKey}/panel`);
                    runSimulation(`/${simGateKey}/panel`);
                  }}
                  className="px-2.5 py-1 rounded-lg bg-emerald-950/40 text-emerald-400 border border-emerald-900 hover:bg-emerald-900/60 transition"
                >
                  ✅ دسترسی مجاز ادمین (/{simGateKey}/panel)
                </button>
                <button
                  onClick={() => {
                    setSimPath(`/panel?gate=${simGateKey}`);
                    runSimulation(`/panel?gate=${simGateKey}`);
                  }}
                  className="px-2.5 py-1 rounded-lg bg-emerald-950/40 text-emerald-400 border border-emerald-900 hover:bg-emerald-900/60 transition"
                >
                  ✅ دسترسی با پارامتر (?gate={simGateKey})
                </button>
                <button
                  onClick={() => {
                    setSimPath("/sub/zeus_user");
                    runSimulation("/sub/zeus_user");
                  }}
                  className="px-2.5 py-1 rounded-lg bg-blue-950/40 text-blue-400 border border-blue-900 hover:bg-blue-900/60 transition"
                >
                  🌐 ساب‌اسکریپشن عمومی (/sub/zeus_user)
                </button>
                <button
                  onClick={() => {
                    setSimPath("/stream/PANEL_ZEUS/default");
                    runSimulation("/stream/PANEL_ZEUS/default");
                  }}
                  className="px-2.5 py-1 rounded-lg bg-purple-950/40 text-purple-400 border border-purple-900 hover:bg-purple-900/60 transition"
                >
                  ⚡ استریم وب‌سوکت پروکسی (/stream)
                </button>
              </div>

              {/* Simulation Result Card */}
              {simResult && (
                <div
                  className={`p-6 rounded-2xl border transition-all ${
                    simResult.passed
                      ? "bg-emerald-950/20 border-emerald-500/40"
                      : "bg-red-950/20 border-red-500/40"
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <span className="font-mono text-sm font-black flex items-center gap-2">
                      <span
                        className={`w-3 h-3 rounded-full ${
                          simResult.passed ? "bg-emerald-400" : "bg-red-500"
                        }`}
                      />
                      {simResult.title}
                    </span>
                    <span
                      className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full uppercase ${
                        simResult.passed
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                          : "bg-red-500/20 text-red-400 border border-red-500/30"
                      }`}
                    >
                      HTTP {simResult.status}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed mb-4">{simResult.description}</p>

                  <div className="space-y-1.5 pt-3 border-t border-slate-800">
                    <span className="text-[11px] font-bold text-slate-400">مسیر پردازش در ساختار چند ورکر:</span>
                    <div className="flex flex-wrap items-center gap-2">
                      {simResult.workerFlow.map((step, idx) => (
                        <React.Fragment key={idx}>
                          <span className="px-2.5 py-1 rounded bg-slate-900 text-xs font-mono border border-slate-800 text-slate-200">
                            {step}
                          </span>
                          {idx < simResult.workerFlow.length - 1 && (
                            <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                          )}
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 4: MULTI-ACCOUNT DEPLOYMENT GUIDE */}
        {activeTab === "deploy" && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 sm:p-8 space-y-6">
              <div>
                <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Terminal className="w-4 h-4" /> دستورالعمل راه‌اندازی و دیپلوی چند اکانت
                </span>
                <h2 className="text-xl sm:text-2xl font-black text-white mt-1">
                  مراحل گام‌به‌گام دیپلوی مستقل در Cloudflare
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  می‌توانید هر ورکر را در یک حساب کاربری متفاوت کلودفلر ثبت کنید تا ترافیک سنگین و محدودیت سهمیه دیتابیس D1 کاملاً ایزوله شوند.
                </p>
              </div>

              {/* Step 1 */}
              <div className="p-5 bg-slate-950 border border-slate-800 rounded-2xl space-y-3">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-blue-600 text-white font-bold text-xs flex items-center justify-center">1</span>
                  <h4 className="font-bold text-sm text-white">دیپلوی ورکر B (سرویس دیتابیس D1)</h4>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  ابتدا ورکر دیتابیس را دیپلوی کنید تا آدرس Endpoint آن برای ورکر A و ورکر D در دسترس باشد:
                </p>
                <div className="bg-slate-900 p-3 rounded-xl font-mono text-xs text-cyan-300 space-y-1" dir="ltr">
                  <div>cd workers/worker-b</div>
                  <div>wrangler d1 create zeus-db</div>
                  <div className="text-slate-500"># شناسه دیتابیس را در wrangler.toml درج کنید</div>
                  <div>wrangler secret put INTERNAL_AUTH_TOKEN</div>
                  <div>wrangler deploy</div>
                </div>
              </div>

              {/* Step 2 */}
              <div className="p-5 bg-slate-950 border border-slate-800 rounded-2xl space-y-3">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-amber-600 text-white font-bold text-xs flex items-center justify-center">2</span>
                  <h4 className="font-bold text-sm text-white">دیپلوی ورکر C (سرویس کش KV و مخزن فایل‌ها)</h4>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  فضای نام KV برای فایل‌های حجیم و کش آی‌پی‌ها را ایجاد و دیپلوی کنید:
                </p>
                <div className="bg-slate-900 p-3 rounded-xl font-mono text-xs text-cyan-300 space-y-1" dir="ltr">
                  <div>cd workers/worker-c</div>
                  <div>wrangler kv:namespace create "FILE_CACHE_KV"</div>
                  <div className="text-slate-500"># شناسه KV را در wrangler.toml ورکر C درج کنید</div>
                  <div>wrangler secret put INTERNAL_AUTH_TOKEN</div>
                  <div>wrangler deploy</div>
                </div>
              </div>

              {/* Step 3 */}
              <div className="p-5 bg-slate-950 border border-slate-800 rounded-2xl space-y-3">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-emerald-600 text-white font-bold text-xs flex items-center justify-center">3</span>
                  <h4 className="font-bold text-sm text-white">دیپلوی ورکر D (موتور استریم وب‌سوکت پروکسی)</h4>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  این ورکر را روی اکانت مجزا یا پرمصرف‌تر دیپلوی کنید و آدرس ورکر B را به آن بدهید:
                </p>
                <div className="bg-slate-900 p-3 rounded-xl font-mono text-xs text-cyan-300 space-y-1" dir="ltr">
                  <div>cd workers/worker-d</div>
                  <div>wrangler secret put INTERNAL_AUTH_TOKEN</div>
                  <div>wrangler deploy</div>
                </div>
              </div>

              {/* Step 4 */}
              <div className="p-5 bg-slate-950 border border-slate-800 rounded-2xl space-y-3">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-purple-600 text-white font-bold text-xs flex items-center justify-center">4</span>
                  <h4 className="font-bold text-sm text-white">دیپلوی ورکر A (گیت‌وی اصلی، پنل ادمین و گیت مخفی)</h4>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  آدرس‌های دریافتی از مراحل ۱ تا ۳ و کلید SECRET_ROUTE_GATE را در wrangler.toml ورکر A قرار دهید:
                </p>
                <div className="bg-slate-900 p-3 rounded-xl font-mono text-xs text-cyan-300 space-y-1" dir="ltr">
                  <div>cd workers/worker-a</div>
                  <div>wrangler secret put INTERNAL_AUTH_TOKEN</div>
                  <div>wrangler deploy</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-950 px-6 py-4 text-center text-xs text-slate-500">
        Cloudflare Distributed 4-Worker Architecture • Ready for Production Deployment
      </footer>
    </div>
  );
}
