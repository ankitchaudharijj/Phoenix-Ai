import { useState, useEffect, useRef } from "react";

const T = {
  parchment: "#f5f4ed", ivory: "#faf9f5", white: "#ffffff",
  nearBlack: "#141413", darkSurface: "#30302e", terracotta: "#c96442",
  coral: "#d97757", oliveGray: "#5e5d59", stoneGray: "#87867f",
  warmSilver: "#b0aea5", charcoalWarm: "#4d4c48", warmSand: "#e8e6dc",
  borderCream: "#f0eee6", borderWarm: "#e8e6dc", borderDark: "#30302e",
  errorCrimson: "#b53333",
};

function Particles() {
  const canvasRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    canvas.width = window.innerWidth; canvas.height = window.innerHeight;
    const particles = Array.from({ length: 40 }, () => ({
      x: Math.random() * canvas.width, y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.3, vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.5 + 0.5, alpha: Math.random() * 0.3 + 0.05,
    }));
    let animId;
    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      particles.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0) p.x = canvas.width; if (p.x > canvas.width) p.x = 0;
        if (p.y < 0) p.y = canvas.height; if (p.y > canvas.height) p.y = 0;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(201,100,66,${p.alpha})`; ctx.fill();
      });
      particles.forEach((p, i) => particles.slice(i + 1).forEach(q => {
        const d = Math.hypot(p.x - q.x, p.y - q.y);
        if (d < 120) {
          ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y);
          ctx.strokeStyle = `rgba(201,100,66,${0.05 * (1 - d / 120)})`;
          ctx.lineWidth = 0.5; ctx.stroke();
        }
      }));
      animId = requestAnimationFrame(draw);
    };
    draw();
    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    window.addEventListener("resize", resize);
    return () => { cancelAnimationFrame(animId); window.removeEventListener("resize", resize); };
  }, []);
  return <canvas ref={canvasRef} style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none" }} />;
}

const PLANS = [
  {
    name: "Free", price: "₹0", period: "forever", color: T.stoneGray,
    features: ["3 scans/month", "URL scanner only", "Basic report", "Community support"],
    limits: { scans: 3, scanners: ["url"] }
  },
  {
    name: "Pro", price: "₹499", period: "/month", color: T.terracotta, popular: true,
    features: ["Unlimited scans", "All 6 scanner types", "Full PDF reports", "AI explanation", "Priority support", "Verified by Phoenix AI"],
    limits: { scans: -1, scanners: ["url","code","zip","api","threat","live"] }
  },
  {
    name: "Enterprise", price: "₹4,999", period: "/month", color: T.charcoalWarm,
    features: ["Everything in Pro", "Team access (5 users)", "API access", "Dedicated support", "Custom branding", "Compliance reports"],
    limits: { scans: -1, scanners: ["url","code","zip","api","threat","live"] }
  }
];

const SCAN_TABS = [
  ["url", "URL Scan", "Scan any website"],
  ["code", "Code Scan", "Static code analysis"],
  ["zip", "ZIP Upload", "Scan code archives"],
  ["api", "API Scan", "REST & GraphQL testing"],
  ["threat", "Threat Intel", "IP & CVE monitoring"],
  ["live", "Live App", "Authenticated testing"],
];

const ADMIN_SECRET = "phoenix_admin_2024";

const loadingMessages = {
  url: ["Checking security headers…","Testing SSL certificate…","Scanning for SQL injection…","Checking XSS vulnerabilities…","Scanning open ports…","Looking for sensitive files…"],
  code: ["Parsing source code…","Detecting hardcoded secrets…","Checking for injection risks…","Analyzing crypto usage…","Scanning for API keys…"],
  zip: ["Extracting ZIP archive…","Scanning Python files…","Scanning JavaScript files…","Checking for secrets…","Analyzing all files…"],
  api: ["Testing API endpoints…","Checking authentication…","Testing for IDOR…","Scanning GraphQL schema…"],
  threat: ["Resolving IP address…","Checking AbuseIPDB…","Scanning blacklists…","Enumerating subdomains…","Checking CVE database…"],
  live: ["Starting authenticated session…","Testing CSRF tokens…","Checking cookie security…","Testing rate limiting…","Scanning for IDOR…"],
};

export default function App() {
  const [page, setPage] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [user, setUser] = useState(null);
  const [userPlan, setUserPlan] = useState("Free");
  const [monthlyScans, setMonthlyScans] = useState(0);
  const [url, setUrl] = useState("");
  const [code, setCode] = useState("");
  const [zipFile, setZipFile] = useState(null);
  const [loginUrl, setLoginUrl] = useState("");
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPass, setLoginPass] = useState("");
  const [scanTab, setScanTab] = useState("url");
  const [result, setResult] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [loadingProgress, setLoadingProgress] = useState(0);
  const [authMsg, setAuthMsg] = useState("");
  const [history, setHistory] = useState([]);
  const [activePage, setActivePage] = useState("scan");
  const [mounted, setMounted] = useState(false);
  const [showUpgrade, setShowUpgrade] = useState(false);
  const [upgradeReason, setUpgradeReason] = useState("");

  // Admin
  const [adminSecret, setAdminSecret] = useState("");
  const [adminLoggedIn, setAdminLoggedIn] = useState(false);
  const [adminStats, setAdminStats] = useState(null);
  const [adminUsers, setAdminUsers] = useState([]);
  const [adminScans, setAdminScans] = useState([]);
  const [adminTab, setAdminTab] = useState("overview");
  const [adminMsg, setAdminMsg] = useState("");

  useEffect(() => { setTimeout(() => setMounted(true), 100); }, []);

  useEffect(() => {
    if (!loading) { setLoadingProgress(0); return; }
    const msgs = loadingMessages[scanTab] || loadingMessages.url;
    let i = 0; let progress = 0;
    setLoadingMsg(msgs[0]);
    const msgInt = setInterval(() => { i = (i + 1) % msgs.length; setLoadingMsg(msgs[i]); }, 3000);
    const progInt = setInterval(() => { progress = Math.min(progress + Math.random() * 8, 90); setLoadingProgress(progress); }, 800);
    return () => { clearInterval(msgInt); clearInterval(progInt); };
  }, [loading, scanTab]);

  const API = import.meta.env.VITE_API_URL;

  const getPlanObj = (planName) => {
  const normalized = planName?.toUpperCase();
  if (normalized === "PRO") return PLANS[1];
  if (normalized === "ENTERPRISE") return PLANS[2];
  return PLANS[0];
};
  const canUseScanType = (tab) => getPlanObj(userPlan).limits.scanners.includes(tab);
  const isLimitReached = () => {
  const normalized = userPlan?.toUpperCase();
  if (normalized === "PRO" || normalized === "ENTERPRISE") return false;
  return monthlyScans >= 3;
};

  const handleRegister = async () => {
    if (!email || !password) return setAuthMsg("Email aur password daalo!");
    try {
      const res = await fetch(`${API}/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
      const data = await res.json();
      if (res.ok) { setAuthMsg("✅ Account created! Sign in karo."); setPage("login"); }
      else setAuthMsg("❌ " + data.detail);
    } catch { setAuthMsg("❌ Server error!"); }
  };

  const handleLogin = async () => {
    if (!email || !password) return setAuthMsg("Email aur password daalo!");
    try {
      const res = await fetch(`${API}/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
      const data = await res.json();
      if (res.ok) {
        setUser(data); setUserPlan(data.plan || "Free");
        setMonthlyScans(data.monthly_scan_count || 0);
        setPage("dashboard"); setAuthMsg("");
      } else setAuthMsg("❌ " + data.detail);
    } catch { setAuthMsg("❌ Server error!"); }
  };

  const submitScan = async () => {
    if (scanTab === "url" && !url) return alert("URL daalo!");
    if (scanTab === "code" && !code) return alert("Code paste karo!");
    if (scanTab === "zip" && !zipFile) return alert("ZIP select karo!");
    if (scanTab === "threat" && !url) return alert("URL ya IP daalo!");
    if (scanTab === "live" && !url) return alert("App URL daalo!");
    if (scanTab === "api" && !url) return alert("API URL daalo!");

    if (!canUseScanType(scanTab)) {
      setUpgradeReason("scanner");
      setShowUpgrade(true);
      return;
    }
    if (isLimitReached()) {
      setUpgradeReason("limit");
      setShowUpgrade(true);
      return;
    }

    setLoading(true); setResult(null); setScanId(null);
    try {
      let data;
      if (scanTab === "zip") {
        const fd = new FormData(); fd.append("file", zipFile);
        const res = await fetch(`${API}/scan/upload`, { method: "POST", body: fd });
        data = await res.json();
      } else {
        const res = await fetch(`${API}/scan`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: scanTab !== "code" ? url : "Source Code Scan", scan_type: scanTab, code, login_url: loginUrl, login_email: loginEmail, login_password: loginPass, user_id: user?.user_id || 0 })
        });
        if (res.status === 429 || res.status === 403) {
          setUpgradeReason(res.status === 429 ? "limit" : "scanner");
          setShowUpgrade(true); setLoading(false); return;
        }
        data = await res.json();
      }
      setLoadingProgress(100);
      if (userPlan === "Free") setMonthlyScans(prev => prev + 1);
      setTimeout(async () => {
  setResult(data.result);
  setScanId(data.scan_id);
  setLoading(false);
  // Fresh count backend se lo
  if (user?.user_id) {
    try {
      const countRes = await fetch(`${API}/user/scan-count?user_id=${user.user_id}`);
      const countData = await countRes.json();
      setMonthlyScans(countData.monthly_scan_count || 0);
    } catch {}
  }
}, 500);
    } catch { alert("Backend chal raha hai?"); setLoading(false); }
  };

  const loadHistory = async () => {
    try { const res = await fetch(`${API}/scans`); const data = await res.json(); setHistory(data.scans || []); } catch { }
  };

  const downloadReport = async (r, t, sid) => {
    if (sid) {
      try {
        const res = await fetch(`${API}/scan/${sid}/pdf`);
        if (res.ok) { const blob = await res.blob(); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `phoenix-ai-${sid}.pdf`; a.click(); return; }
      } catch { }
    }
    const c = `PHOENIX AI REPORT\nTarget: ${t}\nRisk: ${r.risk_score}/100\n\nAI:\n${r.ai_explanation || "N/A"}\n\nVULNS:\n${(r.findings || []).map((f, i) => `\n${i + 1}. [${f.severity}] ${f.type}\n   ${f.detail}\n   Fix: ${f.fix}`).join("")}`;
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([c], { type: "text/plain" })); a.download = `phoenix-ai-${Date.now()}.txt`; a.click();
  };

  const adminLogin = async () => {
    if (adminSecret !== ADMIN_SECRET) return setAdminMsg("❌ Wrong secret key!");
    try {
      const res = await fetch(`${API}/admin/stats?secret=${adminSecret}`);
      if (res.ok) { const data = await res.json(); setAdminStats(data); setAdminLoggedIn(true); setAdminMsg(""); loadAdminUsers(); loadAdminScans(); }
      else setAdminMsg("❌ Access denied!");
    } catch { setAdminMsg("❌ Server error!"); }
  };

  const loadAdminUsers = async () => {
    try { const res = await fetch(`${API}/admin/users?secret=${ADMIN_SECRET}`); const data = await res.json(); setAdminUsers(data.users || []); } catch { }
  };

  const deleteUser = async (userId, email) => {
  if (!window.confirm(`Delete user ${email}? This cannot be undone!`)) return;
  try {
    const res = await fetch(`${API}/admin/delete-user?user_id=${userId}&secret=${ADMIN_SECRET}`, { method: "DELETE" });
    if (res.ok) { alert("✅ User deleted!"); loadAdminUsers(); }
    else alert("❌ Error deleting user");
  } catch { alert("❌ Server error!"); }
};

  const loadAdminScans = async () => {
    try { const res = await fetch(`${API}/admin/scans?secret=${ADMIN_SECRET}`); const data = await res.json(); setAdminScans(data.scans || []); } catch { }
  };

  const updateUserPlan = async (userId, plan) => {
    try {
      const res = await fetch(`${API}/admin/update-plan`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: userId, plan, admin_secret: ADMIN_SECRET }) });
      if (res.ok) { alert(`✅ Plan updated to ${plan}`); loadAdminUsers(); }
    } catch { alert("Error!"); }
  };

  const sColor = (s) => s === "CRITICAL" ? "#b53333" : s === "HIGH" ? "#c96442" : s === "MEDIUM" ? "#87867f" : "#b0aea5";
  const inputStyle = { width: "100%", padding: "12px 16px", background: T.ivory, border: `1px solid ${T.borderWarm}`, borderRadius: 12, color: T.nearBlack, fontSize: 15, outline: "none", marginBottom: 14, fontFamily: "system-ui, sans-serif", boxSizing: "border-box" };
  const darkInputStyle = { ...inputStyle, background: "rgba(250,249,245,0.06)", border: `1px solid ${T.borderDark}`, color: T.ivory };
  const labelStyle = { display: "block", fontSize: 11, fontFamily: "system-ui, sans-serif", color: T.stoneGray, letterSpacing: "0.5px", marginBottom: 6, textTransform: "uppercase" };

  // ── UPGRADE MODAL ──
  const UpgradeModal = () => (
    <div style={{ position: "fixed", inset: 0, background: "rgba(20,20,19,0.85)", backdropFilter: "blur(8px)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div style={{ background: T.ivory, borderRadius: 24, padding: "48px 40px", maxWidth: 500, width: "100%", textAlign: "center", boxShadow: "rgba(0,0,0,0.25) 0px 24px 64px" }}>
        <div style={{ width: 64, height: 64, borderRadius: "50%", background: T.warmSand, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 24px", fontSize: 28 }}>🔒</div>
        <div style={{ fontSize: 11, color: T.terracotta, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 12 }}>
          {upgradeReason === "limit" ? "Monthly limit reached" : "Feature locked"}
        </div>
        <h2 style={{ fontSize: 28, fontWeight: 500, color: T.nearBlack, margin: "0 0 12px", fontFamily: "Georgia, serif", lineHeight: 1.2 }}>
          {upgradeReason === "limit" ? "You've used all 3 free scans this month" : "This scanner requires Pro or Enterprise"}
        </h2>
        <p style={{ fontSize: 15, color: T.oliveGray, margin: "0 0 32px", lineHeight: 1.6 }}>
          {upgradeReason === "limit"
            ? "Your free plan includes 3 scans per month. Upgrade to Pro for unlimited scans, all scanner types, and full PDF reports."
            : "URL scanner is available on Free plan. Upgrade to Pro to access Code, ZIP, API, Threat Intel, and Live App scanners."}
        </p>

        {/* Plan comparison */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 28 }}>
          {[
            { name: "Pro", price: "₹499/mo", color: T.terracotta, features: ["Unlimited scans", "All 6 scanners", "Full PDF reports", "AI analysis", "Priority support"] },
            { name: "Enterprise", price: "₹4,999/mo", color: T.charcoalWarm, features: ["Everything in Pro", "5 team members", "API access", "Dedicated support"] }
          ].map(plan => (
            <div key={plan.name} style={{ background: T.parchment, border: `1px solid ${T.borderWarm}`, borderRadius: 14, padding: 20, textAlign: "left" }}>
              <div style={{ fontSize: 16, fontWeight: 500, color: plan.color, fontFamily: "Georgia, serif", marginBottom: 4 }}>{plan.name}</div>
              <div style={{ fontSize: 13, color: T.stoneGray, marginBottom: 12 }}>{plan.price}</div>
              {plan.features.map((f, i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 6, fontSize: 12, color: T.oliveGray }}>
                  <span style={{ color: T.terracotta }}>✓</span>{f}
                </div>
              ))}
            </div>
          ))}
        </div>

        <div style={{ display: "flex", gap: 12, justifyContent: "center" }}>
          <button onClick={() => setShowUpgrade(false)}
            style={{ padding: "11px 24px", background: T.warmSand, border: `1px solid ${T.borderWarm}`, borderRadius: 10, color: T.charcoalWarm, cursor: "pointer", fontSize: 14, fontFamily: "inherit" }}>
            Maybe later
          </button>
          <button onClick={() => { setShowUpgrade(false); setActivePage("plans"); }}
            style={{ padding: "11px 28px", background: T.terracotta, border: "none", borderRadius: 10, color: T.ivory, cursor: "pointer", fontSize: 15, fontFamily: "Georgia, serif", fontWeight: 500 }}>
            Upgrade now →
          </button>
        </div>
      </div>
    </div>
  );

  // ── AUTH ──
  if (page === "login" || page === "register") {
    const isLogin = page === "login";
    return (
      <div style={{ minHeight: "100vh", background: T.nearBlack, fontFamily: "Georgia, serif", position: "relative", overflow: "hidden" }}>
        <Particles />
        <div style={{ position: "fixed", top: "20%", left: "10%", width: 600, height: 600, background: "radial-gradient(circle, rgba(201,100,66,0.06) 0%, transparent 70%)", pointerEvents: "none", zIndex: 0 }} />
        <div style={{ position: "relative", zIndex: 1, display: "flex", minHeight: "100vh" }}>
          <div style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "center", padding: "80px 72px", borderRight: `1px solid ${T.borderDark}` }}>
            <div style={{ opacity: mounted ? 1 : 0, transform: mounted ? "translateY(0)" : "translateY(24px)", transition: "all 0.7s ease" }}>
              <div style={{ fontSize: 13, fontFamily: "system-ui", color: T.terracotta, letterSpacing: "0.5px", marginBottom: 24, textTransform: "uppercase" }}>AI Security Platform</div>
              <h1 style={{ fontSize: 64, fontWeight: 500, lineHeight: 1.1, letterSpacing: "-1px", color: T.ivory, margin: 0, marginBottom: 24 }}>
                Phoenix <span style={{ color: T.terracotta }}>AI</span>
              </h1>
              <p style={{ fontSize: 20, color: T.warmSilver, lineHeight: 1.6, margin: 0, marginBottom: 56, maxWidth: 440, fontFamily: "system-ui" }}>
                AI-powered security testing that finds vulnerabilities in minutes, not weeks.
              </p>
              {["Scan any website, codebase, or API in under 60 seconds.", "AI explains every finding in plain English.", "Threat intelligence monitors your assets 24/7."].map((text, i) => (
                <div key={i} style={{ display: "flex", gap: 16, marginBottom: 20, opacity: mounted ? 1 : 0, transition: `all 0.6s ease ${i * 0.12 + 0.3}s` }}>
                  <div style={{ width: 6, height: 6, borderRadius: "50%", background: T.terracotta, flexShrink: 0, marginTop: 8 }} />
                  <p style={{ fontSize: 16, color: T.warmSilver, lineHeight: 1.7, margin: 0, fontFamily: "system-ui" }}>{text}</p>
                </div>
              ))}
            </div>
          </div>
          <div style={{ width: 480, display: "flex", flexDirection: "column", justifyContent: "center", padding: "60px 56px", background: "rgba(20,20,19,0.9)", backdropFilter: "blur(20px)" }}>
            <div style={{ opacity: mounted ? 1 : 0, transition: "all 0.6s ease 0.2s" }}>
              <h2 style={{ fontSize: 32, fontWeight: 500, color: T.ivory, margin: 0, marginBottom: 8, fontFamily: "Georgia, serif" }}>{isLogin ? "Welcome back" : "Create account"}</h2>
              <p style={{ fontSize: 15, color: T.stoneGray, marginBottom: 40, fontFamily: "system-ui" }}>{isLogin ? "Sign in to Phoenix AI" : "Start your free assessment"}</p>
              <label style={{ ...labelStyle, color: T.stoneGray }}>Email address</label>
              <input style={darkInputStyle} placeholder="you@example.com" value={email} onChange={e => setEmail(e.target.value)} />
              <label style={{ ...labelStyle, color: T.stoneGray }}>Password</label>
              <input style={darkInputStyle} placeholder="••••••••" type="password" value={password} onChange={e => setPassword(e.target.value)} />
              {authMsg && <div style={{ fontSize: 13, color: T.errorCrimson, marginBottom: 16, padding: "10px 14px", background: "rgba(181,51,51,0.08)", borderRadius: 8, border: "1px solid rgba(181,51,51,0.2)", fontFamily: "system-ui" }}>{authMsg}</div>}
              <button onClick={isLogin ? handleLogin : handleRegister}
                style={{ width: "100%", padding: "13px 20px", background: T.terracotta, border: "none", borderRadius: 12, color: T.ivory, fontSize: 15, fontWeight: 500, cursor: "pointer", fontFamily: "Georgia, serif", transition: "all 0.2s" }}>
                {isLogin ? "Sign in →" : "Create account →"}
              </button>
              <div style={{ textAlign: "center", marginTop: 20, fontSize: 14, color: T.stoneGray, fontFamily: "system-ui" }}>
                {isLogin ? "Don't have an account? " : "Already have an account? "}
                <span style={{ color: T.coral, cursor: "pointer" }} onClick={() => { setPage(isLogin ? "register" : "login"); setAuthMsg(""); }}>
                  {isLogin ? "Create one" : "Sign in"}
                </span>
              </div>
              <div style={{ textAlign: "center", marginTop: 16 }}>
                <span style={{ fontSize: 12, color: T.borderDark, cursor: "pointer", fontFamily: "system-ui" }} onClick={() => setPage("admin")}>Admin →</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ── ADMIN LOGIN ──
  if (page === "admin" && !adminLoggedIn) {
    return (
      <div style={{ minHeight: "100vh", background: T.nearBlack, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "Georgia, serif" }}>
        <Particles />
        <div style={{ position: "relative", zIndex: 1, width: 400, background: "rgba(20,20,19,0.95)", border: `1px solid ${T.borderDark}`, borderRadius: 20, padding: 48 }}>
          <div style={{ fontSize: 12, color: T.terracotta, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 12, fontFamily: "system-ui" }}>Admin Access</div>
          <h2 style={{ fontSize: 28, fontWeight: 500, color: T.ivory, margin: 0, marginBottom: 32 }}>Phoenix AI Admin</h2>
          <label style={{ ...labelStyle, color: T.stoneGray }}>Secret Key</label>
          <input style={darkInputStyle} placeholder="Enter admin secret" type="password" value={adminSecret} onChange={e => setAdminSecret(e.target.value)} />
          {adminMsg && <div style={{ fontSize: 13, color: T.errorCrimson, marginBottom: 16, padding: "10px 14px", background: "rgba(181,51,51,0.08)", borderRadius: 8, fontFamily: "system-ui" }}>{adminMsg}</div>}
          <button onClick={adminLogin} style={{ width: "100%", padding: "13px", background: T.terracotta, border: "none", borderRadius: 12, color: T.ivory, fontSize: 15, fontWeight: 500, cursor: "pointer", fontFamily: "Georgia, serif" }}>
            Access Dashboard →
          </button>
          <div style={{ textAlign: "center", marginTop: 16 }}>
            <span style={{ fontSize: 12, color: T.stoneGray, cursor: "pointer", fontFamily: "system-ui" }} onClick={() => setPage("login")}>← Back to login</span>
          </div>
        </div>
      </div>
    );
  }

  // ── ADMIN DASHBOARD ──
  if (page === "admin" && adminLoggedIn) {
    return (
      <div style={{ minHeight: "100vh", background: T.parchment, fontFamily: "system-ui, sans-serif" }}>
        <nav style={{ background: T.nearBlack, borderBottom: `1px solid ${T.borderDark}`, padding: "0 32px", height: 60, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ fontSize: 20, fontWeight: 500, fontFamily: "Georgia, serif", color: T.ivory }}>
            Phoenix <span style={{ color: T.terracotta }}>AI</span>
            <span style={{ fontSize: 11, color: T.stoneGray, marginLeft: 12, letterSpacing: "0.5px", textTransform: "uppercase" }}>Admin</span>
          </div>
          <div style={{ display: "flex", gap: 4 }}>
            {["overview", "users", "scans"].map(tab => (
              <button key={tab} onClick={() => setAdminTab(tab)}
                style={{ padding: "8px 16px", background: adminTab === tab ? "rgba(201,100,66,0.15)" : "transparent", border: "none", borderRadius: 8, color: adminTab === tab ? T.terracotta : T.stoneGray, cursor: "pointer", fontSize: 14, fontFamily: "inherit", fontWeight: adminTab === tab ? 500 : 400, textTransform: "capitalize" }}>
                {tab}
              </button>
            ))}
          </div>
          <button onClick={() => { setAdminLoggedIn(false); setPage("login"); }}
            style={{ padding: "7px 16px", background: "transparent", border: `1px solid ${T.borderDark}`, borderRadius: 8, color: T.stoneGray, cursor: "pointer", fontSize: 13 }}>
            Sign out
          </button>
        </nav>
        <main style={{ maxWidth: 1200, margin: "0 auto", padding: "40px 32px" }}>
          {adminTab === "overview" && adminStats && (
            <div>
              <div style={{ marginBottom: 40 }}>
                <div style={{ fontSize: 12, color: T.terracotta, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 12 }}>Overview</div>
                <h1 style={{ fontSize: 48, fontWeight: 500, color: T.nearBlack, margin: 0, fontFamily: "Georgia, serif", letterSpacing: "-1px" }}>Dashboard</h1>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16, marginBottom: 32 }}>
                {[["Total Users", adminStats.total_users], ["Total Scans", adminStats.total_scans], ["Pro Users", adminStats.pro_users], ["Enterprise", adminStats.enterprise_users], ["Free Users", adminStats.free_users], ["Scans This Week", adminStats.scans_this_week], ["New Users (7d)", adminStats.new_users_week], ["Est. Revenue", `₹${(adminStats.estimated_revenue || 0).toLocaleString()}`]].map(([l, v]) => (
                  <div key={l} style={{ background: T.ivory, border: `1px solid ${T.borderCream}`, borderRadius: 14, padding: "20px 24px" }}>
                    <div style={{ fontSize: 11, color: T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 10 }}>{l}</div>
                    <div style={{ fontSize: 32, fontWeight: 500, color: T.nearBlack, fontFamily: "Georgia, serif", lineHeight: 1 }}>{v}</div>
                  </div>
                ))}
              </div>
              <div style={{ background: T.ivory, border: `1px solid ${T.borderCream}`, borderRadius: 16, padding: 28 }}>
                <div style={{ fontSize: 16, fontWeight: 500, color: T.nearBlack, fontFamily: "Georgia, serif", marginBottom: 20 }}>Plan Distribution</div>
                {[["Free", adminStats.free_users, T.oliveGray], ["Pro", adminStats.pro_users, T.terracotta], ["Enterprise", adminStats.enterprise_users, T.charcoalWarm]].map(([plan, count, color]) => (
                  <div key={plan} style={{ marginBottom: 16 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                      <span style={{ fontSize: 14, color: T.charcoalWarm }}>{plan}</span>
                      <span style={{ fontSize: 14, color: T.stoneGray }}>{count} ({adminStats.total_users > 0 ? Math.round(count / adminStats.total_users * 100) : 0}%)</span>
                    </div>
                    <div style={{ height: 8, background: T.warmSand, borderRadius: 4, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${adminStats.total_users > 0 ? (count / adminStats.total_users * 100) : 0}%`, background: color, borderRadius: 4, transition: "width 0.5s ease" }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {adminTab === "users" && (
            <div>
              <div style={{ marginBottom: 32 }}>
                <div style={{ fontSize: 12, color: T.terracotta, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 12 }}>Users</div>
                <h1 style={{ fontSize: 48, fontWeight: 500, color: T.nearBlack, margin: 0, fontFamily: "Georgia, serif", letterSpacing: "-1px" }}>All Users</h1>
              </div>
              <div style={{ background: T.ivory, border: `1px solid ${T.borderCream}`, borderRadius: 16, overflow: "hidden" }}>
                <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 1fr 1.5fr", padding: "12px 24px", background: T.warmSand, borderBottom: `1px solid ${T.borderCream}` }}>
                  {["Email", "Plan", "Scans", "Expires", "Last Login", "Actions"].map(h => (
                    <div key={h} style={{ fontSize: 11, color: T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", fontWeight: 500 }}>{h}</div>
                  ))}
                </div>
                {adminUsers.length === 0 && <div style={{ padding: "40px", textAlign: "center", color: T.stoneGray }}>No users yet</div>}
                {adminUsers.map((u, i) => (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 1fr 1.5fr", padding: "16px 24px", borderBottom: i < adminUsers.length - 1 ? `1px solid ${T.borderCream}` : "none", alignItems: "center" }}>
                    <div>
                      <div style={{ fontSize: 14, color: T.nearBlack, fontWeight: 500 }}>{u.email}</div>
                      <div style={{ fontSize: 11, color: T.stoneGray, marginTop: 2 }}>ID: {u.id} · {u.monthly_scan_count || 0} scans this month</div>
                    </div>
                    <span style={{ fontSize: 12, padding: "3px 10px", background: u.plan === "PRO" ? "rgba(201,100,66,0.1)" : u.plan === "ENTERPRISE" ? "rgba(77,76,72,0.1)" : T.warmSand, border: `1px solid ${u.plan === "PRO" ? "rgba(201,100,66,0.3)" : T.borderWarm}`, color: u.plan === "PRO" ? T.terracotta : T.charcoalWarm, borderRadius: 20, fontWeight: 500, display: "inline-block" }}>
                      {u.plan || "FREE"}
                    </span>
                    <div style={{ fontSize: 14, color: T.charcoalWarm }}>{u.scan_count || 0}</div>
                    <div style={{ fontSize: 12, color: T.stoneGray }}>{u.plan_expires ? u.plan_expires.slice(0, 10) : "—"}</div>
                    <div style={{ fontSize: 12, color: T.stoneGray }}>{u.last_login ? u.last_login.slice(0, 10) : "Never"}</div>
                    <div style={{ display: "flex", gap: 6 }}>
                    <button onClick={() => deleteUser(u.id, u.email)}
  style={{ padding: "4px 8px", background: "rgba(181,51,51,0.1)", border: "1px solid rgba(181,51,51,0.3)", borderRadius: 6, color: T.errorCrimson, cursor: "pointer", fontSize: 10, fontFamily: "inherit", fontWeight: 500, marginRight: 4 }}>
  Del
</button>
                      {["FREE", "PRO", "ENTERPRISE"].map(plan => (
                        <button key={plan} onClick={() => updateUserPlan(u.id, plan)}
                          style={{ padding: "4px 8px", background: (u.plan || "FREE") === plan ? T.terracotta : T.warmSand, border: `1px solid ${(u.plan || "FREE") === plan ? T.terracotta : T.borderWarm}`, borderRadius: 6, color: (u.plan || "FREE") === plan ? T.ivory : T.charcoalWarm, cursor: "pointer", fontSize: 10, fontFamily: "inherit", fontWeight: 500 }}>
                          {plan === "FREE" ? "Free" : plan === "PRO" ? "Pro" : "Ent"}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {adminTab === "scans" && (
            <div>
              <div style={{ marginBottom: 32 }}>
                <div style={{ fontSize: 12, color: T.terracotta, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 12 }}>Activity</div>
                <h1 style={{ fontSize: 48, fontWeight: 500, color: T.nearBlack, margin: 0, fontFamily: "Georgia, serif", letterSpacing: "-1px" }}>All Scans</h1>
              </div>
              <div style={{ background: T.ivory, border: `1px solid ${T.borderCream}`, borderRadius: 16, overflow: "hidden" }}>
                <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1.5fr", padding: "12px 24px", background: T.warmSand, borderBottom: `1px solid ${T.borderCream}` }}>
                  {["Target", "Type", "User", "Date"].map(h => (
                    <div key={h} style={{ fontSize: 11, color: T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", fontWeight: 500 }}>{h}</div>
                  ))}
                </div>
                {adminScans.length === 0 && <div style={{ padding: "40px", textAlign: "center", color: T.stoneGray }}>No scans yet</div>}
                {adminScans.map((s, i) => (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1.5fr", padding: "14px 24px", borderBottom: i < adminScans.length - 1 ? `1px solid ${T.borderCream}` : "none", alignItems: "center" }}>
                    <div style={{ fontSize: 14, color: T.nearBlack, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.target}</div>
                    <span style={{ fontSize: 11, padding: "2px 8px", background: T.warmSand, border: `1px solid ${T.borderWarm}`, color: T.charcoalWarm, borderRadius: 20, textTransform: "uppercase", letterSpacing: "0.3px", display: "inline-block" }}>{s.type}</span>
                    <div style={{ fontSize: 13, color: T.oliveGray }}>{s.user || "Anonymous"}</div>
                    <div style={{ fontSize: 12, color: T.stoneGray }}>{s.date?.slice(0, 16).replace("T", " ")}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>
      </div>
    );
  }

  // ── MAIN DASHBOARD ──
  return (
    <div style={{ minHeight: "100vh", background: T.parchment, fontFamily: "system-ui, sans-serif" }}>
      {showUpgrade && <UpgradeModal />}

      {/* NAVBAR */}
      <nav style={{ position: "sticky", top: 0, zIndex: 100, background: T.ivory, borderBottom: `1px solid ${T.borderCream}`, boxShadow: "rgba(0,0,0,0.04) 0px 2px 12px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "0 32px", display: "flex", alignItems: "center", height: 60, justifyContent: "space-between" }}>
          <div style={{ fontSize: 22, fontWeight: 500, fontFamily: "Georgia, serif", color: T.nearBlack, cursor: "pointer" }} onClick={() => setActivePage("scan")}>
            Phoenix <span style={{ color: T.terracotta }}>AI</span>
          </div>
          <div style={{ display: "flex", gap: 4 }}>
            {[{ id: "scan", label: "Scanner" }, { id: "history", label: "History" }, { id: "company", label: "Company" }, { id: "plans", label: "Plans" }].map(item => (
              <button key={item.id} onClick={() => { setActivePage(item.id); if (item.id === "history") loadHistory(); }}
                style={{ padding: "8px 16px", background: activePage === item.id ? T.warmSand : "transparent", border: "none", borderRadius: 8, color: activePage === item.id ? T.nearBlack : T.oliveGray, cursor: "pointer", fontSize: 15, fontFamily: "inherit", fontWeight: activePage === item.id ? 500 : 400, transition: "all 0.15s" }}>
                {item.label}
              </button>
            ))}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            {userPlan?.toUpperCase() === "FREE" && (
              <div style={{ fontSize: 12, color: T.stoneGray, background: T.parchment, border: `1px solid ${T.borderWarm}`, borderRadius: 20, padding: "4px 12px" }}>
                <span style={{ color: monthlyScans >= 3 ? T.errorCrimson : T.terracotta, fontWeight: 500 }}>{monthlyScans}</span>
                <span>/3 scans</span>
              </div>
            )}
            {(userPlan?.toUpperCase() === "PRO") && (
              <div style={{ fontSize: 11, color: T.terracotta, background: "rgba(201,100,66,0.08)", border: `1px solid rgba(201,100,66,0.2)`, borderRadius: 20, padding: "4px 12px", fontWeight: 500 }}>
                ✓ Verified by Phoenix AI
              </div>
            )}
            <span style={{ fontSize: 11, padding: "3px 10px", background: T.warmSand, border: `1px solid ${T.borderWarm}`, color: T.charcoalWarm, borderRadius: 20, fontWeight: 500 }}>{userPlan.toUpperCase()}</span>
            <button onClick={() => { setUser(null); setPage("login"); setResult(null); }}
              style={{ padding: "7px 16px", background: "transparent", border: `1px solid ${T.borderWarm}`, borderRadius: 8, color: T.oliveGray, cursor: "pointer", fontSize: 14, fontFamily: "inherit" }}>
              Sign out
            </button>
          </div>
        </div>
      </nav>

      <main style={{ maxWidth: 1200, margin: "0 auto", padding: "48px 32px" }}>

        {/* SCANNER */}
        {activePage === "scan" && (
          <div>
            <div style={{ marginBottom: 48, borderBottom: `1px solid ${T.borderCream}`, paddingBottom: 40 }}>
              <div style={{ fontSize: 12, color: T.terracotta, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 12 }}>Security Scanner</div>
              <h1 style={{ fontSize: 52, fontWeight: 500, color: T.nearBlack, margin: 0, marginBottom: 16, fontFamily: "Georgia, serif", lineHeight: 1.15, letterSpacing: "-1px" }}>
                Find vulnerabilities<br />before attackers do.
              </h1>
              <p style={{ fontSize: 18, color: T.oliveGray, margin: 0, lineHeight: 1.6, maxWidth: 520 }}>
                AI-powered scanning across URLs, code, APIs, and live applications.
              </p>
            </div>

            {/* Scan limit warning */}
            {userPlan === "Free" && monthlyScans >= 2 && monthlyScans < 3 && (
              <div style={{ background: "rgba(201,100,66,0.06)", border: `1px solid rgba(201,100,66,0.2)`, borderRadius: 12, padding: "14px 20px", marginBottom: 24, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ fontSize: 14, color: T.charcoalWarm }}>⚠️ You have <strong>1 scan remaining</strong> this month on Free plan.</div>
                <button onClick={() => setActivePage("plans")} style={{ padding: "7px 16px", background: T.terracotta, border: "none", borderRadius: 8, color: T.ivory, cursor: "pointer", fontSize: 13, fontFamily: "inherit", fontWeight: 500 }}>Upgrade →</button>
              </div>
            )}

            {/* Tabs */}
            <div style={{ display: "flex", marginBottom: 32, border: `1px solid ${T.borderWarm}`, borderRadius: 12, overflow: "hidden", background: T.ivory }}>
              {SCAN_TABS.map(([tab, label]) => {
                const locked = !canUseScanType(tab);
                return (
                  <button key={tab} onClick={() => { setScanTab(tab); setResult(null); setScanId(null); }}
                    style={{ flex: 1, padding: "14px 8px", background: scanTab === tab ? T.nearBlack : "transparent", border: "none", borderRight: `1px solid ${T.borderWarm}`, color: scanTab === tab ? T.ivory : locked ? T.warmSand : T.oliveGray, cursor: "pointer", fontSize: 13, fontFamily: "inherit", fontWeight: scanTab === tab ? 500 : 400, transition: "all 0.15s", whiteSpace: "nowrap", position: "relative" }}>
                    {label}{locked && " 🔒"}
                  </button>
                );
              })}
            </div>

            {/* Input */}
            {!loading && (
              <div style={{ background: T.ivory, border: `1px solid ${T.borderWarm}`, borderRadius: 16, padding: 36, marginBottom: 36, boxShadow: "rgba(0,0,0,0.03) 0px 4px 24px" }}>
                <div style={{ fontSize: 12, color: T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 20 }}>
                  {SCAN_TABS.find(t => t[0] === scanTab)?.[2]}
                </div>

                {(scanTab === "url" || scanTab === "api") && (<>
                  <label style={labelStyle}>{scanTab === "api" ? "API Base URL" : "Target URL"}</label>
                  <input value={url} onChange={e => setUrl(e.target.value)} placeholder={scanTab === "api" ? "https://api.example.com" : "https://example.com"} style={{ ...inputStyle, fontSize: 16, marginBottom: 0 }} />
                </>)}

                {scanTab === "code" && (<>
                  <label style={labelStyle}>Source Code</label>
                  <textarea value={code} onChange={e => setCode(e.target.value)} placeholder="// Paste source code..." rows={12} style={{ ...inputStyle, marginBottom: 0, resize: "vertical", lineHeight: 1.7, fontFamily: "monospace", fontSize: 13 }} />
                </>)}

                {scanTab === "zip" && (<>
                  <label style={labelStyle}>Upload ZIP Archive</label>
                  <div style={{ border: `2px dashed ${T.borderWarm}`, borderRadius: 12, padding: "48px", textAlign: "center", cursor: "pointer", background: T.parchment }} onClick={() => document.getElementById("zipInput").click()}>
                    <div style={{ fontSize: 36, marginBottom: 12 }}>📦</div>
                    <div style={{ fontSize: 16, color: T.charcoalWarm, fontFamily: "Georgia, serif", marginBottom: 6 }}>{zipFile ? zipFile.name : "Click to select ZIP"}</div>
                    <div style={{ fontSize: 13, color: T.stoneGray }}>Python, JS, PHP, Java, Go, TypeScript</div>
                    <input id="zipInput" type="file" accept=".zip" style={{ display: "none" }} onChange={e => setZipFile(e.target.files[0])} />
                  </div>
                  {zipFile && <div style={{ marginTop: 12, padding: "10px 16px", background: T.warmSand, border: `1px solid ${T.borderWarm}`, borderRadius: 8, display: "flex", justifyContent: "space-between" }}><span style={{ fontSize: 14, color: T.charcoalWarm }}>📦 {zipFile.name}</span><span style={{ fontSize: 12, color: T.stoneGray }}>{(zipFile.size / 1024).toFixed(1)} KB</span></div>}
                </>)}

                {scanTab === "threat" && (<>
                  <label style={labelStyle}>Target URL or IP</label>
                  <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com or 8.8.8.8" style={{ ...inputStyle, fontSize: 16, marginBottom: 12 }} />
                  <div style={{ padding: "12px 16px", background: T.parchment, border: `1px solid ${T.borderCream}`, borderRadius: 10, fontSize: 13, color: T.oliveGray }}>
                    AbuseIPDB · CVE Database · Blacklist · SSL · Ports · Subdomains
                  </div>
                </>)}

                {scanTab === "live" && (<>
                  <label style={labelStyle}>Target App URL</label>
                  <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" style={{ ...inputStyle, fontSize: 16 }} />
                  <label style={labelStyle}>Login URL <span style={{ textTransform: "none", fontSize: 11 }}>(optional)</span></label>
                  <input value={loginUrl} onChange={e => setLoginUrl(e.target.value)} placeholder="https://example.com/login" style={inputStyle} />
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                    <div><label style={labelStyle}>Email</label><input value={loginEmail} onChange={e => setLoginEmail(e.target.value)} placeholder="admin@example.com" style={{ ...inputStyle, marginBottom: 0 }} /></div>
                    <div><label style={labelStyle}>Password</label><input value={loginPass} onChange={e => setLoginPass(e.target.value)} placeholder="••••••••" type="password" style={{ ...inputStyle, marginBottom: 0 }} /></div>
                  </div>
                </>)}

                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 24, paddingTop: 24, borderTop: `1px solid ${T.borderCream}` }}>
                  {userPlan?.toUpperCase() === "FREE" && (
                    <div style={{ fontSize: 13, color: T.stoneGray }}>
                      {3 - monthlyScans} scan{3 - monthlyScans !== 1 ? "s" : ""} remaining this month
                    </div>
                  )}
                  <div style={{ marginLeft: "auto" }}>
                    {isLimitReached() ? (
                      <button onClick={() => { setUpgradeReason("limit"); setShowUpgrade(true); }}
                        style={{ padding: "12px 32px", background: T.terracotta, border: "none", borderRadius: 10, color: T.ivory, fontSize: 15, fontWeight: 500, cursor: "pointer", fontFamily: "Georgia, serif" }}>
                        Upgrade to scan →
                      </button>
                    ) : (
                      <button onClick={submitScan}
                        style={{ padding: "12px 32px", background: T.terracotta, border: "none", borderRadius: 10, color: T.ivory, fontSize: 15, fontWeight: 500, cursor: "pointer", fontFamily: "Georgia, serif", transition: "all 0.2s" }}>
                        Start scan →
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* LOADING */}
            {loading && (
              <div style={{ background: T.ivory, border: `1px solid ${T.borderWarm}`, borderRadius: 16, padding: "48px 40px", marginBottom: 32, textAlign: "center", boxShadow: "rgba(0,0,0,0.03) 0px 4px 24px" }}>
                <div style={{ display: "flex", justifyContent: "center", gap: 10, marginBottom: 32 }}>
                  {[0, 1, 2, 3, 4].map(i => (
                    <div key={i} style={{ width: 10, height: 10, borderRadius: "50%", background: T.terracotta, animation: "bounce 1.2s ease-in-out infinite", animationDelay: `${i * 0.15}s` }} />
                  ))}
                </div>
                <div style={{ fontSize: 22, fontWeight: 500, color: T.nearBlack, fontFamily: "Georgia, serif", marginBottom: 8 }}>Scanning in progress</div>
                <div style={{ fontSize: 15, color: T.terracotta, marginBottom: 32, minHeight: 24, fontFamily: "system-ui" }}>{loadingMsg}</div>
                <div style={{ maxWidth: 400, margin: "0 auto 12px", height: 6, background: T.warmSand, borderRadius: 3, overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${loadingProgress}%`, background: `linear-gradient(90deg, ${T.terracotta}, ${T.coral})`, borderRadius: 3, transition: "width 0.8s ease" }} />
                </div>
                <div style={{ fontSize: 13, color: T.stoneGray }}>{Math.round(loadingProgress)}% complete · This may take 30–60 seconds</div>
              </div>
            )}

            {/* RESULTS */}
            {result && !loading && (
              <div>
                {result.scanned_files?.length > 0 && (
                  <div style={{ background: T.ivory, border: `1px solid ${T.borderWarm}`, borderRadius: 12, padding: 20, marginBottom: 20 }}>
                    <div style={{ fontSize: 11, color: T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 12 }}>Scanned Files ({result.scanned_files.length})</div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                      {result.scanned_files.map((f, i) => <span key={i} style={{ fontSize: 12, padding: "3px 10px", background: T.warmSand, border: `1px solid ${T.borderWarm}`, borderRadius: 20, color: T.charcoalWarm }}>{f}</span>)}
                    </div>
                  </div>
                )}

                {result.intel && (
                  <div style={{ background: T.nearBlack, border: `1px solid ${T.borderDark}`, borderRadius: 16, padding: 28, marginBottom: 24 }}>
                    <div style={{ fontSize: 11, color: T.terracotta, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 20 }}>Threat Intelligence</div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(150px,1fr))", gap: 16, marginBottom: result.intel.subdomains?.length > 0 ? 20 : 0 }}>
                      {[["IP", result.intel.ip], ["Country", result.intel.country], ["ISP", result.intel.isp], ["Abuse Score", (result.intel.abuse_score ?? 0) + "/100"], ["Blacklisted", result.intel.blacklisted ? "YES ⚠" : "Clean ✓"], ["Server", result.intel.server || "—"]].filter(([, v]) => v !== undefined && v !== null).map(([l, v]) => (
                        <div key={l}><div style={{ fontSize: 10, color: T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 4 }}>{l}</div><div style={{ fontSize: 15, color: T.ivory, fontWeight: 500, fontFamily: "Georgia, serif" }}>{String(v)}</div></div>
                      ))}
                    </div>
                    {result.intel.subdomains?.length > 0 && (
                      <div style={{ borderTop: `1px solid ${T.borderDark}`, paddingTop: 16 }}>
                        <div style={{ fontSize: 11, color: T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 10 }}>Subdomains ({result.intel.subdomains.length})</div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                          {result.intel.subdomains.map((s, i) => <span key={i} style={{ fontSize: 12, padding: "4px 12px", background: "rgba(250,249,245,0.06)", border: `1px solid ${T.borderDark}`, borderRadius: 20, color: T.warmSilver }}>{s.subdomain} <span style={{ color: T.stoneGray, fontSize: 10 }}>{s.ip}</span></span>)}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16, marginBottom: 24 }}>
                  {[["Risk Score", (result.risk_score ?? 0) + "/100", (result.risk_score ?? 0) > 70 ? T.errorCrimson : "#2d6a4f"], ["Total Found", result.total_findings ?? 0, T.charcoalWarm], ["High / Critical", result.high ?? 0, T.terracotta], ["Medium", result.medium ?? 0, T.oliveGray]].map(([l, v, c]) => (
                    <div key={l} style={{ background: T.ivory, border: `1px solid ${T.borderWarm}`, borderRadius: 14, padding: "20px 24px", boxShadow: "rgba(0,0,0,0.04) 0px 2px 12px" }}>
                      <div style={{ fontSize: 11, color: T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 10 }}>{l}</div>
                      <div style={{ fontSize: 36, fontWeight: 500, color: c, fontFamily: "Georgia, serif", lineHeight: 1 }}>{v}</div>
                    </div>
                  ))}
                </div>

                {/* Download - only full for Pro+ */}
                {userPlan === "Free" ? (
                  <div style={{ background: T.parchment, border: `1px solid ${T.borderWarm}`, borderRadius: 12, padding: "20px 24px", marginBottom: 24, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                      <div style={{ fontSize: 14, color: T.charcoalWarm, fontWeight: 500, marginBottom: 4 }}>Quick Report Available</div>
                      <div style={{ fontSize: 13, color: T.stoneGray }}>Upgrade to Pro for full PDF reports with AI analysis and PoC details.</div>
                    </div>
                    <div style={{ display: "flex", gap: 10 }}>
                      <button onClick={() => downloadReport(result, url || "Source Code", scanId)}
                        style={{ padding: "8px 16px", background: T.warmSand, border: `1px solid ${T.borderWarm}`, borderRadius: 8, color: T.charcoalWarm, cursor: "pointer", fontSize: 13, fontFamily: "inherit" }}>
                        Basic Report
                      </button>
                      <button onClick={() => { setUpgradeReason("limit"); setShowUpgrade(true); }}
                        style={{ padding: "8px 16px", background: T.terracotta, border: "none", borderRadius: 8, color: T.ivory, cursor: "pointer", fontSize: 13, fontFamily: "Georgia, serif", fontWeight: 500 }}>
                        Get Full PDF →
                      </button>
                    </div>
                  </div>
                ) : (
                  <button onClick={() => downloadReport(result, url || zipFile?.name || "Source Code", scanId)}
                    style={{ width: "100%", padding: "13px", background: T.warmSand, border: `1px solid ${T.borderWarm}`, borderRadius: 10, color: T.charcoalWarm, cursor: "pointer", fontSize: 14, fontFamily: "inherit", fontWeight: 500, marginBottom: 24 }}>
                    Download Full PDF Report
                  </button>
                )}

                {result.ai_explanation && (
                  <div style={{ background: T.nearBlack, border: `1px solid ${T.borderDark}`, borderRadius: 16, padding: 32, marginBottom: 24 }}>
                    <div style={{ fontSize: 11, color: T.terracotta, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 16 }}>AI Analysis</div>
                    <p style={{ fontSize: 16, color: T.warmSilver, lineHeight: 1.8, margin: 0, fontFamily: "Georgia, serif", fontStyle: "italic" }}>{result.ai_explanation}</p>
                  </div>
                )}

                <div style={{ fontSize: 11, color: T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 16 }}>Vulnerabilities ({result.total_findings})</div>
                {(result.findings ?? []).map((f, i) => (
                  <div key={i} style={{ background: T.ivory, borderLeft: `3px solid ${sColor(f.severity)}`, borderRadius: "0 12px 12px 0", padding: "20px 24px", marginBottom: 12, boxShadow: "rgba(0,0,0,0.03) 0px 2px 8px", border: `1px solid ${T.borderCream}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10, flexWrap: "wrap", gap: 10 }}>
                      <span style={{ fontSize: 16, color: T.nearBlack, fontWeight: 500, fontFamily: "Georgia, serif" }}>{f.type}</span>
                      <span style={{ fontSize: 11, padding: "3px 12px", background: T.warmSand, color: sColor(f.severity), border: `1px solid ${T.borderWarm}`, borderRadius: 20, fontWeight: 500, textTransform: "uppercase" }}>{f.severity}</span>
                    </div>
                    {f.file && <div style={{ fontSize: 12, color: T.stoneGray, marginBottom: 6, fontFamily: "monospace" }}>📁 {f.file}</div>}
                    <p style={{ fontSize: 14, color: T.oliveGray, margin: "0 0 8px", lineHeight: 1.6 }}>{f.detail}</p>
                    <p style={{ fontSize: 13, color: "#2d6a4f", margin: 0 }}>✓ {f.fix}</p>
                    {f.poc && userPlan !== "Free" && (
                      <div style={{ fontSize: 12, color: T.stoneGray, marginTop: 10, padding: "8px 12px", background: T.parchment, borderRadius: 8, lineHeight: 1.6, fontFamily: "monospace", border: `1px solid ${T.borderCream}` }}>{f.poc}</div>
                    )}
                    {f.poc && userPlan === "Free" && (
                      <div style={{ fontSize: 12, color: T.warmSilver, marginTop: 10, padding: "8px 12px", background: T.warmSand, borderRadius: 8, border: `1px solid ${T.borderWarm}` }}>
                        🔒 PoC details available on Pro plan
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* HISTORY */}
        {activePage === "history" && (
          <div>
            <div style={{ marginBottom: 40, borderBottom: `1px solid ${T.borderCream}`, paddingBottom: 32 }}>
              <div style={{ fontSize: 12, color: T.terracotta, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 12 }}>History</div>
              <h1 style={{ fontSize: 52, fontWeight: 500, color: T.nearBlack, margin: 0, fontFamily: "Georgia, serif", letterSpacing: "-1px" }}>Past scans</h1>
              <p style={{ fontSize: 16, color: T.oliveGray, marginTop: 12 }}>{history.length} total scans</p>
            </div>
            {history.length === 0 && <div style={{ textAlign: "center", padding: "80px 0" }}><div style={{ fontSize: 48, marginBottom: 16 }}>🔍</div><p style={{ fontSize: 18, color: T.oliveGray, fontFamily: "Georgia, serif" }}>No scans yet.</p></div>}
            {history.map((scan, i) => (
              <div key={i} style={{ background: T.ivory, border: `1px solid ${T.borderCream}`, borderRadius: 14, padding: "20px 28px", marginBottom: 12, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16 }}>
                <div>
                  <div style={{ fontSize: 16, color: T.nearBlack, fontWeight: 500, fontFamily: "Georgia, serif", marginBottom: 4 }}>{scan.target}</div>
                  <div style={{ fontSize: 13, color: T.stoneGray }}>{scan.created_at?.slice(0, 16).replace("T", " ")} · {scan.scan_type?.toUpperCase()}</div>
                </div>
                <div style={{ display: "flex", gap: 20, alignItems: "center" }}>
                  {scan.result && (<>
                    <div style={{ textAlign: "right" }}>
                      <div style={{ fontSize: 28, fontWeight: 500, color: (scan.result.risk_score ?? 0) > 70 ? T.errorCrimson : "#2d6a4f", fontFamily: "Georgia, serif", lineHeight: 1 }}>{scan.result.risk_score ?? 0}</div>
                      <div style={{ fontSize: 10, color: T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", marginTop: 2 }}>Risk</div>
                    </div>
                    <div style={{ width: 1, height: 40, background: T.borderCream }} />
                    <div><div style={{ fontSize: 13, color: T.terracotta }}>H: {scan.result.high ?? 0}</div><div style={{ fontSize: 13, color: T.oliveGray }}>M: {scan.result.medium ?? 0}</div></div>
                    <button onClick={() => downloadReport(scan.result, scan.target, scan.id)}
                      style={{ padding: "8px 20px", background: T.warmSand, border: `1px solid ${T.borderWarm}`, color: T.charcoalWarm, borderRadius: 8, cursor: "pointer", fontSize: 13, fontFamily: "inherit", fontWeight: 500 }}>
                      {userPlan === "Free" ? "Basic Report" : "Download PDF"}
                    </button>
                  </>)}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* COMPANY */}
        {activePage === "company" && (
          <div>
            <div style={{ marginBottom: 40, borderBottom: `1px solid ${T.borderCream}`, paddingBottom: 32 }}>
              <div style={{ fontSize: 12, color: T.terracotta, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 12 }}>Company</div>
              <h1 style={{ fontSize: 52, fontWeight: 500, color: T.nearBlack, margin: 0, fontFamily: "Georgia, serif", letterSpacing: "-1px" }}>Security dashboard</h1>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 16, marginBottom: 32 }}>
              {[["Total Scans", history.length || 0], ["Critical Issues", history.filter(s => (s.result?.high ?? 0) > 0).length || 0], ["Assets", 3], ["Team", userPlan === "Enterprise" || userPlan === "ENTERPRISE" ? "Up to 5" : 1], ["Plan", userPlan], ["Reports", history.length || 0]].map(([l, v]) => (
                <div key={l} style={{ background: T.ivory, border: `1px solid ${T.borderCream}`, borderRadius: 14, padding: "24px 28px" }}>
                  <div style={{ fontSize: 11, color: T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 10 }}>{l}</div>
                  <div style={{ fontSize: 36, fontWeight: 500, color: T.nearBlack, fontFamily: "Georgia, serif", lineHeight: 1 }}>{v}</div>
                </div>
              ))}
            </div>
            <div style={{ background: T.ivory, border: `1px solid ${T.borderCream}`, borderRadius: 16, padding: 28, marginBottom: 20 }}>
              <div style={{ fontSize: 16, fontWeight: 500, color: T.nearBlack, fontFamily: "Georgia, serif", marginBottom: 20 }}>Monitored Assets</div>
              {["https://globalsecurelayerx.in", "https://api.globalsecurelayerx.in", "https://admin.globalsecurelayerx.in"].map((a, i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 0", borderBottom: i < 2 ? `1px solid ${T.borderCream}` : "none" }}>
                  <span style={{ fontSize: 15, color: T.charcoalWarm, fontFamily: "Georgia, serif" }}>{a}</span>
                  <div style={{ display: "flex", gap: 10 }}>
                    <span style={{ fontSize: 11, padding: "4px 12px", background: "#f0fdf4", border: "1px solid #bbf7d0", color: "#166534", borderRadius: 20 }}>Active</span>
                    <button onClick={() => { setUrl(a); setActivePage("scan"); setScanTab("url"); }}
                      style={{ padding: "7px 16px", background: T.terracotta, border: "none", color: T.ivory, borderRadius: 8, cursor: "pointer", fontSize: 13, fontFamily: "inherit", fontWeight: 500 }}>
                      Scan now
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Enterprise team section */}
            {(userPlan === "Enterprise" || userPlan === "ENTERPRISE") && (
              <div style={{ background: T.ivory, border: `1px solid ${T.borderCream}`, borderRadius: 16, padding: 28 }}>
                <div style={{ fontSize: 16, fontWeight: 500, color: T.nearBlack, fontFamily: "Georgia, serif", marginBottom: 8 }}>Team Members</div>
                <div style={{ fontSize: 13, color: T.stoneGray, marginBottom: 20 }}>You can add up to 5 team members on Enterprise plan.</div>
                <button style={{ padding: "10px 20px", background: T.terracotta, border: "none", borderRadius: 8, color: T.ivory, cursor: "pointer", fontSize: 14, fontFamily: "Georgia, serif", fontWeight: 500 }}>
                  + Invite Team Member
                </button>
              </div>
            )}
          </div>
        )}

        {/* PLANS */}
        {activePage === "plans" && (
          <div>
            <div style={{ marginBottom: 56, borderBottom: `1px solid ${T.borderCream}`, paddingBottom: 40, textAlign: "center" }}>
              <div style={{ fontSize: 12, color: T.terracotta, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 12 }}>Pricing</div>
              <h1 style={{ fontSize: 52, fontWeight: 500, color: T.nearBlack, margin: 0, fontFamily: "Georgia, serif", letterSpacing: "-1px" }}>Simple, honest pricing.</h1>
              <p style={{ fontSize: 18, color: T.oliveGray, marginTop: 16 }}>Start free. Scale when you're ready.</p>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 24, marginBottom: 48 }}>
              {PLANS.map((plan, i) => (
                <div key={plan.name} style={{ background: plan.popular ? T.nearBlack : T.ivory, border: `2px solid ${userPlan === plan.name ? T.terracotta : plan.popular ? T.borderDark : T.borderWarm}`, borderRadius: 20, padding: 36, position: "relative", opacity: mounted ? 1 : 0, transform: mounted ? "translateY(0)" : "translateY(20px)", transition: `all 0.4s ease ${i * 0.08}s`, boxShadow: plan.popular ? "rgba(0,0,0,0.12) 0px 8px 32px" : "rgba(0,0,0,0.04) 0px 2px 12px" }}>
                  {plan.popular && <div style={{ position: "absolute", top: -12, left: "50%", transform: "translateX(-50%)", background: T.terracotta, color: T.ivory, fontSize: 11, fontWeight: 500, padding: "4px 16px", borderRadius: 20, letterSpacing: "0.5px", whiteSpace: "nowrap", textTransform: "uppercase" }}>Most popular</div>}
                  {userPlan === plan.name && <div style={{ position: "absolute", top: 16, right: 16, fontSize: 11, color: T.terracotta, fontWeight: 500, background: "rgba(201,100,66,0.1)", padding: "3px 10px", borderRadius: 20 }}>Current</div>}
                  <div style={{ fontSize: 11, color: plan.popular ? T.terracotta : T.stoneGray, letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 16 }}>{plan.name}</div>
                  <div style={{ fontSize: 48, fontWeight: 500, color: plan.popular ? T.ivory : T.nearBlack, fontFamily: "Georgia, serif", lineHeight: 1, marginBottom: 4 }}>{plan.price}</div>
                  <div style={{ fontSize: 14, color: plan.popular ? T.stoneGray : T.oliveGray, marginBottom: 28 }}>{plan.period}</div>
                  <div style={{ width: "100%", height: 1, background: plan.popular ? T.borderDark : T.borderCream, marginBottom: 24 }} />
                  {plan.features.map((f, j) => (
                    <div key={j} style={{ display: "flex", gap: 12, marginBottom: 12, fontSize: 14, color: plan.popular ? T.warmSilver : T.oliveGray }}>
                      <span style={{ color: T.terracotta, flexShrink: 0 }}>✓</span>{f}
                    </div>
                  ))}
                  <button onClick={() => { if (userPlan !== plan.name) alert(`Contact us to upgrade to ${plan.name} plan!`); }}
                    style={{ width: "100%", marginTop: 28, padding: "13px", background: userPlan === plan.name ? T.terracotta : plan.popular ? "rgba(250,249,245,0.08)" : T.warmSand, border: `1px solid ${userPlan === plan.name ? T.terracotta : plan.popular ? T.borderDark : T.borderWarm}`, borderRadius: 10, color: userPlan === plan.name ? T.ivory : plan.popular ? T.ivory : T.charcoalWarm, cursor: userPlan === plan.name ? "default" : "pointer", fontSize: 15, fontFamily: "Georgia, serif", fontWeight: 500 }}>
                    {userPlan === plan.name ? "✓ Current plan" : "Get started →"}
                  </button>
                </div>
              ))}
            </div>
            <div style={{ background: T.nearBlack, border: `1px solid ${T.borderDark}`, borderRadius: 20, padding: "48px 56px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 24 }}>
              <div>
                <h2 style={{ fontSize: 32, fontWeight: 500, color: T.ivory, margin: 0, marginBottom: 8, fontFamily: "Georgia, serif" }}>Need a custom plan?</h2>
                <p style={{ fontSize: 16, color: T.warmSilver, margin: 0 }}>Custom limits, white-label, or on-premise.</p>
              </div>
              <button style={{ padding: "13px 28px", background: T.terracotta, border: "none", borderRadius: 10, color: T.ivory, fontSize: 15, fontFamily: "Georgia, serif", fontWeight: 500, cursor: "pointer" }}>Contact sales →</button>
            </div>
          </div>
        )}

      </main>

      <style>{`
        @keyframes bounce {
          0%, 100% { transform: translateY(0); opacity: 0.4; }
          50% { transform: translateY(-12px); opacity: 1; }
        }
      `}</style>
    </div>
  );
}