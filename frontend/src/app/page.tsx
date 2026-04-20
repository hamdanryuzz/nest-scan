"use client";
import { useState } from "react";

const API = "http://localhost:4000";
type Sev = "critical" | "warning" | "info";
type Confidence = "high" | "medium" | "low";
type Tab = "all" | "security" | "quality" | "endpoints" | "modules";

interface Finding {
  id: string; analyzer: string; severity: Sev; title: string;
  description: string; file: string; line?: number; code?: string; suggestion?: string;
  confidence: Confidence; confidenceScore: number; confidenceReason?: string;
}
interface Endpoint { method: string; path: string; controller: string; handler: string; guards: string[]; dtoName?: string; params: string[]; hasBody: boolean; line: number; }
interface Mod { name: string; path: string; hasController: boolean; hasService: boolean; hasModule: boolean; hasDtoFolder: boolean; hasSpecFile: boolean; }
interface AiFinding { originalId: string; aiSeverity: string; explanation: string; fixCode: string; impact: string; priority: number; }
interface AiReview { executiveSummary: string; overallRiskScore: number; overallRiskLevel: string; prioritizedFindings: AiFinding[]; }
interface Report {
  id: string; repoUrl: string; branch: string; scannedAt: string;
  summary: { critical: number; warning: number; info: number; totalFiles: number; totalModules: number; totalEndpoints: number; scanDurationMs: number; };
  findings: Finding[]; endpoints: Endpoint[]; modules: Mod[]; aiReview?: AiReview;
}

const SEC = ["auth-guard", "idor", "injection", "mass-assignment", "sensitive-data", "rate-limit"];

export default function Home() {
  const [url, setUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [pat, setPat] = useState("");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("all");
  const [open, setOpen] = useState<Set<string>>(new Set());

  const toggle = (id: string) => setOpen(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const scan = async () => {
    if (!url || !branch) return;
    setLoading(true); setError(""); setReport(null);
    try {
      const res = await fetch(`${API}/scanner/scan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: url, branch, pat: pat || undefined }),
      });
      if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.message || `HTTP ${res.status}`); }
      const data = await res.json();
      setReport(data);
      setTab("all");
    } catch (e: any) { setError(e.message); } finally { setLoading(false); }
  };

  const findings = report?.findings.filter(f => {
    if (tab === "security") return SEC.includes(f.analyzer);
    if (tab === "quality") return !SEC.includes(f.analyzer);
    return true;
  }) || [];

  const getAiFinding = (id: string) => report?.aiReview?.prioritizedFindings?.find(a => a.originalId === id);
  const riskClass = (level: string) => level?.toLowerCase() || "medium";
  const confidenceLabel = (f: Finding) => `${f.confidence.toUpperCase()} ${f.confidenceScore}`;

  return (
    <div className="shell">
      {/* Top Bar */}
      <div className="top-bar">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
        <h1>nest-scan</h1>
        <span className="tag">v2.0</span>
      </div>

      {/* Scan Form */}
      <div className="scan-card">
        <div className="field-grid" style={{gridTemplateColumns: '1fr 140px 1fr'}}>
          <div className="field">
            <label>Repository URL</label>
            <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://github.com/owner/repo" />
          </div>
          <div className="field">
            <label>Branch</label>
            <input value={branch} onChange={e => setBranch(e.target.value)} placeholder="main" />
          </div>
          <div className="field">
            <label>GitHub PAT</label>
            <input type="password" value={pat} onChange={e => setPat(e.target.value)} placeholder="Optional — for private repos" />
          </div>
        </div>
        <div className="btn-row">
          <button className={`btn-primary ${loading ? "loading" : ""}`} onClick={scan} disabled={loading || !url || !branch}>
            {loading ? <><div className="spinner" /> Scanning...</> : "Run Scan"}
          </button>
        </div>
      </div>

      {error && <div className="error">✕ {error}</div>}

      {loading && (
        <div className="loading-state">
          <div className="loading-ring" />
          <div className="loading-text">Fetching & analyzing repository via GitHub API...</div>
        </div>
      )}

      {report && !loading && (
        <>
          {/* AI Risk Banner */}
          {report.aiReview && (
            <div className="risk-banner">
              <div className={`risk-score ${riskClass(report.aiReview.overallRiskLevel)}`}>
                {report.aiReview.overallRiskScore}
              </div>
              <div className="risk-body">
                <div className={`risk-level ${riskClass(report.aiReview.overallRiskLevel)}`}>
                  Risk: {report.aiReview.overallRiskLevel}
                </div>
                <div className="risk-summary">{report.aiReview.executiveSummary}</div>
              </div>
            </div>
          )}

          {/* Stats */}
          <div className="stat-row">
            <div className="stat"><div className="stat-num red">{report.summary.critical}</div><div className="stat-label">Critical</div></div>
            <div className="stat"><div className="stat-num orange">{report.summary.warning}</div><div className="stat-label">Warning</div></div>
            <div className="stat"><div className="stat-num blue">{report.summary.info}</div><div className="stat-label">Info</div></div>
            <div className="stat"><div className="stat-num default">{report.summary.totalEndpoints}</div><div className="stat-label">Endpoints</div></div>
            <div className="stat"><div className="stat-num default">{report.summary.totalModules}</div><div className="stat-label">Modules</div></div>
            <div className="stat"><div className="stat-num default">{report.summary.totalFiles}</div><div className="stat-label">Files</div></div>
          </div>

          <div className="scan-meta">
            {(report.summary.scanDurationMs / 1000).toFixed(1)}s · {new Date(report.scannedAt).toLocaleString()}
          </div>

          {/* Tabs */}
          <div className="tabs">
            {([
              ["all", "All Findings", report.findings.length, "o"],
              ["security", "Security", report.findings.filter(f => SEC.includes(f.analyzer)).length, "r"],
              ["quality", "Quality", report.findings.filter(f => !SEC.includes(f.analyzer)).length, "o"],
              ["endpoints", "Endpoints", report.endpoints.length, "b"],
              ["modules", "Modules", report.modules.length, "b"],
            ] as const).map(([key, label, count, color]) => (
              <button key={key} className={`tab-btn ${tab === key ? "active" : ""}`} onClick={() => setTab(key as Tab)}>
                {label}<span className={`tab-count ${color}`}>{count}</span>
              </button>
            ))}
          </div>

          {/* Findings */}
          {(tab === "all" || tab === "security" || tab === "quality") && (
            <div>
              {findings.length === 0 && <div style={{ textAlign: "center", padding: 40, color: "var(--text-2)" }}>No findings in this category.</div>}
              {findings.map(f => {
                const ai = getAiFinding(f.id);
                const isOpen = open.has(f.id);
                return (
                  <div key={f.id} className="finding">
                    <div className="finding-head" onClick={() => toggle(f.id)}>
                      <span className={`sev ${f.severity}`}>{f.severity}</span>
                      <span className="finding-title">{f.title}</span>
                      <span className="finding-tag">{f.analyzer}</span>
                      <span className={`finding-tag confidence ${f.confidence}`}>{confidenceLabel(f)}</span>
                      {ai && <span className="finding-tag" style={{background:"var(--purple-dim)",color:"var(--purple)"}}>AI P{ai.priority}</span>}
                      <span className={`finding-chevron ${isOpen ? "open" : ""}`}>▶</span>
                    </div>
                    {isOpen && (
                      <div className="finding-body">
                        <p className="finding-desc">{ai ? ai.explanation : f.description}</p>
                        {f.confidenceReason && <div className={`confidence-note ${f.confidence}`}>Confidence: {f.confidenceReason}</div>}
                        {f.file && <div className="finding-file">📄 {f.file}{f.line ? `:${f.line}` : ""}</div>}
                        {f.code && <pre className="code-block">{f.code}</pre>}
                        {ai?.fixCode && (
                          <div className="ai-fix">
                            <div className="fix-label">🤖 AI Suggested Fix</div>
                            <pre className="ai-fix-code">{ai.fixCode}</pre>
                          </div>
                        )}
                        {ai?.impact && <div className="ai-impact">⚡ Impact: {ai.impact}</div>}
                        {f.suggestion && !ai?.fixCode && (
                          <div className="fix-block"><div className="fix-label">💡 Suggestion</div>{f.suggestion}</div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Endpoints */}
          {tab === "endpoints" && (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Method</th><th>Path</th><th>Handler</th><th>Guard</th><th>DTO</th></tr></thead>
                <tbody>
                  {report.endpoints.map((ep, i) => (
                    <tr key={i}>
                      <td><span className={`badge ${ep.method.toLowerCase()}`}>{ep.method}</span></td>
                      <td>{ep.path}</td>
                      <td>{ep.handler}()</td>
                      <td>{ep.guards.length ? ep.guards.map((g, j) => <span key={j} className="badge guard">{g}</span>) : <span className="badge no-guard">NONE</span>}</td>
                      <td style={{ color: ep.dtoName ? "var(--text-0)" : "var(--text-2)" }}>{ep.dtoName || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Modules */}
          {tab === "modules" && (
            <div className="module-grid">
              {report.modules.map((m, i) => (
                <div key={i} className="module-card">
                  <div className="module-name">{m.name}</div>
                  <div className="module-path">{m.path}</div>
                  <div className="module-checks">
                    {([ ["Controller", m.hasController], ["Service", m.hasService], ["Module", m.hasModule], ["DTO", m.hasDtoFolder], ["Spec", m.hasSpecFile] ] as const).map(([label, ok], j) => (
                      <span key={j} className={`check ${ok ? "ok" : "miss"}`}>{ok ? "✓" : "✗"} {label}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
