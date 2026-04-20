"use client";

import { useState } from "react";

const API = "http://localhost:4000";

type Sev = "critical" | "warning" | "info";
type Confidence = "high" | "medium" | "low";
type Tab = "all" | "security" | "quality" | "endpoints" | "modules";
type ExportScope = "all" | "security" | "quality";
type AiValidationVerdict = "likely_true_positive" | "needs_manual_review" | "likely_false_positive";
type AiActionType = "explain" | "fix-patch" | "attack-scenario";

interface AiValidation {
  verdict: AiValidationVerdict;
  rationale: string;
  confidence: number;
}

interface Finding {
  id: string;
  analyzer: string;
  severity: Sev;
  title: string;
  description: string;
  file: string;
  line?: number;
  code?: string;
  suggestion?: string;
  confidence: Confidence;
  confidenceScore: number;
  confidenceReason?: string;
  aiValidation?: AiValidation;
}

interface Endpoint {
  method: string;
  path: string;
  controller: string;
  handler: string;
  guards: string[];
  dtoName?: string;
  params: string[];
  hasBody: boolean;
  line: number;
}

interface Mod {
  name: string;
  path: string;
  hasController: boolean;
  hasService: boolean;
  hasModule: boolean;
  hasDtoFolder: boolean;
  hasSpecFile: boolean;
}

interface AiFinding {
  originalId: string;
  aiSeverity: string;
  explanation: string;
  fixCode: string;
  impact: string;
  priority: number;
  reviewNotes?: string;
}

interface AiReview {
  executiveSummary: string;
  overallRiskScore: number;
  overallRiskLevel: string;
  prioritizedFindings: AiFinding[];
}

interface Report {
  id: string;
  repoUrl: string;
  branch: string;
  scannedAt: string;
  summary: {
    critical: number;
    warning: number;
    info: number;
    totalFiles: number;
    totalModules: number;
    totalEndpoints: number;
    scanDurationMs: number;
  };
  findings: Finding[];
  endpoints: Endpoint[];
  modules: Mod[];
  aiReview?: AiReview;
  aiEnabled: boolean;
}

interface AiActionResponse {
  reportId: string;
  findingId: string;
  action: AiActionType;
  title: string;
  content: string;
  generatedAt: string;
}

const SECURITY_ANALYZERS = [
  "auth-guard",
  "idor",
  "injection",
  "mass-assignment",
  "sensitive-data",
  "rate-limit",
];

const SEVERITY_OPTIONS: Sev[] = ["critical", "warning", "info"];
const EXPORT_SCOPE_LABELS: Record<ExportScope, string> = {
  all: "All Findings",
  security: "Security",
  quality: "Quality",
};

const EXPORT_PRESETS: Array<{ label: string; scope: ExportScope; severities: Sev[] }> = [
  { label: "Security Critical", scope: "security", severities: ["critical"] },
  { label: "Security Critical + Warning", scope: "security", severities: ["critical", "warning"] },
  { label: "Warning Only", scope: "all", severities: ["warning"] },
];
const AI_ACTION_LABELS: Record<AiActionType, string> = {
  explain: "Explain",
  "fix-patch": "Fix Patch",
  "attack-scenario": "Attack Scenario",
};
const AI_VALIDATION_LABELS: Record<AiValidationVerdict, string> = {
  likely_true_positive: "AI: likely true positive",
  needs_manual_review: "AI: needs manual review",
  likely_false_positive: "AI: likely false positive",
};

function filterFindingsByScope(findings: Finding[], scope: ExportScope): Finding[] {
  if (scope === "security") {
    return findings.filter(finding => SECURITY_ANALYZERS.includes(finding.analyzer));
  }

  if (scope === "quality") {
    return findings.filter(finding => !SECURITY_ANALYZERS.includes(finding.analyzer));
  }

  return findings;
}

function summarizeFindings(findings: Finding[]) {
  return {
    total: findings.length,
    critical: findings.filter(finding => finding.severity === "critical").length,
    warning: findings.filter(finding => finding.severity === "warning").length,
    info: findings.filter(finding => finding.severity === "info").length,
  };
}

function severityLabel(severity: Sev): string {
  return severity.toUpperCase();
}

function scopeLabel(scope: ExportScope): string {
  return EXPORT_SCOPE_LABELS[scope];
}

function fileNameSafe(value: string): string {
  return value.replace(/[^a-z0-9-]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase();
}

function copyTextFallback(text: string): boolean {
  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "true");
    textarea.style.position = "absolute";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(textarea);
    return copied;
  } catch {
    return false;
  }
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [pat, setPat] = useState("");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("all");
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [exportScope, setExportScope] = useState<ExportScope>("all");
  const [exportSeverities, setExportSeverities] = useState<Sev[]>(["critical", "warning", "info"]);
  const [exportStatus, setExportStatus] = useState("");
  const [aiActionLoading, setAiActionLoading] = useState<Record<string, AiActionType | undefined>>({});
  const [aiActionResults, setAiActionResults] = useState<Record<string, Partial<Record<AiActionType, AiActionResponse>>>>({});
  const [aiActionSelected, setAiActionSelected] = useState<Record<string, AiActionType | undefined>>({});
  const [aiActionErrors, setAiActionErrors] = useState<Record<string, string | undefined>>({});

  const toggle = (id: string) => {
    setOpen(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const getAiFinding = (id: string) =>
    report?.aiReview?.prioritizedFindings?.find(aiFinding => aiFinding.originalId === id);

  const riskClass = (level: string) => level?.toLowerCase() || "medium";
  const confidenceLabel = (finding: Finding) => `${finding.confidence.toUpperCase()} ${finding.confidenceScore}`;
  const aiValidationLabel = (validation: AiValidation) => AI_VALIDATION_LABELS[validation.verdict];

  const scan = async () => {
    if (!url || !branch) return;

    setLoading(true);
    setError("");
    setReport(null);
    setExportStatus("");

    try {
      const res = await fetch(`${API}/scanner/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: url, branch, pat: pat || undefined }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.message || `HTTP ${res.status}`);
      }

      const data = await res.json();
      setReport(data);
      setTab("all");
      setOpen(new Set());
      setExportScope("all");
      setExportSeverities(["critical", "warning", "info"]);
      setAiActionLoading({});
      setAiActionResults({});
      setAiActionSelected({});
      setAiActionErrors({});
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const findings = report?.findings.filter(finding => {
    if (tab === "security") return SECURITY_ANALYZERS.includes(finding.analyzer);
    if (tab === "quality") return !SECURITY_ANALYZERS.includes(finding.analyzer);
    return true;
  }) || [];

  const exportFindings = report
    ? filterFindingsByScope(report.findings, exportScope).filter(finding => exportSeverities.includes(finding.severity))
    : [];

  const exportSummary = summarizeFindings(exportFindings);
  const exportHasFindings = exportFindings.length > 0;

  const selectedSeverityText = exportSeverities.length === SEVERITY_OPTIONS.length
    ? "All severities"
    : exportSeverities.length > 0
      ? exportSeverities.map(severityLabel).join(", ")
      : "No severity selected";

  const toggleSeverity = (severity: Sev) => {
    setExportStatus("");
    setExportSeverities(prev =>
      prev.includes(severity)
        ? prev.filter(value => value !== severity)
        : [...prev, severity],
    );
  };

  const applyExportPreset = (scope: ExportScope, severities: Sev[]) => {
    setExportScope(scope);
    setExportSeverities(severities);
    setExportStatus("");
  };

  const buildExportDocument = (): string => {
    if (!report) return "";

    const lines: string[] = [
      "# nest-scan report",
      "",
      `Repository: ${report.repoUrl}`,
      `Branch: ${report.branch}`,
      `Scan ID: ${report.id}`,
      `Scanned At: ${new Date(report.scannedAt).toLocaleString()}`,
      "",
      "## Export Filter",
      "",
      `- Scope: ${scopeLabel(exportScope)}`,
      `- Severities: ${selectedSeverityText}`,
      "",
      "## Scan Summary",
      "",
      `- Critical: ${report.summary.critical}`,
      `- Warning: ${report.summary.warning}`,
      `- Info: ${report.summary.info}`,
      `- Total Files: ${report.summary.totalFiles}`,
      `- Total Modules: ${report.summary.totalModules}`,
      `- Total Endpoints: ${report.summary.totalEndpoints}`,
      `- Scan Duration (ms): ${report.summary.scanDurationMs}`,
      "",
      "## Exported Findings",
      "",
      `- Findings Exported: ${exportSummary.total}`,
      `- Critical: ${exportSummary.critical}`,
      `- Warning: ${exportSummary.warning}`,
      `- Info: ${exportSummary.info}`,
    ];

    if (report.aiReview) {
      lines.push(
        "",
        "## AI Risk Summary",
        "",
        `- Overall Risk Score: ${report.aiReview.overallRiskScore}`,
        `- Overall Risk Level: ${report.aiReview.overallRiskLevel}`,
        "",
        report.aiReview.executiveSummary,
      );
    }

    lines.push("", "## Findings", "");

    if (!exportFindings.length) {
      lines.push("No findings matched the selected export filter.");
      return lines.join("\n");
    }

    exportFindings.forEach((finding, index) => {
      const aiFinding = getAiFinding(finding.id);

      lines.push(`### ${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title}`);
      lines.push("");
      lines.push(`- Analyzer: ${finding.analyzer}`);
      lines.push(`- Confidence: ${finding.confidence.toUpperCase()} (${finding.confidenceScore}/100)`);
      if (finding.confidenceReason) lines.push(`- Confidence Reason: ${finding.confidenceReason}`);
      if (finding.aiValidation) {
        lines.push(
          `- AI Validation: ${finding.aiValidation.verdict} (${finding.aiValidation.confidence}/100) - ${finding.aiValidation.rationale}`,
        );
      }
      lines.push(`- File: ${finding.file}${finding.line ? `:${finding.line}` : ""}`);
      if (aiFinding) lines.push(`- AI Priority: P${aiFinding.priority}`);
      if (aiFinding?.reviewNotes) lines.push(`- AI Review Notes: ${aiFinding.reviewNotes}`);
      lines.push("");
      lines.push(aiFinding ? aiFinding.explanation : finding.description);

      if (aiFinding?.impact) {
        lines.push("");
        lines.push(`Impact: ${aiFinding.impact}`);
      }

      if (finding.suggestion) {
        lines.push("");
        lines.push(`Suggestion: ${finding.suggestion}`);
      }

      if (finding.code) {
        lines.push("", "```ts", finding.code, "```");
      }

      if (aiFinding?.fixCode) {
        lines.push("", "AI Suggested Fix:", "", "```ts", aiFinding.fixCode, "```");
      }

      lines.push("");
    });

    return lines.join("\n");
  };

  const exportDocument = () => {
    if (!report || !exportHasFindings) return;

    const text = buildExportDocument();
    const blob = new Blob([text], { type: "text/markdown;charset=utf-8" });
    const blobUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = blobUrl;
    anchor.download = `nest-scan-${fileNameSafe(report.id)}-${fileNameSafe(exportScope)}-${fileNameSafe(selectedSeverityText)}.md`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(blobUrl);
    setExportStatus(`Document exported: ${scopeLabel(exportScope)} / ${selectedSeverityText}`);
  };

  const copyToClipboard = async () => {
    if (!report || !exportHasFindings) return;

    const text = buildExportDocument();

    try {
      await navigator.clipboard.writeText(text);
      setExportStatus(`Copied to clipboard: ${scopeLabel(exportScope)} / ${selectedSeverityText}`);
      return;
    } catch {
      const copied = copyTextFallback(text);
      setExportStatus(
        copied
          ? `Copied to clipboard: ${scopeLabel(exportScope)} / ${selectedSeverityText}`
          : "Clipboard export failed on this browser.",
      );
    }
  };

  const runAiAction = async (findingId: string, action: AiActionType) => {
    if (!report?.aiEnabled) return;

    setAiActionSelected(prev => ({ ...prev, [findingId]: action }));
    setAiActionErrors(prev => ({ ...prev, [findingId]: undefined }));

    const existing = aiActionResults[findingId]?.[action];
    if (existing) return;

    setAiActionLoading(prev => ({ ...prev, [findingId]: action }));

    try {
      const response = await fetch(`${API}/scanner/ai-action`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          reportId: report.id,
          findingId,
          action,
        }),
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.message || `HTTP ${response.status}`);
      }

      const data: AiActionResponse = await response.json();
      setAiActionResults(prev => ({
        ...prev,
        [findingId]: {
          ...(prev[findingId] || {}),
          [action]: data,
        },
      }));
    } catch (e: any) {
      setAiActionErrors(prev => ({ ...prev, [findingId]: e.message || "AI action failed." }));
    } finally {
      setAiActionLoading(prev => ({ ...prev, [findingId]: undefined }));
    }
  };

  return (
    <div className="shell">
      <div className="top-bar">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8" />
          <path d="m21 21-4.3-4.3" />
        </svg>
        <h1>nest-scan</h1>
        <span className="tag">v2.0</span>
      </div>

      <div className="scan-card">
        <div className="field-grid" style={{ gridTemplateColumns: "1fr 140px 1fr" }}>
          <div className="field">
            <label>Repository URL</label>
            <input
              value={url}
              onChange={event => setUrl(event.target.value)}
              placeholder="https://github.com/owner/repo"
            />
          </div>
          <div className="field">
            <label>Branch</label>
            <input
              value={branch}
              onChange={event => setBranch(event.target.value)}
              placeholder="main"
            />
          </div>
          <div className="field">
            <label>GitHub PAT</label>
            <input
              type="password"
              value={pat}
              onChange={event => setPat(event.target.value)}
              placeholder="Optional - for private repos"
            />
          </div>
        </div>
        <div className="btn-row">
          <button
            className={`btn-primary ${loading ? "loading" : ""}`}
            onClick={scan}
            disabled={loading || !url || !branch}
          >
            {loading ? (
              <>
                <div className="spinner" />
                Scanning...
              </>
            ) : (
              "Run Scan"
            )}
          </button>
        </div>
      </div>

      {error && <div className="error">x {error}</div>}

      {loading && (
        <div className="loading-state">
          <div className="loading-ring" />
          <div className="loading-text">Fetching and analyzing repository via GitHub API...</div>
        </div>
      )}

      {report && !loading && (
        <>
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

          <div className="stat-row">
            <div className="stat"><div className="stat-num red">{report.summary.critical}</div><div className="stat-label">Critical</div></div>
            <div className="stat"><div className="stat-num orange">{report.summary.warning}</div><div className="stat-label">Warning</div></div>
            <div className="stat"><div className="stat-num blue">{report.summary.info}</div><div className="stat-label">Info</div></div>
            <div className="stat"><div className="stat-num default">{report.summary.totalEndpoints}</div><div className="stat-label">Endpoints</div></div>
            <div className="stat"><div className="stat-num default">{report.summary.totalModules}</div><div className="stat-label">Modules</div></div>
            <div className="stat"><div className="stat-num default">{report.summary.totalFiles}</div><div className="stat-label">Files</div></div>
          </div>

          <div className="scan-meta">
            {(report.summary.scanDurationMs / 1000).toFixed(1)}s - {new Date(report.scannedAt).toLocaleString()}
          </div>

          <div className="export-panel">
            <div className="export-top">
              <div>
                <div className="export-title">Export Report</div>
                <div className="export-subtitle">
                  Export filtered findings as a markdown document or copy the same output to clipboard.
                </div>
              </div>
              <div className="export-summary">
                <span>{scopeLabel(exportScope)}</span>
                <span>{selectedSeverityText}</span>
                <span>{exportSummary.total} findings</span>
              </div>
            </div>

            <div className="export-section">
              <label>Quick Presets</label>
              <div className="chip-row">
                {EXPORT_PRESETS.map(preset => {
                  const isActive = exportScope === preset.scope &&
                    preset.severities.length === exportSeverities.length &&
                    preset.severities.every(severity => exportSeverities.includes(severity));

                  return (
                    <button
                      key={preset.label}
                      className={`filter-chip ${isActive ? "active" : ""}`}
                      onClick={() => applyExportPreset(preset.scope, preset.severities)}
                    >
                      {preset.label}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="export-grid">
              <div className="export-section">
                <label>Scope</label>
                <div className="chip-row">
                  {(Object.keys(EXPORT_SCOPE_LABELS) as ExportScope[]).map(scope => (
                    <button
                      key={scope}
                      className={`filter-chip ${exportScope === scope ? "active" : ""}`}
                      onClick={() => {
                        setExportScope(scope);
                        setExportStatus("");
                      }}
                    >
                      {scopeLabel(scope)}
                    </button>
                  ))}
                </div>
              </div>

              <div className="export-section">
                <label>Severity</label>
                <div className="chip-row">
                  {SEVERITY_OPTIONS.map(severity => (
                    <button
                      key={severity}
                      className={`filter-chip ${exportSeverities.includes(severity) ? "active" : ""}`}
                      onClick={() => toggleSeverity(severity)}
                    >
                      {severityLabel(severity)}
                    </button>
                  ))}
                </div>
              </div>

              <div className="export-actions">
                <button className="btn-secondary" onClick={exportDocument} disabled={!exportHasFindings}>
                  Export Document
                </button>
                <button className="btn-secondary" onClick={copyToClipboard} disabled={!exportHasFindings}>
                  Copy to Clipboard
                </button>
              </div>
            </div>

            <div className="export-note">
              {exportHasFindings
                ? `Ready to export ${exportSummary.total} finding(s): ${scopeLabel(exportScope)} / ${selectedSeverityText}`
                : "No findings match the current export filter."}
            </div>

            {exportStatus && <div className="export-status">{exportStatus}</div>}
          </div>

          <div className="tabs">
            {([
              ["all", "All Findings", report.findings.length, "o"],
              ["security", "Security", report.findings.filter(finding => SECURITY_ANALYZERS.includes(finding.analyzer)).length, "r"],
              ["quality", "Quality", report.findings.filter(finding => !SECURITY_ANALYZERS.includes(finding.analyzer)).length, "o"],
              ["endpoints", "Endpoints", report.endpoints.length, "b"],
              ["modules", "Modules", report.modules.length, "b"],
            ] as const).map(([key, label, count, color]) => (
              <button key={key} className={`tab-btn ${tab === key ? "active" : ""}`} onClick={() => setTab(key as Tab)}>
                {label}<span className={`tab-count ${color}`}>{count}</span>
              </button>
            ))}
          </div>

          {(tab === "all" || tab === "security" || tab === "quality") && (
            <div>
              {findings.length === 0 && (
                <div style={{ textAlign: "center", padding: 40, color: "var(--text-2)" }}>
                  No findings in this category.
                </div>
              )}

              {findings.map(finding => {
                const aiFinding = getAiFinding(finding.id);
                const isOpen = open.has(finding.id);
                const selectedAiAction = aiActionSelected[finding.id];
                const aiActionResult = selectedAiAction ? aiActionResults[finding.id]?.[selectedAiAction] : undefined;
                const aiActionBusy = aiActionLoading[finding.id];
                const aiActionError = aiActionErrors[finding.id];

                return (
                  <div key={finding.id} className="finding">
                    <div className="finding-head" onClick={() => toggle(finding.id)}>
                      <span className={`sev ${finding.severity}`}>{finding.severity}</span>
                      <span className="finding-title">{finding.title}</span>
                      <span className="finding-tag">{finding.analyzer}</span>
                      <span className={`finding-tag confidence ${finding.confidence}`}>{confidenceLabel(finding)}</span>
                      {finding.aiValidation && (
                        <span className={`finding-tag validation ${finding.aiValidation.verdict}`}>
                          {aiValidationLabel(finding.aiValidation)}
                        </span>
                      )}
                      {aiFinding && (
                        <span className="finding-tag ai-tag">AI P{aiFinding.priority}</span>
                      )}
                      <span className={`finding-chevron ${isOpen ? "open" : ""}`}>▶</span>
                    </div>

                    {isOpen && (
                      <div className="finding-body">
                        <p className="finding-desc">{aiFinding ? aiFinding.explanation : finding.description}</p>
                        {finding.confidenceReason && (
                          <div className={`confidence-note ${finding.confidence}`}>
                            Confidence: {finding.confidenceReason}
                          </div>
                        )}
                        {finding.aiValidation && (
                          <div className={`validation-note ${finding.aiValidation.verdict}`}>
                            <strong>{aiValidationLabel(finding.aiValidation)}</strong>
                            <div>{finding.aiValidation.rationale}</div>
                            <div className="validation-meta">Validator confidence {finding.aiValidation.confidence}/100</div>
                          </div>
                        )}
                        {finding.file && (
                          <div className="finding-file">
                            File: {finding.file}{finding.line ? `:${finding.line}` : ""}
                          </div>
                        )}
                        {finding.code && <pre className="code-block">{finding.code}</pre>}
                        {aiFinding?.reviewNotes && (
                          <div className="review-note">AI review note: {aiFinding.reviewNotes}</div>
                        )}
                        {aiFinding?.fixCode && (
                          <div className="ai-fix">
                            <div className="fix-label">AI Suggested Fix</div>
                            <pre className="ai-fix-code">{aiFinding.fixCode}</pre>
                          </div>
                        )}
                        {aiFinding?.impact && <div className="ai-impact">Impact: {aiFinding.impact}</div>}
                        {finding.suggestion && !aiFinding?.fixCode && (
                          <div className="fix-block">
                            <div className="fix-label">Suggestion</div>
                            {finding.suggestion}
                          </div>
                        )}
                        {report.aiEnabled && (
                          <div className="ai-action-panel">
                            <div className="ai-action-title">Per-Finding AI Actions</div>
                            <div className="ai-action-row">
                              {(Object.keys(AI_ACTION_LABELS) as AiActionType[]).map(action => (
                                <button
                                  key={action}
                                  className={`btn-secondary ai-action-btn ${selectedAiAction === action ? "active" : ""}`}
                                  onClick={() => void runAiAction(finding.id, action)}
                                  disabled={!!aiActionBusy}
                                >
                                  {aiActionBusy === action ? "Loading..." : AI_ACTION_LABELS[action]}
                                </button>
                              ))}
                            </div>
                            {aiActionError && <div className="ai-action-error">{aiActionError}</div>}
                            {aiActionResult && (
                              <div className="ai-action-result">
                                <div className="ai-action-result-title">{aiActionResult.title}</div>
                                <div className="ai-action-result-meta">
                                  {AI_ACTION_LABELS[aiActionResult.action]} - {new Date(aiActionResult.generatedAt).toLocaleString()}
                                </div>
                                <pre className="ai-action-content">{aiActionResult.content}</pre>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {tab === "endpoints" && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Handler</th>
                    <th>Guard</th>
                    <th>DTO</th>
                  </tr>
                </thead>
                <tbody>
                  {report.endpoints.map((endpoint, index) => (
                    <tr key={index}>
                      <td><span className={`badge ${endpoint.method.toLowerCase()}`}>{endpoint.method}</span></td>
                      <td>{endpoint.path}</td>
                      <td>{endpoint.handler}()</td>
                      <td>
                        {endpoint.guards.length
                          ? endpoint.guards.map((guard, guardIndex) => (
                            <span key={guardIndex} className="badge guard">{guard}</span>
                          ))
                          : <span className="badge no-guard">NONE</span>}
                      </td>
                      <td style={{ color: endpoint.dtoName ? "var(--text-0)" : "var(--text-2)" }}>
                        {endpoint.dtoName || "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {tab === "modules" && (
            <div className="module-grid">
              {report.modules.map((moduleInfo, index) => (
                <div key={index} className="module-card">
                  <div className="module-name">{moduleInfo.name}</div>
                  <div className="module-path">{moduleInfo.path}</div>
                  <div className="module-checks">
                    {([
                      ["Controller", moduleInfo.hasController],
                      ["Service", moduleInfo.hasService],
                      ["Module", moduleInfo.hasModule],
                      ["DTO", moduleInfo.hasDtoFolder],
                      ["Spec", moduleInfo.hasSpecFile],
                    ] as const).map(([label, ok], checkIndex) => (
                      <span key={checkIndex} className={`check ${ok ? "ok" : "miss"}`}>
                        {ok ? "OK" : "MISS"} {label}
                      </span>
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
