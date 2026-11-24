"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { API_URL, apiFetch as fetch } from "@/lib/api";
import MarkdownReport, { stripEmojis, normalizeMarkdownText } from "@/components/MarkdownReport";
import { AuditObservations, type AuditFinding } from "@/components/AuditObservations";
import { PipelineChecks, type ManualPipelineStatus, type PipelineRun } from "@/components/PipelineChecks";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Code2,
  Compass,
  Download,
  FileText,
  Globe,
  Key,
  Layers,
  Lock,
  Pause,
  Play,
  Radio,
  RefreshCw,
  Shield,
  ShieldAlert,
  X,
  Zap,
} from "lucide-react";

interface PipelineStage {
  title: string;
  detail: string;
  agent: string;
}

interface ToolItem {
  stage: number;
  title: string;
  detail: string;
}

interface AuditState {
  status: "idle" | "queued" | "running" | "complete" | "stopped" | "failed";
  completed: number;
  total_stages: number;
  active: string;
  stage_index: number;
  mode: "guided" | "all";
  scan_depth?: "standard" | "deep" | "aggressive";
  target: string;
  provider: string;
  events: { time: string; label: string; status: string }[];
  report: string;
  reports: Record<string, string>;
  counts: { Critical: number; High: number; Medium: number; Low: number };
  error: string | null;
  started: string | null;
  pipeline: PipelineStage[];
  tools: ToolItem[];
}

function getTabIcon(title: string) {
  const t = title.toLowerCase();
  if (t.includes("overview") || t.includes("target")) return <Shield className="w-3.5 h-3.5 shrink-0" />;
  if (
    t.includes("dns") ||
    t.includes("ip") ||
    t.includes("network") ||
    t.includes("topology") ||
    t.includes("recon") ||
    t.includes("asn") ||
    t.includes("geolocation")
  )
    return <Globe className="w-3.5 h-3.5 shrink-0" />;
  if (t.includes("shodan") || t.includes("port") || t.includes("surface") || t.includes("perimeter"))
    return <Radio className="w-3.5 h-3.5 shrink-0" />;
  if (
    t.includes("header") ||
    t.includes("cookie") ||
    t.includes("ssl") ||
    t.includes("tls") ||
    t.includes("cert") ||
    t.includes("email") ||
    t.includes("posture")
  )
    return <Lock className="w-3.5 h-3.5 shrink-0" />;
  if (t.includes("endpoint") || t.includes("path") || t.includes("discovery") || t.includes("prob"))
    return <Compass className="w-3.5 h-3.5 shrink-0" />;
  if (t.includes("dos") || t.includes("rate limit") || t.includes("load") || t.includes("resilience"))
    return <Zap className="w-3.5 h-3.5 shrink-0" />;
  if (
    t.includes("injection") ||
    t.includes("sql") ||
    t.includes("xss") ||
    t.includes("payload") ||
    t.includes("cpe") ||
    t.includes("software") ||
    t.includes("fingerprint")
  )
    return <Code2 className="w-3.5 h-3.5 shrink-0" />;
  if (t.includes("auth") || t.includes("login") || t.includes("session") || t.includes("token"))
    return <Key className="w-3.5 h-3.5 shrink-0" />;
  if (
    t.includes("cve") ||
    t.includes("owasp") ||
    t.includes("vulnerab") ||
    t.includes("threat") ||
    t.includes("hostname") ||
    t.includes("classification")
  )
    return <ShieldAlert className="w-3.5 h-3.5 shrink-0" />;
  if (t.includes("risk") || t.includes("profile") || t.includes("matrix") || t.includes("score"))
    return <Activity className="w-3.5 h-3.5 shrink-0" />;
  if (
    t.includes("remediation") ||
    t.includes("roadmap") ||
    t.includes("action") ||
    t.includes("recommend") ||
    t.includes("item") ||
    t.includes("summary")
  )
    return <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />;
  return <FileText className="w-3.5 h-3.5 shrink-0" />;
}

function parseReportSections(text: string) {
  if (!text) return [];
  const cleaned = normalizeMarkdownText(text);
  const parts = cleaned.split(/(?=^##\s+)/m).filter((p) => p.trim().length > 0);
  if (parts.length <= 1) {
    return [{ title: "Target Overview", content: cleaned }];
  }
  return parts.map((part) => {
    const match = part.match(/^##\s+(.+?)$/m);
    const rawTitle = match ? match[1].replace(/[*_~`]/g, "").trim().slice(0, 42) : "Target Overview";
    const cleanTitle = stripEmojis(rawTitle).replace(/^\d+\.\s*/, "").trim() || "Target Overview";
    const content = part.replace(/^##\s+.+?$/m, "").trim();
    return { title: cleanTitle, content };
  });
}

export default function DevSecOpsPage() {
  const [audit, setAudit] = useState<AuditState | null>(null);
  const [findings, setFindings] = useState<AuditFinding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(true);
  const [findingsError, setFindingsError] = useState(false);
  const [pipelineRuns, setPipelineRuns] = useState<PipelineRun[]>([]);
  const [pipelineLoading, setPipelineLoading] = useState(true);
  const [pipelineError, setPipelineError] = useState(false);
  const [manualPipelineStatus, setManualPipelineStatus] = useState<ManualPipelineStatus | null>(null);
  const [manualPipelineError, setManualPipelineError] = useState(false);

  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [mode, setMode] = useState<"guided" | "all">("guided");
  const [scanDepth, setScanDepth] = useState<"standard" | "deep" | "aggressive">("deep");
  const [provider, setProvider] = useState("gemini");
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<string>("Overview");
  const [notice, setNotice] = useState<{ type: "error" | "info"; text: string } | null>(null);
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/status`);
      if (!res.ok) throw new Error("Audit status unavailable");
      const data = await res.json();
      setAudit(data);
      setConnectionError(false);
      if (data.target) {
        setTarget((prev) => (prev ? prev : data.target));
      }
    } catch (err) {
      console.error("Failed to fetch audit status:", err);
      setConnectionError(true);
    }
    try {
      const response = await fetch(`${API_URL}/api/devsecops/findings`);
      if (!response.ok) throw new Error("Audit observations unavailable");
      const data = await response.json();
      if (!Array.isArray(data.findings)) throw new Error("Invalid observations response");
      setFindings(data.findings);
      setFindingsError(false);
    } catch (err) {
      console.error("Failed to fetch audit findings:", err);
      setFindingsError(true);
    } finally {
      setFindingsLoading(false);
    }
    try {
      const response = await fetch(`${API_URL}/api/devsecops/runs`);
      if (!response.ok) throw new Error("Pipeline runs unavailable");
      const data = await response.json();
      if (!Array.isArray(data.runs)) throw new Error("Invalid pipeline runs response");
      setPipelineRuns(data.runs);
      setPipelineError(false);
    } catch (err) {
      console.error("Failed to fetch pipeline runs:", err);
      setPipelineError(true);
    } finally {
      setPipelineLoading(false);
    }
    try {
      const response = await fetch(`${API_URL}/api/devsecops/runs/manual/status`);
      if (!response.ok) throw new Error("Manual scan status unavailable");
      setManualPipelineStatus(await response.json());
      setManualPipelineError(false);
    } catch (err) {
      console.error("Failed to fetch manual pipeline status:", err);
      setManualPipelineError(true);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      void fetchStatus();
    }, 0);
    pollIntervalRef.current = setInterval(() => void fetchStatus(), 2000);
    return () => {
      clearTimeout(timer);
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, [fetchStatus]);

  const handleManualRefresh = async () => {
    setRefreshing(true);
    await fetchStatus();
    setRefreshing(false);
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    setNotice(null);
    if (!target.trim()) {
      setNotice({ type: "error", text: "Enter a valid target domain, IP address, or URL." });
      return;
    }
    if (!authorized) {
      setNotice({ type: "error", text: "Confirm authorization to test this target before launching." });
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          authorized,
          mode,
          provider,
          scan_depth: scanDepth,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setNotice({ type: "error", text: data.detail || "Failed to start assessment." });
      } else {
        setAudit(data);
        setNotice({ type: "info", text: `Assessment started for ${target.trim()}.` });
      }
    } catch (err) {
      console.error("Audit start error:", err);
      setNotice({ type: "error", text: "Unable to communicate with the assessment backend." });
    } finally {
      setLoading(false);
    }
  };

  const handleNextStage = async () => {
    setActionLoading(true);
    setNotice(null);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/next`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Could not start the next stage.");
      setAudit(data);
    } catch (err) {
      setNotice({ type: "error", text: err instanceof Error ? err.message : "Could not start the next stage." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleRunAll = async () => {
    setActionLoading(true);
    setNotice(null);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/run-all`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Could not continue the assessment.");
      setAudit(data);
    } catch (err) {
      setNotice({ type: "error", text: err instanceof Error ? err.message : "Could not continue the assessment." });
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async () => {
    setActionLoading(true);
    setNotice(null);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/stop`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Could not stop the assessment.");
      setAudit(data);
    } catch (err) {
      setNotice({ type: "error", text: err instanceof Error ? err.message : "Could not stop the assessment." });
    } finally {
      setActionLoading(false);
    }
  };

  const resolveFinding = async (finding: AuditFinding): Promise<number> => {
    const response = await fetch(`${API_URL}/api/devsecops/findings/${encodeURIComponent(finding.id)}/resolve`, {
      method: "POST",
    });
    if (!response.ok) throw new Error("Could not resolve finding");
    const result = await response.json();
    setFindings((previous) =>
      previous.map((item) =>
        item.target === finding.target && item.title === finding.title ? { ...item, status: "Resolved" } : item
      )
    );
    void fetchStatus();
    return result.resolved_observations;
  };

  const runPipelineChecks = async () => {
    const response = await fetch(`${API_URL}/api/devsecops/runs/manual`, { method: "POST" });
    const result = await response.json();
    if (!response.ok) {
      void fetchStatus();
      throw new Error(
        typeof result.detail === "string" ? result.detail : "Could not start pipeline checks. Please try again."
      );
    }
    setManualPipelineStatus(result);
    setManualPipelineError(false);
  };

  const downloadReport = () => {
    if (!audit?.report) return;
    const blob = new Blob([audit.report], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-audit-${audit.target.replace(/[^a-zA-Z0-9]/g, "_") || "report"}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const reportSections = audit?.report ? parseReportSections(audit.report) : [];
  const maxRiskCount = audit?.counts ? Math.max(...Object.values(audit.counts), 1) : 1;
  const isRunning = audit?.status === "running" || audit?.status === "queued";
  const openFindingsCount = findings.filter((f) => f.status === "Open").length;
  const passedPipelineCount = pipelineRuns.filter(
    (r) => r.status === "PASSED" || r.status === "PASSED WITH WARNINGS"
  ).length;
  const stageTotal = audit?.total_stages || 8;
  const stageCompleted = audit?.completed ?? 0;
  const stagePct = Math.min(100, Math.max(0, Math.round((stageCompleted / stageTotal) * 100)));

  const statusDotColor = isRunning
    ? "bg-amber-500"
    : audit?.status === "complete"
    ? "bg-emerald-600"
    : audit?.status === "failed"
    ? "bg-red-600"
    : "bg-slate-400";

  return (
    <div className="max-w-[1440px] mx-auto space-y-6 pb-12">
      {/* Flat Enterprise Header */}
      <header className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-4 border-b border-border">
        <div className="min-w-0">
          <div className="text-xs font-medium text-slate-500 flex items-center gap-1.5">
            <span>Security Audit</span>
            <span className="text-slate-300">/</span>
            <span className="text-slate-700">DevSecOps Assessment</span>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-semibold tracking-tight text-slate-900">Security Assessment</h1>
            <span
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-700"
              aria-live="polite"
            >
              <span className={`h-1.5 w-1.5 rounded-full ${statusDotColor}`} />
              <span className="capitalize">{audit?.status || (connectionError ? "Unavailable" : "Connecting")}</span>
              {audit?.status === "running" && (
                <span className="border-l border-border pl-2 font-mono text-[11px] text-slate-500">
                  Stage {audit.completed + 1}/{stageTotal}
                </span>
              )}
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-500">
            Configure target scope, run multi-stage active reconnaissance, inspect verified observations, and export reports.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 hover:border-slate-300 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 text-slate-500 ${refreshing ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>

          {isRunning && (
            <button
              type="button"
              onClick={handleStop}
              disabled={actionLoading}
              className="inline-flex items-center gap-1.5 rounded-md border border-red-200 bg-red-50 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-100 transition-colors disabled:opacity-50"
            >
              <Pause className="h-3.5 w-3.5" />
              <span>Stop Scan</span>
            </button>
          )}

          {audit?.report && (
            <button
              type="button"
              onClick={downloadReport}
              className="inline-flex items-center gap-1.5 rounded-md bg-slate-900 px-3.5 py-1.5 text-xs font-medium text-white hover:bg-slate-800 transition-colors"
            >
              <Download className="h-3.5 w-3.5" />
              <span>Export Report (.md)</span>
            </button>
          )}
        </div>
      </header>

      {/* Connection / Validation / Error Notices */}
      {connectionError && (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-amber-200 bg-amber-50 px-4 py-2.5 text-xs text-amber-900"
        >
          <span>Unable to refresh assessment status. Displayed data may be out of date.</span>
          <button type="button" onClick={fetchStatus} className="font-semibold underline">
            Retry
          </button>
        </div>
      )}

      {notice && (
        <div
          role={notice.type === "error" ? "alert" : "status"}
          className={`flex items-center justify-between gap-3 rounded-md border px-4 py-2.5 text-xs ${
            notice.type === "error"
              ? "border-red-200 bg-red-50 text-red-800"
              : "border-blue-200 bg-blue-50 text-blue-900"
          }`}
        >
          <div className="flex items-center gap-2">
            {notice.type === "error" ? (
              <AlertCircle className="h-3.5 w-3.5 shrink-0" />
            ) : (
              <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
            )}
            <span>{notice.text}</span>
          </div>
          <button
            type="button"
            onClick={() => setNotice(null)}
            aria-label="Dismiss notice"
            className="p-0.5 opacity-70 hover:opacity-100"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {audit?.error && (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-xs text-red-800"
        >
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="h-4 w-4 shrink-0 text-red-600" />
            <div>
              <span className="font-semibold">Assessment notice:</span> {audit.error}
            </div>
          </div>
          <button
            type="button"
            onClick={async () => {
              try {
                await fetch(`${API_URL}/api/devsecops/audit/stop`, { method: "POST" });
                void fetchStatus();
              } catch (e) {
                console.error(e);
              }
            }}
            className="rounded-md bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 transition-colors whitespace-nowrap"
          >
            Reset Scanner
          </button>
        </div>
      )}

      {/* Unified 4-Column Summary Strip */}
      <section
        aria-label="Assessment summary metrics"
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-border rounded-lg border border-border bg-white shadow-xs overflow-hidden"
      >
        <div className="p-4 flex flex-col justify-between gap-2">
          <span className="text-xs font-medium text-slate-500">Stage Progress</span>
          <div className="flex items-baseline justify-between gap-2">
            <span className="text-xl font-semibold font-mono tabular-nums text-slate-900">
              {audit ? `${stageCompleted}/${stageTotal}` : "—"}
            </span>
            <span className="text-[11px] font-mono text-slate-500 tabular-nums">{audit ? `${stagePct}%` : "Idle"}</span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-slate-100 overflow-hidden">
            <div className="h-full bg-blue-600 transition-all duration-300" style={{ width: `${stagePct}%` }} />
          </div>
        </div>

        <div className="p-4 flex flex-col justify-between gap-1.5">
          <span className="text-xs font-medium text-slate-500">Audit Observations</span>
          <div className="flex items-baseline justify-between gap-2">
            <span className="text-xl font-semibold font-mono tabular-nums text-slate-900">
              {findingsLoading ? "—" : openFindingsCount}
            </span>
            <span className="text-[11px] font-mono text-slate-500 tabular-nums">
              {findingsLoading ? "" : `${findings.length} total`}
            </span>
          </div>
          <span className="text-[11px] text-slate-500">Open evidence items across runs</span>
        </div>

        <div className="p-4 flex flex-col justify-between gap-1.5">
          <span className="text-xs font-medium text-slate-500">Pipeline Checks</span>
          <div className="flex items-baseline justify-between gap-2">
            <span className="text-xl font-semibold font-mono tabular-nums text-slate-900">
              {pipelineLoading ? "—" : `${passedPipelineCount}/${pipelineRuns.length}`}
            </span>
            <span className="text-[11px] font-mono text-emerald-700">passed</span>
          </div>
          <span className="text-[11px] text-slate-500">SAST, secrets, dependencies, config</span>
        </div>

        <div className="p-4 flex flex-col justify-between gap-1.5">
          <span className="text-xs font-medium text-slate-500">Report Severity Mentions</span>
          <div className="flex items-baseline gap-2 font-mono text-sm font-semibold tabular-nums">
            <span className="text-red-600">{audit?.counts?.Critical ?? 0}C</span>
            <span className="text-slate-300">·</span>
            <span className="text-amber-600">{audit?.counts?.High ?? 0}H</span>
            <span className="text-slate-300">·</span>
            <span className="text-blue-600">{audit?.counts?.Medium ?? 0}M</span>
            <span className="text-slate-300">·</span>
            <span className="text-slate-600">{audit?.counts?.Low ?? 0}L</span>
          </div>
          <span className="text-[11px] text-slate-500">Text mentions, not verified counts</span>
        </div>
      </section>

      {/* Assessment Configuration (8 cols) & Current Session Overview (4 cols) */}
      <div className="grid grid-cols-1 items-start gap-5 lg:grid-cols-12">
        <section className="lg:col-span-8 rounded-lg border border-border bg-white shadow-xs overflow-hidden">
          <div className="px-5 py-3.5 border-b border-border flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Configure Assessment</h2>
              <p className="text-xs text-slate-500">Define target scope, reconnaissance depth, and execution policy</p>
            </div>
            <span className="hidden sm:inline-flex items-center gap-1.5 text-[11px] font-mono text-slate-500">
              8-stage scanner
            </span>
          </div>

          <form onSubmit={handleLaunch} className="space-y-5 p-5">
            {/* Target URL */}
            <div>
              <label htmlFor="audit-target" className="mb-1.5 block text-xs font-semibold text-slate-700">
                Target domain, IP, or URL <span className="text-red-600">*</span>
              </label>
              <div className="relative">
                <Globe className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  id="audit-target"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://app.example.com"
                  className="w-full rounded-md border border-slate-300 bg-white py-2.5 pl-9 pr-3.5 text-sm font-mono text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-600/15 disabled:bg-slate-50 disabled:text-slate-500 transition-colors"
                  disabled={isRunning}
                  required
                  aria-describedby="audit-target-hint"
                />
              </div>
              <div id="audit-target-hint" className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500">
                <span className="mr-1">Active checks:</span>
                {["Soft-404 Filter", "JS Secret Mining", "LFI & Time-Blind SQLi", "Sitemap Crawl", "TLS/X.509"].map(
                  (cap) => (
                    <span
                      key={cap}
                      className="inline-flex items-center rounded border border-border bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium text-slate-600"
                    >
                      {cap}
                    </span>
                  )
                )}
              </div>
            </div>

            {/* Scanning Depth Profile */}
            <fieldset disabled={isRunning} className="min-w-0">
              <legend className="mb-2 block text-xs font-semibold text-slate-700">Scanning depth profile</legend>
              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                {[
                  {
                    value: "standard" as const,
                    label: "Standard Audit",
                    badge: "Fast",
                    description: "Core headers, TLS, 42 endpoints & 8 fuzz inputs.",
                  },
                  {
                    value: "deep" as const,
                    label: "Deep Reconnaissance",
                    badge: "Recommended",
                    description: "95+ cloud/config paths, JS secrets, sitemap, LFI & blind SQLi.",
                  },
                  {
                    value: "aggressive" as const,
                    label: "Aggressive Suite",
                    badge: "Exhaustive",
                    description: "Max concurrency, extended payloads & full auth/DoS probes.",
                  },
                ].map((opt) => {
                  const selected = scanDepth === opt.value;
                  return (
                    <label
                      key={opt.value}
                      className={`flex min-w-0 flex-col gap-1.5 rounded-md border p-3.5 transition-colors ${
                        selected
                          ? "border-blue-600 bg-blue-50/40 ring-1 ring-blue-600/20"
                          : "border-border bg-white hover:border-slate-300 hover:bg-slate-50/60"
                      } ${isRunning ? "cursor-not-allowed opacity-60" : "cursor-pointer"}`}
                    >
                      <span className="flex items-center justify-between gap-2">
                        <input
                          type="radio"
                          name="scanDepth"
                          value={opt.value}
                          checked={selected}
                          onChange={() => setScanDepth(opt.value)}
                          className="h-3.5 w-3.5 shrink-0 accent-blue-600"
                        />
                        <span
                          className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                            opt.value === "deep"
                              ? "bg-blue-100 text-blue-800"
                              : opt.value === "aggressive"
                              ? "bg-red-50 text-red-700 border border-red-200"
                              : "bg-slate-100 text-slate-600"
                          }`}
                        >
                          {opt.badge}
                        </span>
                      </span>
                      <span className="min-w-0 mt-0.5">
                        <span className="block text-xs font-semibold text-slate-900">{opt.label}</span>
                        <span className="mt-1 block text-[11px] leading-relaxed text-slate-500">{opt.description}</span>
                      </span>
                    </label>
                  );
                })}
              </div>
            </fieldset>

            {/* Execution Mode & Analysis Provider Side-by-Side */}
            <div className="grid grid-cols-1 gap-4 md:grid-cols-12">
              <fieldset disabled={isRunning} className="md:col-span-8">
                <legend className="mb-2 block text-xs font-semibold text-slate-700">Assessment mode</legend>
                <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                  {[
                    { value: "guided" as const, label: "Guided assessment", description: "Review and advance one stage at a time." },
                    { value: "all" as const, label: "Run all stages", description: "Execute all 8 stages automatically." },
                  ].map((option) => {
                    const selected = mode === option.value;
                    return (
                      <label
                        key={option.value}
                        className={`flex items-start gap-2.5 rounded-md border p-3 transition-colors ${
                          selected
                            ? "border-blue-600 bg-blue-50/40 ring-1 ring-blue-600/20"
                            : "border-border bg-white hover:border-slate-300 hover:bg-slate-50/60"
                        } ${isRunning ? "cursor-not-allowed opacity-60" : "cursor-pointer"}`}
                      >
                        <input
                          type="radio"
                          name="mode"
                          value={option.value}
                          checked={selected}
                          onChange={() => setMode(option.value)}
                          className="mt-0.5 h-3.5 w-3.5 accent-blue-600"
                        />
                        <span>
                          <span className="block text-xs font-semibold text-slate-900">{option.label}</span>
                          <span className="mt-0.5 block text-[11px] leading-relaxed text-slate-500">
                            {option.description}
                          </span>
                        </span>
                      </label>
                    );
                  })}
                </div>
              </fieldset>

              <div className="md:col-span-4">
                <label htmlFor="audit-provider" className="mb-2 block text-xs font-semibold text-slate-700">
                  Analysis provider
                </label>
                <select
                  id="audit-provider"
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                  disabled={isRunning}
                  className="w-full rounded-md border border-slate-300 bg-white px-3 py-2.5 text-xs font-medium text-slate-900 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-600/15 disabled:bg-slate-50 disabled:text-slate-500"
                >
                  <option value="gemini">Google Gemini (Auto-Failover)</option>
                  <option value="grok">xAI Grok</option>
                  <option value="openai">OpenAI</option>
                </select>
                <p className="mt-1.5 text-[11px] text-slate-500">Synthesis model for report generation.</p>
              </div>
            </div>

            {/* Authorization */}
            <label
              className={`flex items-start gap-2.5 rounded-md border border-border bg-slate-50 px-3.5 py-3 transition-colors ${
                isRunning ? "opacity-60" : "cursor-pointer hover:bg-slate-100/70"
              }`}
            >
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                disabled={isRunning}
                className="mt-0.5 h-4 w-4 shrink-0 accent-blue-600"
                required
              />
              <span className="text-xs leading-relaxed text-slate-600">
                <span className="font-semibold text-slate-900">I have authorization to test this target.</span> Active
                probes generate live HTTP/network requests and safe intrusion-detection payloads.
              </span>
            </label>

            {/* Form Actions */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
              <div className="flex items-center gap-2">
                <button
                  type="submit"
                  disabled={loading || isRunning || !target.trim()}
                  className="inline-flex items-center justify-center gap-2 rounded-md bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-700 transition-colors disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {loading || isRunning ? (
                    <>
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      <span>Executing assessment...</span>
                    </>
                  ) : (
                    <>
                      <Play className="h-3.5 w-3.5 fill-current" />
                      <span>Launch assessment</span>
                      <ArrowRight className="h-3.5 w-3.5" />
                    </>
                  )}
                </button>
              </div>
              <span className="text-[11px] text-slate-400">
                {mode === "guided" ? "Pauses after each stage for review" : "Runs all stages consecutively"}
              </span>
            </div>
          </form>
        </section>

        {/* Right Column: Current Session Metadata */}
        <aside
          className="lg:col-span-4 rounded-lg border border-border bg-white shadow-xs overflow-hidden"
          aria-label="Assessment overview"
        >
          <div className="px-5 py-3.5 border-b border-border">
            <h2 className="text-sm font-semibold text-slate-900">Assessment Overview</h2>
            <p className="text-xs text-slate-500">Current session status and parameters</p>
          </div>

          <div className="p-5 space-y-4">
            <div className="rounded-md border border-border bg-slate-50/70 p-3.5">
              <div className="flex items-center justify-between gap-3 text-xs">
                <span className="font-medium text-slate-600">Stage progress</span>
                <span className="font-mono font-semibold tabular-nums text-slate-900">
                  {audit ? audit.completed : "—"} / {stageTotal}
                </span>
              </div>
              <div
                className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-slate-200"
                role="progressbar"
                aria-label="Assessment stage progress"
                aria-valuemin={0}
                aria-valuemax={stageTotal}
                aria-valuenow={audit ? audit.completed : undefined}
              >
                <div className="h-full rounded-full bg-blue-600 transition-all duration-300" style={{ width: `${stagePct}%` }} />
              </div>
              <p className="mt-2 text-[11px] leading-relaxed text-slate-500">
                {!audit
                  ? connectionError
                    ? "Assessment status unavailable."
                    : "Connecting to assessment service..."
                  : audit.status !== "idle"
                  ? audit.active
                  : "Ready to start when configured."}
              </p>
            </div>

            <dl className="divide-y divide-border text-xs">
              <div className="flex items-center justify-between gap-4 py-2.5 first:pt-0">
                <dt className="text-slate-500">Status</dt>
                <dd className="font-semibold capitalize text-slate-900">
                  {audit?.status || (connectionError ? "Unavailable" : "Connecting")}
                </dd>
              </div>
              <div className="flex items-center justify-between gap-4 py-2.5">
                <dt className="text-slate-500">Scan depth</dt>
                <dd className="font-mono font-semibold uppercase text-slate-900">{audit?.scan_depth || scanDepth}</dd>
              </div>
              <div className="flex items-center justify-between gap-4 py-2.5">
                <dt className="text-slate-500">Critical / High mentions</dt>
                <dd className="font-mono font-semibold tabular-nums text-slate-900">
                  {audit ? (audit.counts?.Critical || 0) + (audit.counts?.High || 0) : "—"}
                </dd>
              </div>
              <div className="flex items-center justify-between gap-4 py-2.5">
                <dt className="text-slate-500">Last started</dt>
                <dd className="font-mono text-slate-700">{audit ? audit.started || "None" : "—"}</dd>
              </div>
              {audit?.target && (
                <div className="flex items-start justify-between gap-4 py-2.5">
                  <dt className="shrink-0 text-slate-500">Target</dt>
                  <dd className="break-all text-right font-mono font-medium text-slate-900">{audit.target}</dd>
                </div>
              )}
            </dl>

            <p className="flex items-start gap-2 rounded-md border border-border bg-slate-50 px-3 py-2.5 text-[11px] leading-relaxed text-slate-600">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500" />
              <span>Severity mentions count occurrences in report text, not verified vulnerability counts.</span>
            </p>
          </div>
        </aside>
      </div>

      {/* Live Assessment Pipeline */}
      {audit && audit.status !== "idle" && (
        <section
          className="rounded-lg border border-border bg-white shadow-xs overflow-hidden"
          aria-labelledby="pipeline-title"
        >
          <div className="flex flex-col gap-3 border-b border-border px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2.5">
                <h2 id="pipeline-title" className="text-sm font-semibold text-slate-900">
                  Assessment Pipeline
                </h2>
                <span
                  className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium capitalize ${
                    isRunning
                      ? "border-blue-200 bg-blue-50 text-blue-700"
                      : audit.status === "complete"
                      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                      : audit.status === "failed"
                      ? "border-red-200 bg-red-50 text-red-700"
                      : "border-border bg-slate-50 text-slate-600"
                  }`}
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${statusDotColor}`} />
                  {audit.status === "complete" && audit.completed < stageTotal ? "Stage complete" : audit.status}
                </span>
              </div>
              <p className="mt-0.5 text-xs text-slate-500">
                Target: <span className="font-mono text-slate-800 break-all">{audit.target}</span>
              </p>
            </div>

            {(audit.status === "stopped" || (audit.status === "complete" && audit.mode === "guided")) && (
              <div className="flex flex-wrap items-center gap-2 shrink-0">
                {audit.completed < stageTotal ? (
                  <>
                    <button
                      type="button"
                      onClick={handleNextStage}
                      disabled={actionLoading}
                      className="inline-flex items-center gap-1.5 rounded-md border border-border bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 hover:border-slate-300 transition-colors disabled:opacity-50"
                    >
                      <ArrowRight className="h-3.5 w-3.5" />
                      Next stage ({audit.completed + 1})
                    </button>
                    <button
                      type="button"
                      onClick={handleRunAll}
                      disabled={actionLoading}
                      className="inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700 transition-colors disabled:opacity-50"
                    >
                      <Play className="h-3.5 w-3.5" />
                      Run all remaining
                    </button>
                  </>
                ) : (
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700">
                    <CheckCircle2 className="h-3.5 w-3.5" /> All stages complete
                  </span>
                )}
              </div>
            )}
          </div>

          <div className="space-y-5 p-5">
            {/* Stage Grid */}
            <ol className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 xl:grid-cols-4">
              {audit.pipeline?.map((item, idx) => {
                const isDone = idx < audit.completed;
                const isCurrent = idx === audit.completed && isRunning;
                return (
                  <li
                    key={idx}
                    aria-current={isCurrent ? "step" : undefined}
                    className={`flex min-w-0 items-start gap-2.5 rounded-md border p-3 transition-colors ${
                      isDone
                        ? "border-emerald-200 bg-emerald-50/40"
                        : isCurrent
                        ? "border-blue-500 bg-blue-50/40"
                        : "border-border bg-white"
                    }`}
                  >
                    <span
                      className={`flex h-6 w-6 shrink-0 items-center justify-center rounded text-[11px] font-mono font-semibold ${
                        isDone
                          ? "bg-emerald-100 text-emerald-700"
                          : isCurrent
                          ? "bg-blue-100 text-blue-700"
                          : "bg-slate-100 text-slate-500"
                      }`}
                    >
                      {isDone ? (
                        <CheckCircle2 className="h-3.5 w-3.5" />
                      ) : isCurrent ? (
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        idx + 1
                      )}
                    </span>
                    <div className="min-w-0">
                      <p className="text-[10px] font-mono uppercase tracking-wide text-slate-500">
                        Stage {idx + 1} · {isDone ? "Done" : isCurrent ? "Running" : "Queued"}
                      </p>
                      <p className="mt-0.5 break-words text-xs font-semibold leading-4 text-slate-900">{item.title}</p>
                    </div>
                  </li>
                );
              })}
            </ol>

            {/* Activity Log & Tools Grid */}
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <section
                className="min-w-0 overflow-hidden rounded-md border border-border bg-white"
                aria-labelledby="pipeline-activity-title"
              >
                <div className="border-b border-border bg-slate-50/70 px-4 py-2.5 flex items-center justify-between">
                  <h3 id="pipeline-activity-title" className="text-xs font-semibold text-slate-900">
                    Execution Activity Log
                  </h3>
                  <span className="text-[11px] font-mono text-slate-500">{audit.events?.length ?? 0} events</span>
                </div>
                <div className="max-h-64 overflow-y-auto px-4" tabIndex={0} aria-label="Assessment activity log">
                  {audit.events && audit.events.length > 0 ? (
                    <ol className="divide-y divide-slate-100">
                      {audit.events.map((evt, idx) => (
                        <li key={idx} className="flex items-start gap-2.5 py-2.5 text-xs">
                          <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-blue-600" />
                          <span className="min-w-0 flex-1 break-words leading-relaxed text-slate-700">{evt.label}</span>
                          <span className="shrink-0 font-mono text-[11px] tabular-nums text-slate-400">{evt.time}</span>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <p className="py-6 text-center text-xs text-slate-500">Waiting for initial stage output.</p>
                  )}
                </div>
              </section>

              <section
                className="min-w-0 overflow-hidden rounded-md border border-border bg-white"
                aria-labelledby="pipeline-tools-title"
              >
                <div className="border-b border-border bg-slate-50/70 px-4 py-2.5 flex items-center justify-between">
                  <h3 id="pipeline-tools-title" className="text-xs font-semibold text-slate-900">
                    Scanner Modules
                  </h3>
                  <span className="text-[11px] font-mono text-slate-500">{audit.tools?.length ?? 0} modules</span>
                </div>
                <div className="max-h-64 overflow-y-auto px-4" tabIndex={0} aria-label="Security tool list">
                  {audit.tools?.length ? (
                    <ul className="divide-y divide-slate-100">
                      {audit.tools.map((tool, idx) => {
                        const done = tool.stage < audit.completed;
                        const active = tool.stage === audit.completed && isRunning;
                        return (
                          <li key={idx} className="flex items-start justify-between gap-3 py-2.5">
                            <div className="min-w-0">
                              <p className="break-words text-xs font-semibold text-slate-800">{tool.title}</p>
                              <p className="mt-0.5 break-words text-[11px] leading-relaxed text-slate-500">
                                {tool.detail}
                              </p>
                            </div>
                            <span
                              className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-medium ${
                                done
                                  ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                                  : active
                                  ? "border-blue-200 bg-blue-50 text-blue-700"
                                  : "border-border bg-slate-50 text-slate-500"
                              }`}
                            >
                              {done ? "Complete" : active ? "Running" : "Queued"}
                            </span>
                          </li>
                        );
                      })}
                    </ul>
                  ) : (
                    <p className="py-6 text-center text-xs text-slate-500">No scanner module metadata available.</p>
                  )}
                </div>
              </section>
            </div>
          </div>
        </section>
      )}

      {/* Executive Findings & Structured Report */}
      {audit?.report ? (
        <section className="rounded-lg border border-border bg-white shadow-xs overflow-hidden">
          <div className="px-5 py-4 border-b border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Assessment Report & Findings Desk</h2>
              <p className="text-xs text-slate-500">
                Structured output categorized by reconnaissance domain, CVSS severity mentions, and remediation steps
              </p>
            </div>
            <button
              type="button"
              onClick={downloadReport}
              className="inline-flex items-center gap-1.5 self-start sm:self-auto rounded-md border border-border bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 hover:border-slate-300 transition-colors"
            >
              <Download className="h-3.5 w-3.5 text-slate-500" />
              Download Report (.md)
            </button>
          </div>

          {/* Unified Severity Mentions Bar (replaces duplicate cards + bar box) */}
          <div className="grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-border border-b border-border bg-slate-50/40">
            {[
              { label: "Critical", count: audit.counts?.Critical || 0, text: "text-red-700", bar: "bg-red-600" },
              { label: "High", count: audit.counts?.High || 0, text: "text-amber-700", bar: "bg-amber-500" },
              { label: "Medium", count: audit.counts?.Medium || 0, text: "text-blue-700", bar: "bg-blue-600" },
              { label: "Low", count: audit.counts?.Low || 0, text: "text-slate-700", bar: "bg-slate-400" },
            ].map((item) => (
              <div key={item.label} className="px-5 py-3.5 space-y-1.5">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">{item.label}</span>
                  <span className={`text-lg font-semibold font-mono tabular-nums ${item.text}`}>{item.count}</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-slate-200/70 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-300 ${item.bar}`}
                    style={{ width: `${Math.min(100, (item.count / maxRiskCount) * 100)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* Section Underline Tabs */}
          <div className="border-b border-border px-5 flex items-center gap-1 overflow-x-auto flex-nowrap">
            {reportSections.map((sec, idx) => {
              const isSelected =
                activeTab === sec.title ||
                ((!activeTab || activeTab === "Overview" || activeTab === "Target Overview") && idx === 0);
              return (
                <button
                  key={idx}
                  type="button"
                  onClick={() => setActiveTab(sec.title)}
                  className={`inline-flex items-center gap-1.5 px-3 py-3 text-xs font-medium border-b-2 transition-colors shrink-0 whitespace-nowrap ${
                    isSelected
                      ? "border-blue-600 text-slate-900 font-semibold"
                      : "border-transparent text-slate-500 hover:text-slate-800 hover:border-slate-300"
                  }`}
                >
                  <span className={isSelected ? "text-blue-600" : "text-slate-400"}>{getTabIcon(sec.title)}</span>
                  <span>{sec.title}</span>
                </button>
              );
            })}
          </div>

          {/* Active Report Body */}
          <div className="p-5 space-y-5">
            <div className="rounded-md border border-border bg-white p-4 sm:p-5">
              <MarkdownReport
                content={
                  reportSections.find((s) => s.title === activeTab)?.content ||
                  reportSections[0]?.content ||
                  audit.report
                }
              />
            </div>

            {/* Individual Stage Logs */}
            {audit.reports && Object.keys(audit.reports).length > 0 && (
              <div className="pt-4 border-t border-border space-y-2.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-700 flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-slate-500" />
                    Completed Stage Logs
                  </span>
                  <span className="font-mono text-[11px] text-slate-500">
                    {Object.keys(audit.reports).length} stages
                  </span>
                </div>
                <div className="divide-y divide-border rounded-md border border-border overflow-hidden">
                  {Object.entries(audit.reports).map(([stageName, stageContent], idx) => (
                    <details key={idx} className="bg-white group/stage">
                      <summary className="px-4 py-2.5 text-xs font-medium text-slate-800 cursor-pointer flex items-center justify-between hover:bg-slate-50/70 transition-colors list-none [&::-webkit-details-marker]:hidden">
                        <span>{stripEmojis(stageName)}</span>
                        <ChevronRight className="w-3.5 h-3.5 text-slate-400 group-open/stage:rotate-90 transition-transform" />
                      </summary>
                      <div className="px-4 pb-4 pt-2 border-t border-border bg-slate-50/40 max-h-96 overflow-y-auto">
                        <MarkdownReport content={stageContent} compact />
                      </div>
                    </details>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>
      ) : (
        <section className="rounded-lg border border-dashed border-border bg-slate-50/40 px-6 py-10 text-center space-y-2">
          <Lock className="w-5 h-5 text-slate-400 mx-auto" />
          <h3 className="text-sm font-semibold text-slate-900">No Assessment Report Generated</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Configure an authorized target URL or domain above and launch an assessment to populate stage telemetry and
            executive findings.
          </p>
        </section>
      )}

      {/* Recorded Observations & Local Pipeline Checks */}
      <AuditObservations
        findings={findings}
        loading={findingsLoading}
        loadError={findingsError}
        onRetry={() => void fetchStatus()}
        onResolve={resolveFinding}
      />

      <PipelineChecks
        runs={pipelineRuns}
        loading={pipelineLoading}
        loadError={pipelineError}
        manualStatus={manualPipelineStatus}
        manualStatusError={manualPipelineError}
        onRetry={() => void fetchStatus()}
        onRun={runPipelineChecks}
      />
    </div>
  );
}
