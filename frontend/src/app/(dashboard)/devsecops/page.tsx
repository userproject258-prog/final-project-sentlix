"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { API_URL, apiFetch as fetch } from "@/lib/api";
import MarkdownReport, { stripEmojis, normalizeMarkdownText } from "@/components/MarkdownReport";
import { AuditObservations, type AuditFinding } from "@/components/AuditObservations";
import { PipelineChecks, type ManualPipelineStatus, type PipelineRun } from "@/components/PipelineChecks";
import {
  Shield,
  Activity,
  Play,
  Pause,
  ArrowRight,
  Download,
  CheckCircle2,
  Layers,
  RefreshCw,
  Lock,
  Globe,
  AlertTriangle,
  Radio,
  Compass,
  Zap,
  Code2,
  Key,
  ShieldAlert,
  FileText,
  ChevronRight,
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
  const [provider, setProvider] = useState("gemini");
  const [loading, setLoading] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<string>("Overview");
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);

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
      fetchStatus();
    }, 0);
    pollIntervalRef.current = setInterval(fetchStatus, 2000);
    return () => {
      clearTimeout(timer);
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, [fetchStatus]);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) {
      alert("Please enter a valid target URL or domain.");
      return;
    }
    if (!authorized) {
      alert("You must verify authorization to test this target.");
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
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.detail || "Failed to start audit");
      } else {
        setAudit(data);
      }
    } catch (err) {
      console.error("Audit start error:", err);
      alert("Failed to communicate with backend server.");
    } finally {
      setLoading(false);
    }
  };

  const handleNextStage = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/next`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Could not start the next stage");
      setAudit(data);
    } catch (err) {
      console.error(err);
      alert(err instanceof Error ? err.message : "Could not start the next stage");
    } finally {
      setActionLoading(false);
    }
  };

  const handleRunAll = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/run-all`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Could not continue the audit");
      setAudit(data);
    } catch (err) {
      console.error(err);
      alert(err instanceof Error ? err.message : "Could not continue the audit");
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/stop`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Could not stop the audit");
      setAudit(data);
    } catch (err) {
      console.error(err);
      alert(err instanceof Error ? err.message : "Could not stop the audit");
    } finally {
      setActionLoading(false);
    }
  };

  const resolveFinding = async (finding: AuditFinding): Promise<number> => {
    const response = await fetch(`${API_URL}/api/devsecops/findings/${encodeURIComponent(finding.id)}/resolve`, { method: "POST" });
    if (!response.ok) throw new Error("Could not resolve finding");
    const result = await response.json();
    setFindings((previous) => previous.map((item) => item.target === finding.target && item.title === finding.title ? { ...item, status: "Resolved" } : item));
    void fetchStatus();
    return result.resolved_observations;
  };

  const runPipelineChecks = async () => {
    const response = await fetch(`${API_URL}/api/devsecops/runs/manual`, { method: "POST" });
    const result = await response.json();
    if (!response.ok) {
      void fetchStatus();
      throw new Error(typeof result.detail === "string" ? result.detail : "Could not start pipeline checks. Please try again.");
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

  // Structured Markdown Sections Parser
  const parseReportSections = (text: string) => {
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
  };

  const getTabIcon = (title: string) => {
    const t = title.toLowerCase();
    if (t.includes("overview") || t.includes("target"))
      return <Shield className="w-3.5 h-3.5 flex-shrink-0 text-primary" />;
    if (t.includes("dns") || t.includes("ip") || t.includes("network") || t.includes("topology") || t.includes("recon") || t.includes("asn") || t.includes("geolocation"))
      return <Globe className="w-3.5 h-3.5 flex-shrink-0 text-cyan-500" />;
    if (t.includes("shodan") || t.includes("port") || t.includes("surface") || t.includes("perimeter"))
      return <Radio className="w-3.5 h-3.5 flex-shrink-0 text-amber-500" />;
    if (t.includes("header") || t.includes("cookie") || t.includes("ssl") || t.includes("tls") || t.includes("cert") || t.includes("email") || t.includes("posture"))
      return <Lock className="w-3.5 h-3.5 flex-shrink-0 text-emerald-500" />;
    if (t.includes("endpoint") || t.includes("path") || t.includes("discovery") || t.includes("prob"))
      return <Compass className="w-3.5 h-3.5 flex-shrink-0 text-primary" />;
    if (t.includes("dos") || t.includes("rate limit") || t.includes("load") || t.includes("resilience"))
      return <Zap className="w-3.5 h-3.5 flex-shrink-0 text-amber-500" />;
    if (t.includes("injection") || t.includes("sql") || t.includes("xss") || t.includes("payload") || t.includes("cpe") || t.includes("software") || t.includes("fingerprint"))
      return <Code2 className="w-3.5 h-3.5 flex-shrink-0 text-rose-500" />;
    if (t.includes("auth") || t.includes("login") || t.includes("session") || t.includes("token"))
      return <Key className="w-3.5 h-3.5 flex-shrink-0 text-violet-500" />;
    if (t.includes("cve") || t.includes("owasp") || t.includes("vulnerab") || t.includes("threat") || t.includes("hostname") || t.includes("classification"))
      return <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0 text-rose-500" />;
    if (t.includes("risk") || t.includes("profile") || t.includes("matrix") || t.includes("score"))
      return <Activity className="w-3.5 h-3.5 flex-shrink-0 text-cyan-500" />;
    if (t.includes("remediation") || t.includes("roadmap") || t.includes("action") || t.includes("recommend") || t.includes("item") || t.includes("summary"))
      return <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 text-emerald-500" />;
    return <FileText className="w-3.5 h-3.5 flex-shrink-0 text-primary" />;
  };

  const reportSections = audit?.report ? parseReportSections(audit.report) : [];
  const maxRiskCount = audit?.counts ? Math.max(...Object.values(audit.counts), 1) : 1;
  const isRunning = audit?.status === "running" || audit?.status === "queued";

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      {/* Page header */}
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-6 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <div className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.14em] text-primary">
            <Shield className="h-3.5 w-3.5" /> Security audit <span className="text-slate-300">/</span> DevSecOps AI
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 sm:text-3xl">Security assessment</h1>
          <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-slate-500">Configure a target and review security evidence across your assessment stages.</p>
        </div>
        <div className="inline-flex w-fit shrink-0 items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-600 shadow-xs" aria-live="polite">
          <span className={`h-2 w-2 rounded-full ${isRunning ? "bg-amber-500" : audit?.status === "complete" ? "bg-emerald-500" : audit?.status === "failed" ? "bg-rose-500" : "bg-slate-400"}`} />
          <span className="capitalize">{audit?.status || (connectionError ? "Unavailable" : "Connecting")}</span>
          {audit?.status === "running" && <span className="border-l border-slate-200 pl-2 font-normal text-slate-500">Stage {audit.completed + 1} of {audit.total_stages}</span>}
        </div>
      </header>

      {connectionError && <div role="alert" className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">Unable to refresh audit status. The information shown may be out of date. <button onClick={fetchStatus} className="font-semibold underline">Retry</button></div>}

      {/* Error Banner if Audit Failed or Errored */}
      {audit?.error && (
        <div className="p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 text-red-500" />
            <div className="text-sm">
              <span className="font-semibold">Assessment Notice:</span> {audit.error}
            </div>
          </div>
          <button
            type="button"
            onClick={async () => {
              try {
                await fetch(`${API_URL}/api/devsecops/audit/stop`, { method: "POST" });
                fetchStatus();
              } catch (e) {
                console.error(e);
              }
            }}
            className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-xs font-semibold whitespace-nowrap transition-colors"
          >
            Reset Scanner
          </button>
        </div>
      )}

      {/* Assessment configuration and status */}
      <div className="grid grid-cols-1 items-start gap-5 lg:grid-cols-3">
        <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-xs lg:col-span-2">
          <div className="flex items-start gap-3 border-b border-slate-100 px-5 py-5 sm:px-6">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-blue-100 bg-blue-50 text-primary"><Globe className="h-5 w-5" /></div>
            <div><h2 className="text-base font-bold text-slate-900">Configure assessment</h2><p className="mt-1 text-xs leading-relaxed text-slate-500">Choose where and how you want to run the audit.</p></div>
          </div>
          <form onSubmit={handleLaunch} className="space-y-5 p-5 sm:p-6">
            <div>
              <label htmlFor="audit-target" className="mb-2 block text-xs font-semibold text-slate-700">Target domain, IP, or URL <span className="text-rose-500">*</span></label>
              <div className="relative">
                <Globe className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                <input type="text" id="audit-target" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://app.example.com" className="w-full rounded-lg border border-slate-300 bg-white py-3 pl-10 pr-4 text-sm text-slate-900 placeholder:text-slate-400 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 disabled:bg-slate-50 disabled:text-slate-500" disabled={isRunning} required aria-describedby="audit-target-hint" />
              </div>
              <p id="audit-target-hint" className="mt-1.5 text-[11px] text-slate-500">Enter a domain, IP address, or full URL.</p>
            </div>

            <div>
              <label htmlFor="audit-provider" className="mb-2 block text-xs font-semibold text-slate-700">AI provider</label>
              <select id="audit-provider" value={provider} onChange={(e) => setProvider(e.target.value)} disabled={isRunning} className="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-3 text-sm text-slate-900 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 disabled:bg-slate-50 disabled:text-slate-500">
                <option value="gemini">Google Gemini</option>
                <option value="grok">xAI Grok</option>
                <option value="openai">OpenAI</option>
              </select>
            </div>

            <fieldset disabled={isRunning}>
              <legend className="mb-2 block text-xs font-semibold text-slate-700">Assessment mode</legend>
              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                {[
                  { value: "guided" as const, label: "Guided assessment", description: "Review and continue one stage at a time." },
                  { value: "all" as const, label: "Run all stages", description: "Run the full assessment automatically." },
                ].map((option) => (
                  <label key={option.value} className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3.5 transition-colors ${mode === option.value ? "border-blue-300 bg-blue-50/60" : "border-slate-200 bg-white hover:border-slate-300"} ${isRunning ? "cursor-not-allowed opacity-60" : ""}`}>
                    <input type="radio" name="mode" value={option.value} checked={mode === option.value} onChange={() => setMode(option.value)} className="mt-0.5 h-4 w-4 accent-primary" />
                    <span><span className="block text-xs font-semibold text-slate-900">{option.label}</span><span className="mt-1 block text-[11px] leading-relaxed text-slate-500">{option.description}</span></span>
                  </label>
                ))}
              </div>
            </fieldset>

            <label className={`flex items-start gap-3 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3.5 ${isRunning ? "opacity-60" : "cursor-pointer"}`}>
              <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} disabled={isRunning} className="mt-0.5 h-4 w-4 shrink-0 accent-primary" required />
              <span className="text-xs leading-relaxed text-slate-600"><span className="font-semibold text-slate-800">I have authorization to test this target.</span> Active probes may generate network traffic and simulate intrusion vectors.</span>
            </label>

            <div className="flex flex-wrap items-center gap-3 border-t border-slate-100 pt-4">
              <button type="submit" disabled={loading || isRunning || !target.trim()} className="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-semibold text-white shadow-xs transition-colors hover:bg-blue-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary disabled:cursor-not-allowed disabled:opacity-50">
                {loading || isRunning ? <><RefreshCw className="h-4 w-4 animate-spin" /><span>Executing audit...</span></> : <><Play className="h-4 w-4 fill-current" /><span>Launch assessment</span><ArrowRight className="ml-1 h-4 w-4" /></>}
              </button>
              {audit && audit.status !== "idle" && <button type="button" onClick={fetchStatus} aria-label="Refresh assessment status" className="rounded-lg border border-slate-200 bg-white p-2.5 text-slate-500 transition-colors hover:bg-slate-50 hover:text-slate-800"><RefreshCw className="h-4 w-4" /></button>}
            </div>
          </form>
        </section>

        <aside className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-xs" aria-label="Assessment overview">
          <div className="flex items-center gap-3 border-b border-slate-100 px-5 py-5">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-slate-600"><Activity className="h-5 w-5" /></div>
            <div><h2 className="text-sm font-bold text-slate-900">Assessment overview</h2><p className="mt-1 text-xs text-slate-500">Your current audit at a glance</p></div>
          </div>
          <div className="space-y-5 p-5">
            <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-4">
              <div className="flex items-center justify-between gap-3"><span className="text-xs font-semibold text-slate-600">Stage progress</span><span className="text-xs font-bold tabular-nums text-slate-900">{audit ? audit.completed : "—"} <span className="font-normal text-slate-400">/</span> {audit?.total_stages || 8}</span></div>
              <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-200" role="progressbar" aria-label="Assessment stage progress" aria-valuemin={0} aria-valuemax={audit?.total_stages || 8} aria-valuenow={audit ? audit.completed : undefined}><div className="h-full rounded-full bg-primary transition-all duration-500" style={{ width: `${Math.min(100, Math.max(0, ((audit?.completed ?? 0) / (audit?.total_stages || 8)) * 100))}%` }} /></div>
              <p className="mt-2.5 text-[11px] leading-relaxed text-slate-500">{!audit ? (connectionError ? "Assessment status unavailable." : "Connecting to the assessment service...") : audit.status !== "idle" ? audit.active : "Ready to begin when you are."}</p>
            </div>

            <dl className="divide-y divide-slate-100">
              <div className="flex items-start justify-between gap-4 py-3 first:pt-0"><dt className="text-xs text-slate-500">Status</dt><dd className="text-right text-xs font-semibold capitalize text-slate-800">{audit?.status || (connectionError ? "Unavailable" : "Connecting")}</dd></div>
              <div className="flex items-start justify-between gap-4 py-3"><dt className="text-xs text-slate-500">Critical / high mentions</dt><dd className="text-right text-xs font-semibold tabular-nums text-slate-800">{audit ? (audit.counts?.Critical || 0) + (audit.counts?.High || 0) : "—"}</dd></div>
              <div className="flex items-start justify-between gap-4 py-3"><dt className="text-xs text-slate-500">Last started</dt><dd className="text-right text-xs font-semibold text-slate-800">{audit ? audit.started || "No assessment yet" : "—"}</dd></div>
              {audit?.target && <div className="flex items-start justify-between gap-4 py-3"><dt className="shrink-0 text-xs text-slate-500">Target</dt><dd className="break-all text-right text-xs font-medium text-slate-800">{audit.target}</dd></div>}
            </dl>
            <p className="flex items-start gap-2 rounded-lg bg-blue-50 px-3 py-2.5 text-[11px] leading-relaxed text-blue-800"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-blue-600" /><span>Severity mentions are counted from report text, not verified findings.</span></p>
          </div>
        </aside>
      </div>

      {/* Live Session Progress Bar & Pipeline Steps */}
      {audit && audit.status !== "idle" && (
        <div className="bg-surface border border-border rounded-xl p-6 shadow-xs space-y-6">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
            <div>
              <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-500" />
                Live Assessment Execution Pipeline
              </h2>
              <p className="text-xs text-muted mt-0.5">
                Active Target: <span className="font-mono text-foreground font-semibold">{audit.target}</span>
              </p>
            </div>

            {/* Guided Controls */}
            {(audit.status === "stopped" || (audit.status === "complete" && audit.mode === "guided")) && (
              <div className="flex items-center gap-2">
                {audit.completed < audit.total_stages ? (
                  <>
                    <button
                      onClick={handleNextStage}
                      disabled={actionLoading}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors cursor-pointer"
                    >
                      <ArrowRight className="w-3.5 h-3.5" /> Next Stage ({audit.completed + 1})
                    </button>
                    <button
                      onClick={handleRunAll}
                      disabled={actionLoading}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors cursor-pointer"
                    >
                      <Play className="w-3.5 h-3.5" /> Run All Remaining
                    </button>
                  </>
                ) : (
                  <div className="flex items-center gap-1.5 text-xs text-emerald-600 font-semibold bg-emerald-50 dark:bg-emerald-950/40 px-3 py-1.5 rounded-lg border border-emerald-200 dark:border-emerald-800">
                    <CheckCircle2 className="w-4 h-4" /> All Stages Complete
                  </div>
                )}
                {isRunning && (
                  <button
                    onClick={handleStop}
                    disabled={actionLoading}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors cursor-pointer"
                  >
                    <Pause className="w-3.5 h-3.5" /> Pause
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Progress Bar */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs font-mono text-muted">
              <span>{audit.active}</span>
              <span>{Math.round((audit.completed / (audit.total_stages || 8)) * 100)}%</span>
            </div>
            <div className="w-full bg-border/60 h-2 rounded-full overflow-hidden">
              <div
                className="bg-primary h-full transition-all duration-500 rounded-full"
                style={{ width: `${(audit.completed / (audit.total_stages || 8)) * 100}%` }}
              />
            </div>
          </div>

          {/* Pipeline Step Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2.5 pt-2">
            {audit.pipeline?.map((item, idx) => {
              const isDone = idx < audit.completed;
              const isCurrent = idx === audit.completed && isRunning;
              return (
                <div
                  key={idx}
                  className={`p-3 rounded-lg border text-center transition-all ${
                    isDone
                      ? "border-emerald-300 dark:border-emerald-800 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                      : isCurrent
                      ? "border-amber-400 bg-amber-500/15 text-amber-700 dark:text-amber-300 ring-2 ring-amber-400/30"
                      : "border-border bg-background text-muted"
                  }`}
                >
                  <div className="text-[10px] font-mono uppercase mb-1">Stage {idx + 1}</div>
                  <div className="font-semibold text-xs truncate" title={item.title}>
                    {item.title}
                  </div>
                  <div className="mt-1.5 flex justify-center">
                    {isDone ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                    ) : isCurrent ? (
                      <RefreshCw className="w-4 h-4 text-amber-500 animate-spin" />
                    ) : (
                      <span className="w-2 h-2 rounded-full bg-border mt-1" />
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Tools & Events Live Activity */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <div className="border border-border/80 rounded-lg p-4 bg-background/50">
              <div className="text-xs font-mono uppercase text-muted mb-2">Live Agent Activities</div>
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-2">
                {audit.events && audit.events.length > 0 ? (
                  audit.events.map((evt, idx) => (
                    <div key={idx} className="flex items-center justify-between text-xs py-1 border-b border-border/40 font-mono">
                      <span className="text-foreground">{evt.label}</span>
                      <span className="text-muted text-[11px]">{evt.time}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-muted py-2">Waiting for first agent event...</div>
                )}
              </div>
            </div>

            <div className="border border-border/80 rounded-lg p-4 bg-background/50">
              <div className="text-xs font-mono uppercase text-muted mb-2">Security Tool Instrumentation</div>
              <div className="grid grid-cols-2 gap-2 text-xs max-h-48 overflow-y-auto pr-1">
                {audit.tools?.map((tool, idx) => {
                  const done = tool.stage < audit.completed;
                  const active = tool.stage === audit.completed && isRunning;
                  return (
                    <div key={idx} className="p-2 border border-border/50 rounded bg-surface/50">
                      <div className="font-semibold text-[11px] text-foreground truncate">{tool.title}</div>
                      <div className="text-[10px] text-muted truncate">{tool.detail}</div>
                      <span
                        className={`text-[9px] font-mono uppercase mt-1 inline-block ${
                          done ? "text-emerald-500" : active ? "text-amber-500 animate-pulse" : "text-muted"
                        }`}
                      >
                        {done ? "Complete" : active ? "Running" : "Queued"}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      <PipelineChecks runs={pipelineRuns} loading={pipelineLoading} loadError={pipelineError} manualStatus={manualPipelineStatus} manualStatusError={manualPipelineError} onRetry={() => void fetchStatus()} onRun={runPipelineChecks} />
      <AuditObservations findings={findings} loading={findingsLoading} loadError={findingsError} onRetry={() => void fetchStatus()} onResolve={resolveFinding} />
      {/* Findings Desk & Risk Breakdown */}
      {audit?.report ? (
        <div className="space-y-6">
          {/* Severity Strip & Download Bar */}
          <div className="bg-surface border border-border rounded-xl p-6 shadow-xs space-y-6">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-border/40 pb-4">
              <div>
                <h2 className="text-lg font-bold text-foreground">Findings Desk & Risk Distribution</h2>
                <p className="text-xs text-muted mt-0.5">Automated triage categorized by CVSS and OWASP standards</p>
              </div>

              <button
                onClick={downloadReport}
                className="flex items-center gap-2 px-4 py-2 bg-foreground text-background font-semibold text-xs rounded-lg hover:opacity-90 transition-opacity cursor-pointer shadow-xs"
              >
                <Download className="w-3.5 h-3.5" /> Download Executive Report (.md)
              </button>
            </div>

            <p className="text-xs text-muted">The numbers below count severity words in the current report, not verified findings. Review the evidence before prioritizing remediation.</p>
            {/* Severity Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl border border-red-500/20 bg-red-500/10">
                <span className="text-xs font-mono font-bold text-red-500 uppercase">Critical</span>
                <div className="text-2xl font-extrabold text-red-600 dark:text-red-400 mt-1">
                  {audit.counts?.Critical || 0}
                </div>
                <div className="text-[11px] text-muted mt-0.5">Word mentions</div>
              </div>

              <div className="p-4 rounded-xl border border-amber-500/20 bg-amber-500/10">
                <span className="text-xs font-mono font-bold text-amber-500 uppercase">High</span>
                <div className="text-2xl font-extrabold text-amber-600 dark:text-amber-400 mt-1">
                  {audit.counts?.High || 0}
                </div>
                <div className="text-[11px] text-muted mt-0.5">Word mentions</div>
              </div>

              <div className="p-4 rounded-xl border border-cyan-500/20 bg-cyan-500/10">
                <span className="text-xs font-mono font-bold text-cyan-500 uppercase">Medium</span>
                <div className="text-2xl font-extrabold text-cyan-600 dark:text-cyan-400 mt-1">
                  {audit.counts?.Medium || 0}
                </div>
                <div className="text-[11px] text-muted mt-0.5">Word mentions</div>
              </div>

              <div className="p-4 rounded-xl border border-slate-500/20 bg-slate-500/10">
                <span className="text-xs font-mono font-bold text-slate-500 uppercase">Low</span>
                <div className="text-2xl font-extrabold text-slate-600 dark:text-slate-400 mt-1">
                  {audit.counts?.Low || 0}
                </div>
                <div className="text-[11px] text-muted mt-0.5">Word mentions</div>
              </div>
            </div>

            {/* Risk Graph Track */}
            <div className="p-4 border border-border rounded-lg bg-background space-y-3">
              <div className="text-xs font-mono uppercase text-muted">Severity Word Mentions</div>
              <div className="space-y-2.5">
                {[
                  { label: "Critical", count: audit.counts?.Critical || 0, color: "bg-red-500" },
                  { label: "High", count: audit.counts?.High || 0, color: "bg-amber-500" },
                  { label: "Medium", count: audit.counts?.Medium || 0, color: "bg-cyan-500" },
                  { label: "Low", count: audit.counts?.Low || 0, color: "bg-slate-400" },
                ].map((item) => (
                  <div key={item.label} className="flex items-center gap-3 text-xs font-mono">
                    <span className="w-16 font-semibold text-foreground">{item.label}</span>
                    <div className="flex-1 bg-border/40 h-2.5 rounded-full overflow-hidden">
                      <div
                        className={`${item.color} h-full rounded-full transition-all duration-500`}
                        style={{ width: `${(item.count / maxRiskCount) * 100}%` }}
                      />
                    </div>
                    <span className="w-8 text-right font-bold text-foreground">{item.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Structured Report Tabs */}
          <div className="bg-surface border border-border rounded-xl p-6 shadow-xs space-y-6">
            <div className="border-b border-border/60 pb-3 flex items-center justify-between">
              <h3 className="text-base font-bold text-foreground flex items-center gap-2">
                <Layers className="w-4 h-4 text-primary" /> Structured Executive Findings
              </h3>
              <span className="text-xs text-muted font-mono">Interactive Tabs</span>
            </div>

            {/* Tabs Header with Real Lucide Icons */}
            <div className="flex gap-2 overflow-x-auto pb-2 border-b border-border/40 flex-nowrap scrollbar-none">
              {reportSections.map((sec, idx) => (
                <button
                  key={idx}
                  onClick={() => setActiveTab(sec.title)}
                  className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex-shrink-0 whitespace-nowrap ${
                    activeTab === sec.title || ((!activeTab || activeTab === "Overview" || activeTab === "Target Overview") && idx === 0)
                      ? "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30 shadow-2xs"
                      : "text-muted hover:text-foreground hover:bg-surface border border-transparent"
                  }`}
                >
                  {getTabIcon(sec.title)}
                  <span>{sec.title}</span>
                </button>
              ))}
            </div>

            {/* Tab Body Data Sheet */}
            <div className="p-4 sm:p-5 rounded-xl bg-background/80 border border-border/80">
              <MarkdownReport
                content={
                  reportSections.find((s) => s.title === activeTab)?.content ||
                  reportSections[0]?.content ||
                  audit.report
                }
              />
            </div>

            {/* Guided Individual Stage Reports if Available */}
            {audit.reports && Object.keys(audit.reports).length > 0 && (
              <div className="pt-4 border-t border-border/40 space-y-3">
                <div className="text-xs font-mono uppercase text-muted flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-primary" />
                  Completed Stage Logs ({Object.keys(audit.reports).length} stages)
                </div>
                <div className="grid grid-cols-1 gap-3">
                  {Object.entries(audit.reports).map(([stageName, stageContent], idx) => (
                    <details key={idx} className="border border-border rounded-lg p-3 bg-background group">
                      <summary className="text-xs font-semibold text-foreground cursor-pointer flex items-center justify-between">
                        <span className="flex items-center gap-2">
                          <Layers className="w-3.5 h-3.5 text-primary/70" />
                          {stripEmojis(stageName)}
                        </span>
                        <ChevronRight className="w-4 h-4 text-primary group-open:rotate-90 transition-transform" />
                      </summary>
                      <div className="mt-3 p-3 rounded-lg bg-surface border border-border/60 max-h-96 overflow-y-auto">
                        <MarkdownReport content={stageContent} compact />
                      </div>
                    </details>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="bg-surface border border-dashed border-border rounded-xl p-10 text-center space-y-3">
          <div className="w-12 h-12 rounded-full bg-primary/10 text-primary flex items-center justify-center mx-auto">
            <Lock className="w-6 h-6" />
          </div>
          <h3 className="text-base font-semibold text-foreground">No Assessment Active</h3>
          <p className="text-xs text-muted max-w-md mx-auto">
            Enter an authorized domain, URL, or IP address in the configuration panel above to kick off the multi-agent AI security audit.
          </p>
        </div>
      )}
    </div>
  );
}
