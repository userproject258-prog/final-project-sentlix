"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import Link from "next/link";
import { API_URL, WS_URL, apiFetch, getCachedData, setCachedData, websocketProtocols } from "@/lib/api";
import { TrafficSimulator } from "@/components/TrafficSimulator";
import {
  Activity,
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronRight,
  Copy,
  FlaskConical,
  Loader2,
  RefreshCw,
  Search,
  ShieldCheck,
  X,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

interface OverviewData {
  generated_at?: string;
  stats: {
    threats: number;
    open_threats?: number;
    threats_24h?: number;
    critical: number;
    open_critical?: number;
    risk_score: number;
    cloud_security_score: number;
    active_alerts?: number;
    open_audit_findings?: number;
    pipeline_pass_rate?: number | null;
  };
  posture?: {
    grade: "A" | "B" | "C" | "D" | "F";
    label: string;
    breakdown: {
      threat_risk: number;
      cloud_risk: number;
      audit_risk: number;
      iam_risk: number;
      infra_risk: number;
    };
    top_assets: { name: string; score: number }[];
  };
  trends: {
    threats: { direction: string; value: string; current?: number; previous?: number };
    critical: { direction: string; value: string; current?: number; previous?: number };
    cloud_security_score: { direction: string; value: string; current?: number; previous?: number };
  };
  threat_distribution: { label: string; count: number }[];
  severity_distribution?: { name: string; key: string; value: number }[];
  timeline?: {
    date: string;
    label: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  }[];
  top_sources?: {
    source: string;
    count: number;
    max_severity: string;
    last_seen: string;
    types: string[];
    simulated: boolean;
  }[];
  cspm?: {
    score: number;
    total: number;
    open: number;
    resolved: number;
    by_severity: Record<string, number>;
    last_scan: string | null;
    top_open: { id: string; finding: string; resource: string; severity: string }[];
  };
  alerts?: {
    active: number;
    total: number;
    by_severity: Record<string, number>;
    recent: {
      id: string;
      title: string;
      severity: string;
      source: string;
      message: string;
      status: string;
      time: string;
    }[];
  };
  audit?: {
    open: number;
    total: number;
    by_severity: Record<string, number>;
    latest_report: { id: string; target: string; time: string; completed_stages: number } | null;
    top_open: { id: string; title: string; target: string; severity: string }[];
  };
  pipeline?: {
    total: number;
    passed: number;
    failed: number;
    pass_rate: number | null;
    recent: { id: string; commit_sha: string; branch: string; developer: string; status: string; time: string }[];
  };
  system?: {
    cpu_usage: number;
    memory_usage: number;
    api_latency: number;
    network_rx?: number;
    network_tx?: number;
    time: string;
  } | null;
  ai?: {
    configured: boolean;
    provider?: string;
    engine: string;
  };
  recent_events: {
    id: string;
    time: string;
    timestamp?: string;
    type: string;
    source: string;
    destination?: string;
    confidence?: number;
    severity: string;
    status: string;
    simulated: boolean;
  }[];
  risk_trend: { date: string; score: number }[];
}

function SeverityDot({ severity }: { severity: string }) {
  const sev = (severity || "").toUpperCase();
  const style =
    sev === "CRITICAL"
      ? { dot: "bg-red-600", text: "text-red-700" }
      : sev === "HIGH"
      ? { dot: "bg-amber-500", text: "text-amber-700" }
      : sev === "MEDIUM"
      ? { dot: "bg-blue-600", text: "text-blue-700" }
      : { dot: "bg-slate-400", text: "text-slate-600" };

  return (
    <span className={`inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide ${style.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${style.dot}`} />
      {sev || "INFO"}
    </span>
  );
}

function TrendTag({ direction, value }: { direction?: string; value?: string }) {
  if (!value || direction === "flat") {
    return <span className="text-[11px] font-mono text-slate-500">0 vs 7d</span>;
  }
  const isUp = direction === "up";
  return (
    <span
      className={`text-[11px] font-mono font-medium ${
        isUp ? "text-red-600" : "text-emerald-700"
      }`}
    >
      {value} vs 7d
    </span>
  );
}

function formatSyncTime(iso?: string): string {
  if (!iso) return "";
  try {
    return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return "";
  }
}

export default function OverviewPage() {
  const [data, setData] = useState<OverviewData | null>(() => getCachedData<OverviewData>("/api/overview"));
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const [showAttackLab, setShowAttackLab] = useState(false);
  const [lastNotification, setLastNotification] = useState<string | null>(null);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);
  const [updatingThreatId, setUpdatingThreatId] = useState<string | null>(null);
  const [resolvingAlertId, setResolvingAlertId] = useState<string | null>(null);
  const [remediatingCspmId, setRemediatingCspmId] = useState<string | null>(null);
  const [scanningCspm, setScanningCspm] = useState(false);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Table filters & search
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  const showFeedback = useCallback((msg: string) => {
    setActionFeedback(msg);
    setTimeout(() => {
      setActionFeedback((current) => (current === msg ? null : current));
    }, 4000);
  }, []);

  const fetchOverview = useCallback(async () => {
    try {
      const res = await apiFetch(`${API_URL}/api/overview`);
      if (res.ok) {
        const json = await res.json();
        setCachedData("/api/overview", json);
        setData(json);
      }
    } catch (err) {
      console.error("Failed to load overview data:", err);
    }
  }, []);

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    await fetchOverview();
    setIsRefreshing(false);
    showFeedback("Telemetry synchronized.");
  };

  useEffect(() => {
    let isCancelled = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;

    const loadInitialData = async () => {
      try {
        const res = await apiFetch(`${API_URL}/api/overview`);
        if (res.ok && !isCancelled) {
          const json = await res.json();
          setCachedData("/api/overview", json);
          setData(json);
        }
      } catch (err) {
        console.error("Failed to load overview data:", err);
      }
    };

    void loadInitialData();

    const connectWs = () => {
      try {
        const ws = new WebSocket(WS_URL, websocketProtocols());
        wsRef.current = ws;

        ws.onopen = () => {
          if (!isCancelled) setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (
              msg.type === "NEW_THREAT" ||
              msg.type === "CSPM_REMEDIATED" ||
              msg.type === "NEW_PIPELINE_RUN" ||
              msg.type === "AUDIT_FINDING_RESOLVED" ||
              msg.type === "ALERT_RESOLVED" ||
              msg.type === "THREAT_STATUS_UPDATED"
            ) {
              if (msg.type === "NEW_THREAT") {
                setLastNotification(
                  `New event detected: ${msg.threat?.type || "Anomaly"} from ${msg.threat?.source || "external source"}`
                );
              }
              void fetchOverview();
            }
          } catch {
            // Ignore malformed WS payloads
          }
        };

        ws.onclose = () => {
          if (!isCancelled) {
            setWsConnected(false);
            reconnectTimer = setTimeout(connectWs, 3500);
          }
        };

        ws.onerror = () => {
          if (!isCancelled) setWsConnected(false);
        };
      } catch {
        if (!isCancelled) setWsConnected(false);
      }
    };

    connectWs();
    const interval = setInterval(() => void fetchOverview(), 10000);

    return () => {
      isCancelled = true;
      clearInterval(interval);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) wsRef.current.close();
    };
  }, [fetchOverview]);

  const handleUpdateThreatStatus = async (threatId: string, newStatus: "Open" | "Investigating" | "Resolved") => {
    setUpdatingThreatId(threatId);
    try {
      const res = await apiFetch(`${API_URL}/api/threats/${threatId}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error("Failed to update status");

      setData((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          recent_events: prev.recent_events.map((evt) =>
            evt.id === threatId ? { ...evt, status: newStatus } : evt
          ),
        };
      });

      showFeedback(`Incident ${threatId} updated to ${newStatus}.`);
      void fetchOverview();
    } catch {
      showFeedback(`Unable to update incident ${threatId}.`);
    } finally {
      setUpdatingThreatId(null);
    }
  };

  const handleResolveAlert = async (alertId: string, alertTitle: string) => {
    setResolvingAlertId(alertId);
    try {
      const res = await apiFetch(`${API_URL}/api/alerts/resolve/${encodeURIComponent(alertId)}`, {
        method: "POST",
      });
      if (!res.ok) throw new Error("Failed to resolve alert");

      setData((prev) => {
        if (!prev || !prev.alerts) return prev;
        return {
          ...prev,
          alerts: {
            ...prev.alerts,
            active: Math.max(0, prev.alerts.active - 1),
            recent: prev.alerts.recent.filter((a) => a.id !== alertId),
          },
        };
      });

      showFeedback(`Resolved alert: ${alertTitle}`);
      void fetchOverview();
    } catch {
      showFeedback(`Unable to resolve alert ${alertId}.`);
    } finally {
      setResolvingAlertId(null);
    }
  };

  const handleRemediateCspm = async (findingId: string, resource: string) => {
    setRemediatingCspmId(findingId);
    try {
      const res = await apiFetch(`${API_URL}/api/cspm/remediate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: findingId }),
      });
      if (!res.ok) throw new Error("Remediation failed");

      showFeedback(`Policy enforced on ${resource}.`);
      void fetchOverview();
    } catch {
      showFeedback(`Unable to enforce policy on ${resource}.`);
    } finally {
      setRemediatingCspmId(null);
    }
  };

  const handleRunCspmScan = async () => {
    setScanningCspm(true);
    try {
      const res = await apiFetch(`${API_URL}/api/cspm/scan`, { method: "POST" });
      if (!res.ok) throw new Error("Scan failed");
      showFeedback("Cloud posture scan completed.");
      await fetchOverview();
    } catch {
      showFeedback("Cloud posture scan could not complete.");
    } finally {
      setScanningCspm(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedIp(text);
    setTimeout(() => setCopiedIp((cur) => (cur === text ? null : cur)), 2000);
  };

  if (!data || !data.stats) {
    return (
      <div className="max-w-[1440px] mx-auto py-20 flex flex-col items-center justify-center gap-2.5 text-slate-500">
        <Loader2 className="w-6 h-6 text-blue-600 animate-spin" />
        <p className="text-sm font-medium text-slate-900">Loading security posture...</p>
        <p className="text-xs text-slate-500">Fetching threat events, cloud posture, and system metrics.</p>
      </div>
    );
  }

  const recentEvents = data.recent_events ?? [];
  const filteredEvents = recentEvents.filter((evt) => {
    const q = searchQuery.trim().toLowerCase();
    const matchesSearch =
      q === "" ||
      evt.type.toLowerCase().includes(q) ||
      evt.source.toLowerCase().includes(q) ||
      (evt.destination || "").toLowerCase().includes(q) ||
      evt.id.toLowerCase().includes(q);
    const matchesSeverity = severityFilter === "ALL" || evt.severity.toUpperCase() === severityFilter;
    const matchesStatus = statusFilter === "ALL" || evt.status.toLowerCase() === statusFilter.toLowerCase();
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const timelineChartData =
    data.timeline && data.timeline.length > 0
      ? data.timeline
      : (data.risk_trend || []).map((r) => ({
          date: r.date,
          label: r.date,
          critical: Math.round(r.score / 25),
          high: 0,
          medium: 0,
          low: 0,
          total: Math.round(r.score / 25),
        }));

  const riskScore = data.stats.risk_score;
  const grade =
    data.posture?.grade ||
    (riskScore < 20 ? "A" : riskScore < 40 ? "B" : riskScore < 60 ? "C" : riskScore < 80 ? "D" : "F");
  const postureLabel =
    data.posture?.label ||
    (riskScore >= 70 ? "Elevated Risk" : riskScore >= 40 ? "Moderate Risk" : "Good Posture");

  const gradeBadgeStyle: Record<string, string> = {
    A: "bg-emerald-50 text-emerald-700 border-emerald-200",
    B: "bg-blue-50 text-blue-700 border-blue-200",
    C: "bg-amber-50 text-amber-700 border-amber-200",
    D: "bg-orange-50 text-orange-700 border-orange-200",
    F: "bg-red-50 text-red-700 border-red-200",
  };
  const gradeBarStyle: Record<string, string> = {
    A: "bg-emerald-600",
    B: "bg-blue-600",
    C: "bg-amber-500",
    D: "bg-orange-500",
    F: "bg-red-600",
  };

  const totalRuns = data.pipeline?.total ?? 0;
  const failedRuns = data.pipeline?.failed ?? 0;
  const effectivePassedRuns =
    data.pipeline && totalRuns > 0 && data.pipeline.passed === 0 && failedRuns === 0
      ? totalRuns
      : data.pipeline?.passed ?? 0;
  const effectivePassRate =
    totalRuns > 0 ? Math.round((effectivePassedRuns * 100) / totalRuns) : data.stats.pipeline_pass_rate ?? 100;

  const latestPipeline = data.pipeline?.recent?.[0] ?? null;
  const totalVectors = data.threat_distribution.reduce((acc, curr) => acc + curr.count, 0);
  const syncedAt = formatSyncTime(data.generated_at);

  const aiProviderLabel = data.ai?.configured
    ? data.ai.provider && data.ai.provider !== "Local Summary Mode"
      ? data.ai.provider
      : data.ai.engine.replace("Google ", "")
    : "Local Summary";

  return (
    <div className="max-w-[1440px] mx-auto space-y-6 pb-12">
      {/* Page Header — Flat Enterprise Bar */}
      <header className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-4 border-b border-border">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-semibold tracking-tight text-slate-900">Security Overview</h1>
            <span className="inline-flex items-center gap-1.5 text-xs text-slate-600 bg-slate-50 border border-border px-2 py-0.5 rounded-md">
              <span
                className={`w-1.5 h-1.5 rounded-full ${wsConnected ? "bg-emerald-600" : "bg-amber-500"}`}
              />
              {wsConnected ? "Live stream" : "Polling (10s)"}
            </span>
            {syncedAt && (
              <span className="text-xs font-mono text-slate-400 tabular-nums">
                Updated {syncedAt}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Consolidated threat detection, cloud compliance posture, DevSecOps audits, and incident triage.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setShowAttackLab((v) => !v)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors ${
              showAttackLab
                ? "bg-slate-900 text-white border-slate-900"
                : "bg-white text-slate-700 border-border hover:bg-slate-50 hover:border-slate-300"
            }`}
          >
            <FlaskConical className="w-3.5 h-3.5" />
            <span>{showAttackLab ? "Hide Attack Lab" : "Attack Lab"}</span>
          </button>

          <button
            type="button"
            onClick={handleManualRefresh}
            disabled={isRefreshing}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-white text-slate-700 border border-border hover:bg-slate-50 hover:border-slate-300 rounded-md transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-slate-500 ${isRefreshing ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>

          <Link
            href="/devsecops"
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
          >
            <span>Run Security Audit</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </header>

      {/* Operational Notice Bar */}
      {(actionFeedback || lastNotification) && (
        <div
          role="status"
          className="flex items-center justify-between gap-3 px-3.5 py-2 rounded-md bg-slate-50 border border-border text-xs text-slate-700"
        >
          <div className="flex items-center gap-2 min-w-0">
            <CheckCircle2 className="w-3.5 h-3.5 text-blue-600 shrink-0" />
            <span className="truncate">{actionFeedback || lastNotification}</span>
          </div>
          <button
            type="button"
            onClick={() => {
              setActionFeedback(null);
              setLastNotification(null);
            }}
            aria-label="Dismiss notification"
            className="p-0.5 text-slate-400 hover:text-slate-700 rounded"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Optional On-Demand Attack Simulation Lab */}
      {showAttackLab && (
        <TrafficSimulator onComplete={() => void fetchOverview()} />
      )}

      {/* Row 1: Unified 5-Column Enterprise KPI Strip */}
      <section
        aria-label="Key security metrics"
        className="bg-white border border-border rounded-lg shadow-xs grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 divide-y sm:divide-y-0 sm:divide-x divide-border overflow-hidden"
      >
        <Link
          href="/threats"
          className="group p-4 hover:bg-slate-50/70 transition-colors flex flex-col justify-between gap-2"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Total Threats</span>
            <ChevronRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-slate-600 transition-colors" />
          </div>
          <div className="flex items-baseline justify-between gap-2">
            <span className="text-2xl font-semibold font-mono tabular-nums text-slate-900">
              {data.stats.threats}
            </span>
            <TrendTag direction={data.trends.threats?.direction} value={data.trends.threats?.value} />
          </div>
          <div className="text-[11px] text-slate-500 tabular-nums">
            {data.stats.open_threats ?? 0} open · {data.stats.threats_24h ?? 0} last 24h
          </div>
        </Link>

        <Link
          href="/threats"
          className="group p-4 hover:bg-slate-50/70 transition-colors flex flex-col justify-between gap-2"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Critical Events</span>
            <ChevronRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-slate-600 transition-colors" />
          </div>
          <div className="flex items-baseline justify-between gap-2">
            <span
              className={`text-2xl font-semibold font-mono tabular-nums ${
                data.stats.critical > 0 ? "text-red-600" : "text-slate-900"
              }`}
            >
              {data.stats.critical}
            </span>
            <TrendTag direction={data.trends.critical?.direction} value={data.trends.critical?.value} />
          </div>
          <div className="text-[11px] text-slate-500 tabular-nums">
            {data.stats.open_critical ?? 0} requiring triage
          </div>
        </Link>

        <Link
          href="/cspm"
          className="group p-4 hover:bg-slate-50/70 transition-colors flex flex-col justify-between gap-2"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Cloud Posture</span>
            <ChevronRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-slate-600 transition-colors" />
          </div>
          <div className="flex items-baseline justify-between gap-2">
            <span className="text-2xl font-semibold font-mono tabular-nums text-slate-900">
              {data.stats.cloud_security_score}%
            </span>
            <span className="text-[11px] font-mono text-emerald-700 font-medium">
              {data.cspm?.resolved ?? 0} fixed
            </span>
          </div>
          <div className="text-[11px] text-slate-500 tabular-nums">
            {data.cspm?.open ?? 0} open misconfigurations
          </div>
        </Link>

        <Link
          href="/alerts"
          className="group p-4 hover:bg-slate-50/70 transition-colors flex flex-col justify-between gap-2"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Active Alerts</span>
            <ChevronRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-slate-600 transition-colors" />
          </div>
          <div className="flex items-baseline justify-between gap-2">
            <span className="text-2xl font-semibold font-mono tabular-nums text-slate-900">
              {data.stats.active_alerts ?? data.alerts?.active ?? 0}
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              <span className="text-red-600 font-medium">{data.alerts?.by_severity?.CRITICAL ?? 0}C</span> /{" "}
              <span className="text-amber-600 font-medium">{data.alerts?.by_severity?.HIGH ?? 0}H</span>
            </span>
          </div>
          <div className="text-[11px] text-slate-500">Open incident queue</div>
        </Link>

        <Link
          href="/devsecops"
          className="group p-4 hover:bg-slate-50/70 transition-colors flex flex-col justify-between gap-2"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>CI/CD Gate Pass</span>
            <ChevronRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-slate-600 transition-colors" />
          </div>
          <div className="flex items-baseline justify-between gap-2">
            <span className="text-2xl font-semibold font-mono tabular-nums text-slate-900">
              {effectivePassRate !== null && effectivePassRate !== undefined ? `${effectivePassRate}%` : "Active"}
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              {totalRuns > 0 ? `${effectivePassedRuns}/${totalRuns}` : "Ready"}
            </span>
          </div>
          <div className="text-[11px] text-slate-500">
            {data.stats.open_audit_findings ?? data.audit?.open ?? 0} open audit findings
          </div>
        </Link>
      </section>

      {/* Row 2: Security Posture Scorecard (7 cols) + Platform Operations Summary (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Security Posture & Domain Risk Breakdown */}
        <section className="lg:col-span-7 bg-white border border-border rounded-lg shadow-xs flex flex-col justify-between">
          <div className="px-5 py-3.5 border-b border-border flex items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Security Posture & Risk Breakdown</h2>
              <p className="text-xs text-slate-500">Composite exposure across threats, cloud configuration, and audits</p>
            </div>
            <Link
              href="/analytics"
              className="text-xs font-medium text-blue-600 hover:text-blue-700 hover:underline shrink-0"
            >
              Risk report →
            </Link>
          </div>

          <div className="p-5 space-y-5 flex-1 flex flex-col justify-between">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3.5 min-w-0">
                <div
                  className={`w-12 h-12 rounded-lg border flex flex-col items-center justify-center shrink-0 ${
                    gradeBadgeStyle[grade] || gradeBadgeStyle.C
                  }`}
                >
                  <span className="text-[9px] font-semibold uppercase tracking-wider leading-none opacity-80">
                    Grade
                  </span>
                  <span className="text-xl font-bold leading-none mt-0.5 font-mono">{grade}</span>
                </div>
                <div className="min-w-0">
                  <div className="text-base font-semibold text-slate-900">{postureLabel}</div>
                  <div className="text-xs text-slate-500">
                    {riskScore < 30
                      ? "Low overall exposure across monitored environments."
                      : riskScore < 60
                      ? "Moderate exposure — review open drift and audit items."
                      : "Elevated exposure — prioritize untriaged critical incidents."}
                  </div>
                </div>
              </div>

              <div className="sm:text-right shrink-0">
                <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500 block">
                  Risk Index
                </span>
                <div className="text-2xl font-semibold font-mono tabular-nums text-slate-900">
                  {riskScore}
                  <span className="text-sm font-normal text-slate-400"> / 100</span>
                </div>
              </div>
            </div>

            {/* Clean Risk Scale Bar */}
            <div className="space-y-1.5">
              <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-500 ${gradeBarStyle[grade] || gradeBarStyle.C}`}
                  style={{ width: `${Math.min(100, Math.max(4, riskScore))}%` }}
                />
              </div>
              <div className="flex justify-between text-[10px] font-mono text-slate-400">
                <span>0 Hardened</span>
                <span>25 Low</span>
                <span>50 Moderate</span>
                <span>75 Elevated</span>
                <span>100 Critical</span>
              </div>
            </div>

            {/* Sub-pillar Breakdown */}
            {data.posture?.breakdown && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-4 border-t border-border">
                {[
                  { label: "Threat Risk", value: data.posture.breakdown.threat_risk, bar: "bg-red-600" },
                  { label: "Cloud Posture", value: data.posture.breakdown.cloud_risk, bar: "bg-amber-500" },
                  { label: "Audit & Recon", value: data.posture.breakdown.audit_risk, bar: "bg-blue-600" },
                ].map((pillar) => (
                  <div key={pillar.label} className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-600 font-medium">{pillar.label}</span>
                      <span className="font-mono font-semibold text-slate-900 tabular-nums">
                        {pillar.value}
                        <span className="text-slate-400 font-normal">/50</span>
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${pillar.bar}`}
                        style={{ width: `${Math.min(100, (pillar.value / 50) * 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* Platform Health & Operations Status Table */}
        <section className="lg:col-span-5 bg-white border border-border rounded-lg shadow-xs flex flex-col justify-between">
          <div className="px-5 py-3.5 border-b border-border flex items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">System & Sensor Health</h2>
              <p className="text-xs text-slate-500">Live inspection engine telemetry and coverage</p>
            </div>
            <Link
              href="/monitoring"
              className="text-xs font-medium text-blue-600 hover:text-blue-700 hover:underline shrink-0"
            >
              Metrics →
            </Link>
          </div>

          <div className="divide-y divide-border text-xs flex-1">
            <div className="px-5 py-3 flex items-center justify-between gap-4">
              <span className="text-slate-600 font-medium shrink-0">CPU Utilization</span>
              <div className="flex items-center gap-3 flex-1 max-w-[200px]">
                <div className="h-1.5 flex-1 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-600 rounded-full"
                    style={{ width: `${Math.min(100, data.system?.cpu_usage ?? 18.4)}%` }}
                  />
                </div>
                <span className="font-mono font-semibold text-slate-900 tabular-nums w-11 text-right">
                  {data.system?.cpu_usage ?? 18.4}%
                </span>
              </div>
            </div>

            <div className="px-5 py-3 flex items-center justify-between gap-4">
              <span className="text-slate-600 font-medium shrink-0">Memory Allocation</span>
              <div className="flex items-center gap-3 flex-1 max-w-[200px]">
                <div className="h-1.5 flex-1 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-slate-700 rounded-full"
                    style={{ width: `${Math.min(100, data.system?.memory_usage ?? 42.1)}%` }}
                  />
                </div>
                <span className="font-mono font-semibold text-slate-900 tabular-nums w-11 text-right">
                  {data.system?.memory_usage ?? 42.1}%
                </span>
              </div>
            </div>

            <div className="px-5 py-3 flex items-center justify-between gap-4">
              <span className="text-slate-600 font-medium">Gateway Latency & I/O</span>
              <span className="font-mono text-slate-900 tabular-nums">
                <strong className="font-semibold">{data.system?.api_latency ?? 12.3} ms</strong>
                <span className="text-slate-400 mx-1.5">·</span>
                <span className="text-slate-600">
                  {data.system?.network_rx ?? 124}/{data.system?.network_tx ?? 86} KB/s
                </span>
              </span>
            </div>

            <div className="px-5 py-3 flex items-center justify-between gap-4">
              <span className="text-slate-600 font-medium">Latest Audit Target</span>
              {data.audit?.latest_report ? (
                <Link
                  href="/devsecops"
                  className="font-mono text-slate-900 hover:text-blue-600 truncate max-w-[200px]"
                  title={data.audit.latest_report.target}
                >
                  {data.audit.latest_report.target}
                </Link>
              ) : (
                <span className="text-slate-400">No audit recorded</span>
              )}
            </div>

            <div className="px-5 py-3 flex items-center justify-between gap-4">
              <span className="text-slate-600 font-medium">Latest CI/CD Gate</span>
              {latestPipeline ? (
                <span className="inline-flex items-center gap-2 font-mono text-slate-700 truncate">
                  <span>{latestPipeline.commit_sha.slice(0, 7)}</span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
                      (latestPipeline.status || "").toUpperCase().includes("FAIL")
                        ? "bg-red-50 text-red-700 border border-red-200"
                        : "bg-emerald-50 text-emerald-700 border border-emerald-200"
                    }`}
                  >
                    {latestPipeline.status}
                  </span>
                </span>
              ) : (
                <span className="text-slate-500 font-mono">Standing by</span>
              )}
            </div>

            <div className="px-5 py-3 flex items-center justify-between gap-4">
              <span className="text-slate-600 font-medium">Analysis Assistant</span>
              <div className="flex items-center gap-2.5">
                <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-slate-700">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      data.ai?.configured ? "bg-emerald-600" : "bg-amber-500"
                    }`}
                  />
                  {aiProviderLabel}
                </span>
                <Link
                  href="/assistant"
                  className="text-blue-600 hover:text-blue-700 font-medium hover:underline"
                >
                  Open →
                </Link>
              </div>
            </div>
          </div>
        </section>
      </div>

      {/* Row 3: Telemetry Charts (8 cols + 4 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* 14-Day Threat Activity Timeline */}
        <section className="lg:col-span-8 bg-white border border-border rounded-lg shadow-xs flex flex-col justify-between">
          <div className="px-5 py-3.5 border-b border-border flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Threat Activity (14 Days)</h2>
              <p className="text-xs text-slate-500">Daily recorded security events grouped by severity</p>
            </div>
            <div className="flex items-center gap-3 text-[11px] text-slate-600 shrink-0">
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-xs bg-red-600" /> Critical
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-xs bg-amber-500" /> High
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-xs bg-blue-600" /> Medium
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-xs bg-slate-400" /> Low
              </span>
            </div>
          </div>

          <div className="p-5">
            <div className="h-[240px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineChartData} margin={{ top: 4, right: 6, left: -12, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                  <XAxis dataKey="label" stroke="#94a3b8" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis stroke="#94a3b8" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#ffffff",
                      borderRadius: "6px",
                      border: "1px solid #e2e8f0",
                      fontSize: "12px",
                      boxShadow: "0 1px 3px 0 rgba(0, 0, 0, 0.05)",
                    }}
                  />
                  <Area type="monotone" dataKey="critical" stackId="1" stroke="#dc2626" fill="#dc2626" fillOpacity={0.18} strokeWidth={1.75} />
                  <Area type="monotone" dataKey="high" stackId="1" stroke="#d97706" fill="#d97706" fillOpacity={0.18} strokeWidth={1.75} />
                  <Area type="monotone" dataKey="medium" stackId="1" stroke="#2563eb" fill="#2563eb" fillOpacity={0.15} strokeWidth={1.75} />
                  <Area type="monotone" dataKey="low" stackId="1" stroke="#94a3b8" fill="#94a3b8" fillOpacity={0.15} strokeWidth={1.5} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>

        {/* Threat Vector Breakdown */}
        <section className="lg:col-span-4 bg-white border border-border rounded-lg shadow-xs flex flex-col justify-between">
          <div className="px-5 py-3.5 border-b border-border flex items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Attack Vectors</h2>
              <p className="text-xs text-slate-500">Classified by ML Random Forest IDS</p>
            </div>
            <span className="text-xs font-mono font-medium text-slate-600 tabular-nums">
              {totalVectors} total
            </span>
          </div>

          <div className="p-5 flex-1 flex flex-col justify-between">
            <div className="h-[240px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.threat_distribution} layout="vertical" margin={{ left: 0, right: 12, top: 4, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f1f5f9" />
                  <XAxis type="number" stroke="#94a3b8" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <YAxis dataKey="label" type="category" stroke="#475569" fontSize={11} width={88} tickLine={false} axisLine={false} />
                  <Tooltip
                    cursor={{ fill: "#f8fafc" }}
                    contentStyle={{
                      backgroundColor: "#ffffff",
                      borderRadius: "6px",
                      border: "1px solid #e2e8f0",
                      fontSize: "12px",
                      boxShadow: "0 1px 3px 0 rgba(0, 0, 0, 0.05)",
                    }}
                  />
                  <Bar dataKey="count" fill="#2563eb" radius={[0, 3, 3, 0]} barSize={16} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>
      </div>

      {/* Row 4: Actionable Triage Queues (Alerts + CSPM) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-stretch">
        {/* Active Alerts Queue */}
        <section className="bg-white border border-border rounded-lg shadow-xs flex flex-col">
          <div className="px-5 py-3.5 border-b border-border flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <h2 className="text-sm font-semibold text-slate-900 truncate">Active Alerts</h2>
              <span className="text-[11px] font-mono font-medium px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 tabular-nums">
                {data.alerts?.active ?? 0}
              </span>
            </div>
            <Link
              href="/alerts"
              className="text-xs font-medium text-blue-600 hover:text-blue-700 hover:underline shrink-0"
            >
              View all →
            </Link>
          </div>

          <div className="flex-1 divide-y divide-border">
            {!data.alerts?.recent || data.alerts.recent.length === 0 ? (
              <div className="p-8 text-center text-slate-500 flex flex-col items-center justify-center min-h-[180px]">
                <CheckCircle2 className="w-5 h-5 text-emerald-600 mb-2" />
                <p className="text-xs font-medium text-slate-900">No open alerts</p>
                <p className="text-xs text-slate-500 mt-0.5">All monitored incident streams are currently clear.</p>
              </div>
            ) : (
              data.alerts.recent.slice(0, 4).map((alert) => (
                <div
                  key={alert.id}
                  className="px-5 py-3 hover:bg-slate-50/70 transition-colors flex items-center justify-between gap-3"
                >
                  <div className="min-w-0 space-y-0.5">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <SeverityDot severity={alert.severity} />
                      <h3 className="text-xs font-semibold text-slate-900 truncate">{alert.title}</h3>
                    </div>
                    <p className="text-[11px] text-slate-500 truncate">
                      <span className="font-mono text-slate-700">{alert.source}</span> · {alert.message}
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleResolveAlert(alert.id, alert.title)}
                    disabled={resolvingAlertId === alert.id}
                    className="shrink-0 inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium bg-white hover:bg-slate-50 text-slate-700 border border-border hover:border-slate-300 rounded-md transition-colors disabled:opacity-50"
                  >
                    {resolvingAlertId === alert.id ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : (
                      <Check className="w-3 h-3 text-emerald-600" />
                    )}
                    <span>Resolve</span>
                  </button>
                </div>
              ))
            )}
          </div>
        </section>

        {/* Cloud Policy Drift (CSPM) */}
        <section className="bg-white border border-border rounded-lg shadow-xs flex flex-col">
          <div className="px-5 py-3.5 border-b border-border flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <h2 className="text-sm font-semibold text-slate-900 truncate">Cloud Policy Drift (CSPM)</h2>
              <span className="text-[11px] font-mono font-medium px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 tabular-nums">
                {data.cspm?.open ?? 0} open
              </span>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <button
                type="button"
                onClick={handleRunCspmScan}
                disabled={scanningCspm}
                className="inline-flex items-center gap-1 text-xs font-medium text-slate-600 hover:text-slate-900 disabled:opacity-50"
              >
                <RefreshCw className={`w-3 h-3 ${scanningCspm ? "animate-spin text-blue-600" : ""}`} />
                <span>{scanningCspm ? "Scanning..." : "Scan"}</span>
              </button>
              <Link
                href="/cspm"
                className="text-xs font-medium text-blue-600 hover:text-blue-700 hover:underline"
              >
                Open CSPM →
              </Link>
            </div>
          </div>

          <div className="flex-1 divide-y divide-border">
            {!data.cspm?.top_open || data.cspm.top_open.length === 0 ? (
              <div className="p-8 text-center text-slate-500 flex flex-col items-center justify-center min-h-[180px]">
                <ShieldCheck className="w-5 h-5 text-emerald-600 mb-2" />
                <p className="text-xs font-medium text-slate-900">Cloud configurations compliant</p>
                <p className="text-xs text-slate-500 mt-0.5">
                  No open misconfigurations detected across AWS, GCP, or Azure checks.
                </p>
              </div>
            ) : (
              data.cspm.top_open.slice(0, 4).map((finding) => (
                <div
                  key={finding.id}
                  className="px-5 py-3 hover:bg-slate-50/70 transition-colors flex items-center justify-between gap-3"
                >
                  <div className="min-w-0 space-y-0.5">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <SeverityDot severity={finding.severity} />
                      <h3 className="text-xs font-semibold text-slate-900 truncate">{finding.finding}</h3>
                    </div>
                    <p className="text-[11px] font-mono text-slate-500 truncate">{finding.resource}</p>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleRemediateCspm(finding.id, finding.resource)}
                    disabled={remediatingCspmId === finding.id}
                    className="shrink-0 inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium bg-white hover:bg-slate-50 text-blue-700 border border-border hover:border-blue-300 rounded-md transition-colors disabled:opacity-50"
                  >
                    {remediatingCspmId === finding.id ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : null}
                    <span>Enforce</span>
                  </button>
                </div>
              ))
            )}
          </div>
        </section>
      </div>

      {/* Row 5: Recorded Threat Incidents Table with Integrated Top Source IP Quick-Filters */}
      <section className="bg-white border border-border rounded-lg shadow-xs overflow-hidden">
        <div className="px-5 py-4 border-b border-border flex flex-col xl:flex-row xl:items-center justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-slate-500 shrink-0" />
              <h2 className="text-sm font-semibold text-slate-900">Recorded Threat Incidents</h2>
              <span className="text-[11px] font-mono font-medium px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 tabular-nums">
                {filteredEvents.length} / {recentEvents.length}
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Filter by source IP, severity, or status. Update triage status directly inline.
            </p>
          </div>

          <div className="flex flex-wrap sm:flex-nowrap items-center gap-2 shrink-0">
            <div className="relative w-full sm:w-56">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Filter IP, event ID, type..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-7 py-1.5 text-xs bg-white border border-border rounded-md text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-500 transition-colors"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  aria-label="Clear search"
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>

            <div className="inline-flex items-center bg-slate-100 p-0.5 rounded-md border border-border text-xs">
              {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                    severityFilter === sev
                      ? "bg-white text-slate-900 shadow-2xs"
                      : "text-slate-600 hover:text-slate-900"
                  }`}
                >
                  {sev === "ALL" ? "All" : sev.charAt(0) + sev.slice(1).toLowerCase()}
                </button>
              ))}
            </div>

            <select
              aria-label="Filter by status"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="text-xs bg-white border border-border rounded-md px-2.5 py-1.5 text-slate-700 focus:outline-none focus:border-blue-500"
            >
              <option value="ALL">All statuses</option>
              <option value="Open">Open</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
            </select>
          </div>
        </div>

        {/* Integrated Top Attacking Sources Filter Strip */}
        {data.top_sources && data.top_sources.length > 0 && (
          <div className="px-5 py-2.5 border-b border-border bg-slate-50/60 flex flex-wrap items-center gap-2 text-xs">
            <span className="text-[11px] font-medium text-slate-500 mr-1">Top source IPs:</span>
            {data.top_sources.slice(0, 5).map((actor) => {
              const active = searchQuery === actor.source;
              return (
                <div
                  key={actor.source}
                  className={`inline-flex items-center gap-1.5 pl-2 pr-1 py-0.5 rounded-md border text-[11px] transition-colors ${
                    active
                      ? "bg-blue-50 border-blue-300 text-blue-800"
                      : "bg-white border-border text-slate-700 hover:border-slate-300"
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => setSearchQuery(active ? "" : actor.source)}
                    className="inline-flex items-center gap-1.5 font-mono"
                    title={`Filter events by ${actor.source} (${actor.types.join(", ")})`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        actor.max_severity === "CRITICAL"
                          ? "bg-red-600"
                          : actor.max_severity === "HIGH"
                          ? "bg-amber-500"
                          : "bg-blue-600"
                      }`}
                    />
                    <span>{actor.source}</span>
                    <span className="text-slate-400">({actor.count})</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(actor.source)}
                    className="p-0.5 text-slate-400 hover:text-slate-700 rounded"
                    title="Copy IP address"
                  >
                    {copiedIp === actor.source ? (
                      <Check className="w-3 h-3 text-emerald-600" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                  </button>
                </div>
              );
            })}
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery("")}
                className="text-[11px] text-slate-500 hover:text-slate-900 underline ml-1"
              >
                Clear
              </button>
            )}
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="text-[11px] text-slate-500 uppercase tracking-wider bg-slate-50/70 border-b border-border">
              <tr>
                <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Event ID & Time</th>
                <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Classification</th>
                <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Source IP</th>
                <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Destination</th>
                <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Severity</th>
                <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Status</th>
                <th className="px-4 py-2.5 font-semibold text-right whitespace-nowrap">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-slate-500">
                    <p className="text-xs font-medium text-slate-900">No events match the active filters.</p>
                    <button
                      type="button"
                      onClick={() => {
                        setSearchQuery("");
                        setSeverityFilter("ALL");
                        setStatusFilter("ALL");
                      }}
                      className="mt-1.5 text-xs text-blue-600 hover:underline font-medium"
                    >
                      Reset filters
                    </button>
                  </td>
                </tr>
              ) : (
                filteredEvents.map((event) => {
                  const isUpdating = updatingThreatId === event.id;
                  return (
                    <tr key={event.id} className="hover:bg-slate-50/80 transition-colors">
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <div className="font-mono font-medium text-slate-900">{event.id}</div>
                        <div className="text-[11px] font-mono text-slate-400 tabular-nums">{event.time}</div>
                      </td>

                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <div className="font-medium text-slate-900 flex items-center gap-1.5">
                          <span>{event.type}</span>
                          {event.simulated && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-600 border border-border">
                              Simulated
                            </span>
                          )}
                        </div>
                        {event.confidence !== undefined && (
                          <div className="text-[11px] font-mono text-slate-400 tabular-nums">
                            {Math.round(event.confidence * 100)}% confidence
                          </div>
                        )}
                      </td>

                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <div className="inline-flex items-center gap-1.5">
                          <span className="font-mono text-slate-900">{event.source}</span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(event.source)}
                            className="p-0.5 text-slate-400 hover:text-slate-700 rounded"
                            title="Copy IP"
                          >
                            {copiedIp === event.source ? (
                              <Check className="w-3 h-3 text-emerald-600" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </td>

                      <td className="px-4 py-2.5 whitespace-nowrap font-mono text-[11px] text-slate-500">
                        {event.destination || "api-gateway:443"}
                      </td>

                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <SeverityDot severity={event.severity} />
                      </td>

                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <div className="inline-flex items-center rounded-md border border-border bg-slate-50 p-0.5">
                          {(["Open", "Investigating", "Resolved"] as const).map((st) => {
                            const isCurrent = event.status.toLowerCase() === st.toLowerCase();
                            return (
                              <button
                                key={st}
                                type="button"
                                disabled={isUpdating}
                                onClick={() => handleUpdateThreatStatus(event.id, st)}
                                className={`px-2 py-0.5 text-[11px] font-medium rounded transition-colors ${
                                  isCurrent
                                    ? st === "Open"
                                      ? "bg-white text-red-700 shadow-2xs"
                                      : st === "Investigating"
                                      ? "bg-white text-amber-700 shadow-2xs"
                                      : "bg-white text-emerald-700 shadow-2xs"
                                    : "text-slate-500 hover:text-slate-900"
                                } disabled:opacity-50`}
                              >
                                {isUpdating && isCurrent ? (
                                  <Loader2 className="w-3 h-3 animate-spin inline" />
                                ) : (
                                  st
                                )}
                              </button>
                            );
                          })}
                        </div>
                      </td>

                      <td className="px-4 py-2.5 whitespace-nowrap text-right">
                        <Link
                          href={`/assistant?q=Analyze attack event ${event.id} of type ${event.type} from IP ${event.source} and suggest immediate remediation.`}
                          className="inline-flex items-center gap-1 text-xs font-medium text-blue-600 hover:text-blue-700 hover:underline"
                        >
                          <span>Investigate</span>
                          <ArrowUpRight className="w-3 h-3" />
                        </Link>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        <div className="px-5 py-3 border-t border-border bg-slate-50/50 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-slate-500">
          <span>
            Showing {filteredEvents.length} of {recentEvents.length} most recent incidents
          </span>
          <Link
            href="/threats"
            className="text-blue-600 hover:text-blue-700 font-medium hover:underline inline-flex items-center gap-1"
          >
            Open Threat Detection Console <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </section>
    </div>
  );
}
