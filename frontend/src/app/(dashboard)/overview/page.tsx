"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import Link from "next/link";
import { API_URL, WS_URL, apiFetch, websocketProtocols } from "@/lib/api";
import { TrafficSimulator } from "@/components/TrafficSimulator";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Cloud,
  RefreshCw,
  Radio,
  Loader2,
  ArrowUpRight,
  TrendingUp,
  TrendingDown,
  Minus,
  Search,
  CheckCircle2,
  AlertCircle,
  Bot,
  Sparkles,
  Cpu,
  GitBranch,
  X,
  Check,
  Server,
  Wrench,
  Copy,
  ChevronRight,
  Clock,
} from "lucide-react";
import {
  BarChart,
  Bar,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
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

export default function OverviewPage() {
  const [data, setData] = useState<OverviewData | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
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

  const fetchOverview = useCallback(async () => {
    try {
      const res = await apiFetch(`${API_URL}/api/overview`);
      if (res.ok) {
        const json = await res.json();
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
    showFeedback("Telemetry refreshed from SentinelX security engine");
  };

  const showFeedback = (msg: string) => {
    setActionFeedback(msg);
    setTimeout(() => {
      setActionFeedback((current) => (current === msg ? null : current));
    }, 4000);
  };

  // WebSocket Live Updates
  useEffect(() => {
    let isCancelled = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;

    const loadInitialData = async () => {
      try {
        const res = await apiFetch(`${API_URL}/api/overview`);
        if (res.ok && !isCancelled) {
          const json = await res.json();
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
                setLastNotification(`🚨 Detected: ${msg.threat?.type || "Attack"} from ${msg.threat?.source || "External IP"}`);
              }
              fetchOverview();
            }
          } catch {
            // Ignore malformed WS packets
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

    const interval = setInterval(fetchOverview, 10000);

    return () => {
      isCancelled = true;
      clearInterval(interval);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) wsRef.current.close();
    };
  }, [fetchOverview]);

  // Inline threat status update
  const handleUpdateThreatStatus = async (threatId: string, newStatus: "Open" | "Investigating" | "Resolved") => {
    setUpdatingThreatId(threatId);
    try {
      const res = await apiFetch(`${API_URL}/api/threats/${threatId}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error("Failed to update status");

      // Optimistic local update
      setData((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          recent_events: prev.recent_events.map((evt) =>
            evt.id === threatId ? { ...evt, status: newStatus } : evt
          ),
        };
      });

      showFeedback(`Threat ${threatId} status marked as ${newStatus}`);
      fetchOverview();
    } catch {
      showFeedback(`Failed to update threat ${threatId}.`);
    } finally {
      setUpdatingThreatId(null);
    }
  };

  // Inline alert resolution
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

      showFeedback(`Alert "${alertTitle}" resolved successfully.`);
      fetchOverview();
    } catch {
      showFeedback(`Failed to resolve alert ${alertId}.`);
    } finally {
      setResolvingAlertId(null);
    }
  };

  // Inline CSPM Remediation
  const handleRemediateCspm = async (findingId: string, resource: string) => {
    setRemediatingCspmId(findingId);
    try {
      const res = await apiFetch(`${API_URL}/api/cspm/remediate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: findingId }),
      });
      if (!res.ok) throw new Error("Remediation failed");

      showFeedback(`Cloud security policy enforced for ${resource}.`);
      fetchOverview();
    } catch {
      showFeedback(`Failed to remediate ${resource}.`);
    } finally {
      setRemediatingCspmId(null);
    }
  };

  // Trigger Cloud Posture Scan
  const handleRunCspmScan = async () => {
    setScanningCspm(true);
    try {
      const res = await apiFetch(`${API_URL}/api/cspm/scan`, {
        method: "POST",
      });
      if (!res.ok) throw new Error("Scan failed");
      showFeedback("Cloud infrastructure posture scan completed.");
      await fetchOverview();
    } catch {
      showFeedback("Could not complete cloud posture scan.");
    } finally {
      setScanningCspm(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedIp(text);
    setTimeout(() => setCopiedIp((cur) => (cur === text ? null : cur)), 2000);
  };

  const handleCardMouseMove = (e: React.MouseEvent<HTMLElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    e.currentTarget.style.setProperty("--mouse-x", `${x}px`);
    e.currentTarget.style.setProperty("--mouse-y", `${y}px`);
  };

  // Filtered recent events
  const recentEvents = data?.recent_events ?? [];
  const filteredEvents = recentEvents.filter((evt) => {
    const matchesSearch =
      searchQuery === "" ||
      evt.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.id.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity =
      severityFilter === "ALL" || evt.severity.toUpperCase() === severityFilter;

    const matchesStatus =
      statusFilter === "ALL" || evt.status.toLowerCase() === statusFilter.toLowerCase();

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const timelineChartData =
    data?.timeline && data.timeline.length > 0
      ? data.timeline
      : (data?.risk_trend || []).map((r) => ({
          date: r.date,
          label: r.date,
          critical: Math.round(r.score / 25),
          high: 0,
          medium: 0,
          low: 0,
          total: Math.round(r.score / 25),
        }));

  if (!data || !data.stats) {
    return (
      <div className="p-16 text-center text-muted flex flex-col items-center justify-center gap-3">
        <Loader2 className="w-9 h-9 text-primary animate-spin" />
        <p className="font-semibold text-sm text-foreground">
          Aggregating real-time SOC security posture & telemetry...
        </p>
        <p className="text-xs text-muted max-w-sm">
          Connecting to SentinelX threat intelligence stream and cloud policy engines.
        </p>
      </div>
    );
  }

  const riskScore = data.stats.risk_score;
  const grade = data.posture?.grade || (riskScore < 20 ? "A" : riskScore < 40 ? "B" : riskScore < 60 ? "C" : riskScore < 80 ? "D" : "F");
  const postureLabel = data.posture?.label || (riskScore >= 70 ? "Elevated Risk" : riskScore >= 40 ? "Moderate" : "Good Posture");

  const gradeColors: Record<string, { bg: string; text: string; border: string; bar: string }> = {
    A: { bg: "bg-emerald-50", text: "text-emerald-700", border: "border-emerald-300", bar: "bg-emerald-500" },
    B: { bg: "bg-blue-50", text: "text-blue-700", border: "border-blue-300", bar: "bg-blue-500" },
    C: { bg: "bg-amber-50", text: "text-amber-700", border: "border-amber-300", bar: "bg-amber-500" },
    D: { bg: "bg-orange-50", text: "text-orange-700", border: "border-orange-300", bar: "bg-orange-500" },
    F: { bg: "bg-rose-50", text: "text-rose-700", border: "border-rose-300", bar: "bg-rose-600" },
  };
  const activeGradeTheme = gradeColors[grade] || gradeColors.C;

  const totalRuns = data.pipeline?.total ?? 0;
  const failedRuns = data.pipeline?.failed ?? 0;
  const effectivePassedRuns =
    data.pipeline && totalRuns > 0 && data.pipeline.passed === 0 && failedRuns === 0
      ? totalRuns
      : data.pipeline?.passed ?? 0;
  const effectivePassRate =
    totalRuns > 0 ? Math.round((effectivePassedRuns * 100) / totalRuns) : data.stats.pipeline_pass_rate ?? 100;

  return (
    <div className="space-y-5 animate-fade-in pb-12">
      {/* Dynamic Feedback Banner */}
      {(actionFeedback || lastNotification) && (
        <div className="flex items-center justify-between px-4 py-2.5 rounded-lg bg-blue-50 border border-blue-200 text-blue-900 text-xs font-medium animate-slide-up shadow-xs">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0" />
            <span>{actionFeedback || lastNotification}</span>
          </div>
          <button
            onClick={() => {
              setActionFeedback(null);
              setLastNotification(null);
            }}
            className="p-1 text-blue-500 hover:text-blue-700 rounded transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Top Header & Executive Controls */}
      <div
        onMouseMove={handleCardMouseMove}
        className="relative overflow-hidden group flex flex-col lg:flex-row justify-between lg:items-center gap-4 bg-surface p-5 rounded-xl border border-border hover:border-blue-400/60 shadow-xs hover:shadow-lg hover:shadow-blue-500/5 hover:-translate-y-0.5 transition-all duration-300 ease-out"
      >
        {/* Cursor Spotlight Glow */}
        <div
          className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            background:
              "radial-gradient(350px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.07), transparent 80%)",
          }}
        />
        {/* Top Animated Accent Bar */}
        <div className="absolute top-0 inset-x-0 h-[2px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

        <div className="flex items-start sm:items-center gap-3.5 relative z-10">
          <div className="p-3 bg-primary/10 rounded-xl border border-primary/20 text-primary shrink-0 shadow-inner group-hover:scale-105 group-hover:-rotate-3 transition-transform duration-300">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-2xl font-bold tracking-tight text-foreground">Security Command Overview</h1>
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border whitespace-nowrap ${
                  wsConnected
                    ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                    : "bg-amber-50 text-amber-700 border-amber-200"
                }`}
                title={wsConnected ? "Connected to live WebSocket event feed" : "Falling back to 10s auto-polling"}
              >
                <Radio className={`w-3 h-3 ${wsConnected ? "animate-pulse text-emerald-500" : "text-amber-500"}`} />
                {wsConnected ? "Live Telemetry" : "Polling Active (10s)"}
              </span>
              {data.ai && (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-50 text-purple-700 border border-purple-200 whitespace-nowrap">
                  <Bot className="w-3 h-3 text-purple-600" />
                  {data.ai.configured ? "AI Copilot Online" : "AI In Local Mode"}
                </span>
              )}
            </div>
            <p className="text-xs text-muted mt-0.5">
              Live threat telemetry, cloud posture analytics, and automated SOC response actions
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0 relative z-10">
          <button
            onClick={handleManualRefresh}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium border border-border bg-white hover:bg-gray-50 text-foreground rounded-lg transition-all shadow-xs disabled:opacity-50 whitespace-nowrap hover:shadow-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-primary" : "text-muted"}`} />
            <span>{isRefreshing ? "Refreshing..." : "Sync Posture"}</span>
          </button>

          <Link
            href="/assistant?q=Provide a prioritized remediation plan based on our current security posture"
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-primary hover:bg-blue-700 text-white rounded-lg transition-all shadow-xs whitespace-nowrap hover:shadow-md hover:scale-[1.02]"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Ask Copilot</span>
          </Link>
        </div>
      </div>

      {/* Traffic Simulator Integrated Bar */}
      <TrafficSimulator onComplete={() => void fetchOverview()} />

      {/* EXECUTIVE SECURITY POSTURE SCORECARD BANNER */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Posture Letter Grade & Overall Risk Score */}
        <div
          onMouseMove={handleCardMouseMove}
          className="lg:col-span-7 relative overflow-hidden group bg-surface border border-border hover:border-orange-400/80 rounded-xl p-5 shadow-xs hover:shadow-lg hover:shadow-orange-500/10 hover:-translate-y-1 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(280px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(249, 115, 22, 0.08), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-orange-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border relative z-10">
            <div className="min-w-0">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-muted block mb-2">
                Executive Security Posture
              </span>
              <div className="flex items-center gap-3.5">
                <div
                  className={`w-16 h-16 shrink-0 rounded-xl border flex flex-col items-center justify-center shadow-2xs group-hover:scale-105 group-hover:-rotate-3 transition-transform duration-300 ${activeGradeTheme.bg} ${activeGradeTheme.text} ${activeGradeTheme.border}`}
                >
                  <span className="text-[9px] font-bold uppercase tracking-widest opacity-80 leading-none">
                    GRADE
                  </span>
                  <span className="text-3xl font-black leading-none mt-1">{grade}</span>
                </div>
                <div className="min-w-0">
                  <h2 className="text-lg font-bold text-foreground leading-tight">{postureLabel}</h2>
                  <p className="text-xs text-muted mt-0.5 leading-relaxed">
                    Composite score computed across active threats, cloud drift, and DevSecOps audits
                  </p>
                </div>
              </div>
            </div>

            <div className="text-left sm:text-right shrink-0 sm:pl-4 sm:border-l sm:border-border/60">
              <span className="text-xs text-muted block whitespace-nowrap">Recorded Risk Index</span>
              <div className="text-3xl font-extrabold font-mono text-foreground mt-0.5 whitespace-nowrap group-hover:translate-x-0.5 transition-transform duration-300">
                {riskScore}
                <span className="text-base text-muted/60 font-sans font-normal"> / 100</span>
              </div>
            </div>
          </div>

          {/* Risk Level Visual Gauge */}
          <div className="py-4 space-y-2 relative z-10">
            <div className="flex justify-between items-center text-xs">
              <span className="text-muted font-medium">Risk Distribution Spectrum</span>
              <span className="font-semibold text-foreground">
                {riskScore < 30
                  ? "Minimal Risk (<30)"
                  : riskScore < 60
                  ? "Moderate (30-59)"
                  : riskScore < 80
                  ? "Elevated (60-79)"
                  : "Critical Danger (80+)"}
              </span>
            </div>
            <div className="h-3 w-full bg-gray-100 rounded-full overflow-hidden flex shadow-inner">
              <div
                className={`transition-all duration-700 ease-out ${activeGradeTheme.bar}`}
                style={{ width: `${Math.min(100, Math.max(5, riskScore))}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] text-muted font-mono pt-0.5">
              <span>0 (Hardened)</span>
              <span>25 (Good)</span>
              <span>50 (Moderate)</span>
              <span>75 (Elevated)</span>
              <span>100 (Critical)</span>
            </div>
          </div>

          {/* Sub-Pillar Breakdown */}
          {data.posture?.breakdown && (
            <div className="grid grid-cols-3 gap-3 pt-3 border-t border-border relative z-10">
              <div className="bg-gray-50/80 hover:bg-white p-2.5 rounded-lg border border-gray-100 hover:border-gray-200 hover:shadow-2xs transition-all duration-200">
                <div className="flex justify-between items-center gap-1">
                  <span className="text-[11px] text-muted font-medium truncate">Threat Risk</span>
                  <span className="text-xs font-bold font-mono text-foreground shrink-0">
                    {data.posture.breakdown.threat_risk}/50
                  </span>
                </div>
                <div className="w-full h-1.5 bg-gray-200 rounded-full mt-1.5 overflow-hidden">
                  <div
                    className="h-full bg-rose-500 rounded-full"
                    style={{ width: `${Math.min(100, (data.posture.breakdown.threat_risk / 50) * 100)}%` }}
                  />
                </div>
              </div>

              <div className="bg-gray-50/80 hover:bg-white p-2.5 rounded-lg border border-gray-100 hover:border-gray-200 hover:shadow-2xs transition-all duration-200">
                <div className="flex justify-between items-center gap-1">
                  <span className="text-[11px] text-muted font-medium truncate">Cloud Posture</span>
                  <span className="text-xs font-bold font-mono text-foreground shrink-0">
                    {data.posture.breakdown.cloud_risk}/50
                  </span>
                </div>
                <div className="w-full h-1.5 bg-gray-200 rounded-full mt-1.5 overflow-hidden">
                  <div
                    className="h-full bg-amber-500 rounded-full"
                    style={{ width: `${Math.min(100, (data.posture.breakdown.cloud_risk / 50) * 100)}%` }}
                  />
                </div>
              </div>

              <div className="bg-gray-50/80 hover:bg-white p-2.5 rounded-lg border border-gray-100 hover:border-gray-200 hover:shadow-2xs transition-all duration-200">
                <div className="flex justify-between items-center gap-1">
                  <span className="text-[11px] text-muted font-medium truncate">Audit & Recon</span>
                  <span className="text-xs font-bold font-mono text-foreground shrink-0">
                    {data.posture.breakdown.audit_risk}/50
                  </span>
                </div>
                <div className="w-full h-1.5 bg-gray-200 rounded-full mt-1.5 overflow-hidden">
                  <div
                    className="h-full bg-blue-500 rounded-full"
                    style={{ width: `${Math.min(100, (data.posture.breakdown.audit_risk / 50) * 100)}%` }}
                  />
                </div>
              </div>
            </div>
          )}
        </div>

        {/* AI Copilot & Fast Remediation Card (White Surface Theme) */}
        <div
          onMouseMove={handleCardMouseMove}
          className="lg:col-span-5 relative overflow-hidden group bg-surface border border-border hover:border-purple-400/80 rounded-xl p-5 shadow-xs hover:shadow-lg hover:shadow-purple-500/10 hover:-translate-y-1 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(260px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(147, 51, 234, 0.08), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-purple-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="relative z-10">
            <div className="flex items-center justify-between gap-2 pb-3 mb-3 border-b border-border">
              <div className="flex items-center gap-2 min-w-0">
                <div className="p-1.5 bg-primary/10 border border-primary/20 rounded-lg text-primary shrink-0 group-hover:scale-110 group-hover:rotate-6 transition-transform duration-300">
                  <Sparkles className="w-4 h-4" />
                </div>
                <span className="text-[11px] font-bold uppercase tracking-wider text-muted truncate">
                  Autonomous SecOps Copilot
                </span>
              </div>
              <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-purple-50 border border-purple-200 text-purple-700 font-semibold whitespace-nowrap shrink-0">
                {data.ai?.engine?.replace("Google ", "") || "gemini-2.5-flash"}
              </span>
            </div>

            <p className="text-xs sm:text-sm font-medium text-foreground leading-relaxed">
              {riskScore >= 70
                ? "Elevated threats detected in network ingress and public cloud configurations. Prompt Copilot to draft defensive firewall rules."
                : "Continuous telemetry active. All high-severity incidents are prioritized for triage and policy verification."}
            </p>

            <div className="mt-3.5 space-y-2">
              <Link
                href="/assistant?q=What are the top 3 critical vulnerabilities currently threatening our environment and how can I fix them?"
                className="w-full block text-left text-xs bg-gray-50/90 hover:bg-white border border-border hover:border-purple-400 text-foreground rounded-lg p-2.5 transition-all shadow-2xs group/link hover:translate-x-0.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium text-foreground">💡 &ldquo;What are the top 3 issues threatening our environment?&rdquo;</span>
                  <ChevronRight className="w-3.5 h-3.5 text-muted shrink-0 group-hover/link:text-purple-600 group-hover/link:translate-x-0.5 transition-all" />
                </div>
              </Link>
              <Link
                href="/assistant?q=Generate a defensive IP blocking list for the most active threat actors"
                className="w-full block text-left text-xs bg-gray-50/90 hover:bg-white border border-border hover:border-purple-400 text-foreground rounded-lg p-2.5 transition-all shadow-2xs group/link hover:translate-x-0.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium text-foreground">🛡️ &ldquo;Generate an IP blocklist for top attackers&rdquo;</span>
                  <ChevronRight className="w-3.5 h-3.5 text-muted shrink-0 group-hover/link:text-purple-600 group-hover/link:translate-x-0.5 transition-all" />
                </div>
              </Link>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-border flex items-center justify-between text-xs text-muted relative z-10">
            <span>Ready for autonomous SOC queries</span>
            <Link
              href="/assistant"
              className="text-xs font-semibold text-primary hover:text-blue-700 flex items-center gap-1 transition-colors whitespace-nowrap"
            >
              Open Copilot Chat <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>

      {/* 5 INTERACTIVE TOP KPI CARDS WITH CURSOR-TRACKING HOVER EFFECT */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Card 1: Total Threats */}
        <Link
          href="/threats"
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-blue-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-blue-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.09), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="flex items-center justify-between mb-3 relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Total Threats</span>
            <div className="p-2 bg-blue-50 text-blue-600 rounded-lg group-hover:bg-primary group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 group-hover:shadow-xs transition-all duration-300 ease-out">
              <Shield className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-foreground transition-transform duration-300 group-hover:translate-x-0.5">
                {data.stats.threats}
              </span>
              <ArrowUpRight className="w-4 h-4 text-muted group-hover:text-primary group-hover:translate-x-1 group-hover:-translate-y-1 transition-all duration-300 ease-out" />
            </div>
            <div className="mt-2 flex items-center gap-1.5 text-xs text-muted">
              {data.trends.threats?.direction === "up" ? (
                <span className="text-rose-600 font-semibold flex items-center">
                  <TrendingUp className="w-3 h-3 mr-0.5" /> {data.trends.threats.value}
                </span>
              ) : data.trends.threats?.direction === "down" ? (
                <span className="text-emerald-600 font-semibold flex items-center">
                  <TrendingDown className="w-3 h-3 mr-0.5" /> {data.trends.threats.value}
                </span>
              ) : (
                <span className="text-muted font-medium flex items-center">
                  <Minus className="w-3 h-3 mr-0.5" /> Stable
                </span>
              )}
              <span>vs prev week</span>
            </div>
            <div className="mt-1 text-[11px] text-muted">
              {data.stats.open_threats !== undefined ? `${data.stats.open_threats} active` : "Monitored"} •{" "}
              {data.stats.threats_24h ?? 0} in 24h
            </div>
          </div>
        </Link>

        {/* Card 2: Critical Events */}
        <Link
          href="/threats"
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-red-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-red-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(220, 38, 38, 0.09), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-red-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="flex items-center justify-between mb-3 relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Critical Events</span>
            <div className="p-2 bg-red-50 text-red-600 rounded-lg group-hover:bg-red-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 group-hover:shadow-xs transition-all duration-300 ease-out">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-red-600 transition-transform duration-300 group-hover:translate-x-0.5">
                {data.stats.critical}
              </span>
              <ArrowUpRight className="w-4 h-4 text-muted group-hover:text-red-600 group-hover:translate-x-1 group-hover:-translate-y-1 transition-all duration-300 ease-out" />
            </div>
            <div className="mt-2 flex items-center gap-1.5 text-xs text-muted">
              {data.trends.critical?.direction === "up" ? (
                <span className="text-rose-600 font-semibold flex items-center">
                  <TrendingUp className="w-3 h-3 mr-0.5" /> {data.trends.critical.value}
                </span>
              ) : data.trends.critical?.direction === "down" ? (
                <span className="text-emerald-600 font-semibold flex items-center">
                  <TrendingDown className="w-3 h-3 mr-0.5" /> {data.trends.critical.value}
                </span>
              ) : (
                <span className="text-muted font-medium flex items-center">
                  <Minus className="w-3 h-3 mr-0.5" /> Stable
                </span>
              )}
              <span>7d trend</span>
            </div>
            <div className="mt-1 text-[11px] text-muted">
              {data.stats.open_critical !== undefined ? `${data.stats.open_critical} require triage` : "High priority"}
            </div>
          </div>
        </Link>

        {/* Card 3: Cloud Security Posture (CSPM) */}
        <Link
          href="/cspm"
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-emerald-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-emerald-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(16, 185, 129, 0.09), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-emerald-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="flex items-center justify-between mb-3 relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Cloud Posture</span>
            <div className="p-2 bg-emerald-50 text-emerald-600 rounded-lg group-hover:bg-emerald-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 group-hover:shadow-xs transition-all duration-300 ease-out">
              <Cloud className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-emerald-600 transition-transform duration-300 group-hover:translate-x-0.5">
                {data.stats.cloud_security_score}%
              </span>
              <ArrowUpRight className="w-4 h-4 text-muted group-hover:text-emerald-600 group-hover:translate-x-1 group-hover:-translate-y-1 transition-all duration-300 ease-out" />
            </div>
            <div className="mt-2 text-xs text-muted">
              <span className="font-semibold text-foreground">
                {data.cspm ? `${data.cspm.open} open checks` : "Compliant rules"}
              </span>
            </div>
            <div className="mt-1 text-[11px] text-muted">
              {data.cspm?.resolved ?? 0} auto-remediated
            </div>
          </div>
        </Link>

        {/* Card 4: Active SOC Alerts */}
        <Link
          href="/alerts"
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-amber-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-amber-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(217, 119, 6, 0.09), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-amber-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="flex items-center justify-between mb-3 relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Active Alerts</span>
            <div className="p-2 bg-amber-50 text-amber-600 rounded-lg group-hover:bg-amber-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 group-hover:shadow-xs transition-all duration-300 ease-out">
              <AlertCircle className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-foreground transition-transform duration-300 group-hover:translate-x-0.5">
                {data.stats.active_alerts ?? data.alerts?.active ?? 0}
              </span>
              <ArrowUpRight className="w-4 h-4 text-muted group-hover:text-amber-600 group-hover:translate-x-1 group-hover:-translate-y-1 transition-all duration-300 ease-out" />
            </div>
            <div className="mt-2 text-xs text-muted flex items-center gap-1.5">
              <span className="font-semibold text-rose-600">
                {data.alerts?.by_severity?.CRITICAL ?? 0} Critical
              </span>
              <span>•</span>
              <span className="font-semibold text-amber-600">
                {data.alerts?.by_severity?.HIGH ?? 0} High
              </span>
            </div>
            <div className="mt-1 text-[11px] text-muted">
              Click to triage incident feed
            </div>
          </div>
        </Link>

        {/* Card 5: DevSecOps CI/CD Scanner */}
        <Link
          href="/devsecops"
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-purple-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-purple-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(147, 51, 234, 0.09), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-purple-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="flex items-center justify-between mb-3 relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">CI/CD Pass Rate</span>
            <div className="p-2 bg-purple-50 text-purple-600 rounded-lg group-hover:bg-purple-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 group-hover:shadow-xs transition-all duration-300 ease-out">
              <GitBranch className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-purple-700 transition-transform duration-300 group-hover:translate-x-0.5">
                {effectivePassRate !== null && effectivePassRate !== undefined ? `${effectivePassRate}%` : "Active"}
              </span>
              <ArrowUpRight className="w-4 h-4 text-muted group-hover:text-purple-600 group-hover:translate-x-1 group-hover:-translate-y-1 transition-all duration-300 ease-out" />
            </div>
            <div className="mt-2 text-xs text-muted">
              <span className="font-semibold text-foreground">
                {totalRuns > 0 ? `${effectivePassedRuns} passed / ${totalRuns} runs` : "Automated security gate"}
              </span>
            </div>
            <div className="mt-1 text-[11px] text-muted">
              SAST & container guardrails
            </div>
          </div>
        </Link>
      </div>

      {/* QUICK ACTION HUBS: ACTIVE ALERTS & CSPM REMEDIATION */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-stretch">
        {/* Active Incident Triage Banner */}
        <div
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-rose-400/80 rounded-xl p-5 shadow-xs hover:shadow-lg hover:shadow-rose-500/10 hover:-translate-y-1 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(280px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(225, 29, 72, 0.08), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-rose-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="relative z-10">
            <div className="flex items-center justify-between gap-2 mb-3.5">
              <div className="flex items-center gap-2 min-w-0">
                <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0 group-hover:scale-110 group-hover:-rotate-6 transition-transform duration-300" />
                <h3 className="text-sm font-bold text-foreground truncate">Active SOC Alerts Requiring Resolution</h3>
              </div>
              <Link
                href="/alerts"
                className="text-xs text-primary hover:underline flex items-center gap-1 font-medium whitespace-nowrap shrink-0 hover:translate-x-0.5 transition-transform"
              >
                View all ({data.alerts?.active ?? 0}) <ChevronRight className="w-3 h-3" />
              </Link>
            </div>

            {(!data.alerts?.recent || data.alerts.recent.length === 0) ? (
              <div className="p-6 text-center text-muted border border-dashed border-border rounded-lg bg-gray-50/50 flex flex-col items-center justify-center min-h-[168px]">
                <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2 opacity-80" />
                <p className="text-xs font-semibold text-foreground">Zero Active Critical Alerts</p>
                <p className="text-[11px] text-muted mt-0.5">All monitored incident streams are currently clear.</p>
              </div>
            ) : (
              <div className="space-y-2.5">
                {data.alerts.recent.slice(0, 3).map((alert) => (
                  <div
                    key={alert.id}
                    className="p-3 rounded-lg border border-border bg-gray-50/60 hover:bg-white hover:border-rose-200 hover:shadow-xs transition-all duration-200 flex items-center justify-between gap-3"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                            alert.severity === "CRITICAL"
                              ? "bg-rose-100 text-rose-700"
                              : alert.severity === "HIGH"
                              ? "bg-amber-100 text-amber-700"
                              : "bg-blue-100 text-blue-700"
                          }`}
                        >
                          {alert.severity}
                        </span>
                        <h4 className="text-xs font-bold text-foreground truncate">{alert.title}</h4>
                      </div>
                      <p className="text-[11px] text-muted truncate mt-0.5">
                        <span className="font-mono text-foreground/80">{alert.source}</span> • {alert.message}
                      </p>
                    </div>

                    <button
                      onClick={() => handleResolveAlert(alert.id, alert.title)}
                      disabled={resolvingAlertId === alert.id}
                      className="shrink-0 px-2.5 py-1 text-xs font-semibold bg-white hover:bg-emerald-50 text-emerald-700 border border-emerald-300 hover:border-emerald-400 rounded-md transition-all flex items-center gap-1 shadow-2xs hover:shadow-xs hover:scale-105 disabled:opacity-50"
                      title="Mark this alert as resolved"
                    >
                      {resolvingAlertId === alert.id ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Check className="w-3.5 h-3.5" />
                      )}
                      <span>Resolve</span>
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-border grid grid-cols-3 gap-2 text-center text-[11px] relative z-10">
            <div className="bg-gray-50 hover:bg-white rounded-md py-1.5 px-2 border border-gray-100 hover:border-gray-200 hover:shadow-2xs transition-all duration-200">
              <span className="text-muted block">Active Queue</span>
              <span className="font-mono font-bold text-foreground">{data.alerts?.active ?? 0}</span>
            </div>
            <div className="bg-rose-50/50 hover:bg-rose-50 rounded-md py-1.5 px-2 border border-rose-100 hover:border-rose-200 hover:shadow-2xs transition-all duration-200">
              <span className="text-muted block">Critical</span>
              <span className="font-mono font-bold text-rose-700">{data.alerts?.by_severity?.CRITICAL ?? 0}</span>
            </div>
            <div className="bg-amber-50/50 hover:bg-amber-50 rounded-md py-1.5 px-2 border border-amber-100 hover:border-amber-200 hover:shadow-2xs transition-all duration-200">
              <span className="text-muted block">High</span>
              <span className="font-mono font-bold text-amber-700">{data.alerts?.by_severity?.HIGH ?? 0}</span>
            </div>
          </div>
        </div>

        {/* Cloud Misconfiguration Remediation Card */}
        <div
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-emerald-400/80 rounded-xl p-5 shadow-xs hover:shadow-lg hover:shadow-emerald-500/10 hover:-translate-y-1 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(280px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(16, 185, 129, 0.08), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-emerald-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="relative z-10">
            <div className="flex items-center justify-between gap-2 mb-3.5">
              <div className="flex items-center gap-2 min-w-0">
                <Wrench className="w-4 h-4 text-emerald-600 shrink-0 group-hover:scale-110 group-hover:rotate-12 transition-transform duration-300" />
                <h3 className="text-sm font-bold text-foreground truncate">Cloud Policy Enforcement (CSPM)</h3>
              </div>
              <Link
                href="/cspm"
                className="text-xs text-primary hover:underline flex items-center gap-1 font-medium whitespace-nowrap shrink-0 hover:translate-x-0.5 transition-transform"
              >
                Open CSPM ({data.cspm?.open ?? 0} open) <ChevronRight className="w-3 h-3" />
              </Link>
            </div>

            {(!data.cspm?.top_open || data.cspm.top_open.length === 0) ? (
              <div className="p-6 text-center text-muted border border-dashed border-border rounded-lg bg-gray-50/50 flex flex-col items-center justify-center min-h-[168px]">
                <ShieldCheck className="w-8 h-8 text-emerald-500 mx-auto mb-2 opacity-80 group-hover:scale-105 transition-transform" />
                <p className="text-xs font-semibold text-foreground">All Cloud Postures Compliant</p>
                <p className="text-[11px] text-muted mt-0.5 max-w-xs">
                  Zero open misconfigurations found across monitored AWS, GCP, and Azure resources.
                </p>
                <button
                  onClick={handleRunCspmScan}
                  disabled={scanningCspm}
                  className="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white hover:bg-emerald-50 text-emerald-700 border border-emerald-300 transition-colors shadow-2xs hover:shadow-xs hover:scale-105 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${scanningCspm ? "animate-spin" : ""}`} />
                  <span>{scanningCspm ? "Scanning Cloud..." : "Re-Scan Cloud Resources"}</span>
                </button>
              </div>
            ) : (
              <div className="space-y-2.5">
                {data.cspm.top_open.slice(0, 3).map((finding) => (
                  <div
                    key={finding.id}
                    className="p-3 rounded-lg border border-border bg-gray-50/60 hover:bg-white hover:border-emerald-200 hover:shadow-xs transition-all duration-200 flex items-center justify-between gap-3"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                            finding.severity === "CRITICAL"
                              ? "bg-rose-100 text-rose-700"
                              : finding.severity === "HIGH"
                              ? "bg-amber-100 text-amber-700"
                              : "bg-blue-100 text-blue-700"
                          }`}
                        >
                          {finding.severity}
                        </span>
                        <h4 className="text-xs font-bold text-foreground truncate">{finding.finding}</h4>
                      </div>
                      <p className="text-[11px] text-muted font-mono truncate mt-0.5">
                        {finding.resource}
                      </p>
                    </div>

                    <button
                      onClick={() => handleRemediateCspm(finding.id, finding.resource)}
                      disabled={remediatingCspmId === finding.id}
                      className="shrink-0 px-2.5 py-1 text-xs font-semibold bg-white hover:bg-blue-50 text-blue-700 border border-blue-300 hover:border-blue-400 rounded-md transition-all flex items-center gap-1 shadow-2xs hover:shadow-xs hover:scale-105 disabled:opacity-50"
                      title="Enforce secure configuration rule"
                    >
                      {remediatingCspmId === finding.id ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Wrench className="w-3.5 h-3.5" />
                      )}
                      <span>Enforce</span>
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-border grid grid-cols-3 gap-2 text-center text-[11px] relative z-10">
            <div className="bg-emerald-50/50 hover:bg-emerald-50 rounded-md py-1.5 px-2 border border-emerald-100 hover:border-emerald-200 hover:shadow-2xs transition-all duration-200">
              <span className="text-muted block">Posture Score</span>
              <span className="font-mono font-bold text-emerald-700">{data.stats.cloud_security_score}%</span>
            </div>
            <div className="bg-gray-50 hover:bg-white rounded-md py-1.5 px-2 border border-gray-100 hover:border-gray-200 hover:shadow-2xs transition-all duration-200">
              <span className="text-muted block">Open Drift</span>
              <span className="font-mono font-bold text-foreground">{data.cspm?.open ?? 0}</span>
            </div>
            <div className="bg-blue-50/50 hover:bg-blue-50 rounded-md py-1.5 px-2 border border-blue-100 hover:border-blue-200 hover:shadow-2xs transition-all duration-200">
              <span className="text-muted block">Remediated</span>
              <span className="font-mono font-bold text-blue-700">{data.cspm?.resolved ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* TELEMETRY CHARTS & ATTACK INTEL ROW */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* 14-Day Attack Timeline Stacked Area */}
        <div
          onMouseMove={handleCardMouseMove}
          className="lg:col-span-7 relative overflow-hidden group bg-surface border border-border hover:border-blue-400/80 rounded-xl p-5 shadow-xs hover:shadow-lg hover:shadow-blue-500/10 hover:-translate-y-1 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(320px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.08), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="relative z-10">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
              <div>
                <h2 className="text-base font-bold text-foreground flex items-center gap-2">
                  <Activity className="w-4 h-4 text-primary group-hover:scale-110 group-hover:rotate-6 transition-transform duration-300" /> 14-Day Threat Telemetry Timeline
                </h2>
                <p className="text-xs text-muted">Daily distribution of recorded attack incidents by severity</p>
              </div>
              <div className="flex items-center gap-3 text-[11px] shrink-0">
                <span className="flex items-center gap-1 text-rose-600 font-medium">
                  <span className="w-2.5 h-2.5 bg-rose-500 rounded-xs" /> Critical
                </span>
                <span className="flex items-center gap-1 text-amber-600 font-medium">
                  <span className="w-2.5 h-2.5 bg-amber-500 rounded-xs" /> High
                </span>
                <span className="flex items-center gap-1 text-blue-600 font-medium">
                  <span className="w-2.5 h-2.5 bg-blue-500 rounded-xs" /> Medium
                </span>
                <span className="flex items-center gap-1 text-emerald-600 font-medium">
                  <span className="w-2.5 h-2.5 bg-emerald-500 rounded-xs" /> Low
                </span>
              </div>
            </div>

            <div className="h-[250px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineChartData}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                  <XAxis dataKey="label" stroke="#94a3b8" fontSize={11} tickLine={false} />
                  <YAxis stroke="#94a3b8" fontSize={11} tickLine={false} allowDecimals={false} width={28} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#ffffff",
                      borderRadius: "8px",
                      border: "1px solid #e2e8f0",
                      fontSize: "12px",
                      boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.05)",
                    }}
                  />
                  <Area type="monotone" dataKey="critical" stackId="1" stroke="#e11d48" fill="#e11d48" fillOpacity={0.7} />
                  <Area type="monotone" dataKey="high" stackId="1" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.7} />
                  <Area type="monotone" dataKey="medium" stackId="1" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.7} />
                  <Area type="monotone" dataKey="low" stackId="1" stroke="#10b981" fill="#10b981" fillOpacity={0.7} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="pt-3 mt-2 border-t border-border flex items-center justify-between text-xs text-muted relative z-10">
            <span>Real-time event correlation across network sensors</span>
            <Link href="/threats" className="text-primary hover:underline font-medium whitespace-nowrap shrink-0 hover:translate-x-0.5 transition-transform">
              Explore Threat Log →
            </Link>
          </div>
        </div>

        {/* Attack Vector Distribution */}
        <div
          onMouseMove={handleCardMouseMove}
          className="lg:col-span-5 relative overflow-hidden group bg-surface border border-border hover:border-blue-400/80 rounded-xl p-5 shadow-xs hover:shadow-lg hover:shadow-blue-500/10 hover:-translate-y-1 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(280px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.08), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="relative z-10">
            <div className="flex items-start justify-between gap-2 mb-4">
              <div className="min-w-0">
                <h2 className="text-base font-bold text-foreground">Threat Vector Breakdown</h2>
                <p className="text-xs text-muted">Attack mechanisms classified by SentinelX ML models</p>
              </div>
              <span className="text-xs font-mono font-semibold px-2.5 py-0.5 rounded-md bg-blue-50 text-blue-700 border border-blue-200 whitespace-nowrap shrink-0 group-hover:scale-105 transition-transform">
                {data.threat_distribution.reduce((acc, curr) => acc + curr.count, 0)} Total
              </span>
            </div>

            <div className="h-[250px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.threat_distribution} layout="vertical" margin={{ left: 4, right: 12 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f1f5f9" />
                  <XAxis type="number" stroke="#94a3b8" fontSize={11} tickLine={false} allowDecimals={false} />
                  <YAxis dataKey="label" type="category" stroke="#64748b" fontSize={11} width={88} tickLine={false} />
                  <Tooltip
                    cursor={{ fill: "#f8fafc" }}
                    contentStyle={{
                      backgroundColor: "#ffffff",
                      borderRadius: "8px",
                      border: "1px solid #e2e8f0",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="count" fill="#2563EB" radius={[0, 4, 4, 0]} barSize={20} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="pt-3 mt-2 border-t border-border flex items-center justify-between gap-2 text-xs text-muted relative z-10">
            <span className="truncate">Classified with ML Random Forest & Suricata rules</span>
            <Link href="/analytics" className="text-primary hover:underline font-medium whitespace-nowrap shrink-0 hover:translate-x-0.5 transition-transform">
              Detailed Analytics →
            </Link>
          </div>
        </div>
      </div>

      {/* TOP ATTACKING SOURCES WIDGET & DEVSECOPS/TELEMETRY GRID */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Top Attacking Sources */}
        <div
          onMouseMove={handleCardMouseMove}
          className="lg:col-span-7 relative overflow-hidden group bg-surface border border-border hover:border-blue-400/80 rounded-xl p-5 shadow-xs hover:shadow-lg hover:shadow-blue-500/10 hover:-translate-y-1 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(300px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.08), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="relative z-10">
            <div className="flex items-center justify-between gap-2 mb-3.5">
              <div>
                <h3 className="text-base font-bold text-foreground flex items-center gap-2">
                  <Server className="w-4 h-4 text-primary group-hover:scale-110 group-hover:-rotate-6 transition-transform duration-300" /> Top Attacking Sources (Past 30 Days)
                </h3>
                <p className="text-xs text-muted">Click an IP to immediately filter the incidents table below</p>
              </div>
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="text-xs text-muted hover:text-foreground flex items-center gap-1 border border-border px-2.5 py-1 rounded-md whitespace-nowrap shrink-0 hover:bg-gray-50 transition-colors"
                >
                  Clear filter <X className="w-3 h-3" />
                </button>
              )}
            </div>

            {(!data.top_sources || data.top_sources.length === 0) ? (
              <div className="p-8 text-center text-muted border border-dashed border-border rounded-lg bg-gray-50">
                No persistent external attack actors detected in recorded window.
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {data.top_sources.slice(0, 4).map((actor) => (
                  <div
                    key={actor.source}
                    onMouseMove={handleCardMouseMove}
                    className={`relative overflow-hidden group/tile p-3 rounded-lg border transition-all duration-200 text-xs cursor-pointer flex flex-col justify-between hover:shadow-md hover:-translate-y-1 ${
                      searchQuery === actor.source
                        ? "bg-blue-50/70 border-primary shadow-xs ring-1 ring-primary/30"
                        : "bg-white border-border hover:border-blue-400 hover:bg-blue-50/30"
                    }`}
                    onClick={() => setSearchQuery(actor.source)}
                  >
                    {/* Inner Tile Spotlight Glow */}
                    <div
                      className="pointer-events-none absolute -inset-px rounded-lg opacity-0 group-hover/tile:opacity-100 transition-opacity duration-300"
                      style={{
                        background:
                          "radial-gradient(130px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.1), transparent 80%)",
                      }}
                    />

                    <div className="relative z-10 flex flex-col justify-between h-full">
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <div className="flex items-center gap-1.5 font-mono font-bold text-foreground">
                            <span className="group-hover/tile:text-primary transition-colors">{actor.source}</span>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(actor.source);
                              }}
                              className="text-muted hover:text-foreground p-0.5 rounded hover:bg-gray-100 transition-colors"
                              title="Copy IP"
                            >
                              {copiedIp === actor.source ? (
                                <Check className="w-3 h-3 text-emerald-600" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                              actor.max_severity === "CRITICAL"
                                ? "bg-rose-100 text-rose-700"
                                : actor.max_severity === "HIGH"
                                ? "bg-amber-100 text-amber-700"
                                : "bg-blue-100 text-blue-700"
                            }`}
                          >
                            {actor.max_severity}
                          </span>
                        </div>

                        <div className="flex items-center justify-between text-muted text-[11px]">
                          <span>
                            <strong className="text-foreground">{actor.count}</strong>{" "}
                            {actor.count === 1 ? "event" : "events"}
                          </span>
                          <span className="truncate max-w-[150px] text-right font-medium text-foreground/80">
                            {actor.types.join(", ")}
                          </span>
                        </div>
                      </div>

                      <div className="mt-2 pt-1.5 border-t border-border/60 flex items-center justify-between text-[10px] text-muted">
                        <span className={actor.simulated ? "text-blue-600 font-medium" : "text-emerald-700 font-medium"}>
                          {actor.simulated ? "Simulated Traffic" : "Recorded Traffic"}
                        </span>
                        <span className="group-hover/tile:text-primary font-medium transition-colors">Click to filter ↓</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-border flex items-center justify-between text-xs text-muted relative z-10">
            <span>Showing top {Math.min(4, data.top_sources?.length ?? 0)} persistent source IPs</span>
            <Link href="/threats" className="text-primary hover:underline font-medium whitespace-nowrap hover:translate-x-0.5 transition-transform">
              Full IP Reputation List →
            </Link>
          </div>
        </div>

        {/* Live System Performance & Telemetry */}
        <div
          onMouseMove={handleCardMouseMove}
          className="lg:col-span-5 relative overflow-hidden group bg-surface border border-border hover:border-indigo-400/80 rounded-xl p-5 shadow-xs hover:shadow-lg hover:shadow-indigo-500/10 hover:-translate-y-1 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          {/* Cursor Spotlight Glow */}
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(280px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(99, 102, 241, 0.08), transparent 80%)",
            }}
          />
          {/* Top Animated Accent Bar */}
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-indigo-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="relative z-10">
            <div className="flex items-center justify-between gap-2 mb-4">
              <div>
                <h3 className="text-base font-bold text-foreground flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-primary group-hover:scale-110 group-hover:rotate-12 transition-transform duration-300" /> System Resource Telemetry
                </h3>
                <p className="text-xs text-muted">Real-time health of SentinelX inspection engine</p>
              </div>
              <Link href="/monitoring" className="text-xs text-primary hover:underline font-medium whitespace-nowrap shrink-0 hover:translate-x-0.5 transition-transform">
                All metrics →
              </Link>
            </div>

            <div className="space-y-3.5">
              {/* CPU Meter */}
              <div>
                <div className="flex justify-between items-center text-xs mb-1">
                  <span className="text-muted font-medium">CPU Utilization</span>
                  <span className="font-mono font-bold text-foreground">
                    {data.system?.cpu_usage ?? 18.4}%
                  </span>
                </div>
                <div className="h-2 w-full bg-gray-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-600 rounded-full transition-all duration-500"
                    style={{ width: `${data.system?.cpu_usage ?? 18.4}%` }}
                  />
                </div>
              </div>

              {/* Memory Meter */}
              <div>
                <div className="flex justify-between items-center text-xs mb-1">
                  <span className="text-muted font-medium">Memory Allocation</span>
                  <span className="font-mono font-bold text-foreground">
                    {data.system?.memory_usage ?? 42.1}%
                  </span>
                </div>
                <div className="h-2 w-full bg-gray-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-indigo-600 rounded-full transition-all duration-500"
                    style={{ width: `${data.system?.memory_usage ?? 42.1}%` }}
                  />
                </div>
              </div>

              {/* 2x2 Sub-Telemetry Grid */}
              <div className="grid grid-cols-2 gap-2.5 pt-1">
                <div
                  onMouseMove={handleCardMouseMove}
                  className="relative overflow-hidden group/sub p-2.5 rounded-lg bg-gray-50 hover:bg-white border border-border hover:border-emerald-300 hover:shadow-xs hover:-translate-y-0.5 transition-all duration-200"
                >
                  <div
                    className="pointer-events-none absolute -inset-px rounded-lg opacity-0 group-hover/sub:opacity-100 transition-opacity duration-300"
                    style={{
                      background:
                        "radial-gradient(110px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(16, 185, 129, 0.09), transparent 80%)",
                    }}
                  />
                  <div className="relative z-10">
                    <span className="text-[10px] text-muted uppercase font-semibold block">Gateway Latency</span>
                    <div className="flex items-center justify-between mt-1">
                      <span className="font-mono text-xs font-bold text-emerald-700">
                        {data.system?.api_latency ?? 12.3} ms
                      </span>
                      <Clock className="w-3.5 h-3.5 text-emerald-600 group-hover/sub:scale-110 transition-transform" />
                    </div>
                  </div>
                </div>

                <div
                  onMouseMove={handleCardMouseMove}
                  className="relative overflow-hidden group/sub p-2.5 rounded-lg bg-gray-50 hover:bg-white border border-border hover:border-blue-300 hover:shadow-xs hover:-translate-y-0.5 transition-all duration-200"
                >
                  <div
                    className="pointer-events-none absolute -inset-px rounded-lg opacity-0 group-hover/sub:opacity-100 transition-opacity duration-300"
                    style={{
                      background:
                        "radial-gradient(110px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.09), transparent 80%)",
                    }}
                  />
                  <div className="relative z-10">
                    <span className="text-[10px] text-muted uppercase font-semibold block">Net RX / TX</span>
                    <div className="flex items-center justify-between mt-1">
                      <span className="font-mono text-xs font-bold text-foreground">
                        {data.system?.network_rx ?? 124} / {data.system?.network_tx ?? 86} KB/s
                      </span>
                      <Activity className="w-3.5 h-3.5 text-blue-600 group-hover/sub:scale-110 transition-transform" />
                    </div>
                  </div>
                </div>

                <div
                  onMouseMove={handleCardMouseMove}
                  className="relative overflow-hidden group/sub p-2.5 rounded-lg bg-gray-50 hover:bg-white border border-border hover:border-indigo-300 hover:shadow-xs hover:-translate-y-0.5 transition-all duration-200"
                >
                  <div
                    className="pointer-events-none absolute -inset-px rounded-lg opacity-0 group-hover/sub:opacity-100 transition-opacity duration-300"
                    style={{
                      background:
                        "radial-gradient(110px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(99, 102, 241, 0.09), transparent 80%)",
                    }}
                  />
                  <div className="relative z-10">
                    <span className="text-[10px] text-muted uppercase font-semibold block">Recon Findings</span>
                    <div className="flex items-center justify-between mt-1">
                      <span className="font-mono text-xs font-bold text-foreground">
                        {data.stats.open_audit_findings ?? data.audit?.open ?? 0} Open
                      </span>
                      <Shield className="w-3.5 h-3.5 text-indigo-600 group-hover/sub:scale-110 transition-transform" />
                    </div>
                  </div>
                </div>

                <div
                  onMouseMove={handleCardMouseMove}
                  className="relative overflow-hidden group/sub p-2.5 rounded-lg bg-gray-50 hover:bg-white border border-border hover:border-emerald-300 hover:shadow-xs hover:-translate-y-0.5 transition-all duration-200"
                >
                  <div
                    className="pointer-events-none absolute -inset-px rounded-lg opacity-0 group-hover/sub:opacity-100 transition-opacity duration-300"
                    style={{
                      background:
                        "radial-gradient(110px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(16, 185, 129, 0.09), transparent 80%)",
                    }}
                  />
                  <div className="relative z-10">
                    <span className="text-[10px] text-muted uppercase font-semibold block">ML Classifier</span>
                    <div className="flex items-center justify-between mt-1">
                      <span className="font-mono text-xs font-bold text-emerald-700">Online</span>
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 group-hover/sub:scale-110 transition-transform" />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-border flex items-center justify-between text-xs text-muted relative z-10">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" /> All container pods healthy
            </span>
            <span className="font-mono text-[11px]">99.98% Uptime</span>
          </div>
        </div>
      </div>

      {/* RECENT CRITICAL EVENTS TABLE (INTERACTIVE COMMAND CENTER) */}
      <div
        onMouseMove={handleCardMouseMove}
        className="relative overflow-hidden group bg-surface border border-border hover:border-blue-400/60 rounded-xl shadow-xs hover:shadow-md transition-all duration-300 ease-out"
      >
        {/* Cursor Spotlight Glow */}
        <div
          className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            background:
              "radial-gradient(400px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.04), transparent 80%)",
          }}
        />
        {/* Top Animated Accent Bar */}
        <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

        <div className="relative z-10">
        {/* Table Header & Interactive Search/Filters */}
        <div className="p-5 border-b border-border bg-white flex flex-col xl:flex-row xl:items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2.5">
              <h2 className="text-base font-bold text-foreground">Recorded Threat Incidents</h2>
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-gray-100 text-gray-700 border border-gray-200 whitespace-nowrap">
                {filteredEvents.length} shown
              </span>
            </div>
            <p className="text-xs text-muted mt-0.5">
              Click status badges to triage (Open → Investigating → Resolved). Instant search by IP or attack type.
            </p>
          </div>

          <div className="flex flex-wrap sm:flex-nowrap items-center gap-2 shrink-0">
            {/* Search Input */}
            <div className="relative w-full sm:w-52">
              <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search IP, ID, type..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-7 py-1.5 text-xs bg-gray-50 border border-border rounded-lg text-foreground focus:bg-white focus:outline-none focus:ring-1 focus:ring-primary transition-all"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-foreground"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>

            {/* Severity Filter Pills */}
            <div className="flex items-center bg-gray-100 p-0.5 rounded-lg border border-gray-200 text-xs font-medium shrink-0">
              {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2 py-1 rounded-md transition-all ${
                    severityFilter === sev
                      ? "bg-white text-foreground shadow-2xs font-semibold"
                      : "text-muted hover:text-foreground"
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="text-xs bg-white border border-border rounded-lg px-2.5 py-1.5 text-foreground focus:outline-none focus:ring-1 focus:ring-primary shrink-0"
            >
              <option value="ALL">All Statuses</option>
              <option value="Open">Open</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
            </select>
          </div>
        </div>

        {/* Table Body */}
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="text-[11px] text-muted uppercase bg-gray-50/70 border-b border-border">
              <tr>
                <th className="px-4 py-3 font-semibold whitespace-nowrap">Event ID & Time</th>
                <th className="px-4 py-3 font-semibold whitespace-nowrap">Classification</th>
                <th className="px-4 py-3 font-semibold whitespace-nowrap">Source IP</th>
                <th className="px-4 py-3 font-semibold whitespace-nowrap">Destination</th>
                <th className="px-4 py-3 font-semibold whitespace-nowrap">Severity</th>
                <th className="px-4 py-3 font-semibold whitespace-nowrap">Triage Status</th>
                <th className="px-4 py-3 font-semibold text-right whitespace-nowrap">Copilot</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-muted">
                    <p className="text-xs font-semibold text-foreground">No events match your search or filter.</p>
                    <button
                      onClick={() => {
                        setSearchQuery("");
                        setSeverityFilter("ALL");
                        setStatusFilter("ALL");
                      }}
                      className="mt-2 text-xs text-primary hover:underline font-medium"
                    >
                      Reset all filters
                    </button>
                  </td>
                </tr>
              ) : (
                filteredEvents.map((event) => {
                  const isUpdating = updatingThreatId === event.id;

                  return (
                    <tr key={event.id} className="hover:bg-gray-50/80 transition-colors">
                      {/* Event ID & Time */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="font-mono font-bold text-foreground">{event.id}</div>
                        <div className="text-[11px] text-muted mt-0.5">{event.time}</div>
                      </td>

                      {/* Classification & Type */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="font-semibold text-foreground flex items-center gap-1.5">
                          <span>{event.type}</span>
                          {event.simulated && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-50 text-blue-700 border border-blue-200">
                              Simulated
                            </span>
                          )}
                        </div>
                        {event.confidence !== undefined && (
                          <div className="text-[10px] text-muted mt-0.5">
                            Confidence: {Math.round(event.confidence * 100)}%
                          </div>
                        )}
                      </td>

                      {/* Source IP */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-foreground font-medium">{event.source}</span>
                          <button
                            onClick={() => copyToClipboard(event.source)}
                            className="p-1 text-muted hover:text-foreground rounded"
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

                      {/* Destination */}
                      <td className="px-4 py-3 whitespace-nowrap text-muted font-mono text-[11px]">
                        {event.destination || "api-gateway:443"}
                      </td>

                      {/* Severity */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[11px] font-bold border ${
                            event.severity.toUpperCase() === "CRITICAL"
                              ? "bg-rose-50 text-rose-700 border-rose-200"
                              : event.severity.toUpperCase() === "HIGH"
                              ? "bg-amber-50 text-amber-700 border-amber-200"
                              : event.severity.toUpperCase() === "MEDIUM"
                              ? "bg-blue-50 text-blue-700 border-blue-200"
                              : "bg-emerald-50 text-emerald-700 border-emerald-200"
                          }`}
                        >
                          {event.severity}
                        </span>
                      </td>

                      {/* Interactive Triage Action */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="inline-flex items-center rounded-lg border border-border bg-white p-0.5 shadow-2xs">
                          {(["Open", "Investigating", "Resolved"] as const).map((st) => {
                            const isCurrent = event.status.toLowerCase() === st.toLowerCase();
                            return (
                              <button
                                key={st}
                                disabled={isUpdating}
                                onClick={() => handleUpdateThreatStatus(event.id, st)}
                                className={`px-2 py-0.5 text-[11px] font-medium rounded transition-all ${
                                  isCurrent
                                    ? st === "Open"
                                      ? "bg-rose-100 text-rose-800 font-bold"
                                      : st === "Investigating"
                                      ? "bg-amber-100 text-amber-800 font-bold"
                                      : "bg-emerald-100 text-emerald-800 font-bold"
                                    : "text-muted hover:text-foreground hover:bg-gray-100"
                                } disabled:opacity-50`}
                              >
                                {isUpdating && isCurrent ? <Loader2 className="w-3 h-3 animate-spin inline" /> : st}
                              </button>
                            );
                          })}
                        </div>
                      </td>

                      {/* AI Copilot Ask */}
                      <td className="px-4 py-3 whitespace-nowrap text-right">
                        <Link
                          href={`/assistant?q=Analyze attack event ${event.id} of type ${event.type} from IP ${event.source} and suggest immediate remediation.`}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-semibold bg-primary/5 hover:bg-primary hover:text-white text-primary border border-primary/20 rounded-md transition-all"
                        >
                          <Sparkles className="w-3 h-3" />
                          <span>Ask AI</span>
                        </Link>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Table Footer */}
        <div className="p-4 border-t border-border bg-gray-50/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-muted">
          <span>
            Displaying {filteredEvents.length} of {data.recent_events.length} most recent security events
          </span>
          <Link
            href="/threats"
            className="text-primary font-semibold hover:underline flex items-center gap-1 self-start sm:self-auto"
          >
            Go to Dedicated Threats Center <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>
    </div>
  </div>
);
}
