"use client";

import { API_URL, apiFetch as fetch } from "@/lib/api";
import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import {
  BarChart2,
  Shield,
  AlertTriangle,
  CheckCircle2,
  CircleDot,
  Globe,
  Copy,
  Check,
  Search,
  X,
  Sparkles,
  RefreshCw,
  ArrowUpRight,
  ChevronRight,
  ClipboardList,
  TrendingUp,
  Activity,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  PieChart,
  Pie,
  Cell,
} from "recharts";

interface AnalyticsData {
  trend: {
    date: string;
    critical: number;
    high: number;
    medium: number;
    low?: number;
  }[];
  severity_distribution: {
    name: string;
    value: number;
  }[];
  audit_distribution: { name: string; value: number }[];
  audit_summary: {
    total: number;
    open: number;
    resolved: number;
    recent: {
      id: string;
      target: string;
      title: string;
      severity: string;
      status: string;
      time: string;
    }[];
  };
}

const COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#3b82f6",
};

export default function AnalyticsPage() {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(false);
  const [copiedTarget, setCopiedTarget] = useState<string | null>(null);

  // Search & Filter State for Audit Observations
  const [observationSearch, setObservationSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  const handleCardMouseMove = (e: React.MouseEvent<HTMLElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    e.currentTarget.style.setProperty("--mouse-x", `${x}px`);
    e.currentTarget.style.setProperty("--mouse-y", `${y}px`);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedTarget(text);
    setTimeout(() => setCopiedTarget((cur) => (cur === text ? null : cur)), 2000);
  };

  const fetchAnalytics = async () => {
    try {
      const res = await fetch(`${API_URL}/api/analytics`);
      if (!res.ok) throw new Error("Could not load analytics");
      const json = await res.json();
      setData(json);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  const handleManualRefresh = () => {
    setIsRefreshing(true);
    void fetchAnalytics();
  };

  useEffect(() => {
    let isCancelled = false;

    const loadInitialData = async () => {
      try {
        const res = await fetch(`${API_URL}/api/analytics`);
        if (!res.ok) throw new Error("Could not load analytics");
        const json = await res.json();
        if (!isCancelled) {
          setData(json);
          setError(false);
        }
      } catch {
        if (!isCancelled) setError(true);
      } finally {
        if (!isCancelled) setLoading(false);
      }
    };

    void loadInitialData();

    const timer = setInterval(() => {
      void fetchAnalytics();
    }, 12000);

    return () => {
      isCancelled = true;
      clearInterval(timer);
    };
  }, []);

  // Filtered Audit Observations
  const filteredObservations = useMemo(() => {
    if (!data?.audit_summary?.recent) return [];
    return data.audit_summary.recent.filter((obs) => {
      const query = observationSearch.trim().toLowerCase();
      const matchesSearch =
        query === "" ||
        obs.title.toLowerCase().includes(query) ||
        obs.target.toLowerCase().includes(query) ||
        obs.id.toLowerCase().includes(query);

      const matchesSeverity =
        severityFilter === "ALL" || obs.severity.toUpperCase() === severityFilter;

      const matchesStatus =
        statusFilter === "ALL" || obs.status.toLowerCase() === statusFilter.toLowerCase();

      return matchesSearch && matchesSeverity && matchesStatus;
    });
  }, [data, observationSearch, severityFilter, statusFilter]);

  // Derived KPI Stats
  const totalThreatEvents = useMemo(() => {
    if (!data?.severity_distribution) return 0;
    return data.severity_distribution.reduce((acc, curr) => acc + curr.value, 0);
  }, [data]);

  const criticalThreats = useMemo(() => {
    if (!data?.severity_distribution) return 0;
    return (
      data.severity_distribution.find((item) => item.name.toLowerCase() === "critical")?.value ?? 0
    );
  }, [data]);

  const highThreats = useMemo(() => {
    if (!data?.severity_distribution) return 0;
    return (
      data.severity_distribution.find((item) => item.name.toLowerCase() === "high")?.value ?? 0
    );
  }, [data]);

  if (error) {
    return (
      <div className="p-12 text-center" role="alert">
        <div className="w-12 h-12 rounded-full bg-red-50 text-red-600 flex items-center justify-center mx-auto mb-3">
          <AlertTriangle className="w-6 h-6" />
        </div>
        <p className="text-sm font-semibold text-foreground">Could not load analytics telemetry.</p>
        <p className="text-xs text-muted mt-1">Please verify backend service status and retry.</p>
        <button
          className="mt-4 px-4 py-2 rounded-lg bg-primary text-white text-xs font-semibold hover:bg-blue-700 transition-all shadow-xs"
          onClick={() => void fetchAnalytics()}
        >
          Retry Connection
        </button>
      </div>
    );
  }

  if (loading || !data) {
    return (
      <div className="p-16 text-center text-muted flex flex-col items-center justify-center gap-3">
        <RefreshCw className="w-8 h-8 text-primary animate-spin" />
        <p className="font-semibold text-sm text-foreground">Synthesizing Security Analytics...</p>
        <p className="text-xs text-muted max-w-sm">
          Aggregating 30-day threat distributions and DevSecOps audit evidence.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16 animate-fade-in">
      {/* Header Banner Card with Mouse Tracking Animation */}
      <div
        onMouseMove={handleCardMouseMove}
        className="relative overflow-hidden group flex flex-col lg:flex-row justify-between lg:items-center gap-4 bg-surface p-6 rounded-2xl border border-border hover:border-blue-400/60 shadow-xs hover:shadow-lg hover:shadow-blue-500/5 hover:-translate-y-0.5 transition-all duration-300 ease-out"
      >
        {/* Cursor Spotlight Glow */}
        <div
          className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            background:
              "radial-gradient(350px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.07), transparent 80%)",
          }}
        />
        {/* Top Animated Accent Bar */}
        <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

        <div className="flex items-start sm:items-center gap-3.5 relative z-10 min-w-0">
          <div className="p-3 bg-blue-50 border border-blue-200/80 rounded-xl text-primary shrink-0 shadow-inner group-hover:scale-105 group-hover:-rotate-3 transition-transform duration-300">
            <BarChart2 className="w-6 h-6" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-2xl font-bold tracking-tight text-foreground truncate">
                Security Analytics & Threat Intelligence
              </h1>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border bg-blue-50 text-blue-700 border-blue-200 whitespace-nowrap shadow-2xs">
                <Activity className="w-3 h-3 text-primary animate-pulse" />
                30-Day Velocity Horizon
              </span>
            </div>
            <p className="text-xs text-muted mt-1 leading-relaxed">
              Historical attack vectors, multi-severity incident timelines, and synthesized DevSecOps audit discoveries.
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
            <span>{isRefreshing ? "Refreshing..." : "Sync Analytics"}</span>
          </button>

          <Link
            href="/assistant?q=Provide executive analysis of the 30-day threat trend and prioritize our open audit observations."
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-primary hover:bg-blue-700 text-white rounded-lg transition-all shadow-xs whitespace-nowrap hover:shadow-md hover:scale-[1.02]"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Ask Copilot</span>
          </Link>
        </div>
      </div>

      {/* 4 TOP TELEMETRY KPI METRIC BOXES */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Total Recorded Incidents */}
        <div
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-blue-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-blue-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.09), transparent 80%)",
            }}
          />
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="flex items-center justify-between mb-3 relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Threat Events</span>
            <div className="p-2 bg-blue-50 text-blue-600 rounded-lg group-hover:bg-primary group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300 ease-out">
              <Shield className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-foreground transition-transform duration-300 group-hover:translate-x-0.5">
                {totalThreatEvents}
              </span>
              <span className="text-xs font-mono text-muted">30-day recorded</span>
            </div>
            <div className="mt-2 text-xs text-muted flex items-center justify-between">
              <span>{criticalThreats + highThreats} Critical/High</span>
              <span>•</span>
              <span className="text-blue-600 font-medium">IDS Classified</span>
            </div>
          </div>
        </div>

        {/* Metric 2: Critical Severity Pressure */}
        <div
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-red-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-red-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(220, 38, 38, 0.09), transparent 80%)",
            }}
          />
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-red-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="flex items-center justify-between mb-3 relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Critical Incidents</span>
            <div className="p-2 bg-red-50 text-red-600 rounded-lg group-hover:bg-red-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300 ease-out">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-red-600 transition-transform duration-300 group-hover:translate-x-0.5">
                {criticalThreats}
              </span>
              <span className="text-xs font-mono font-semibold text-amber-600">
                +{highThreats} High
              </span>
            </div>
            <div className="mt-2 text-xs text-muted">
              Immediate containment candidates
            </div>
          </div>
        </div>

        {/* Metric 3: Open Audit Observations */}
        <div
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-amber-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-amber-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(217, 119, 6, 0.09), transparent 80%)",
            }}
          />
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-amber-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="flex items-center justify-between mb-3 relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Open Observations</span>
            <div className="p-2 bg-amber-50 text-amber-600 rounded-lg group-hover:bg-amber-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300 ease-out">
              <CircleDot className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-amber-600 transition-transform duration-300 group-hover:translate-x-0.5">
                {data.audit_summary.open}
              </span>
              <span className="text-xs font-mono text-muted">of {data.audit_summary.total}</span>
            </div>
            <div className="mt-2 text-xs text-muted">
              Candidate findings awaiting resolution
            </div>
          </div>
        </div>

        {/* Metric 4: Resolved & Remediated */}
        <div
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-emerald-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-emerald-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(16, 185, 129, 0.09), transparent 80%)",
            }}
          />
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-emerald-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="flex items-center justify-between mb-3 relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Remediated Findings</span>
            <div className="p-2 bg-emerald-50 text-emerald-600 rounded-lg group-hover:bg-emerald-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300 ease-out">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-emerald-600 transition-transform duration-300 group-hover:translate-x-0.5">
                {data.audit_summary.resolved}
              </span>
              <span className="text-xs font-semibold text-emerald-700">Verified</span>
            </div>
            <div className="mt-2 text-xs text-muted">
              Enforced across infrastructure targets
            </div>
          </div>
        </div>
      </div>

      {/* CHARTS GRID: 30-DAY TIMELINE & SEVERITY PIE */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Trend Area Chart (8 cols) */}
        <div
          onMouseMove={handleCardMouseMove}
          className="lg:col-span-7 xl:col-span-8 relative overflow-hidden group bg-surface border border-border hover:border-blue-400/80 rounded-2xl p-5 shadow-xs hover:shadow-lg hover:shadow-blue-500/10 hover:-translate-y-1 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          <div
            className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(350px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.08), transparent 80%)",
            }}
          />
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="relative z-10">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
              <div>
                <h2 className="text-base font-bold text-foreground flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-primary group-hover:scale-110 group-hover:rotate-6 transition-transform duration-300" />
                  30-Day Threat Incident Velocity
                </h2>
                <p className="text-xs text-muted">Daily distribution of recorded attack events by severity</p>
              </div>
              <div className="flex items-center gap-3 text-[11px] shrink-0">
                <span className="flex items-center gap-1 text-rose-600 font-medium">
                  <span className="w-2.5 h-2.5 bg-rose-500 rounded-xs" /> Critical
                </span>
                <span className="flex items-center gap-1 text-amber-600 font-medium">
                  <span className="w-2.5 h-2.5 bg-amber-500 rounded-xs" /> High
                </span>
                <span className="flex items-center gap-1 text-yellow-600 font-medium">
                  <span className="w-2.5 h-2.5 bg-yellow-500 rounded-xs" /> Medium
                </span>
              </div>
            </div>

            <div className="h-[340px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.trend}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                  <XAxis dataKey="date" stroke="#94a3b8" fontSize={11} tickMargin={8} minTickGap={28} tickLine={false} />
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
                  <Area type="monotone" dataKey="critical" stackId="1" stroke={COLORS.Critical} fill={COLORS.Critical} fillOpacity={0.65} />
                  <Area type="monotone" dataKey="high" stackId="1" stroke={COLORS.High} fill={COLORS.High} fillOpacity={0.65} />
                  <Area type="monotone" dataKey="medium" stackId="1" stroke={COLORS.Medium} fill={COLORS.Medium} fillOpacity={0.65} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="pt-3 mt-2 border-t border-border flex items-center justify-between text-xs text-muted relative z-10">
            <span>Includes live sensor events & authenticated test traffic</span>
            <Link href="/threats" className="text-primary hover:underline font-medium whitespace-nowrap shrink-0 hover:translate-x-0.5 transition-transform">
              Explore Threat Stream →
            </Link>
          </div>
        </div>

        {/* Severity Distribution Pie Chart (4 cols) */}
        <div
          onMouseMove={handleCardMouseMove}
          className="lg:col-span-5 xl:col-span-4 relative overflow-hidden group bg-surface border border-border hover:border-orange-400/80 rounded-2xl p-5 shadow-xs hover:shadow-lg hover:shadow-orange-500/10 hover:-translate-y-1 transition-all duration-300 ease-out flex flex-col justify-between"
        >
          <div
            className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(280px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(249, 115, 22, 0.08), transparent 80%)",
            }}
          />
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-orange-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="relative z-10">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-base font-bold text-foreground">Severity Distribution</h2>
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-orange-50 text-orange-700 border border-orange-200">
                {totalThreatEvents} Events
              </span>
            </div>
            <p className="text-xs text-muted mb-4">Breakdown by CVSS severity impact</p>

            <div className="h-[210px] w-full">
              {data.severity_distribution.every((item) => item.value === 0) ? (
                <div className="h-full flex items-center justify-center text-xs text-muted">
                  No threat events recorded in this window.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={data.severity_distribution}
                      cx="50%"
                      cy="50%"
                      innerRadius={55}
                      outerRadius={85}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {data.severity_distribution.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={COLORS[entry.name as keyof typeof COLORS] || "#94a3b8"}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#ffffff",
                        borderRadius: "8px",
                        border: "1px solid #e2e8f0",
                        fontSize: "12px",
                      }}
                    />
                    <Legend iconSize={8} wrapperStyle={{ fontSize: "11px" }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="mt-4 pt-4 border-t border-border space-y-2">
              <div className="text-[11px] font-bold uppercase tracking-wider text-muted">
                Audit Findings by Severity
              </div>
              <div className="grid grid-cols-2 gap-2">
                {data.audit_distribution.map((item) => (
                  <div
                    key={item.name}
                    className="p-2 rounded-lg bg-gray-50 border border-border/80 flex items-center justify-between text-xs"
                  >
                    <span className="flex items-center gap-1.5 font-medium text-slate-700">
                      <span
                        className="w-2 h-2 rounded-full"
                        style={{ backgroundColor: COLORS[item.name as keyof typeof COLORS] || "#94a3b8" }}
                      />
                      {item.name}
                    </span>
                    <span className="font-mono font-bold text-foreground">{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="pt-3 mt-2 border-t border-border flex items-center justify-between text-xs text-muted relative z-10">
            <span>Classified with ML Random Forest</span>
            <Link href="/devsecops" className="text-primary hover:underline font-medium whitespace-nowrap shrink-0 hover:translate-x-0.5 transition-transform">
              DevSecOps →
            </Link>
          </div>
        </div>
      </div>

      {/* AUDIT OBSERVATIONS COMMAND CARD (THE USER'S CORE REQUEST) */}
      <div
        onMouseMove={handleCardMouseMove}
        className="relative overflow-hidden group bg-surface border border-border hover:border-purple-400/80 rounded-2xl shadow-xs hover:shadow-lg hover:shadow-purple-500/10 hover:-translate-y-1 transition-all duration-300 ease-out"
      >
        {/* Cursor Spotlight Glow */}
        <div
          className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            background:
              "radial-gradient(380px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(147, 51, 234, 0.08), transparent 80%)",
          }}
        />
        {/* Top Animated Accent Bar */}
        <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-purple-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

        <div className="relative z-10">
          {/* Card Header & Controls Toolbar */}
          <div className="p-5 sm:p-6 border-b border-border bg-white flex flex-col xl:flex-row xl:items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2.5">
                <div className="p-2 bg-purple-50 text-purple-600 rounded-xl group-hover:scale-110 group-hover:rotate-6 transition-transform duration-300">
                  <ClipboardList className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-base sm:text-lg font-bold text-foreground flex items-center gap-2">
                    Audit Observations & Reconnaissance Evidence
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-full bg-purple-50 text-purple-700 border border-purple-200">
                      {data.audit_summary.total} total
                    </span>
                  </h2>
                  <p className="text-xs text-muted mt-0.5">
                    {data.audit_summary.open} open action items • {data.audit_summary.resolved} resolved across all target assessment stages.
                  </p>
                </div>
              </div>
            </div>

            <div className="flex flex-wrap sm:flex-nowrap items-center gap-2 shrink-0">
              {/* Search Input */}
              <div className="relative w-full sm:w-56">
                <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search observation, target..."
                  value={observationSearch}
                  onChange={(e) => setObservationSearch(e.target.value)}
                  className="w-full pl-8 pr-7 py-1.5 text-xs bg-gray-50 border border-border rounded-lg text-foreground focus:bg-white focus:outline-none focus:ring-1 focus:ring-primary transition-all"
                />
                {observationSearch && (
                  <button
                    onClick={() => setObservationSearch("")}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-foreground"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>

              {/* Severity Filter Pills */}
              <div className="flex items-center bg-gray-100 p-0.5 rounded-lg border border-gray-200 text-xs font-medium shrink-0">
                {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
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
                <option value="Resolved">Resolved</option>
              </select>

              <Link
                href="/devsecops"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-blue-700 text-white text-xs font-semibold transition-all shadow-xs shrink-0 hover:scale-105"
              >
                <span>Audit Center</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>

          {/* Observations Grid Body */}
          <div className="p-5 sm:p-6">
            {filteredObservations.length === 0 ? (
              <div className="p-8 text-center text-muted border border-dashed border-border rounded-xl bg-gray-50/50 flex flex-col items-center justify-center">
                <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2 opacity-80" />
                <p className="text-xs font-semibold text-foreground">No audit observations match this criteria.</p>
                <p className="text-[11px] text-muted mt-0.5">Try resetting the search keyword or severity filters.</p>
                {(observationSearch || severityFilter !== "ALL" || statusFilter !== "ALL") && (
                  <button
                    onClick={() => {
                      setObservationSearch("");
                      setSeverityFilter("ALL");
                      setStatusFilter("ALL");
                    }}
                    className="mt-3 text-xs text-primary font-semibold hover:underline"
                  >
                    Reset all filters
                  </button>
                )}
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {filteredObservations.map((finding) => {
                  const isResolved = finding.status.toLowerCase() === "resolved";

                  return (
                    <div
                      key={finding.id}
                      className="p-4 rounded-xl border border-border bg-white hover:border-purple-300 hover:shadow-xs hover:-translate-y-0.5 transition-all duration-200 flex flex-col justify-between"
                    >
                      <div>
                        {/* Title & Severity */}
                        <div className="flex items-start justify-between gap-2 mb-2">
                          <h4 className="text-xs sm:text-sm font-bold text-foreground leading-snug line-clamp-2">
                            {finding.title}
                          </h4>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide shrink-0 ${
                              finding.severity.toUpperCase() === "CRITICAL"
                                ? "bg-rose-100 text-rose-700 border border-rose-200"
                                : finding.severity.toUpperCase() === "HIGH"
                                ? "bg-amber-100 text-amber-700 border border-amber-200"
                                : finding.severity.toUpperCase() === "MEDIUM"
                                ? "bg-blue-100 text-blue-700 border border-blue-200"
                                : "bg-emerald-100 text-emerald-700 border border-emerald-200"
                            }`}
                          >
                            {finding.severity}
                          </span>
                        </div>

                        {/* Target Endpoint & Copy */}
                        <div className="flex items-center gap-1.5 text-xs text-muted mb-3 font-mono bg-gray-50 px-2.5 py-1.5 rounded-lg border border-gray-100">
                          <Globe className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                          <span className="truncate flex-1 text-slate-700 font-medium">{finding.target}</span>
                          <button
                            onClick={() => copyToClipboard(finding.target)}
                            className="p-1 text-slate-400 hover:text-slate-700 rounded hover:bg-gray-200/60 transition-colors"
                            title="Copy target URL"
                          >
                            {copiedTarget === finding.target ? (
                              <Check className="w-3 h-3 text-emerald-600" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </div>

                      {/* Footer Actions */}
                      <div className="pt-3 border-t border-border/60 flex items-center justify-between text-[11px]">
                        <span
                          className={`inline-flex items-center gap-1 font-semibold rounded-full px-2 py-0.5 ${
                            isResolved
                              ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                              : "bg-amber-50 text-amber-700 border border-amber-200"
                          }`}
                        >
                          {isResolved ? (
                            <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                          ) : (
                            <CircleDot className="w-3 h-3 text-amber-600" />
                          )}
                          {finding.status}
                        </span>

                        <div className="flex items-center gap-2">
                          <Link
                            href={`/assistant?q=Analyze audit observation '${finding.title}' for target ${finding.target} and generate a defensive remediation plan.`}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-semibold bg-purple-50 hover:bg-purple-600 hover:text-white text-purple-700 border border-purple-200 transition-all shadow-2xs"
                          >
                            <Sparkles className="w-3 h-3" />
                            <span>Remediate with AI</span>
                          </Link>
                          <Link
                            href="/devsecops"
                            className="p-1 text-slate-400 hover:text-primary transition-colors"
                            title="Open in DevSecOps assessment"
                          >
                            <ArrowUpRight className="w-3.5 h-3.5" />
                          </Link>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Footer Bar */}
          <div className="p-4 border-t border-border bg-gray-50/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-muted">
            <span>
              Displaying {filteredObservations.length} of {data.audit_summary.recent.length} recent audit observations
            </span>
            <Link
              href="/devsecops"
              className="text-primary font-semibold hover:underline flex items-center gap-1 self-start sm:self-auto hover:translate-x-0.5 transition-transform"
            >
              Open Full Multi-Agent DevSecOps Center <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
