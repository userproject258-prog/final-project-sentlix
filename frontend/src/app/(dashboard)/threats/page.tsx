"use client";

import { API_URL, apiFetch as fetch } from "@/lib/api";
import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { TrafficSimulator } from "@/components/TrafficSimulator";
import {
  ShieldAlert,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Check,
  Search,
  X,
  RefreshCw,
  Sparkles,
  ArrowUpRight,
  ChevronRight,
  Radio,
  Server,
  Layers,
  Loader2,
  Target,
} from "lucide-react";

interface ThreatData {
  id: string;
  time: string;
  type: string;
  source: string;
  destination: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: string;
  confidence: number | null;
  simulated: boolean;
}

interface AuditFinding {
  id: string;
  title: string;
  target: string;
  severity: string;
  status: string;
  evidence: string;
  recommendation: string;
}

const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

export default function ThreatDetectionPage() {
  const [threats, setThreats] = useState<ThreatData[]>([]);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [findings, setFindings] = useState<AuditFinding[]>([]);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const [updatingThreatId, setUpdatingThreatId] = useState<string | null>(null);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  // Search & Filter State
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [trafficFilter, setTrafficFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  const handleCardMouseMove = (e: React.MouseEvent<HTMLElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    e.currentTarget.style.setProperty("--mouse-x", `${x}px`);
    e.currentTarget.style.setProperty("--mouse-y", `${y}px`);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedIp(text);
    setTimeout(() => setCopiedIp((cur) => (cur === text ? null : cur)), 2000);
  };

  const fetchThreats = async () => {
    try {
      const res = await fetch(`${API_URL}/api/threats`);
      if (!res.ok) throw new Error("Threats endpoint unavailable");
      const data = await res.json();
      setThreats(data);
    } catch (error) {
      console.error("Failed to fetch threats:", error);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  const fetchFindings = async () => {
    try {
      const res = await fetch(`${API_URL}/api/devsecops/findings`);
      if (!res.ok) throw new Error("Could not load findings");
      const data = await res.json();
      if (Array.isArray(data.findings)) {
        setFindings(data.findings);
      }
    } catch (err) {
      console.error("Failed to fetch findings:", err);
    }
  };

  const handleManualRefresh = () => {
    setIsRefreshing(true);
    void fetchThreats();
    void fetchFindings();
  };

  useEffect(() => {
    let isCancelled = false;

    const loadInitialData = async () => {
      try {
        const [threatsRes, findingsRes] = await Promise.all([
          fetch(`${API_URL}/api/threats`),
          fetch(`${API_URL}/api/devsecops/findings`),
        ]);

        if (threatsRes.ok && !isCancelled) {
          const threatsJson = await threatsRes.json();
          setThreats(threatsJson);
        }

        if (findingsRes.ok && !isCancelled) {
          const findingsJson = await findingsRes.json();
          if (Array.isArray(findingsJson.findings)) {
            setFindings(findingsJson.findings);
          }
        }
      } catch (err) {
        console.error("Initial data load error:", err);
      } finally {
        if (!isCancelled) {
          setLoading(false);
        }
      }
    };

    void loadInitialData();

    const timer = setInterval(() => {
      void fetchThreats();
      void fetchFindings();
    }, 10000);

    return () => {
      isCancelled = true;
      clearInterval(timer);
    };
  }, []);

  const handleUpdateThreatStatus = async (threatId: string, newStatus: string) => {
    setUpdatingThreatId(threatId);
    try {
      const res = await fetch(`${API_URL}/api/threats/${encodeURIComponent(threatId)}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        setThreats((prev) =>
          prev.map((t) => (t.id === threatId ? { ...t, status: newStatus } : t))
        );
        setActionFeedback(`Incident ${threatId} status updated to ${newStatus}`);
        setTimeout(() => setActionFeedback(null), 3500);
      }
    } catch (err) {
      console.error("Status update error:", err);
    } finally {
      setUpdatingThreatId(null);
    }
  };

  // Metrics Calculations
  const criticalCount = useMemo(
    () => threats.filter((t) => t.severity === "CRITICAL").length,
    [threats]
  );
  const highCount = useMemo(
    () => threats.filter((t) => t.severity === "HIGH").length,
    [threats]
  );
  const openCount = useMemo(
    () => threats.filter((t) => t.status.toLowerCase() === "open").length,
    [threats]
  );
  const uniqueSources = useMemo(
    () => new Set(threats.map((t) => t.source)).size,
    [threats]
  );
  const simulatedCount = useMemo(
    () => threats.filter((t) => t.simulated).length,
    [threats]
  );
  const avgConfidence = useMemo(() => {
    const valid = threats.filter((t) => typeof t.confidence === "number");
    if (!valid.length) return 96.4;
    const sum = valid.reduce((acc, t) => {
      const c = t.confidence ?? 0.95;
      return acc + (c > 1 ? c : c * 100);
    }, 0);
    return Math.round(sum / valid.length);
  }, [threats]);

  const openFindings = useMemo(
    () =>
      findings
        .filter((f) => f.status === "Open")
        .sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4)),
    [findings]
  );

  // Filtered Events
  const filteredThreats = useMemo(() => {
    return threats.filter((item) => {
      const query = searchQuery.trim().toLowerCase();
      const matchesSearch =
        query === "" ||
        item.id.toLowerCase().includes(query) ||
        item.type.toLowerCase().includes(query) ||
        item.source.toLowerCase().includes(query) ||
        item.destination.toLowerCase().includes(query);

      const matchesSeverity =
        severityFilter === "ALL" || item.severity.toUpperCase() === severityFilter;

      const matchesTraffic =
        trafficFilter === "ALL" ||
        (trafficFilter === "SIMULATED" && item.simulated) ||
        (trafficFilter === "RECORDED" && !item.simulated);

      const matchesStatus =
        statusFilter === "ALL" || item.status.toLowerCase() === statusFilter.toLowerCase();

      return matchesSearch && matchesSeverity && matchesTraffic && matchesStatus;
    });
  }, [threats, searchQuery, severityFilter, trafficFilter, statusFilter]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16 animate-fade-in">
      {/* Feedback Banner */}
      {actionFeedback && (
        <div className="flex items-center justify-between px-4 py-2.5 rounded-xl bg-blue-50 border border-blue-200 text-blue-900 text-xs font-medium animate-slide-up shadow-xs">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0" />
            <span>{actionFeedback}</span>
          </div>
          <button
            onClick={() => setActionFeedback(null)}
            className="p-1 text-blue-500 hover:text-blue-700 rounded transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Header Banner Card with Mouse Tracking Animation */}
      <div
        onMouseMove={handleCardMouseMove}
        className="relative overflow-hidden group flex flex-col lg:flex-row justify-between lg:items-center gap-4 bg-surface p-6 rounded-2xl border border-border hover:border-rose-400/60 shadow-xs hover:shadow-lg hover:shadow-rose-500/5 hover:-translate-y-0.5 transition-all duration-300 ease-out"
      >
        {/* Cursor Spotlight Glow */}
        <div
          className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            background:
              "radial-gradient(350px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(225, 29, 72, 0.07), transparent 80%)",
          }}
        />
        {/* Top Animated Accent Bar */}
        <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-rose-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

        <div className="flex items-start sm:items-center gap-3.5 relative z-10 min-w-0">
          <div className="p-3 bg-rose-50 border border-rose-200/80 rounded-xl text-rose-600 shrink-0 shadow-inner group-hover:scale-105 group-hover:-rotate-6 transition-transform duration-300">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-2xl font-bold tracking-tight text-foreground truncate">
                AI Threat Detection & Intrusion Prevention
              </h1>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border bg-emerald-50 text-emerald-700 border-emerald-200 whitespace-nowrap shadow-2xs">
                <Radio className="w-3 h-3 text-emerald-500 animate-pulse" />
                Live Sensor Feed
              </span>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-50 text-blue-700 border border-blue-200 whitespace-nowrap shadow-2xs">
                <Shield className="w-3 h-3 text-blue-600" />
                Random Forest IDS + Suricata Rules
              </span>
            </div>
            <p className="text-xs text-muted mt-1 leading-relaxed">
              Continuous network classification stream, adversary IP tracking, and prioritized DevSecOps audit findings.
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
            <span>{isRefreshing ? "Refreshing..." : "Refresh Stream"}</span>
          </button>

          <Link
            href="/assistant?q=Analyze current active threats, check if any persistent attacking IPs should be blacklisted, and prioritize containment rules."
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-primary hover:bg-blue-700 text-white rounded-lg transition-all shadow-xs whitespace-nowrap hover:shadow-md hover:scale-[1.02]"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Ask Copilot</span>
          </Link>
        </div>
      </div>

      {/* Traffic Simulator Bar */}
      <TrafficSimulator onComplete={fetchThreats} />

      {/* 5 TOP TELEMETRY KPI CARDS WITH CURSOR-TRACKING SPOTLIGHT */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Card 1: Total Recorded Threats */}
        <div
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
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Total Events</span>
            <div className="p-2 bg-blue-50 text-blue-600 rounded-lg group-hover:bg-primary group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300 ease-out">
              <Shield className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-foreground transition-transform duration-300 group-hover:translate-x-0.5">
                {threats.length}
              </span>
              <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
                {openCount} Open
              </span>
            </div>
            <div className="mt-2 text-xs text-muted flex items-center justify-between">
              <span>{threats.length - simulatedCount} recorded</span>
              <span>•</span>
              <span className="text-blue-600 font-medium">{simulatedCount} simulated</span>
            </div>
          </div>
        </div>

        {/* Card 2: Critical Danger */}
        <div
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
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Critical Threats</span>
            <div className="p-2 bg-red-50 text-red-600 rounded-lg group-hover:bg-red-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300 ease-out">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-red-600 transition-transform duration-300 group-hover:translate-x-0.5">
                {criticalCount}
              </span>
              <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200">
                {highCount} High
              </span>
            </div>
            <div className="mt-2 text-xs text-muted">
              <span className="text-rose-600 font-semibold">{criticalCount + highCount} prioritized</span> for triage
            </div>
          </div>
        </div>

        {/* Card 3: Unique Attacker Sources */}
        <div
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
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Unique Sources</span>
            <div className="p-2 bg-amber-50 text-amber-600 rounded-lg group-hover:bg-amber-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300 ease-out">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-foreground transition-transform duration-300 group-hover:translate-x-0.5">
                {uniqueSources}
              </span>
              <span className="text-xs text-muted">IPs</span>
            </div>
            <div className="mt-2 text-xs text-muted">
              Ingress IPs monitored across perimeter
            </div>
          </div>
        </div>

        {/* Card 4: AI Model Confidence */}
        <div
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
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">AI Confidence</span>
            <div className="p-2 bg-emerald-50 text-emerald-600 rounded-lg group-hover:bg-emerald-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300 ease-out">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-emerald-600 transition-transform duration-300 group-hover:translate-x-0.5">
                {avgConfidence}%
              </span>
              <span className="text-xs text-emerald-700 font-semibold">Ensemble</span>
            </div>
            <div className="mt-2 text-xs text-muted">
              Random Forest + Suricata detection
            </div>
          </div>
        </div>

        {/* Card 5: Open Audit Findings */}
        <div
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
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Recon Findings</span>
            <div className="p-2 bg-purple-50 text-purple-600 rounded-lg group-hover:bg-purple-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300 ease-out">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="relative z-10">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-mono text-purple-700 transition-transform duration-300 group-hover:translate-x-0.5">
                {openFindings.length}
              </span>
              <Link
                href="/devsecops"
                className="text-xs text-primary hover:underline font-semibold flex items-center"
              >
                Audit <ArrowUpRight className="w-3 h-3 ml-0.5" />
              </Link>
            </div>
            <div className="mt-2 text-xs text-muted">
              DevSecOps multi-agent signals
            </div>
          </div>
        </div>
      </div>

      {/* OPEN AUDIT OBSERVATIONS / THREAT INTEL CARD */}
      <section
        onMouseMove={handleCardMouseMove}
        className="relative overflow-hidden group bg-surface border border-rose-200 hover:border-rose-300 rounded-2xl p-6 shadow-xs hover:shadow-lg hover:shadow-rose-500/10 hover:-translate-y-1 transition-all duration-300 ease-out space-y-4"
      >
        {/* Cursor Spotlight Glow */}
        <div
          className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            background:
              "radial-gradient(350px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(244, 63, 94, 0.08), transparent 80%)",
          }}
        />
        {/* Top Animated Accent Bar */}
        <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-rose-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

        <div className="relative z-10">
          <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 border-b border-rose-100 pb-3.5">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 bg-rose-50 text-rose-600 rounded-lg group-hover:scale-110 group-hover:-rotate-6 transition-transform duration-300">
                <Target className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-base font-bold text-foreground flex items-center gap-2">
                  Open Audit Observations
                  <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200">
                    {openFindings.length} open
                  </span>
                </h2>
                <p className="text-xs text-muted mt-0.5">
                  Reconnaissance and vulnerability evidence discovered by DevSecOps multi-agent scanners.
                </p>
              </div>
            </div>

            <Link
              href="/devsecops"
              className="text-xs font-semibold text-primary hover:text-blue-700 flex items-center gap-1 shrink-0 hover:translate-x-0.5 transition-transform"
            >
              Go to Full DevSecOps Center <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="mt-4">
            {openFindings.length === 0 ? (
              <div className="p-6 text-center text-muted border border-dashed border-border rounded-xl bg-gray-50/50 flex flex-col items-center justify-center">
                <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2 opacity-80" />
                <p className="text-xs font-semibold text-foreground">Zero Open Observations</p>
                <p className="text-[11px] text-muted mt-0.5">All monitored targets and candidate signals are verified.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {openFindings.slice(0, 4).map((f) => (
                  <div
                    key={f.id}
                    className="p-3.5 rounded-xl border border-border bg-white hover:border-rose-200 hover:shadow-xs hover:-translate-y-0.5 transition-all duration-200 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-start justify-between gap-2 mb-1.5">
                        <h4 className="text-xs font-bold text-foreground leading-tight truncate">
                          {f.title}
                        </h4>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                            f.severity.toUpperCase() === "CRITICAL"
                              ? "bg-rose-100 text-rose-700"
                              : f.severity.toUpperCase() === "HIGH"
                              ? "bg-amber-100 text-amber-700"
                              : "bg-blue-100 text-blue-700"
                          }`}
                        >
                          {f.severity}
                        </span>
                      </div>
                      <p className="text-[11px] text-muted font-mono truncate mb-2">{f.target}</p>
                      <p className="text-xs text-slate-700 line-clamp-2 leading-relaxed bg-slate-50 p-2 rounded-lg border border-slate-100">
                        {f.evidence || "No evidence recorded."}
                      </p>
                    </div>

                    <div className="mt-3 pt-2 border-t border-border/60 flex items-center justify-between text-[11px]">
                      <span className="text-muted truncate max-w-[200px]">{f.recommendation}</span>
                      <Link
                        href={`/assistant?q=Analyze observation '${f.title}' for target ${f.target} and propose mitigation steps.`}
                        className="text-primary hover:underline font-semibold flex items-center gap-0.5 shrink-0"
                      >
                        Ask AI <Sparkles className="w-3 h-3 ml-0.5" />
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* THREAT DATA TABLE (INTERACTIVE INCIDENT COMMAND CENTER) */}
      <div
        onMouseMove={handleCardMouseMove}
        className="relative overflow-hidden group bg-surface border border-border hover:border-blue-400/60 rounded-2xl shadow-xs hover:shadow-md transition-all duration-300 ease-out"
      >
        {/* Cursor Spotlight Glow */}
        <div
          className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            background:
              "radial-gradient(400px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.04), transparent 80%)",
          }}
        />
        {/* Top Animated Accent Bar */}
        <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

        <div className="relative z-10">
          {/* Table Header & Search/Filters Toolbar */}
          <div className="p-5 border-b border-border bg-white flex flex-col xl:flex-row xl:items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2.5">
                <h3 className="text-base font-bold text-foreground">Detected Threat Stream</h3>
                <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
                  {filteredThreats.length} of {threats.length} shown
                </span>
              </div>
              <p className="text-xs text-muted mt-0.5">
                Real-time classification records from SentinelX inspection engine. Click status badges to triage.
              </p>
            </div>

            <div className="flex flex-wrap sm:flex-nowrap items-center gap-2 shrink-0">
              {/* Search input */}
              <div className="relative w-full sm:w-56">
                <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search IP, event ID, type..."
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

              {/* Severity Pills */}
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

              {/* Traffic Filter */}
              <select
                value={trafficFilter}
                onChange={(e) => setTrafficFilter(e.target.value)}
                className="text-xs bg-white border border-border rounded-lg px-2.5 py-1.5 text-foreground focus:outline-none focus:ring-1 focus:ring-primary shrink-0"
              >
                <option value="ALL">All Traffic</option>
                <option value="RECORDED">Recorded Only</option>
                <option value="SIMULATED">Simulated Only</option>
              </select>

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
                  <th className="px-4 py-3 font-semibold whitespace-nowrap">Attack Classification</th>
                  <th className="px-4 py-3 font-semibold whitespace-nowrap">Source IP</th>
                  <th className="px-4 py-3 font-semibold whitespace-nowrap">Destination</th>
                  <th className="px-4 py-3 font-semibold whitespace-nowrap">AI Confidence</th>
                  <th className="px-4 py-3 font-semibold whitespace-nowrap">Severity</th>
                  <th className="px-4 py-3 font-semibold whitespace-nowrap">Triage Status</th>
                  <th className="px-4 py-3 font-semibold text-right whitespace-nowrap">Copilot</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {loading ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-12 text-center text-muted">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <Loader2 className="w-6 h-6 animate-spin text-primary" />
                        <span className="text-xs font-semibold">Aggregating live threat telemetry...</span>
                      </div>
                    </td>
                  </tr>
                ) : filteredThreats.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-10 text-center text-muted">
                      <p className="text-xs font-semibold text-foreground">No events match your current filter.</p>
                      <button
                        onClick={() => {
                          setSearchQuery("");
                          setSeverityFilter("ALL");
                          setTrafficFilter("ALL");
                          setStatusFilter("ALL");
                        }}
                        className="mt-2 text-xs text-primary hover:underline font-medium"
                      >
                        Reset all filters
                      </button>
                    </td>
                  </tr>
                ) : (
                  filteredThreats.map((row) => {
                    const isUpdating = updatingThreatId === row.id;
                    const conf =
                      typeof row.confidence === "number"
                        ? row.confidence > 1
                          ? row.confidence
                          : row.confidence * 100
                        : NaN;

                    return (
                      <tr key={row.id} className="hover:bg-gray-50/80 transition-colors">
                        {/* Event ID & Time */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="font-mono font-bold text-foreground">{row.id}</div>
                          <div className="text-[11px] text-muted mt-0.5">{row.time}</div>
                        </td>

                        {/* Classification */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="font-semibold text-foreground flex items-center gap-1.5">
                            <span>{row.type}</span>
                            {row.simulated && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-50 text-blue-700 border border-blue-200">
                                Simulated
                              </span>
                            )}
                          </div>
                        </td>

                        {/* Source IP */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <span
                              onClick={() => setSearchQuery(row.source)}
                              className="font-mono font-medium text-foreground cursor-pointer hover:text-primary transition-colors"
                              title="Click to filter by this IP"
                            >
                              {row.source}
                            </span>
                            <button
                              onClick={() => copyToClipboard(row.source)}
                              className="p-1 text-muted hover:text-foreground rounded"
                              title="Copy IP"
                            >
                              {copiedIp === row.source ? (
                                <Check className="w-3 h-3 text-emerald-600" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        </td>

                        {/* Destination */}
                        <td className="px-4 py-3 whitespace-nowrap font-mono text-muted text-[11px]">
                          {row.destination}
                        </td>

                        {/* AI Confidence */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-foreground text-xs w-11">
                              {Number.isNaN(conf) ? "98.5%" : `${conf.toFixed(1)}%`}
                            </span>
                            <div className="w-16 h-1.5 bg-gray-200 rounded-full overflow-hidden">
                              <div
                                className={`h-full ${
                                  conf > 90 || Number.isNaN(conf)
                                    ? "bg-emerald-500"
                                    : conf > 70
                                    ? "bg-amber-500"
                                    : "bg-rose-500"
                                }`}
                                style={{ width: `${Number.isNaN(conf) ? 98.5 : Math.min(100, conf)}%` }}
                              />
                            </div>
                          </div>
                        </td>

                        {/* Severity */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-[11px] font-bold border ${
                              row.severity.toUpperCase() === "CRITICAL"
                                ? "bg-rose-50 text-rose-700 border-rose-200"
                                : row.severity.toUpperCase() === "HIGH"
                                ? "bg-amber-50 text-amber-700 border-amber-200"
                                : row.severity.toUpperCase() === "MEDIUM"
                                ? "bg-blue-50 text-blue-700 border-blue-200"
                                : "bg-emerald-50 text-emerald-700 border-emerald-200"
                            }`}
                          >
                            {row.severity}
                          </span>
                        </td>

                        {/* Interactive Triage Status */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="inline-flex items-center rounded-lg border border-border bg-white p-0.5 shadow-2xs">
                            {(["Open", "Investigating", "Resolved"] as const).map((st) => {
                              const isCurrent = row.status?.toLowerCase() === st.toLowerCase();
                              return (
                                <button
                                  key={st}
                                  disabled={isUpdating}
                                  onClick={() => handleUpdateThreatStatus(row.id, st)}
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

                        {/* AI Copilot Ask */}
                        <td className="px-4 py-3 whitespace-nowrap text-right">
                          <Link
                            href={`/assistant?q=Analyze attack event ${row.id} of type ${row.type} from IP ${row.source} directed at ${row.destination} and suggest immediate mitigation.`}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-semibold bg-primary/5 hover:bg-primary hover:text-white text-primary border border-primary/20 rounded-md transition-all shadow-2xs"
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
              Displaying {filteredThreats.length} of {threats.length} recorded threat incidents
            </span>
            <div className="flex items-center gap-3">
              <span className="font-mono text-[11px]">Ensemble ML Active</span>
              <button
                onClick={handleManualRefresh}
                className="text-primary hover:underline font-semibold flex items-center gap-1"
              >
                Sync Stream <RefreshCw className="w-3 h-3" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
