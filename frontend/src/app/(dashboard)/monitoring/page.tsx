"use client";

import { API_URL, apiFetch as fetch } from "@/lib/api";

import { useEffect, useState } from "react";
import { Activity, Cpu, HardDrive, Network, Server, Zap } from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

interface SystemMetric {
  time: string;
  cpu_usage: number;
  memory_usage: number;
  network_rx: number;
  network_tx: number;
  api_latency: number;
}

interface SystemHealth {
  uptime: string;
  active_containers: number;
  error_rate: string;
  status: string;
}

export default function MonitoringPage() {
  const [metrics, setMetrics] = useState<SystemMetric[]>([]);
  const [health, setHealth] = useState<SystemHealth | null>(null);

  useEffect(() => {
    const fetchData = () => {
      fetch(`${API_URL}/api/monitoring/metrics`)
        .then((res) => res.json())
        .then((data) => {
          // Format time for chart display
          const formatted = data.metrics.map((m: SystemMetric) => ({
            ...m,
            timeLabel: new Date(m.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          }));
          setMetrics(formatted);
        })
        .catch(console.error);

      fetch(`${API_URL}/api/monitoring/health`)
        .then((res) => res.json())
        .then((data) => setHealth(data))
        .catch(console.error);
    };

    fetchData();
    const interval = setInterval(fetchData, 5000); // Poll every 5s for the live effect
    return () => clearInterval(interval);
  }, []);

  const handleCardMouseMove = (e: React.MouseEvent<HTMLElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    e.currentTarget.style.setProperty("--mouse-x", `${e.clientX - rect.left}px`);
    e.currentTarget.style.setProperty("--mouse-y", `${e.clientY - rect.top}px`);
  };

  if (!metrics.length || !health) {
    return (
      <div className="max-w-7xl mx-auto p-12 text-center text-muted flex flex-col items-center gap-3">
        <Activity className="w-6 h-6 animate-pulse text-primary" />
        <span className="text-sm font-medium">Loading monitoring telemetry...</span>
      </div>
    );
  }

  const latest = metrics[metrics.length - 1];

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16 animate-fade-in">
      {/* Header Banner Card with Cursor-Tracking Spotlight */}
      <div
        onMouseMove={handleCardMouseMove}
        className="relative overflow-hidden group flex flex-col sm:flex-row justify-between sm:items-center gap-4 bg-surface border border-border hover:border-emerald-400/60 p-6 rounded-2xl shadow-xs hover:shadow-lg hover:shadow-emerald-500/5 hover:-translate-y-0.5 transition-all duration-300 ease-out"
      >
        <div
          className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            background:
              "radial-gradient(350px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(16, 185, 129, 0.08), transparent 80%)",
          }}
        />
        <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-emerald-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

        <div className="flex items-start sm:items-center gap-3.5 relative z-10 min-w-0">
          <div className="p-3 bg-emerald-50 border border-emerald-200/80 rounded-xl text-emerald-600 shrink-0 shadow-inner group-hover:scale-105 group-hover:-rotate-6 transition-transform duration-300">
            <Activity className="w-6 h-6" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-2xl font-bold tracking-tight text-foreground">
                Infrastructure Monitoring
              </h1>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border bg-emerald-50 text-emerald-700 border-emerald-200 whitespace-nowrap shadow-2xs">
                <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
                Live · 5s Stream
              </span>
            </div>
            <p className="text-xs text-muted mt-1 leading-relaxed">
              Real-time compute, memory, network throughput, and API gateway latency telemetry.
            </p>
          </div>
        </div>
      </div>

      {/* Top Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="System Status"
          value={health.status}
          icon={<Server className="w-4 h-4" />}
          subtitle={`Uptime: ${health.uptime}`}
          accent="emerald"
          onMouseMove={handleCardMouseMove}
        />
        <StatCard
          title="API Latency"
          value={`${latest.api_latency}ms`}
          icon={<Zap className="w-4 h-4" />}
          subtitle="Avg Response Time"
          accent="amber"
          onMouseMove={handleCardMouseMove}
        />
        <StatCard
          title="Active Containers"
          value={health.active_containers.toString()}
          icon={<HardDrive className="w-4 h-4" />}
          subtitle="Docker Services"
          accent="blue"
          onMouseMove={handleCardMouseMove}
        />
        <StatCard
          title="Error Rate"
          value={health.error_rate}
          icon={<Activity className="w-4 h-4" />}
          subtitle="Last 5 minutes"
          accent="rose"
          onMouseMove={handleCardMouseMove}
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* CPU & Memory */}
        <div
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-blue-400/80 p-5 sm:p-6 rounded-2xl shadow-xs hover:shadow-lg hover:shadow-blue-500/10 hover:-translate-y-1 transition-all duration-300 ease-out"
        >
          <div
            className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(350px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(14, 165, 233, 0.08), transparent 80%)",
            }}
          />
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-sky-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="relative z-10">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
              <h2 className="text-base font-bold text-foreground flex items-center gap-2">
                <span className="p-1.5 rounded-lg bg-sky-50 text-sky-600 border border-sky-200/80 group-hover:scale-110 group-hover:rotate-6 transition-transform duration-300">
                  <Cpu className="w-4 h-4" />
                </span>
                Resource Usage
              </h2>
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="px-2 py-0.5 rounded bg-sky-50 text-sky-700 border border-sky-200">
                  CPU {latest.cpu_usage}%
                </span>
                <span className="px-2 py-0.5 rounded bg-violet-50 text-violet-700 border border-violet-200">
                  MEM {latest.memory_usage}%
                </span>
              </div>
            </div>
            <div className="h-[300px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={metrics}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
                  <XAxis dataKey="timeLabel" stroke="#9ca3af" fontSize={12} tickMargin={10} minTickGap={30} />
                  <YAxis stroke="#9ca3af" fontSize={12} domain={[0, 100]} tickFormatter={(val) => `${val}%`} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderRadius: '8px', border: '1px solid #e5e7eb' }}
                    itemStyle={{ fontSize: '14px' }}
                  />
                  <Legend />
                  <Line type="monotone" name="CPU Usage (%)" dataKey="cpu_usage" stroke="#0ea5e9" strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                  <Line type="monotone" name="Memory Usage (%)" dataKey="memory_usage" stroke="#8b5cf6" strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Network */}
        <div
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-surface border border-border hover:border-emerald-400/80 p-5 sm:p-6 rounded-2xl shadow-xs hover:shadow-lg hover:shadow-emerald-500/10 hover:-translate-y-1 transition-all duration-300 ease-out"
        >
          <div
            className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(350px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(16, 185, 129, 0.08), transparent 80%)",
            }}
          />
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-emerald-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

          <div className="relative z-10">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
              <h2 className="text-base font-bold text-foreground flex items-center gap-2">
                <span className="p-1.5 rounded-lg bg-emerald-50 text-emerald-600 border border-emerald-200/80 group-hover:scale-110 group-hover:-rotate-6 transition-transform duration-300">
                  <Network className="w-4 h-4" />
                </span>
                Network Traffic
              </h2>
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                  RX {latest.network_rx} MB/s
                </span>
                <span className="px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200">
                  TX {latest.network_tx} MB/s
                </span>
              </div>
            </div>
            <div className="h-[300px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={metrics}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
                  <XAxis dataKey="timeLabel" stroke="#9ca3af" fontSize={12} tickMargin={10} minTickGap={30} />
                  <YAxis stroke="#9ca3af" fontSize={12} tickFormatter={(val) => `${val} MB/s`} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderRadius: '8px', border: '1px solid #e5e7eb' }}
                    itemStyle={{ fontSize: '14px' }}
                  />
                  <Legend />
                  <Line type="monotone" name="Network RX (MB/s)" dataKey="network_rx" stroke="#10b981" strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                  <Line type="monotone" name="Network TX (MB/s)" dataKey="network_tx" stroke="#f59e0b" strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

const ACCENT_MAP = {
  emerald: {
    borderHover: "hover:border-emerald-400/80 hover:shadow-emerald-500/10",
    glow: "rgba(16, 185, 129, 0.09)",
    bar: "via-emerald-500",
    iconBg: "bg-emerald-50 text-emerald-600 group-hover:bg-emerald-600 group-hover:text-white",
  },
  amber: {
    borderHover: "hover:border-amber-400/80 hover:shadow-amber-500/10",
    glow: "rgba(245, 158, 11, 0.09)",
    bar: "via-amber-500",
    iconBg: "bg-amber-50 text-amber-600 group-hover:bg-amber-600 group-hover:text-white",
  },
  blue: {
    borderHover: "hover:border-blue-400/80 hover:shadow-blue-500/10",
    glow: "rgba(37, 99, 235, 0.09)",
    bar: "via-blue-500",
    iconBg: "bg-blue-50 text-blue-600 group-hover:bg-blue-600 group-hover:text-white",
  },
  rose: {
    borderHover: "hover:border-rose-400/80 hover:shadow-rose-500/10",
    glow: "rgba(244, 63, 94, 0.09)",
    bar: "via-rose-500",
    iconBg: "bg-rose-50 text-rose-600 group-hover:bg-rose-600 group-hover:text-white",
  },
};

function StatCard({
  title,
  value,
  icon,
  subtitle,
  accent,
  onMouseMove,
}: {
  title: string;
  value: string;
  icon: React.ReactNode;
  subtitle: string;
  accent: keyof typeof ACCENT_MAP;
  onMouseMove: (e: React.MouseEvent<HTMLElement>) => void;
}) {
  const style = ACCENT_MAP[accent];
  return (
    <div
      onMouseMove={onMouseMove}
      className={`relative overflow-hidden group bg-surface border border-border ${style.borderHover} p-5 rounded-xl shadow-xs hover:shadow-lg hover:-translate-y-1.5 transition-all duration-300 ease-out flex items-start justify-between`}
    >
      <div
        className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{
          background: `radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), ${style.glow}, transparent 80%)`,
        }}
      />
      <div className={`absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent ${style.bar} to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center`} />

      <div className="relative z-10">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-muted mb-2">{title}</h3>
        <p className="text-2xl font-bold font-mono text-foreground group-hover:translate-x-0.5 transition-transform duration-300">
          {value}
        </p>
        <p className="text-xs text-muted mt-1.5">{subtitle}</p>
      </div>
      <div className={`relative z-10 p-2 rounded-lg transition-all duration-300 ease-out group-hover:scale-110 group-hover:-rotate-6 ${style.iconBg}`}>
        {icon}
      </div>
    </div>
  );
}
