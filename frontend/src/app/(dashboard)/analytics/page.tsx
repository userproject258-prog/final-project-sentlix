"use client";

import { API_URL, apiFetch as fetch } from "@/lib/api";

import { useEffect, useState } from "react";
import { BarChart2 } from "lucide-react";
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
  Cell
} from "recharts";

interface AnalyticsData {
  trend: {
    date: string;
    critical: number;
    high: number;
    medium: number;
  }[];
  severity_distribution: {
    name: string;
    value: number;
  }[];
  audit_distribution: { name: string; value: number }[];
  audit_summary: { total: number; open: number; resolved: number; recent: { id: string; target: string; title: string; severity: string; status: string; time: string }[] };
}

const COLORS = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#3b82f6'
};

export default function AnalyticsPage() {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetch(`${API_URL}/api/analytics`)
      .then((res) => { if (!res.ok) throw new Error("Could not load analytics"); return res.json(); })
      .then((json) => setData(json))
      .catch(() => setError(true));
  }, []);

  if (error) return <div className="p-8 text-center" role="alert"><p className="text-muted">Could not load analytics. Check the backend connection.</p><button className="mt-3 text-primary underline" onClick={() => window.location.reload()}>Try again</button></div>;
  if (!data) return <div className="p-8 text-center text-muted">Loading analytics data...</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <BarChart2 className="w-7 h-7 text-primary" />
        <h1 className="text-2xl font-bold text-foreground">Security Analytics</h1>
      </div>
      <p className="text-sm text-muted">Counts come from recorded threat events, including any traffic simulations run from the dashboard.</p>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend Chart */}
        <div className="col-span-1 lg:col-span-2 bg-surface border-sentinel p-5 rounded-lg shadow-sm">
          <h2 className="text-lg font-semibold mb-4 text-foreground">Threat Trend (30 Days)</h2>
          <div className="h-[400px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.trend}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
                <XAxis dataKey="date" stroke="#9ca3af" fontSize={12} tickMargin={10} minTickGap={30} />
                <YAxis stroke="#9ca3af" fontSize={12} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#ffffff', borderRadius: '8px', border: '1px solid #e5e7eb' }}
                />
                <Legend />
                <Area type="monotone" dataKey="critical" stackId="1" stroke={COLORS.Critical} fill={COLORS.Critical} fillOpacity={0.6} />
                <Area type="monotone" dataKey="high" stackId="1" stroke={COLORS.High} fill={COLORS.High} fillOpacity={0.6} />
                <Area type="monotone" dataKey="medium" stackId="1" stroke={COLORS.Medium} fill={COLORS.Medium} fillOpacity={0.6} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Distribution Chart */}
        <div className="bg-surface border-sentinel p-5 rounded-lg shadow-sm">
          <h2 className="text-lg font-semibold mb-4 text-foreground">Severity Distribution</h2>
          <div className="h-[300px] w-full">
            {data.severity_distribution.every((item) => item.value === 0) ? (
              <div className="h-full flex items-center justify-center text-sm text-muted">No threat events recorded yet.</div>
            ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data.severity_distribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {data.severity_distribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[entry.name as keyof typeof COLORS]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#ffffff', borderRadius: '8px', border: '1px solid #e5e7eb' }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
            )}
          </div>
          
          <div className="mt-6 pt-6 border-t border-border">
            <h3 className="text-sm font-semibold mb-3">Threat events</h3>
            <div className="space-y-2">
              {data.severity_distribution.map((item, i) => (
                <div key={i} className="flex justify-between items-center text-sm">
                  <span className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[item.name as keyof typeof COLORS] }}></div>
                    {item.name}
                  </span>
                  <span className="font-semibold">{item.value}</span>
                </div>
              ))}
            </div>
            <h3 className="text-sm font-semibold mt-5 mb-3">Audit observations across all runs</h3>
            <div className="space-y-2">
              {data.audit_distribution.map((item) => (
                <div key={item.name} className="flex justify-between text-sm"><span>{item.name}</span><span className="font-semibold">{item.value}</span></div>
              ))}
            </div>
          </div>
        </div>
      </div>
      <div className="bg-surface border-sentinel rounded-lg p-5 space-y-4">
        <h2 className="text-lg font-semibold">Audit observations</h2>
        <p className="text-sm text-muted">{data.audit_summary.open} open · {data.audit_summary.resolved} resolved · {data.audit_summary.total} observations across all runs. Repeat scans are counted separately; candidate findings require validation.</p>
        {data.audit_summary.recent.length === 0 && <p className="text-sm text-muted">No audit observations recorded.</p>}
        {data.audit_summary.recent.map((finding) => (
          <div key={finding.id} className="border-t border-border pt-3 text-sm">
            <p className="font-semibold">{finding.title} · {finding.severity} · {finding.status}</p>
            <p className="text-muted break-all">{finding.target} · {new Date(finding.time).toLocaleString()}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
