"use client";

import { API_URL, apiFetch as fetch } from "@/lib/api";

import { useEffect, useState } from "react";
import { DataTable } from "@/components/ui/DataTable";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { TrafficSimulator } from "@/components/TrafficSimulator";
import { 
  ShieldAlert
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
  const [findings, setFindings] = useState<AuditFinding[]>([]);

  const fetchThreats = () => {
    fetch(`${API_URL}/api/threats`)
      .then((res) => res.json())
      .then((data) => {
        setThreats(data);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Failed to fetch threats:", error);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchThreats();
    const fetchFindings = () => {
      fetch(`${API_URL}/api/devsecops/findings`)
        .then((res) => { if (!res.ok) throw new Error("Could not load findings"); return res.json(); })
        .then((data) => setFindings(data.findings))
        .catch(console.error);
    };
    fetchFindings();
    const timer = setInterval(() => { fetchThreats(); fetchFindings(); }, 10000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-primary" /> AI Threat Detection & Intrusion Prevention
          </h1>
          <p className="text-xs text-muted mt-1">
            Recorded model classifications and audit observations; traffic simulations may be included. Automatic intrusion blocking is not configured.
          </p>
        </div>

      </div>

      <TrafficSimulator onComplete={fetchThreats} />

      <section className="bg-surface border border-red-200 rounded-xl p-5 space-y-4">
        <div>
          <h2 className="font-semibold text-red-700">Open audit observations</h2>
          <p className="text-xs text-muted mt-1">Candidate findings require validation. Resolve or review details in the DevSecOps audit page.</p>
        </div>
        {findings.filter(f => f.status === "Open").length === 0 && <p className="text-sm text-muted">No open audit observations are recorded.</p>}
        {findings.filter(f => f.status === "Open").sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4)).map(f => (
          <div key={f.id} className="border-t border-border pt-3 text-sm">
            <div className="font-semibold">{f.title} <span className="text-red-700">· {f.severity}</span></div>
            <div className="text-muted break-all">{f.target}</div>
            <div>{f.evidence}</div>
            <div className="text-muted">{f.recommendation}</div>
          </div>
        ))}
      </section>

      {/* Threat Data Table */}
      <div className="bg-surface border border-sentinel rounded-xl shadow-xs overflow-hidden">
        <div className="px-5 py-4 border-b border-border flex justify-between items-center">
          <div>
            <h3 className="text-sm font-semibold text-foreground uppercase tracking-wider">Detected Threats Stream</h3>
            <p className="text-[11px] text-muted mt-0.5">Real-time classification records from IDS engine</p>
          </div>
          <span className="text-xs font-semibold px-2.5 py-1 rounded bg-gray-100 text-gray-700 font-mono">
            {threats.length} Total Events
          </span>
        </div>
        
        {loading ? (
          <div className="p-8 text-center text-muted">Loading threats...</div>
        ) : (
          <DataTable
            data={threats}
            keyExtractor={(row) => row.id}
            columns={[
              { header: "Event ID", accessor: (row) => <span className="font-mono text-muted text-xs font-medium">{row.id}</span> },
              { header: "Attack Type", accessor: (row) => <span>{row.type} {row.simulated && <span className="text-xs text-blue-700">(Simulated)</span>}</span>, className: "font-semibold text-gray-900" },
              { 
                header: "Source IP", 
                accessor: (row) => (
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-gray-100 text-gray-800 border border-gray-200">
                    {row.source}
                  </span>
                ) 
              },
              { 
                header: "Destination", 
                accessor: (row) => (
                  <span className="font-mono text-xs text-gray-600">
                    {row.destination}
                  </span>
                ) 
              },
              { 
                header: "AI Confidence", 
                accessor: (row) => {
                  const conf = typeof row.confidence === 'number' 
                    ? (row.confidence > 1 ? row.confidence : row.confidence * 100) 
                    : NaN;
                  return (
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold">{Number.isNaN(conf) ? "Unavailable" : `${conf.toFixed(1)}%`}</span>
                      <div className="w-16 h-1.5 bg-gray-200 rounded-full overflow-hidden">
                        <div 
                          className={`h-full ${conf > 90 ? 'bg-emerald-500' : conf > 70 ? 'bg-amber-500' : 'bg-rose-500'}`}
                          style={{ width: `${(Number.isNaN(conf) ? 0 : Math.min(100, conf))}%` }}
                        />
                      </div>
                    </div>
                  );
                } 
              },
              { header: "Severity", accessor: (row) => <SeverityBadge severity={row.severity} /> },
              { header: "Logged Time", accessor: (row) => <span className="font-mono text-muted text-xs">{row.time}</span> },
            ]}
          />
        )}
      </div>
    </div>
  );
}
