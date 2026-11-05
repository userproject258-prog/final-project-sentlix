"use client";

import { useState } from "react";
import { AlertCircle, CheckCircle2, ChevronDown, CircleDot, ClipboardList, FileSearch, Globe, Search, ShieldCheck } from "lucide-react";

export interface AuditFinding {
  id: string;
  run_id: string;
  time: string;
  target: string;
  title: string;
  severity: string;
  evidence: string;
  recommendation: string;
  status: string;
}

const severityStyles: Record<string, string> = {
  CRITICAL: "border-rose-200 bg-rose-50 text-rose-700",
  HIGH: "border-orange-200 bg-orange-50 text-orange-700",
  MEDIUM: "border-amber-200 bg-amber-50 text-amber-700",
  LOW: "border-blue-200 bg-blue-50 text-blue-700",
};

function formatTime(value: string) {
  if (!value) return "Time unavailable";
  // SQLite may return UTC timestamps without a timezone suffix.
  const timestamp = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value) ? value : `${value}Z`;
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "Time unavailable" : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function filterAuditFindings(findings: AuditFinding[], search: string, status: string, severity: string) {
  const query = search.trim().toLowerCase();
  return findings.filter((finding) =>
    (status === "All" || finding.status === status) &&
    (severity === "All" || finding.severity.toUpperCase() === severity) &&
    [finding.title, finding.target, finding.evidence, finding.recommendation, finding.run_id].some((value) => (value || "").toLowerCase().includes(query))
  );
}

export function AuditObservations({ findings, loading, loadError, onRetry, onResolve }: {
  findings: AuditFinding[];
  loading: boolean;
  loadError: boolean;
  onRetry: () => void;
  onResolve: (finding: AuditFinding) => Promise<number>;
}) {
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("All");
  const [severity, setSeverity] = useState("All");
  const [resolving, setResolving] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string; findingId: string } | null>(null);

  const openCount = findings.filter((finding) => finding.status === "Open").length;
  const resolvedCount = findings.filter((finding) => finding.status === "Resolved").length;
  const filtered = filterAuditFindings(findings, search, status, severity);

  async function handleResolve(finding: AuditFinding) {
    setResolving(finding.id);
    setMessage(null);
    try {
      const count = await onResolve(finding);
      setMessage({ type: "success", text: `${count} matching ${count === 1 ? "observation" : "observations"} marked resolved for this target.`, findingId: finding.id });
    } catch {
      setMessage({ type: "error", text: "Could not resolve this observation. Please try again.", findingId: finding.id });
    } finally {
      setResolving(null);
    }
  }

  return (
    <details className="group overflow-hidden rounded-xl border border-border bg-surface shadow-xs">
      <summary className="flex cursor-pointer list-none flex-wrap items-center gap-3 p-5 marker:content-none sm:p-6 [&::-webkit-details-marker]:hidden">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-blue-100 bg-blue-50 text-primary"><ClipboardList className="h-5 w-5" /></span>
        <span className="min-w-0 flex-1">
          <span className="block text-base font-bold text-foreground">Recorded audit observations</span>
          <span className="mt-1 block text-xs text-muted">Review evidence and track remediation across audit runs</span>
        </span>
        {!loading && !(loadError && findings.length === 0) && <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-semibold text-slate-600">{findings.length} recorded</span>}
        <ChevronDown className="h-4 w-4 shrink-0 text-muted transition-transform group-open:rotate-180" />
      </summary>

      <div className="space-y-5 border-t border-border p-5 sm:p-6">
        <p className="text-xs leading-relaxed text-muted">Showing up to the 100 most recent observations across all runs. Input-test signals are candidates and require manual validation.</p>

        {loadError && <div role="alert" className="flex flex-wrap items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2.5 text-xs text-amber-900"><AlertCircle className="h-4 w-4 shrink-0" /> Could not refresh observations. {findings.length > 0 && "The list may be out of date."} <button type="button" onClick={onRetry} className="font-semibold underline">Retry</button></div>}
        {message && <div role={message.type === "error" ? "alert" : "status"} className={`flex items-start gap-2 rounded-lg border px-3 py-2.5 text-xs ${message.type === "error" ? "border-rose-200 bg-rose-50 text-rose-800" : "border-emerald-200 bg-emerald-50 text-emerald-800"}`}>{message.type === "error" ? <AlertCircle className="h-4 w-4 shrink-0" /> : <CheckCircle2 className="h-4 w-4 shrink-0" />}{message.text}</div>}

        <div className="grid grid-cols-3 gap-2 sm:gap-3">
          {[
            { label: "Recorded", value: findings.length, color: "text-slate-900", icon: <FileSearch className="h-4 w-4 text-slate-500" /> },
            { label: "Open", value: openCount, color: "text-amber-700", icon: <CircleDot className="h-4 w-4 text-amber-600" /> },
            { label: "Resolved", value: resolvedCount, color: "text-emerald-700", icon: <CheckCircle2 className="h-4 w-4 text-emerald-600" /> },
          ].map((item) => (
            <div key={item.label} className="rounded-xl border border-slate-200 bg-slate-50/70 p-3 sm:p-4">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">{item.icon}<span>{item.label}</span></div>
              <div className={`mt-1.5 text-xl font-bold ${item.color}`}>{loading || (loadError && findings.length === 0) ? "—" : item.value}</div>
            </div>
          ))}
        </div>

        <div className="flex flex-col gap-2 sm:flex-row">
          <label className="relative flex-1">
            <span className="sr-only">Search observations</span>
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search findings, targets or evidence" className="w-full rounded-lg border border-slate-300 bg-white py-2 pl-9 pr-3 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
          </label>
          <label><span className="sr-only">Filter by status</span><select value={status} onChange={(event) => setStatus(event.target.value)} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"><option value="All">All statuses</option><option value="Open">Open</option><option value="Resolved">Resolved</option></select></label>
          <label><span className="sr-only">Filter by severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"><option value="All">All severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select></label>
        </div>

        {loading ? <p className="py-6 text-center text-sm text-muted">Loading observations...</p> : loadError && findings.length === 0 ? null : findings.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50/50 px-4 py-8 text-center"><ShieldCheck className="mx-auto h-6 w-6 text-slate-400" /><p className="mt-2 text-sm font-semibold text-slate-700">No observations recorded yet</p><p className="mt-1 text-xs text-muted">Observations from supported audit stages will appear here.</p></div>
        ) : filtered.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-200 px-4 py-8 text-center"><p className="text-sm font-semibold text-slate-700">No observations match your filters</p><button type="button" onClick={() => { setSearch(""); setStatus("All"); setSeverity("All"); }} className="mt-2 text-xs font-semibold text-primary hover:underline">Clear filters</button></div>
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-muted">Showing {filtered.length} of {findings.length} recorded observations</p>
            {filtered.map((finding) => {
              const resolved = finding.status === "Resolved";
              return (
                <article key={finding.id} className="overflow-hidden rounded-xl border border-slate-200 bg-white">
                  <div className="p-4 sm:p-5">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0 flex-1"><h3 className="break-words text-sm font-bold leading-5 text-slate-900">{finding.title}</h3><div className="mt-2 flex items-start gap-1.5 text-xs text-muted"><Globe className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" /><span className="break-all">{finding.target}</span></div></div>
                      <div className="flex flex-wrap gap-1.5"><span className={`rounded-full border px-2.5 py-1 text-[11px] font-bold ${severityStyles[finding.severity.toUpperCase()] || "border-slate-200 bg-slate-50 text-slate-700"}`}>{finding.severity}</span><span className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-semibold ${resolved ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-amber-200 bg-amber-50 text-amber-700"}`}>{resolved ? <CheckCircle2 className="h-3 w-3" /> : <CircleDot className="h-3 w-3" />}{finding.status}</span></div>
                    </div>
                    <p className="mt-3 line-clamp-2 break-words text-xs leading-relaxed text-slate-600">{finding.evidence || "No evidence provided."}</p>
                    <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted"><span>{formatTime(finding.time)}</span>{finding.run_id && <span className="break-all">Run: {finding.run_id}</span>}</div>
                  </div>
                  <details className="group/observation border-t border-slate-100 bg-slate-50/60">
                    <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-4 py-3 text-xs font-semibold text-primary marker:content-none sm:px-5 [&::-webkit-details-marker]:hidden">View evidence and recommendation<ChevronDown className="h-4 w-4 transition-transform group-open/observation:rotate-180" /></summary>
                    <div className="space-y-3 px-4 pb-4 sm:px-5">
                      <div className="rounded-lg border border-slate-200 bg-white p-3"><h4 className="text-[11px] font-bold uppercase tracking-wide text-slate-500">Evidence</h4><p className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-slate-700">{finding.evidence || "No evidence provided."}</p></div>
                      <div className="rounded-lg border border-blue-100 bg-blue-50/50 p-3"><h4 className="text-[11px] font-bold uppercase tracking-wide text-blue-700">Recommended action</h4><p className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-slate-700">{finding.recommendation || "No recommendation provided."}</p></div>
                      {!resolved && finding.status === "Open" && <div className="flex flex-col items-start gap-2 border-t border-slate-200 pt-3"><button type="button" onClick={() => void handleResolve(finding)} disabled={resolving !== null} className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-200 bg-white px-3 py-2 text-xs font-semibold text-emerald-700 hover:bg-emerald-50 disabled:opacity-50"><CheckCircle2 className="h-4 w-4" />{resolving === finding.id ? "Marking resolved..." : "Mark resolved for this target"}</button><p className="text-[11px] leading-relaxed text-muted">This resolves observations with the same title and target across all runs.</p></div>}
                      {message?.type === "error" && message.findingId === finding.id && <p className="text-xs text-rose-700">{message.text}</p>}
                    </div>
                  </details>
                </article>
              );
            })}
          </div>
        )}
      </div>
    </details>
  );
}
