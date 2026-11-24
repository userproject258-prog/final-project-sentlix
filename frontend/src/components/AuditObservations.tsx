"use client";

import { useState } from "react";
import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  CircleDot,
  ClipboardList,
  Globe,
  Search,
  ShieldCheck,
} from "lucide-react";

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
  CRITICAL: "border-red-200 bg-red-50 text-red-700",
  HIGH: "border-amber-200 bg-amber-50 text-amber-800",
  MEDIUM: "border-blue-200 bg-blue-50 text-blue-700",
  LOW: "border-slate-200 bg-slate-100 text-slate-700",
};

function formatTime(value: string) {
  if (!value) return "Time unavailable";
  // SQLite may return UTC timestamps without a timezone suffix.
  const timestamp = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value) ? value : `${value}Z`;
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime())
    ? "Time unavailable"
    : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function filterAuditFindings(findings: AuditFinding[], search: string, status: string, severity: string) {
  const query = search.trim().toLowerCase();
  return findings.filter(
    (finding) =>
      (status === "All" || finding.status === status) &&
      (severity === "All" || finding.severity.toUpperCase() === severity) &&
      [finding.title, finding.target, finding.evidence, finding.recommendation, finding.run_id].some((value) =>
        (value || "").toLowerCase().includes(query)
      )
  );
}

export function AuditObservations({
  findings,
  loading,
  loadError,
  onRetry,
  onResolve,
}: {
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
      setMessage({
        type: "success",
        text: `${count} matching ${count === 1 ? "observation" : "observations"} marked resolved for this target.`,
        findingId: finding.id,
      });
    } catch {
      setMessage({
        type: "error",
        text: "Could not resolve this observation. Please try again.",
        findingId: finding.id,
      });
    } finally {
      setResolving(null);
    }
  }

  return (
    <details className="group/obs rounded-lg border border-border bg-white shadow-xs overflow-hidden">
      <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-3 px-5 py-4 hover:bg-slate-50/70 transition-colors marker:content-none [&::-webkit-details-marker]:hidden">
        <div className="flex items-center gap-3 min-w-0">
          <ClipboardList className="h-4 w-4 shrink-0 text-slate-600" />
          <div className="min-w-0">
            <span className="block text-sm font-semibold text-slate-900">Recorded audit observations</span>
            <span className="mt-0.5 block text-xs text-slate-500">
              Review verified evidence and track remediation across assessment runs
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2.5 shrink-0">
          {!loading && !(loadError && findings.length === 0) && (
            <span className="rounded-md border border-border bg-slate-50 px-2 py-0.5 text-xs font-mono font-medium text-slate-600 tabular-nums">
              {findings.length} recorded
            </span>
          )}
          <ChevronDown className="h-4 w-4 shrink-0 text-slate-400 transition-transform group-open/obs:rotate-180" />
        </div>
      </summary>

      <div className="space-y-4 border-t border-border p-5">
        <p className="text-xs leading-relaxed text-slate-500">
          Showing up to the 100 most recent observations across all runs. Input-test signals are candidates and require
          manual validation.
        </p>

        {loadError && (
          <div
            role="alert"
            className="flex flex-wrap items-center gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900"
          >
            <AlertCircle className="h-4 w-4 shrink-0" /> Could not refresh observations.{" "}
            {findings.length > 0 && "The list may be out of date."}{" "}
            <button type="button" onClick={onRetry} className="font-semibold underline">
              Retry
            </button>
          </div>
        )}
        {message && (
          <div
            role={message.type === "error" ? "alert" : "status"}
            className={`flex items-start gap-2 rounded-md border px-3 py-2 text-xs ${
              message.type === "error"
                ? "border-red-200 bg-red-50 text-red-800"
                : "border-emerald-200 bg-emerald-50 text-emerald-800"
            }`}
          >
            {message.type === "error" ? (
              <AlertCircle className="h-4 w-4 shrink-0" />
            ) : (
              <CheckCircle2 className="h-4 w-4 shrink-0" />
            )}
            {message.text}
          </div>
        )}

        {/* Unified 3-column summary bar */}
        <div className="grid grid-cols-3 divide-x divide-border rounded-md border border-border bg-slate-50/50 overflow-hidden">
          {[
            { label: "Recorded", value: findings.length, color: "text-slate-900" },
            { label: "Open", value: openCount, color: "text-amber-700" },
            { label: "Resolved", value: resolvedCount, color: "text-emerald-700" },
          ].map((item) => (
            <div key={item.label} className="px-4 py-3">
              <div className="text-[11px] font-medium text-slate-500">{item.label}</div>
              <div className={`mt-1 text-lg font-semibold font-mono tabular-nums ${item.color}`}>
                {loading || (loadError && findings.length === 0) ? "—" : item.value}
              </div>
            </div>
          ))}
        </div>

        <div className="flex flex-col gap-2 sm:flex-row">
          <label className="relative flex-1">
            <span className="sr-only">Search observations</span>
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search findings, targets or evidence"
              className="w-full rounded-md border border-border bg-white py-1.5 pl-8 pr-3 text-xs text-slate-900 outline-none focus:border-blue-500 transition-colors"
            />
          </label>
          <label>
            <span className="sr-only">Filter by status</span>
            <select
              value={status}
              onChange={(event) => setStatus(event.target.value)}
              className="w-full rounded-md border border-border bg-white px-3 py-1.5 text-xs text-slate-700 outline-none focus:border-blue-500 transition-colors"
            >
              <option value="All">All statuses</option>
              <option value="Open">Open</option>
              <option value="Resolved">Resolved</option>
            </select>
          </label>
          <label>
            <span className="sr-only">Filter by severity</span>
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
              className="w-full rounded-md border border-border bg-white px-3 py-1.5 text-xs text-slate-700 outline-none focus:border-blue-500 transition-colors"
            >
              <option value="All">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </label>
        </div>

        {loading ? (
          <p className="py-6 text-center text-xs text-slate-500">Loading observations...</p>
        ) : loadError && findings.length === 0 ? null : findings.length === 0 ? (
          <div className="rounded-md border border-dashed border-border bg-slate-50/50 px-4 py-8 text-center">
            <ShieldCheck className="mx-auto h-5 w-5 text-slate-400" />
            <p className="mt-2 text-xs font-semibold text-slate-800">No observations recorded yet</p>
            <p className="mt-1 text-xs text-slate-500">Observations from supported audit stages will appear here.</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="rounded-md border border-dashed border-border px-4 py-8 text-center">
            <p className="text-xs font-semibold text-slate-800">No observations match your filters</p>
            <button
              type="button"
              onClick={() => {
                setSearch("");
                setStatus("All");
                setSeverity("All");
              }}
              className="mt-1.5 text-xs font-medium text-blue-600 hover:underline"
            >
              Clear filters
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-slate-500">
              Showing {filtered.length} of {findings.length} recorded observations
            </p>
            {filtered.map((finding) => {
              const resolved = finding.status === "Resolved";
              return (
                <article key={finding.id} className="overflow-hidden rounded-md border border-border bg-white">
                  <div className="p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <h3 className="break-words text-sm font-semibold leading-5 text-slate-900">{finding.title}</h3>
                        <div className="mt-1.5 flex items-center gap-1.5 text-xs font-mono text-slate-500">
                          <Globe className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                          <span className="break-all">{finding.target}</span>
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        <span
                          className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
                            severityStyles[finding.severity.toUpperCase()] ||
                            "border-slate-200 bg-slate-50 text-slate-700"
                          }`}
                        >
                          {finding.severity}
                        </span>
                        <span
                          className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium ${
                            resolved
                              ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                              : "border-amber-200 bg-amber-50 text-amber-700"
                          }`}
                        >
                          {resolved ? <CheckCircle2 className="h-3 w-3" /> : <CircleDot className="h-3 w-3" />}
                          {finding.status}
                        </span>
                      </div>
                    </div>
                    <p className="mt-2.5 line-clamp-2 break-words text-xs leading-relaxed text-slate-600">
                      {finding.evidence || "No evidence provided."}
                    </p>
                    <div className="mt-2.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] font-mono text-slate-500">
                      <span>{formatTime(finding.time)}</span>
                      {finding.run_id && <span className="break-all">Run: {finding.run_id}</span>}
                    </div>
                  </div>
                  <details className="group/observation border-t border-border bg-slate-50/50">
                    <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-4 py-2.5 text-xs font-medium text-blue-600 hover:text-blue-700 marker:content-none [&::-webkit-details-marker]:hidden">
                      View evidence and recommendation
                      <ChevronDown className="h-3.5 w-3.5 transition-transform group-open/observation:rotate-180" />
                    </summary>
                    <div className="space-y-3 px-4 pb-4">
                      <div className="rounded-md border border-border bg-white p-3">
                        <h4 className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Evidence</h4>
                        <p className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-slate-700">
                          {finding.evidence || "No evidence provided."}
                        </p>
                      </div>
                      <div className="rounded-md border border-blue-200 bg-blue-50/40 p-3">
                        <h4 className="text-[11px] font-semibold uppercase tracking-wide text-blue-700">
                          Recommended action
                        </h4>
                        <p className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-slate-700">
                          {finding.recommendation || "No recommendation provided."}
                        </p>
                      </div>
                      {!resolved && finding.status === "Open" && (
                        <div className="flex flex-col items-start gap-2 border-t border-border pt-3">
                          <button
                            type="button"
                            onClick={() => void handleResolve(finding)}
                            disabled={resolving !== null}
                            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-white px-3 py-1.5 text-xs font-medium text-emerald-700 hover:bg-emerald-50 hover:border-emerald-300 transition-colors disabled:opacity-50"
                          >
                            <CheckCircle2 className="h-3.5 w-3.5" />
                            {resolving === finding.id ? "Marking resolved..." : "Mark resolved for this target"}
                          </button>
                          <p className="text-[11px] leading-relaxed text-slate-500">
                            This resolves observations with the same title and target across all runs.
                          </p>
                        </div>
                      )}
                      {message?.type === "error" && message.findingId === finding.id && (
                        <p className="text-xs text-red-700">{message.text}</p>
                      )}
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
