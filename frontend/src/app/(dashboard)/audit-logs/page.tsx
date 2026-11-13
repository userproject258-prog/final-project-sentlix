"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertCircle, CheckCircle2, Download, History, RefreshCw, Search, ShieldAlert, X } from "lucide-react";
import { API_URL, apiFetch } from "@/lib/api";

interface AuditLog {
  id: number;
  time: string;
  user: string;
  action: string;
  status: "Success" | "Failure";
  status_code: number;
}

function csvCell(value: string | number) {
  let text = String(value);
  // Prevent spreadsheet programs from interpreting untrusted values as formulas.
  if (/^[\s\u0000-\u001f]*[=+@-]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("All");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadLogs = useCallback((signal?: AbortSignal) => {
    return apiFetch(`${API_URL}/api/audit-logs`, { signal })
      .then((response) => {
        if (!response.ok) throw new Error("Unable to load audit logs.");
        return response.json();
      })
      .then((data) => {
        if (!Array.isArray(data.logs)) throw new Error("The server returned an invalid response.");
        if (!signal?.aborted) setLogs(data.logs);
      })
      .catch((err) => {
        if (!signal?.aborted) setError(err instanceof Error ? err.message : "Unable to load audit logs.");
      })
      .finally(() => {
        if (!signal?.aborted) setLoading(false);
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void loadLogs(controller.signal);
    return () => controller.abort();
  }, [loadLogs]);

  function refreshLogs() {
    setLoading(true);
    setError("");
    void loadLogs();
  }

  const filteredLogs = useMemo(() => {
    const query = search.trim().toLowerCase();
    return logs.filter((log) =>
      (status === "All" || log.status === status) &&
      [log.time, log.user, log.action, log.status, String(log.status_code)].some((value) => value.toLowerCase().includes(query))
    );
  }, [logs, search, status]);

  function exportCsv() {
    const rows = [
      ["Timestamp (UTC)", "User / Identity", "Action", "Status", "HTTP status"],
      ...filteredLogs.map((log) => [log.time, log.user, log.action, log.status, log.status_code]),
    ];
    const blob = new Blob([rows.map((row) => row.map(csvCell).join(",")).join("\r\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "audit-logs.csv";
    link.click();
    URL.revokeObjectURL(url);
  }

  const handleCardMouseMove = (e: React.MouseEvent<HTMLElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    e.currentTarget.style.setProperty("--mouse-x", `${e.clientX - rect.left}px`);
    e.currentTarget.style.setProperty("--mouse-y", `${e.clientY - rect.top}px`);
  };

  const successCount = useMemo(() => logs.filter((l) => l.status === "Success").length, [logs]);
  const failureCount = useMemo(() => logs.filter((l) => l.status === "Failure").length, [logs]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16 animate-fade-in">
      {/* Header Banner Card with Cursor-Tracking Spotlight */}
      <div
        onMouseMove={handleCardMouseMove}
        className="relative overflow-hidden group flex flex-col gap-4 rounded-2xl border border-gray-200 hover:border-blue-400/60 bg-white p-6 shadow-xs hover:shadow-lg hover:shadow-blue-500/5 hover:-translate-y-0.5 transition-all duration-300 ease-out sm:flex-row sm:items-center sm:justify-between"
      >
        <div
          className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            background:
              "radial-gradient(350px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.07), transparent 80%)",
          }}
        />
        <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

        <div className="flex items-start sm:items-center gap-3.5 relative z-10 min-w-0">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-primary/20 bg-primary/10 group-hover:scale-110 group-hover:-rotate-6 transition-transform duration-300">
            <History className="h-6 w-6 text-primary" />
          </div>
          <div className="min-w-0">
            <h1 className="text-xl font-bold text-gray-900 sm:text-2xl">Audit Logs</h1>
            <p className="mt-1 text-xs text-muted">Review recorded API write requests and their HTTP responses.</p>
          </div>
        </div>
        <button
          type="button"
          onClick={refreshLogs}
          disabled={loading}
          className="relative z-10 flex items-center justify-center gap-2 self-start sm:self-auto rounded-lg border border-gray-200 bg-gray-50 px-3.5 py-2 text-xs font-semibold text-gray-700 hover:bg-gray-100 hover:scale-[1.02] transition-all shadow-2xs disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-primary" : ""}`} /> Refresh
        </button>
      </div>

      {error && (
        <div role="alert" className="flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800 shadow-xs">
          <AlertCircle className="h-4 w-4 shrink-0" /> {error} Please try refreshing.
        </div>
      )}

      {/* 3 Telemetry KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-white border border-gray-200 hover:border-blue-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-blue-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex items-start justify-between"
        >
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.09), transparent 80%)",
            }}
          />
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />
          <div className="relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Loaded Records</span>
            <p className="text-2xl font-bold font-mono text-gray-900 mt-1.5 group-hover:translate-x-0.5 transition-transform duration-300">{logs.length}</p>
            <p className="text-[11px] text-muted mt-1">Up to 500 most recent API writes</p>
          </div>
          <div className="relative z-10 p-2 rounded-lg bg-blue-50 text-blue-600 group-hover:bg-primary group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300">
            <History className="w-4 h-4" />
          </div>
        </div>

        <div
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-white border border-gray-200 hover:border-emerald-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-emerald-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex items-start justify-between"
        >
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(16, 185, 129, 0.09), transparent 80%)",
            }}
          />
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-emerald-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />
          <div className="relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Accepted Writes</span>
            <p className="text-2xl font-bold font-mono text-emerald-600 mt-1.5 group-hover:translate-x-0.5 transition-transform duration-300">{successCount}</p>
            <p className="text-[11px] text-muted mt-1">2xx / 3xx HTTP status responses</p>
          </div>
          <div className="relative z-10 p-2 rounded-lg bg-emerald-50 text-emerald-600 group-hover:bg-emerald-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300">
            <CheckCircle2 className="w-4 h-4" />
          </div>
        </div>

        <div
          onMouseMove={handleCardMouseMove}
          className="relative overflow-hidden group bg-white border border-gray-200 hover:border-rose-400/80 rounded-xl p-4 shadow-xs hover:shadow-lg hover:shadow-rose-500/10 hover:-translate-y-1.5 transition-all duration-300 ease-out flex items-start justify-between"
        >
          <div
            className="pointer-events-none absolute -inset-px rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
            style={{
              background:
                "radial-gradient(160px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(244, 63, 94, 0.09), transparent 80%)",
            }}
          />
          <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-rose-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />
          <div className="relative z-10">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Failed / Rejected</span>
            <p className="text-2xl font-bold font-mono text-rose-600 mt-1.5 group-hover:translate-x-0.5 transition-transform duration-300">{failureCount}</p>
            <p className="text-[11px] text-muted mt-1">Denied or errored write requests</p>
          </div>
          <div className="relative z-10 p-2 rounded-lg bg-rose-50 text-rose-600 group-hover:bg-rose-600 group-hover:text-white group-hover:scale-110 group-hover:-rotate-6 transition-all duration-300">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>
      </div>

      {/* Main Audit Table Card with Cursor Spotlight */}
      <div
        onMouseMove={handleCardMouseMove}
        className="relative overflow-hidden group rounded-2xl border border-gray-200 hover:border-blue-400/60 bg-white shadow-xs hover:shadow-lg hover:shadow-blue-500/5 transition-all duration-300 ease-out"
      >
        <div
          className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            background:
              "radial-gradient(380px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.05), transparent 80%)",
          }}
        />
        <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

        <div className="relative z-10">
          <div className="flex flex-col gap-3 border-b border-gray-200 bg-slate-50/70 p-4 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
              <input
                type="search"
                aria-label="Search audit logs"
                placeholder="Search identity, action or status..."
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                className="w-full rounded-lg border border-gray-300 bg-white py-2 pl-9 pr-8 text-xs sm:text-sm text-gray-900 focus:outline-none focus:ring-2 focus:ring-primary/30 transition-all"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-700"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
            <select
              aria-label="Filter by status"
              value={status}
              onChange={(event) => setStatus(event.target.value)}
              className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-xs sm:text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-primary/30"
            >
              <option value="All">All statuses</option>
              <option value="Success">Success</option>
              <option value="Failure">Failure</option>
            </select>
            <button
              type="button"
              onClick={exportCsv}
              disabled={filteredLogs.length === 0}
              className="flex items-center justify-center gap-2 rounded-lg border border-gray-200 bg-white px-3.5 py-2 text-xs sm:text-sm font-medium text-gray-700 hover:bg-gray-50 hover:scale-[1.02] transition-all shadow-2xs disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Download className="h-4 w-4" /> Export CSV
            </button>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-100 px-5 py-3 text-xs text-muted bg-white">
            <span>{filteredLogs.length} of {logs.length} loaded {logs.length === 1 ? "record" : "records"}</span>
            <span>Showing up to the 500 most recent records · Times shown in your local timezone</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="border-b border-gray-200 bg-gray-50/80 text-xs uppercase tracking-wide text-gray-500">
                <tr><th scope="col" className="px-5 py-3">Timestamp</th><th scope="col" className="px-5 py-3">User / Identity</th><th scope="col" className="px-5 py-3">Action</th><th scope="col" className="px-5 py-3">Response</th></tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="whitespace-nowrap px-5 py-3.5 text-xs text-gray-500">{new Date(log.time).toLocaleString()}</td>
                    <td className="px-5 py-3.5 text-xs font-medium text-gray-700">{log.user}</td>
                    <td className="px-5 py-3.5 font-mono text-xs text-gray-900">{log.action}</td>
                    <td className="whitespace-nowrap px-5 py-3.5"><span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${log.status === "Success" ? "bg-emerald-50 text-emerald-700 border border-emerald-200/80" : "bg-rose-50 text-rose-700 border border-rose-200/80"}`}>{log.status} · {log.status_code}</span></td>
                  </tr>
                ))}
                {!loading && !error && filteredLogs.length === 0 && (
                  <tr><td colSpan={4} className="px-5 py-12 text-center text-sm text-gray-500">{logs.length === 0 ? "No activity recorded yet. New API write requests will appear here." : "No records match your filters."}</td></tr>
                )}
                {loading && logs.length === 0 && <tr><td colSpan={4} className="px-5 py-12 text-center text-sm text-gray-500">Loading audit logs...</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <p className="text-xs leading-relaxed text-muted">Records begin when activity logging is enabled. Request bodies and query strings are not stored; sign-in attempts and requests without an authenticated session are shown as unauthenticated. HTTP success indicates the request was accepted, not necessarily that a background operation completed.</p>
    </div>
  );
}
