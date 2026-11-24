"use client";

import { useState } from "react";
import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  Code2,
  Container,
  Download,
  GitBranch,
  KeyRound,
  Loader2,
  PackageSearch,
  Play,
  RefreshCw,
  Search,
  ShieldCheck,
} from "lucide-react";

interface Vulnerability {
  package: string | null;
  version: string | null;
  id: string | null;
  fix_versions: string[] | null;
}

interface ScanDetails {
  status?: string;
  engine?: string;
  scope?: string;
  reason?: string;
  error?: string;
  high_issues?: number;
  medium_issues?: number;
  low_issues?: number;
  loc_scanned?: number;
  skipped?: number;
  vulnerabilities?: Vulnerability[];
}

export interface PipelineRun {
  id: string;
  time: string;
  commit_sha: string;
  branch: string;
  developer: string;
  status: string;
  sast_status: string;
  secret_status: string;
  dependency_status: string;
  container_status: string;
  details: { sast?: ScanDetails; secrets?: ScanDetails; dependencies?: ScanDetails; container?: ScanDetails } | null;
}

export interface ManualPipelineStatus {
  status: "idle" | "running" | "complete" | "failed";
  run_id: string | null;
  error: string | null;
}

const statusStyle: Record<string, string> = {
  PASSED: "border-emerald-200 bg-emerald-50 text-emerald-700",
  FAILED: "border-red-200 bg-red-50 text-red-700",
  WARNING: "border-amber-200 bg-amber-50 text-amber-800",
  "PASSED WITH WARNINGS": "border-amber-200 bg-amber-50 text-amber-800",
  INCOMPLETE: "border-amber-200 bg-amber-50 text-amber-800",
  ERROR: "border-red-200 bg-red-50 text-red-700",
  "NOT RUN": "border-slate-200 bg-slate-100 text-slate-600",
};

function Status({ value }: { value: string }) {
  const text = value || "Unavailable";
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
        statusStyle[text.toUpperCase()] || "border-slate-200 bg-slate-50 text-slate-600"
      }`}
    >
      {text}
    </span>
  );
}

function formatTime(value: string) {
  if (!value) return "Time unavailable";
  const timestamp = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value) ? value : `${value}Z`;
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime())
    ? "Time unavailable"
    : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function filterPipelineRuns(runs: PipelineRun[], search: string, status: string) {
  const query = search.trim().toLowerCase();
  return runs.filter(
    (run) =>
      (status === "All" || run.status === status) &&
      [
        run.id,
        run.branch,
        run.commit_sha,
        run.developer,
        run.status,
        run.sast_status,
        run.secret_status,
        run.dependency_status,
        run.container_status,
      ].some((value) => (value || "").toLowerCase().includes(query))
  );
}

function downloadRun(run: PipelineRun) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(run, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `pipeline-${run.id.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function CheckCard({
  title,
  icon,
  status,
  details,
  fallbackScope,
}: {
  title: string;
  icon: React.ReactNode;
  status: string;
  details?: ScanDetails;
  fallbackScope: string;
}) {
  return (
    <div className="rounded-md border border-border hover:border-violet-300/90 bg-white p-3.5 hover:shadow-sm hover:shadow-violet-500/10 transition-all duration-200">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
          {icon}
          {title}
        </div>
        <Status value={status} />
      </div>
      <p className="mt-2 text-xs leading-relaxed text-slate-500">{details?.scope || fallbackScope}</p>
      {details?.engine && <p className="mt-1 text-[11px] font-mono text-slate-500">Scanner: {details.engine}</p>}
      {(details?.reason || details?.error) && (
        <p className="mt-2 break-words text-xs text-red-700">{details.reason || details.error}</p>
      )}
      {typeof details?.loc_scanned === "number" && (
        <p className="mt-2 text-xs font-mono text-slate-600 tabular-nums">
          {details.loc_scanned.toLocaleString()} lines scanned · {details.high_issues ?? 0} high ·{" "}
          {details.medium_issues ?? 0} medium · {details.low_issues ?? 0} low
        </p>
      )}
      {typeof details?.skipped === "number" && details.skipped > 0 && (
        <p className="mt-2 text-xs text-amber-800">{details.skipped} dependencies skipped by the scanner.</p>
      )}
    </div>
  );
}

const PAGE_SIZE = 5;

function handleSpotlightMove(e: React.MouseEvent<HTMLElement>) {
  const rect = e.currentTarget.getBoundingClientRect();
  e.currentTarget.style.setProperty("--mouse-x", `${e.clientX - rect.left}px`);
  e.currentTarget.style.setProperty("--mouse-y", `${e.clientY - rect.top}px`);
}

export function PipelineChecks({
  runs,
  loading,
  loadError,
  manualStatus,
  manualStatusError,
  onRetry,
  onRun,
  defaultOpen = false,
}: {
  runs: PipelineRun[];
  loading: boolean;
  loadError: boolean;
  manualStatus: ManualPipelineStatus | null;
  manualStatusError: boolean;
  onRetry: () => void;
  onRun: () => Promise<void>;
  defaultOpen?: boolean;
}) {
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("All");
  const [page, setPage] = useState(1);
  const [starting, setStarting] = useState(false);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const filtered = filterPipelineRuns(runs, search, status);
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const visibleRuns = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
  const statusOptions = [...new Set(runs.map((run) => run.status).filter(Boolean))];
  const failed = runs.filter((run) => run.status === "FAILED").length;
  const incomplete = runs.filter((run) => run.status === "INCOMPLETE").length;
  const passed = runs.filter((run) => run.status === "PASSED" || run.status === "PASSED WITH WARNINGS").length;
  const running = starting || manualStatus?.status === "running";

  async function runChecks() {
    setStarting(true);
    setMessage(null);
    try {
      await onRun();
      setMessage(null);
    } catch (err) {
      setMessage({
        type: "error",
        text: err instanceof Error ? err.message : "Could not start pipeline checks. Please try again.",
      });
    } finally {
      setStarting(false);
    }
  }

  return (
    <div
      onMouseMove={handleSpotlightMove}
      className="relative overflow-hidden group rounded-lg border border-border hover:border-violet-400/80 bg-white shadow-xs hover:shadow-lg hover:shadow-violet-500/10 transition-all duration-300 ease-out"
    >
      <div
        className="pointer-events-none absolute -inset-px rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{
          background:
            "radial-gradient(380px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(139, 92, 246, 0.08), transparent 80%)",
        }}
      />
      <div className="pointer-events-none absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-violet-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center z-20" />
      <details open={defaultOpen || undefined} className="relative z-10 group/pipeline">
        <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-3 px-5 py-4 hover:bg-slate-50/50 transition-colors marker:content-none [&::-webkit-details-marker]:hidden">
        <div className="flex items-center gap-3 min-w-0">
          <ShieldCheck className="h-4 w-4 shrink-0 text-slate-600" />
          <div className="min-w-0">
            <span className="block text-sm font-semibold text-slate-900">Pipeline security checks</span>
            <span className="mt-0.5 block text-xs text-slate-500">
              Review local SAST, secret, dependency, and container configuration scans
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2.5 shrink-0">
          {!loading && !(loadError && runs.length === 0) && (
            <span className="rounded-md border border-border bg-slate-50 px-2 py-0.5 text-xs font-mono font-medium text-slate-600 tabular-nums">
              {runs.length} {runs.length === 1 ? "run" : "runs"}
            </span>
          )}
          <ChevronDown className="h-4 w-4 shrink-0 text-slate-400 transition-transform group-open/pipeline:rotate-180" />
        </div>
      </summary>

      <div className="space-y-4 border-t border-border p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="max-w-2xl text-xs leading-relaxed text-slate-500">
            Checks run against this backend environment, not the audit target URL. Container checks inspect
            configuration, not a built image. Missing scanners are shown as not run.
          </p>
          <div className="flex shrink-0 gap-2">
            <button
              type="button"
              onClick={onRetry}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 hover:border-slate-300 transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5 text-slate-500" /> Refresh
            </button>
            <button
              type="button"
              onClick={() => void runChecks()}
              disabled={running || !manualStatus || manualStatusError}
              className="inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700 transition-colors disabled:opacity-60"
            >
              {running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              {running ? "Running checks..." : "Run local checks"}
            </button>
          </div>
        </div>

        {running && (
          <p role="status" className="text-xs text-slate-600">
            Running installed scanners. This may take several minutes; you can return to this page to check progress.
          </p>
        )}
        {manualStatusError && (
          <p role="alert" className="text-xs text-amber-800">
            Could not check whether a manual scan is running. Refresh before starting another run.
          </p>
        )}
        {!running && !manualStatusError && manualStatus?.status === "complete" && (
          <p role="status" className="flex items-center gap-1.5 text-xs text-emerald-700">
            <CheckCircle2 className="h-4 w-4" />
            Manual checks completed: <span className="font-mono">{manualStatus.run_id}</span>.
          </p>
        )}
        {!running && !manualStatusError && manualStatus?.status === "failed" && (
          <p role="alert" className="text-xs text-red-700">
            {manualStatus.error || "Manual checks could not be completed."}
          </p>
        )}
        {loadError && (
          <div
            role="alert"
            className="flex flex-wrap items-center gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900"
          >
            <AlertCircle className="h-4 w-4 shrink-0" />
            Could not refresh pipeline runs. {runs.length > 0 && "The list may be out of date."}
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

        <div className="grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-border rounded-md border border-border bg-slate-50/50 overflow-hidden">
          {[
            { label: "Total runs", value: runs.length, color: "text-slate-900", glow: "rgba(99, 102, 241, 0.11)", bar: "via-indigo-500" },
            { label: "Passed", value: passed, color: "text-emerald-700", glow: "rgba(16, 185, 129, 0.11)", bar: "via-emerald-500" },
            { label: "Failed", value: failed, color: "text-red-700", glow: "rgba(225, 29, 72, 0.11)", bar: "via-rose-500" },
            { label: "Incomplete", value: incomplete, color: "text-amber-700", glow: "rgba(245, 158, 11, 0.12)", bar: "via-amber-500" },
          ].map((item) => (
            <div
              key={item.label}
              onMouseMove={handleSpotlightMove}
              className="relative overflow-hidden group/tile px-4 py-3"
            >
              <div
                className="pointer-events-none absolute -inset-px opacity-0 group-hover/tile:opacity-100 transition-opacity duration-300"
                style={{
                  background: `radial-gradient(180px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), ${item.glow}, transparent 80%)`,
                }}
              />
              <div
                className={`pointer-events-none absolute top-0 inset-x-0 h-[2px] bg-gradient-to-r from-transparent ${item.bar} to-transparent scale-x-0 group-hover/tile:scale-x-100 transition-transform duration-300 origin-center`}
              />
              <div className="relative z-10">
                <div className="text-[11px] font-medium text-slate-500">{item.label}</div>
                <div className={`mt-1 text-lg font-semibold font-mono tabular-nums ${item.color}`}>
                  {loading || (loadError && runs.length === 0) ? "—" : item.value}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="flex flex-col gap-2 sm:flex-row">
          <label className="relative flex-1">
            <span className="sr-only">Search pipeline runs</span>
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <input
              type="search"
              value={search}
              onChange={(event) => {
                setSearch(event.target.value);
                setPage(1);
              }}
              placeholder="Search run ID, branch, commit or scanner status"
              className="w-full rounded-md border border-border bg-white py-1.5 pl-8 pr-3 text-xs text-slate-900 outline-none focus:border-blue-500 transition-colors"
            />
          </label>
          <label>
            <span className="sr-only">Filter pipeline runs by status</span>
            <select
              value={status}
              onChange={(event) => {
                setStatus(event.target.value);
                setPage(1);
              }}
              className="w-full rounded-md border border-border bg-white px-3 py-1.5 text-xs text-slate-700 outline-none focus:border-blue-500 transition-colors"
            >
              <option value="All">All statuses</option>
              {statusOptions.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </label>
        </div>

        {loading ? (
          <p className="py-6 text-center text-xs text-slate-500">Loading pipeline runs...</p>
        ) : loadError && runs.length === 0 ? null : runs.length === 0 ? (
          <div className="rounded-md border border-dashed border-border bg-slate-50/50 px-4 py-8 text-center">
            <ShieldCheck className="mx-auto h-5 w-5 text-slate-400" />
            <p className="mt-2 text-xs font-semibold text-slate-800">No pipeline runs recorded</p>
            <p className="mt-1 text-xs text-slate-500">Run the local checks or connect a CI webhook to create a run.</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="rounded-md border border-dashed border-border px-4 py-8 text-center">
            <p className="text-xs font-semibold text-slate-800">No runs match your filters</p>
            <button
              type="button"
              onClick={() => {
                setSearch("");
                setStatus("All");
              }}
              className="mt-1.5 text-xs font-medium text-blue-600 hover:underline"
            >
              Clear filters
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs text-slate-500">
                Showing {visibleRuns.length} of {filtered.length} matching runs ({runs.length} total) · Passed includes runs with warnings
              </p>
              {totalPages > 1 && (
                <div className="inline-flex items-center gap-1.5 text-xs">
                  <button
                    type="button"
                    disabled={currentPage <= 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    className="rounded-md border border-border bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-40"
                  >
                    Previous
                  </button>
                  <span className="px-2 font-mono text-[11px] text-slate-600 tabular-nums">
                    {currentPage} / {totalPages}
                  </span>
                  <button
                    type="button"
                    disabled={currentPage >= totalPages}
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    className="rounded-md border border-border bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              )}
            </div>
            {visibleRuns.map((run) => (
              <article
                key={run.id}
                className="overflow-hidden rounded-md border border-border hover:border-violet-300/90 bg-white hover:shadow-md hover:shadow-violet-500/10 hover:-translate-y-0.5 transition-all duration-200"
              >
                <div className="p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h3 className="font-mono text-xs font-semibold text-slate-900">{run.id}</h3>
                      <p className="mt-0.5 text-[11px] font-mono text-slate-500">{formatTime(run.time)}</p>
                    </div>
                    <Status value={run.status} />
                  </div>
                  <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600">
                    <span className="inline-flex items-center gap-1">
                      <GitBranch className="h-3.5 w-3.5 text-slate-400" />
                      {run.branch || "Not specified"}
                    </span>
                    <span>
                      Commit: <span className="font-mono text-slate-800">{run.commit_sha || "Not available"}</span>
                    </span>
                    <span className="break-all">By: {run.developer || "Unknown"}</span>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {[
                      ["SAST", run.sast_status],
                      ["Secrets", run.secret_status],
                      ["Dependencies", run.dependency_status],
                      ["Container config", run.container_status],
                    ].map(([label, value]) => (
                      <span
                        key={label}
                        className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] ${
                          statusStyle[(value || "").toUpperCase()] || "border-slate-200 bg-slate-50 text-slate-700"
                        }`}
                      >
                        <span className="font-semibold">{label}</span>
                        <span>· {value || "Unavailable"}</span>
                      </span>
                    ))}
                  </div>
                </div>
                <details className="group/run border-t border-border bg-slate-50/50">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-4 py-2.5 text-xs font-medium text-blue-600 hover:text-blue-700 marker:content-none [&::-webkit-details-marker]:hidden">
                    View check details
                    <ChevronDown className="h-3.5 w-3.5 transition-transform group-open/run:rotate-180" />
                  </summary>
                  <div className="space-y-3 px-4 pb-4">
                    {!run.details && (
                      <p className="text-xs text-slate-500">
                        Detailed scanner results are unavailable for this run. Recorded check statuses are shown below.
                      </p>
                    )}
                    <div className="grid gap-3 md:grid-cols-2">
                      <CheckCard
                        title="SAST"
                        icon={<Code2 className="h-3.5 w-3.5 text-slate-600" />}
                        status={run.sast_status}
                        details={run.details?.sast}
                        fallbackScope="Backend Python source"
                      />
                      <CheckCard
                        title="Secrets"
                        icon={<KeyRound className="h-3.5 w-3.5 text-slate-600" />}
                        status={run.secret_status}
                        details={run.details?.secrets}
                        fallbackScope="Backend source directory"
                      />
                      <CheckCard
                        title="Dependencies"
                        icon={<PackageSearch className="h-3.5 w-3.5 text-slate-600" />}
                        status={run.dependency_status}
                        details={run.details?.dependencies}
                        fallbackScope="Installed local Python environment"
                      />
                      <CheckCard
                        title="Container configuration"
                        icon={<Container className="h-3.5 w-3.5 text-slate-600" />}
                        status={run.container_status}
                        details={run.details?.container}
                        fallbackScope="Backend container configuration, not an image scan"
                      />
                    </div>
                    {(run.details?.dependencies?.vulnerabilities?.length ?? 0) > 0 && (
                      <div className="rounded-md border border-red-200 bg-white p-3.5">
                        <h4 className="text-xs font-semibold text-red-800">
                          Dependency vulnerabilities ({run.details?.dependencies?.vulnerabilities?.length})
                        </h4>
                        <div className="mt-2 divide-y divide-slate-100">
                          {run.details?.dependencies?.vulnerabilities?.map((vulnerability, index) => (
                            <div
                              key={`${vulnerability.id}-${vulnerability.package}-${index}`}
                              className="flex flex-wrap justify-between gap-1 py-2 text-xs"
                            >
                              <span className="break-words font-mono font-medium text-slate-800">
                                {vulnerability.package || "Unknown package"} {vulnerability.version || ""} ·{" "}
                                {vulnerability.id || "Unknown advisory"}
                              </span>
                              <span className="text-slate-500">
                                Fix versions: {vulnerability.fix_versions?.join(", ") || "not listed"}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    <button
                      type="button"
                      onClick={() => downloadRun(run)}
                      className="inline-flex items-center gap-1.5 rounded-md border border-border bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors"
                    >
                      <Download className="h-3.5 w-3.5 text-slate-500" />
                      Download run JSON
                    </button>
                  </div>
                </details>
              </article>
            ))}
          </div>
        )}
      </div>
      </details>
    </div>
  );
}
