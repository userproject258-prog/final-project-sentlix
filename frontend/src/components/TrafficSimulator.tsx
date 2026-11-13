"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertCircle,
  Loader2,
  Zap,
  Sliders,
  Gauge,
  CheckCircle2,
  Sparkles,
  Crosshair,
  ShieldAlert,
  Play,
  Layers,
} from "lucide-react";
import { API_URL, apiFetch } from "@/lib/api";

interface Scenario {
  id: string;
  name: string;
  target: string;
  mitre_id?: string;
  mitre_tactic?: string;
  protocol?: string;
  description?: string;
  expected_class?: string;
  packet_size?: number;
  duration?: number;
  failed_logins?: number;
  unique_ports_accessed?: number;
  bytes_sent?: number;
}

interface SimulationResult {
  scenario: string;
  scenario_id: string;
  target: string;
  burst_count?: number;
  logged_count?: number;
  avg_inference_ms?: number;
  mitre?: { id: string; tactic: string };
  feature_vector?: {
    packet_size: number;
    duration: number;
    failed_logins: number;
    unique_ports_accessed: number;
    bytes_sent: number;
  };
  analysis: {
    prediction: string;
    confidence: number;
    severity: string;
    inference_ms?: number;
    probabilities?: Record<string, number>;
  };
  logged: boolean;
}

interface BenchmarkSummary {
  total_vectors: number;
  matched: number;
  accuracy_pct: number;
  avg_confidence_pct: number;
  avg_inference_ms: number;
  total_elapsed_ms: number;
  throughput_eps: number;
}

interface BenchmarkVectorResult {
  id: string;
  name: string;
  mitre_id: string;
  expected: string;
  predicted: string;
  matched: boolean;
  severity: string;
  confidence: number;
  inference_ms: number;
}

export function TrafficSimulator({ onComplete }: { onComplete: () => void }) {
  const [open, setOpen] = useState(false);
  const [labTab, setLabTab] = useState<"scenarios" | "custom" | "benchmark">("scenarios");
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [scenarioId, setScenarioId] = useState("");
  const [target, setTarget] = useState("");
  const [burstCount, setBurstCount] = useState<number>(1);
  const [loading, setLoading] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [error, setError] = useState("");
  const [lastResult, setLastResult] = useState<SimulationResult | null>(null);

  // Custom Vector Lab state
  const [customTarget, setCustomTarget] = useState("10.0.1.100:443");
  const [customIp, setCustomIp] = useState("");
  const [packetSize, setPacketSize] = useState<number>(1400);
  const [duration, setDuration] = useState<number>(6.0);
  const [failedLogins, setFailedLogins] = useState<number>(0);
  const [uniquePorts, setUniquePorts] = useState<number>(1);
  const [bytesSent, setBytesSent] = useState<number>(11500);

  // Benchmark Suite state
  const [benchmarkTarget, setBenchmarkTarget] = useState("prod-edge-gw");
  const [benchmarkLogEvents, setBenchmarkLogEvents] = useState(false);
  const [benchmarkRunning, setBenchmarkRunning] = useState(false);
  const [benchmarkSummary, setBenchmarkSummary] = useState<BenchmarkSummary | null>(null);
  const [benchmarkRows, setBenchmarkRows] = useState<BenchmarkVectorResult[]>([]);

  const handleCardMouseMove = (e: React.MouseEvent<HTMLElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    e.currentTarget.style.setProperty("--mouse-x", `${e.clientX - rect.left}px`);
    e.currentTarget.style.setProperty("--mouse-y", `${e.clientY - rect.top}px`);
  };

  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    apiFetch(`${API_URL}/api/threats/simulation-scenarios`, { signal: controller.signal })
      .then((res) => {
        if (!res.ok) throw new Error("Could not load simulation scenarios.");
        return res.json();
      })
      .then((data) => {
        if (!Array.isArray(data.scenarios) || data.scenarios.length === 0)
          throw new Error("No simulation scenarios are available.");
        if (!controller.signal.aborted) {
          setScenarios(data.scenarios);
          setScenarioId((previous) => previous || data.scenarios[0].id);
          setTarget((previous) => previous || data.scenarios[0].target);
        }
      })
      .catch((err) => {
        if (!controller.signal.aborted)
          setError(err instanceof Error ? err.message : "Could not load scenarios.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [open]);

  function togglePanel() {
    if (!open) {
      setLoading(true);
      setError("");
    }
    setOpen(!open);
  }

  const selectedScenario = scenarios.find((s) => s.id === scenarioId);

  async function simulateScenario(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSimulating(true);
    setError("");
    try {
      const response = await apiFetch(`${API_URL}/api/threats/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario: scenarioId,
          target: target.trim(),
          burst_count: burstCount,
        }),
      });
      const result = await response.json();
      if (!response.ok)
        throw new Error(typeof result.detail === "string" ? result.detail : "Simulation failed.");
      setLastResult(result);
      onComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Simulation failed.");
    } finally {
      setSimulating(false);
    }
  }

  async function simulateCustomVector(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSimulating(true);
    setError("");
    try {
      const response = await apiFetch(`${API_URL}/api/threats/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario: "custom",
          target: customTarget.trim(),
          burst_count: burstCount,
          packet_size: packetSize,
          duration,
          failed_logins: failedLogins,
          unique_ports_accessed: uniquePorts,
          bytes_sent: bytesSent,
          source_ip: customIp.trim() || undefined,
        }),
      });
      const result = await response.json();
      if (!response.ok)
        throw new Error(typeof result.detail === "string" ? result.detail : "Custom simulation failed.");
      setLastResult(result);
      onComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Custom simulation failed.");
    } finally {
      setSimulating(false);
    }
  }

  async function runBenchmarkSuite() {
    setBenchmarkRunning(true);
    setError("");
    try {
      const response = await apiFetch(`${API_URL}/api/threats/simulate/benchmark`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: benchmarkTarget.trim() || "prod-edge-gw",
          log_events: benchmarkLogEvents,
        }),
      });
      const data = await response.json();
      if (!response.ok)
        throw new Error(typeof data.detail === "string" ? data.detail : "Benchmark execution failed.");
      setBenchmarkSummary(data.summary);
      setBenchmarkRows(data.results || []);
      if (benchmarkLogEvents) {
        onComplete();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Benchmark failed.");
    } finally {
      setBenchmarkRunning(false);
    }
  }

  const applyCustomPreset = (preset: "dos" | "scan" | "brute" | "normal") => {
    if (preset === "dos") {
      setPacketSize(1480);
      setDuration(10);
      setFailedLogins(0);
      setUniquePorts(1);
      setBytesSent(13500);
    } else if (preset === "scan") {
      setPacketSize(64);
      setDuration(0.9);
      setFailedLogins(0);
      setUniquePorts(220);
      setBytesSent(210);
    } else if (preset === "brute") {
      setPacketSize(130);
      setDuration(5.5);
      setFailedLogins(32);
      setUniquePorts(1);
      setBytesSent(540);
    } else {
      setPacketSize(320);
      setDuration(1.4);
      setFailedLogins(0);
      setUniquePorts(2);
      setBytesSent(420);
    }
  };

  return (
    <section
      onMouseMove={handleCardMouseMove}
      className="relative overflow-hidden group rounded-2xl border border-border hover:border-rose-300 bg-surface shadow-xs hover:shadow-md transition-all duration-300"
      aria-label="Attack testing and intrusion simulation platform"
    >
      {/* Cursor Spotlight Glow */}
      <div
        className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{
          background:
            "radial-gradient(360px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(225, 29, 72, 0.06), transparent 80%)",
        }}
      />
      {/* Top Animated Accent Bar */}
      <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-rose-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center" />

      {/* Top Header Strip */}
      <div className="relative z-10 flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-5 py-4 bg-white">
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-2 rounded-xl bg-rose-50 text-rose-600 border border-rose-200/80 shrink-0 group-hover:scale-105 group-hover:-rotate-6 transition-transform duration-300">
            <Zap className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm font-bold text-foreground">
                Attack Simulation & Intrusion Testing Platform
              </h2>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                MITRE ATT&CK Lab
              </span>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">
                RF-IDS Stress & Benchmark
              </span>
            </div>
            <p className="text-xs text-muted mt-0.5 truncate">
              Replay MITRE attack vectors, craft custom flow payloads, or run full 10-vector ML detection benchmarks
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={togglePanel}
          aria-expanded={open}
          aria-controls="traffic-simulator-form"
          className={`shrink-0 flex items-center justify-center gap-1.5 rounded-xl px-4 py-2 text-xs font-semibold transition-all shadow-2xs ${
            open
              ? "bg-gray-100 text-gray-700 hover:bg-gray-200 border border-gray-300"
              : "bg-red-600 text-white hover:bg-red-700 hover:scale-[1.02]"
          }`}
        >
          <Zap className="h-3.5 w-3.5" /> {open ? "Close Attack Lab" : "Open Attack Testing Lab"}
        </button>
      </div>

      {/* Expanded Platform Panel */}
      {open && (
        <div id="traffic-simulator-form" className="relative z-10 space-y-5 border-t border-border bg-slate-50/40 p-5">
          {/* Sub-navigation Tabs */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="inline-flex items-center gap-1 bg-white p-1 rounded-xl border border-border shadow-2xs">
              {[
                { id: "scenarios", label: "Scenario Replay", icon: Crosshair },
                { id: "custom", label: "Custom Vector Lab", icon: Sliders },
                { id: "benchmark", label: "ML Performance Benchmark", icon: Gauge },
              ].map((t) => {
                const Icon = t.icon;
                const active = labTab === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setLabTab(t.id as typeof labTab)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                      active
                        ? "bg-rose-600 text-white shadow-2xs"
                        : "text-muted hover:text-foreground hover:bg-gray-50"
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span>{t.label}</span>
                  </button>
                );
              })}
            </div>

            <span className="text-[11px] text-muted font-medium">
              Safe synthetic telemetry — no external packets leave the sandbox
            </span>
          </div>

          {/* TAB 1: SCENARIO REPLAY */}
          {labTab === "scenarios" && (
            <div className="bg-white rounded-xl border border-border p-4 sm:p-5 space-y-4 shadow-2xs">
              <form onSubmit={simulateScenario} className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
                <label className="md:col-span-5 space-y-1.5 text-xs font-semibold text-gray-700">
                  <span>MITRE Attack Scenario</span>
                  <select
                    value={scenarioId}
                    disabled={loading || !scenarios.length || simulating}
                    onChange={(event) => {
                      const selected = scenarios.find((item) => item.id === event.target.value);
                      setScenarioId(event.target.value);
                      if (selected) setTarget(selected.target);
                    }}
                    className="block w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-xs font-normal text-gray-900 disabled:opacity-50 focus:border-rose-500 focus:outline-none"
                  >
                    {loading && <option>Loading scenarios...</option>}
                    {!loading && scenarios.length === 0 && <option>No scenarios available</option>}
                    {scenarios.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.name} {item.mitre_id ? `[${item.mitre_id}]` : ""}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="md:col-span-3 space-y-1.5 text-xs font-semibold text-gray-700">
                  <span>Target Label / Asset</span>
                  <input
                    required
                    maxLength={200}
                    value={target}
                    onChange={(event) => setTarget(event.target.value)}
                    disabled={simulating || !scenarioId}
                    placeholder="IP address, hostname or service"
                    className="block w-full rounded-lg border border-gray-300 px-3 py-2 text-xs font-normal text-gray-900 disabled:opacity-50 focus:border-rose-500 focus:outline-none"
                  />
                </label>

                <label className="md:col-span-2 space-y-1.5 text-xs font-semibold text-gray-700">
                  <span>Burst Waves</span>
                  <select
                    value={burstCount}
                    onChange={(e) => setBurstCount(Number(e.target.value))}
                    disabled={simulating}
                    className="block w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-xs font-normal text-gray-900"
                  >
                    <option value={1}>1x Single Event</option>
                    <option value={3}>3x Rapid Burst</option>
                    <option value={5}>5x Attack Wave</option>
                    <option value={10}>10x Sustained Flood</option>
                  </select>
                </label>

                <div className="md:col-span-2">
                  <button
                    type="submit"
                    disabled={loading || simulating || !scenarioId || !target.trim()}
                    className="w-full flex items-center justify-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-700 disabled:opacity-50 transition-all shadow-2xs"
                  >
                    {simulating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5 fill-current" />}
                    <span>{simulating ? "Firing..." : "Launch Attack"}</span>
                  </button>
                </div>
              </form>

              {selectedScenario && (
                <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3.5 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-slate-800">
                      <span>{selectedScenario.name}</span>
                      {selectedScenario.mitre_id && (
                        <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 text-[10px] font-mono">
                          {selectedScenario.mitre_id} · {selectedScenario.mitre_tactic}
                        </span>
                      )}
                      {selectedScenario.protocol && (
                        <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 text-[10px] font-mono">
                          {selectedScenario.protocol}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-500">
                      {selectedScenario.description || "Synthetic attack flow crafted for Random Forest IDS validation."}
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 shrink-0 text-[11px] font-mono">
                    <span className="px-2 py-1 rounded bg-white border border-slate-200">
                      pkt: <strong>{selectedScenario.packet_size}B</strong>
                    </span>
                    <span className="px-2 py-1 rounded bg-white border border-slate-200">
                      bytes: <strong>{selectedScenario.bytes_sent}</strong>
                    </span>
                    <span className="px-2 py-1 rounded bg-white border border-slate-200">
                      ports: <strong>{selectedScenario.unique_ports_accessed}</strong>
                    </span>
                    <span className="px-2 py-1 rounded bg-white border border-slate-200">
                      fails: <strong>{selectedScenario.failed_logins}</strong>
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: CUSTOM VECTOR LAB */}
          {labTab === "custom" && (
            <form onSubmit={simulateCustomVector} className="bg-white rounded-xl border border-border p-4 sm:p-5 space-y-4 shadow-2xs">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-3">
                <div>
                  <h3 className="text-xs font-bold text-foreground">Custom Adversarial Flow Vector Crafting</h3>
                  <p className="text-[11px] text-muted mt-0.5">
                    Adjust ML network telemetry features manually to test edge-case detection boundaries
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[11px] text-muted mr-1">Quick Templates:</span>
                  {[
                    { key: "dos" as const, label: "Volumetric DoS" },
                    { key: "scan" as const, label: "Stealth Scan" },
                    { key: "brute" as const, label: "Brute Force" },
                    { key: "normal" as const, label: "Benign Traffic" },
                  ].map((p) => (
                    <button
                      key={p.key}
                      type="button"
                      onClick={() => applyCustomPreset(p.key)}
                      className="px-2.5 py-1 rounded-md text-[11px] font-medium border border-border bg-slate-50 hover:bg-slate-100 text-slate-700 transition-colors"
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs font-medium">
                    <span className="text-slate-700">Bytes Sent</span>
                    <span className="font-mono text-primary font-bold">{bytesSent}</span>
                  </div>
                  <input
                    type="range"
                    min={50}
                    max={20000}
                    step={50}
                    value={bytesSent}
                    onChange={(e) => setBytesSent(Number(e.target.value))}
                    className="w-full accent-primary"
                  />
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs font-medium">
                    <span className="text-slate-700">Packet Size (B)</span>
                    <span className="font-mono text-primary font-bold">{packetSize}</span>
                  </div>
                  <input
                    type="range"
                    min={40}
                    max={1600}
                    step={10}
                    value={packetSize}
                    onChange={(e) => setPacketSize(Number(e.target.value))}
                    className="w-full accent-primary"
                  />
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs font-medium">
                    <span className="text-slate-700">Failed Logins</span>
                    <span className="font-mono text-amber-600 font-bold">{failedLogins}</span>
                  </div>
                  <input
                    type="range"
                    min={0}
                    max={100}
                    step={1}
                    value={failedLogins}
                    onChange={(e) => setFailedLogins(Number(e.target.value))}
                    className="w-full accent-amber-600"
                  />
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs font-medium">
                    <span className="text-slate-700">Unique Ports</span>
                    <span className="font-mono text-purple-600 font-bold">{uniquePorts}</span>
                  </div>
                  <input
                    type="range"
                    min={1}
                    max={500}
                    step={1}
                    value={uniquePorts}
                    onChange={(e) => setUniquePorts(Number(e.target.value))}
                    className="w-full accent-purple-600"
                  />
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs font-medium">
                    <span className="text-slate-700">Duration (sec)</span>
                    <span className="font-mono text-slate-800 font-bold">{duration}s</span>
                  </div>
                  <input
                    type="range"
                    min={0.1}
                    max={30}
                    step={0.1}
                    value={duration}
                    onChange={(e) => setDuration(Number(e.target.value))}
                    className="w-full accent-slate-700"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 pt-2 border-t border-border/50 items-end">
                <label className="sm:col-span-4 space-y-1 text-xs font-semibold text-gray-700">
                  <span>Target Destination</span>
                  <input
                    required
                    value={customTarget}
                    onChange={(e) => setCustomTarget(e.target.value)}
                    placeholder="e.g. api.internal:443"
                    className="block w-full rounded-lg border border-gray-300 px-3 py-2 text-xs font-normal"
                  />
                </label>

                <label className="sm:col-span-3 space-y-1 text-xs font-semibold text-gray-700">
                  <span>Spoofed Source IP (Optional)</span>
                  <input
                    value={customIp}
                    onChange={(e) => setCustomIp(e.target.value)}
                    placeholder="Auto (198.51.100.x)"
                    className="block w-full rounded-lg border border-gray-300 px-3 py-2 text-xs font-normal font-mono"
                  />
                </label>

                <label className="sm:col-span-2 space-y-1 text-xs font-semibold text-gray-700">
                  <span>Burst Waves</span>
                  <select
                    value={burstCount}
                    onChange={(e) => setBurstCount(Number(e.target.value))}
                    className="block w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-xs font-normal"
                  >
                    <option value={1}>1x Flow</option>
                    <option value={3}>3x Burst</option>
                    <option value={5}>5x Wave</option>
                  </select>
                </label>

                <div className="sm:col-span-3">
                  <button
                    type="submit"
                    disabled={simulating || !customTarget.trim()}
                    className="w-full flex items-center justify-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-700 disabled:opacity-50 transition-all shadow-2xs"
                  >
                    {simulating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sliders className="h-3.5 w-3.5" />}
                    <span>{simulating ? "Evaluating..." : "Test Crafted Vector"}</span>
                  </button>
                </div>
              </div>
            </form>
          )}

          {/* TAB 3: AUTOMATED ML BENCHMARK SUITE */}
          {labTab === "benchmark" && (
            <div className="bg-white rounded-xl border border-border p-4 sm:p-5 space-y-4 shadow-2xs">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-border/60 pb-3.5">
                <div>
                  <h3 className="text-xs font-bold text-foreground flex items-center gap-1.5">
                    <Gauge className="w-4 h-4 text-primary" />
                    Automated Adversarial Detection & Throughput Benchmark
                  </h3>
                  <p className="text-[11px] text-muted mt-0.5">
                    Tests 10 multi-class telemetry vectors (DoS, Brute Force, Port Scan, Normal) to benchmark precision & latency
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2.5">
                  <input
                    value={benchmarkTarget}
                    onChange={(e) => setBenchmarkTarget(e.target.value)}
                    placeholder="Target label"
                    className="rounded-lg border border-gray-300 px-3 py-1.5 text-xs w-36"
                  />
                  <label className="inline-flex items-center gap-1.5 text-xs text-slate-700 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={benchmarkLogEvents}
                      onChange={(e) => setBenchmarkLogEvents(e.target.checked)}
                      className="accent-primary"
                    />
                    <span>Record to SOC stream</span>
                  </label>
                  <button
                    type="button"
                    onClick={runBenchmarkSuite}
                    disabled={benchmarkRunning}
                    className="flex items-center gap-1.5 rounded-lg bg-primary hover:bg-blue-700 px-4 py-2 text-xs font-semibold text-white transition-all shadow-2xs disabled:opacity-50"
                  >
                    {benchmarkRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                    <span>{benchmarkRunning ? "Running Suite..." : "Run 10-Vector Benchmark"}</span>
                  </button>
                </div>
              </div>

              {benchmarkSummary && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                    <div className="p-3 rounded-xl border border-emerald-200 bg-emerald-50/50">
                      <span className="text-[10px] font-semibold uppercase text-emerald-700">Suite Accuracy</span>
                      <div className="text-xl font-bold font-mono text-emerald-700 mt-0.5">
                        {benchmarkSummary.accuracy_pct}%
                      </div>
                      <span className="text-[11px] text-emerald-800/80">
                        {benchmarkSummary.matched}/{benchmarkSummary.total_vectors} matched
                      </span>
                    </div>
                    <div className="p-3 rounded-xl border border-blue-200 bg-blue-50/50">
                      <span className="text-[10px] font-semibold uppercase text-blue-700">Avg Confidence</span>
                      <div className="text-xl font-bold font-mono text-blue-700 mt-0.5">
                        {benchmarkSummary.avg_confidence_pct}%
                      </div>
                      <span className="text-[11px] text-blue-800/80">RF-IDS probability</span>
                    </div>
                    <div className="p-3 rounded-xl border border-purple-200 bg-purple-50/50">
                      <span className="text-[10px] font-semibold uppercase text-purple-700">Avg Inference</span>
                      <div className="text-xl font-bold font-mono text-purple-700 mt-0.5">
                        {benchmarkSummary.avg_inference_ms} ms
                      </div>
                      <span className="text-[11px] text-purple-800/80">Per flow vector</span>
                    </div>
                    <div className="p-3 rounded-xl border border-amber-200 bg-amber-50/50">
                      <span className="text-[10px] font-semibold uppercase text-amber-700">Throughput</span>
                      <div className="text-xl font-bold font-mono text-amber-700 mt-0.5">
                        {benchmarkSummary.throughput_eps} ev/s
                      </div>
                      <span className="text-[11px] text-amber-800/80">Sustained rate</span>
                    </div>
                    <div className="p-3 rounded-xl border border-slate-200 bg-slate-50">
                      <span className="text-[10px] font-semibold uppercase text-slate-600">Total Elapsed</span>
                      <div className="text-xl font-bold font-mono text-slate-900 mt-0.5">
                        {benchmarkSummary.total_elapsed_ms} ms
                      </div>
                      <span className="text-[11px] text-slate-500">10-vector batch</span>
                    </div>
                  </div>

                  <div className="overflow-x-auto border border-border rounded-xl">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-slate-50 text-[11px] uppercase text-muted border-b border-border">
                        <tr>
                          <th className="px-3.5 py-2.5 font-semibold">Attack Vector</th>
                          <th className="px-3.5 py-2.5 font-semibold">MITRE</th>
                          <th className="px-3.5 py-2.5 font-semibold">Expected</th>
                          <th className="px-3.5 py-2.5 font-semibold">RF-IDS Predicted</th>
                          <th className="px-3.5 py-2.5 font-semibold">Confidence</th>
                          <th className="px-3.5 py-2.5 font-semibold">Latency</th>
                          <th className="px-3.5 py-2.5 font-semibold text-right">Match</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border bg-white">
                        {benchmarkRows.map((row) => (
                          <tr key={row.id} className="hover:bg-slate-50/80">
                            <td className="px-3.5 py-2 font-medium text-foreground">{row.name}</td>
                            <td className="px-3.5 py-2 font-mono text-[11px] text-muted">{row.mitre_id}</td>
                            <td className="px-3.5 py-2 font-mono text-slate-700">{row.expected}</td>
                            <td className="px-3.5 py-2 font-semibold text-slate-900">{row.predicted}</td>
                            <td className="px-3.5 py-2 font-mono">{row.confidence}%</td>
                            <td className="px-3.5 py-2 font-mono text-muted">{row.inference_ms}ms</td>
                            <td className="px-3.5 py-2 text-right">
                              {row.matched ? (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-bold">
                                  <CheckCircle2 className="w-3 h-3" /> PASS
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 text-[10px] font-bold">
                                  MISS
                                </span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Error Banner */}
          {error && (
            <p role="alert" className="flex items-center gap-2 text-xs text-red-700 bg-red-50 border border-red-200 rounded-xl px-3.5 py-2.5">
              <AlertCircle className="h-4 w-4 shrink-0" /> {error}
            </p>
          )}

          {/* Live Telemetry & ML Feature Attribution Inspector for Last Run */}
          {lastResult && labTab !== "benchmark" && (
            <div
              role="status"
              className="rounded-xl border border-blue-200 bg-white p-4 shadow-2xs space-y-3"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-600" />
                  <span className="text-xs font-bold text-slate-900">
                    {lastResult.scenario} → <code className="font-mono text-primary">{lastResult.target}</code>
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      lastResult.analysis.severity === "CRITICAL"
                        ? "bg-rose-50 text-rose-700 border-rose-200"
                        : lastResult.analysis.severity === "HIGH"
                        ? "bg-amber-50 text-amber-700 border-amber-200"
                        : lastResult.analysis.severity === "MEDIUM"
                        ? "bg-blue-50 text-blue-700 border-blue-200"
                        : "bg-emerald-50 text-emerald-700 border-emerald-200"
                    }`}
                  >
                    {lastResult.analysis.prediction} · {lastResult.analysis.severity}
                  </span>
                  <span className="text-xs font-mono font-semibold text-emerald-700">
                    {(lastResult.analysis.confidence * 100).toFixed(1)}% confidence
                  </span>
                  {typeof lastResult.avg_inference_ms === "number" && (
                    <span className="text-[11px] font-mono text-muted">
                      ({lastResult.avg_inference_ms}ms inference · {lastResult.burst_count || 1}x waves)
                    </span>
                  )}
                </div>

                <Link
                  href={`/assistant?q=Analyze simulated ${lastResult.analysis.prediction} attack targeting ${lastResult.target} (severity ${lastResult.analysis.severity}) and recommend firewall or WAF mitigation rules.`}
                  className="inline-flex items-center gap-1 text-[11px] font-semibold text-primary hover:underline shrink-0"
                >
                  <Sparkles className="w-3 h-3" /> Ask Copilot to Mitigate
                </Link>
              </div>

              {lastResult.analysis.probabilities && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {Object.entries(lastResult.analysis.probabilities).map(([clsName, prob]) => {
                    const pct = Math.round(prob * 1000) / 10;
                    const isWinner = clsName === lastResult.analysis.prediction;
                    return (
                      <div
                        key={clsName}
                        className={`p-2 rounded-lg border text-xs ${
                          isWinner ? "border-blue-300 bg-blue-50/50" : "border-slate-200 bg-slate-50/60"
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-semibold text-[11px] text-slate-700">{clsName}</span>
                          <span className="font-mono font-bold text-[11px] text-slate-900">{pct}%</span>
                        </div>
                        <div className="h-1.5 bg-slate-200 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all duration-500 ${
                              isWinner ? "bg-primary" : "bg-slate-400"
                            }`}
                            style={{ width: `${Math.min(100, pct)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              <div className="text-[11px] text-muted flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-slate-400" />
                {lastResult.logged
                  ? `${lastResult.logged_count || 1} simulated threat event(s) & SOC alert(s) persisted to live monitoring feed.`
                  : "Classified as Low/Normal severity — no threat alert logged."}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
