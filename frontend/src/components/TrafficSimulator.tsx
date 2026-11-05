"use client";

import { useEffect, useState } from "react";
import { AlertCircle, Loader2, Zap } from "lucide-react";
import { API_URL, apiFetch } from "@/lib/api";

interface Scenario {
  id: string;
  name: string;
  target: string;
}

export function TrafficSimulator({ onComplete }: { onComplete: () => void }) {
  const [open, setOpen] = useState(false);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [scenarioId, setScenarioId] = useState("");
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");

  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    apiFetch(`${API_URL}/api/threats/simulation-scenarios`, { signal: controller.signal })
      .then((res) => {
        if (!res.ok) throw new Error("Could not load simulation scenarios.");
        return res.json();
      })
      .then((data) => {
        if (!Array.isArray(data.scenarios) || data.scenarios.length === 0) throw new Error("No simulation scenarios are available.");
        if (!controller.signal.aborted) {
          setScenarios(data.scenarios);
          setScenarioId((previous) => previous || data.scenarios[0].id);
          setTarget((previous) => previous || data.scenarios[0].target);
        }
      })
      .catch((err) => {
        if (!controller.signal.aborted) setError(err instanceof Error ? err.message : "Could not load scenarios.");
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [open]);

  function togglePanel() {
    if (!open) {
      setLoading(true);
      setError("");
    }
    setOpen(!open);
  }

  async function simulate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSimulating(true);
    setError("");
    setFeedback("");
    try {
      const response = await apiFetch(`${API_URL}/api/threats/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario: scenarioId, target: target.trim() }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : "Simulation failed.");
      const confidence = (result.analysis.confidence * 100).toFixed(1);
      setFeedback(`${result.scenario} for ${result.target}: classified as ${result.analysis.prediction} (${result.analysis.severity}, ${confidence}% confidence). ${result.logged ? "A simulated threat and alert were recorded." : "No threat was recorded because the classification was low severity."}`);
      onComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Simulation failed.");
    } finally {
      setSimulating(false);
    }
  }

  return (
    <section className="space-y-3" aria-label="Attack traffic simulator">
      <button type="button" onClick={togglePanel} aria-expanded={open} aria-controls="traffic-simulator-form" className="flex items-center gap-1.5 rounded-md bg-red-600 px-3 py-2 text-xs font-semibold text-white shadow-xs transition-colors hover:bg-red-700">
        <Zap className="h-3.5 w-3.5" /> {open ? "Close Simulator" : "Simulate Attack Traffic"}
      </button>
      {open && (
        <div id="traffic-simulator-form" className="space-y-4 rounded-xl border border-red-200 bg-white p-4 shadow-xs sm:p-5">
          <div>
            <h2 className="text-sm font-semibold text-gray-900">Test the intrusion detector</h2>
            <p className="mt-1 text-xs leading-relaxed text-muted">Creates a synthetic traffic record for the selected target label. No network traffic is sent to the target. The model classifies scenarios as brute force, port scan, DoS, or normal.</p>
          </div>
          <form onSubmit={simulate} className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <label className="flex-1 space-y-1 text-xs font-semibold text-gray-700">
              <span>Attack scenario</span>
              <select value={scenarioId} disabled={loading || !scenarios.length || simulating} onChange={(event) => {
                const selected = scenarios.find((item) => item.id === event.target.value);
                setScenarioId(event.target.value);
                if (selected) setTarget(selected.target);
              }} className="block w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm font-normal text-gray-900 disabled:opacity-50">
                {loading && <option>Loading scenarios...</option>}
                {!loading && scenarios.length === 0 && <option>No scenarios available</option>}
                {scenarios.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
              </select>
            </label>
            <label className="flex-1 space-y-1 text-xs font-semibold text-gray-700">
              <span>Target label</span>
              <input required maxLength={200} value={target} onChange={(event) => setTarget(event.target.value)} disabled={simulating || !scenarioId} placeholder="IP address, hostname or service" className="block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm font-normal text-gray-900 disabled:opacity-50" />
            </label>
            <button type="submit" disabled={loading || simulating || !scenarioId || !target.trim()} className="flex items-center justify-center gap-2 rounded-lg bg-red-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-red-700 disabled:opacity-50">
              {simulating && <Loader2 className="h-4 w-4 animate-spin" />} {simulating ? "Simulating..." : "Run simulation"}
            </button>
          </form>
          {error && <p role="alert" className="flex items-center gap-2 text-xs text-red-700"><AlertCircle className="h-4 w-4 shrink-0" /> {error} {scenarios.length === 0 && "Close and reopen the simulator to retry."}</p>}
          {feedback && <p role="status" className="rounded-lg border border-blue-200 bg-blue-50 px-3 py-2 text-xs leading-relaxed text-blue-900">{feedback}</p>}
        </div>
      )}
    </section>
  );
}
