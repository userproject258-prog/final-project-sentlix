"use client";

import Link from "next/link";
import { API_URL, apiFetch as fetch } from "@/lib/api";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import {
  Activity,
  AlertCircle,
  ArrowRight,
  Bell,
  Check,
  CheckCircle2,
  Cloud,
  Copy,
  Cpu,
  ExternalLink,
  Eye,
  EyeOff,
  Key,
  Layers,
  Lock,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Settings,
  Shield,
  Sliders,
  Sparkles,
  Terminal,
  Trash2,
  User as UserIcon,
  Webhook,
  X,
  XCircle,
  Zap,
} from "lucide-react";

interface Integration {
  id?: string;
  name: string;
  category?: string;
  account?: string;
  region?: string;
  status: string;
  last_sync: string;
}

interface AIConfig {
  configured: boolean;
  key_present: boolean;
  masked_key: string;
  provider?: string;
  available_providers?: string[];
  engine: string;
  model: string;
}

interface MLEngineInfo {
  name: string;
  version: string;
  accuracy: number;
  classifier: string;
}

interface AlertPolicies {
  emailCritical: boolean;
  slackWebhook: boolean;
  autoAlertIds: boolean;
  weeklyDigest: boolean;
  strictCspmDrift: boolean;
}

interface UserProfile {
  id: number;
  name: string;
  email: string;
  role: string;
  created_at?: string | null;
  active_sessions: number;
}

interface ApiTokenItem {
  id: string;
  label: string;
  prefix: string;
  token?: string;
  scopes: string[];
  created: string;
  lastUsed: string;
}

type SettingsTab = "overview" | "ai" | "integrations" | "api" | "profile";
type IntegrationFilter = "All" | "Connected" | "Disconnected";
type ResponseMode = "deep" | "executive" | "concise";
type AccentColor = "blue" | "emerald" | "indigo" | "amber" | "rose";

const DEFAULT_POLICIES: AlertPolicies = {
  emailCritical: true,
  slackWebhook: true,
  autoAlertIds: true,
  weeklyDigest: false,
  strictCspmDrift: true,
};

const DEFAULT_TOKENS: ApiTokenItem[] = [
  {
    id: "tok-1",
    label: "GitHub Actions CI/CD Runner",
    prefix: "sx_live_94f8a2••••••••••c71e",
    scopes: ["ci:scan", "findings:write"],
    created: "14 days ago",
    lastUsed: "2 mins ago",
  },
  {
    id: "tok-2",
    label: "Terraform CSPM State Collector",
    prefix: "sx_live_31b0e4••••••••••89a2",
    scopes: ["cspm:read", "cspm:remediate"],
    created: "30 days ago",
    lastUsed: "1 hour ago",
  },
];

const ALL_TOKEN_SCOPES = ["ci:scan", "findings:write", "threats:write", "cspm:read", "cspm:remediate"];
const TOKENS_STORAGE_KEY = "sentinelx_api_tokens_v1";
const MODE_STORAGE_KEY = "sentinelx_assistant_mode";

const ACCENT_MAP: Record<AccentColor, { border: string; glow: string; bar: string; shadow: string }> = {
  blue: {
    border: "hover:border-blue-400/70",
    glow: "rgba(37, 99, 235, 0.08)",
    bar: "via-blue-500",
    shadow: "hover:shadow-blue-500/10",
  },
  emerald: {
    border: "hover:border-emerald-400/70",
    glow: "rgba(16, 185, 129, 0.08)",
    bar: "via-emerald-500",
    shadow: "hover:shadow-emerald-500/10",
  },
  indigo: {
    border: "hover:border-indigo-400/70",
    glow: "rgba(99, 102, 241, 0.08)",
    bar: "via-indigo-500",
    shadow: "hover:shadow-indigo-500/10",
  },
  amber: {
    border: "hover:border-amber-400/70",
    glow: "rgba(245, 158, 11, 0.09)",
    bar: "via-amber-500",
    shadow: "hover:shadow-amber-500/10",
  },
  rose: {
    border: "hover:border-rose-400/70",
    glow: "rgba(244, 63, 94, 0.08)",
    bar: "via-rose-500",
    shadow: "hover:shadow-rose-500/10",
  },
};

function handleCardMouseMove(e: React.MouseEvent<HTMLElement>) {
  const rect = e.currentTarget.getBoundingClientRect();
  e.currentTarget.style.setProperty("--mouse-x", `${e.clientX - rect.left}px`);
  e.currentTarget.style.setProperty("--mouse-y", `${e.clientY - rect.top}px`);
}

function getProviderMonogram(int: Integration): { code: string; badgeClass: string } {
  const lower = `${int.id || ""} ${int.name}`.toLowerCase();
  if (lower.includes("aws") || lower.includes("amazon")) {
    return { code: "AWS", badgeClass: "bg-amber-50 text-amber-700 border-amber-200" };
  }
  if (lower.includes("gcp") || lower.includes("google")) {
    return { code: "GCP", badgeClass: "bg-blue-50 text-blue-700 border-blue-200" };
  }
  if (lower.includes("github")) {
    return { code: "GH", badgeClass: "bg-slate-100 text-slate-800 border-slate-300" };
  }
  if (lower.includes("slack")) {
    return { code: "SLK", badgeClass: "bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200" };
  }
  if (lower.includes("azure")) {
    return { code: "AZ", badgeClass: "bg-sky-50 text-sky-700 border-sky-200" };
  }
  return { code: "API", badgeClass: "bg-indigo-50 text-indigo-700 border-indigo-200" };
}

function formatAiBadgeLabel(aiConfig: AIConfig): string {
  if (!aiConfig.configured) return "Local Summary Mode";
  const provider = aiConfig.provider && aiConfig.provider !== "Local Summary Mode" ? aiConfig.provider : "AI Engine";
  return `${provider} Active`;
}

function SpotlightCard({
  accent = "blue",
  hoverLift = false,
  className = "",
  children,
}: {
  accent?: AccentColor;
  hoverLift?: boolean;
  className?: string;
  children: ReactNode;
}) {
  const palette = ACCENT_MAP[accent];
  return (
    <div
      onMouseMove={handleCardMouseMove}
      className={`relative overflow-hidden group bg-surface border border-gray-200/90 ${palette.border} rounded-2xl shadow-xs hover:shadow-lg ${palette.shadow} ${
        hoverLift ? "hover:-translate-y-1.5" : "hover:-translate-y-0.5"
      } transition-all duration-300 ease-out ${className}`}
    >
      <div
        className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{
          background: `radial-gradient(360px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), ${palette.glow}, transparent 80%)`,
        }}
      />
      <div
        className={`pointer-events-none absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent ${palette.bar} to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center z-20`}
      />
      {children}
    </div>
  );
}

function ToggleSwitch({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary/30 ${
        checked ? "bg-primary" : "bg-gray-200"
      }`}
    >
      <span
        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-0 transition duration-200 ease-in-out ${
          checked ? "translate-x-4" : "translate-x-0"
        }`}
      />
    </button>
  );
}

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<SettingsTab>("overview");
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [integrationSearch, setIntegrationSearch] = useState("");
  const [integrationFilter, setIntegrationFilter] = useState<IntegrationFilter>("All");
  const [syncingAll, setSyncingAll] = useState(false);

  const [aiConfig, setAiConfig] = useState<AIConfig>({
    configured: false,
    key_present: false,
    masked_key: "Loading...",
    provider: "Checking...",
    available_providers: [],
    engine: "Checking...",
    model: "gemini-2.5-flash",
  });
  const [mlEngine, setMlEngine] = useState<MLEngineInfo>({
    name: "RF-IDS",
    version: "1.0.4",
    accuracy: 94.2,
    classifier: "Random Forest Classifier Active",
  });
  const [userProfile, setUserProfile] = useState<UserProfile>({
    id: 1,
    name: "Security Administrator",
    email: "admin@sentinelx.io",
    role: "Lead Security Administrator",
    active_sessions: 1,
  });

  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<{ message: string; type: "success" | "info" | "error" } | null>(null);

  // AI Key & Default Mode state
  const [newAiKey, setNewAiKey] = useState("");
  const [showKeyInput, setShowKeyInput] = useState(false);
  const [savingAiKey, setSavingAiKey] = useState(false);
  const [testingAiKey, setTestingAiKey] = useState(false);
  const [defaultAssistantMode, setDefaultAssistantMode] = useState<ResponseMode>("deep");

  // Integration action state
  const [busyIntegration, setBusyIntegration] = useState<string | null>(null);

  // API Tokens & Webhooks state
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [newTokenLabel, setNewTokenLabel] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<string[]>(["ci:scan", "threats:write", "cspm:read"]);
  const [latestCreatedToken, setLatestCreatedToken] = useState<{ label: string; token: string } | null>(null);
  const [testingWebhook, setTestingWebhook] = useState(false);
  const [webhookLastResult, setWebhookLastResult] = useState<{
    ok: boolean;
    message: string;
    timestamp: string;
  } | null>(null);
  const [snippetTab, setSnippetTab] = useState<"curl" | "github">("curl");
  const [apiTokens, setApiTokens] = useState<ApiTokenItem[]>(DEFAULT_TOKENS);

  // Profile & Preferences state
  const [editName, setEditName] = useState("");
  const [savingProfile, setSavingProfile] = useState(false);
  const [prefs, setPrefs] = useState<AlertPolicies>(DEFAULT_POLICIES);
  const [savingPrefs, setSavingPrefs] = useState(false);

  const connectedCount = integrations.filter((i) => i.status === "Connected").length;
  const connectorPct = integrations.length > 0 ? Math.round((connectedCount / integrations.length) * 100) : 0;
  const enabledPoliciesCount = Object.values(prefs).filter(Boolean).length;

  const showToast = useCallback((message: string, type: "success" | "info" | "error" = "success") => {
    setToast({ message, type });
    setTimeout(() => {
      setToast((prev) => (prev?.message === message ? null : prev));
    }, 4500);
  }, []);

  const applySettingsPayload = useCallback((data: Record<string, unknown>) => {
    if (Array.isArray(data.integrations)) {
      setIntegrations(data.integrations as Integration[]);
    }
    if (data.ai_config && typeof data.ai_config === "object") {
      setAiConfig(data.ai_config as AIConfig);
    }
    if (data.ml_engine && typeof data.ml_engine === "object") {
      setMlEngine(data.ml_engine as MLEngineInfo);
    }
    if (data.policies && typeof data.policies === "object") {
      setPrefs(data.policies as AlertPolicies);
    }
    if (data.user && typeof data.user === "object") {
      const u = data.user as UserProfile;
      setUserProfile(u);
      setEditName(u.name);
    }
  }, []);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/settings`);
      if (res.ok) {
        const data = await res.json();
        applySettingsPayload(data);
        showToast("Control plane telemetry refreshed.", "info");
      }
    } catch (err) {
      console.error("Failed to fetch settings:", err);
      showToast("Failed to refresh settings telemetry.", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let isCancelled = false;

    const loadInitial = async () => {
      try {
        if (typeof window !== "undefined") {
          const savedTokens = localStorage.getItem(TOKENS_STORAGE_KEY);
          if (savedTokens) {
            const parsed = JSON.parse(savedTokens);
            if (Array.isArray(parsed)) setApiTokens(parsed as ApiTokenItem[]);
          }
          const savedMode = localStorage.getItem(MODE_STORAGE_KEY);
          if (savedMode === "deep" || savedMode === "executive" || savedMode === "concise") {
            setDefaultAssistantMode(savedMode);
          }
        }
      } catch {
        // Ignore storage read errors
      }

      try {
        const res = await fetch(`${API_URL}/api/settings`);
        if (!isCancelled && res.ok) {
          const data = await res.json();
          applySettingsPayload(data);
        }
      } catch (err) {
        console.error("Failed to fetch settings:", err);
      } finally {
        if (!isCancelled) setLoading(false);
      }
    };

    void loadInitial();
    return () => {
      isCancelled = true;
    };
  }, [applySettingsPayload]);

  const persistTokens = (tokens: ApiTokenItem[]) => {
    setApiTokens(tokens);
    try {
      if (typeof window !== "undefined") {
        // Persist masked prefixes for already-saved tokens; keep session value clean
        const sanitized = tokens.map((item) => {
          const rest = { ...item };
          delete rest.token;
          return rest;
        });
        localStorage.setItem(TOKENS_STORAGE_KEY, JSON.stringify(sanitized));
      }
    } catch {
      // Ignore storage write errors
    }
  };

  const copyText = (text: string, id: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    showToast("Copied to clipboard", "info");
    setTimeout(() => setCopiedId((cur) => (cur === id ? null : cur)), 2000);
  };

  const handleAssistantModeChange = (mode: ResponseMode) => {
    setDefaultAssistantMode(mode);
    try {
      if (typeof window !== "undefined") {
        localStorage.setItem(MODE_STORAGE_KEY, mode);
      }
    } catch {
      // Ignore storage errors
    }
    showToast(`Default Copilot mode set to "${mode}".`, "info");
  };

  const handleUpdateAiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAiKey.trim()) return;
    setSavingAiKey(true);
    try {
      const res = await fetch(`${API_URL}/api/settings/ai-key`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ api_key: newAiKey.trim() }),
      });
      const data = await res.json();
      if (res.ok) {
        setAiConfig((prev) => ({
          ...prev,
          configured: !!data.configured,
          key_present: true,
          masked_key: data.masked_key || prev.masked_key,
          provider: data.provider || prev.provider,
          available_providers: Array.isArray(data.available_providers) ? data.available_providers : prev.available_providers,
          engine: data.engine || prev.engine,
        }));
        setNewAiKey("");
        if (data.configured) {
          showToast(`${data.provider || "AI"} key verified & activated! Copilot is now live.`, "success");
        } else {
          showToast("Key saved, but provider verification failed. Failover / Local Summary active.", "error");
        }
      }
    } catch {
      showToast("Could not update AI key.", "error");
    } finally {
      setSavingAiKey(false);
    }
  };

  const handleVerifyAiConnection = async () => {
    setTestingAiKey(true);
    try {
      const res = await fetch(`${API_URL}/api/assistant/status`);
      const data = await res.json();
      const isOk = !!data.gemini_api_key_configured;
      const providerName = typeof data.provider === "string" ? data.provider : isOk ? "AI Engine" : "Local Summary Mode";
      const engineName =
        typeof data.engine === "string"
          ? data.engine
          : isOk
          ? `${providerName} Active`
          : "Local recorded-data summary";
      setAiConfig((prev) => ({
        ...prev,
        configured: isOk,
        key_present: !!data.key_present,
        provider: providerName,
        available_providers: Array.isArray(data.available_providers) ? data.available_providers : prev.available_providers,
        engine: engineName,
      }));
      if (isOk) {
        showToast(`AI Copilot connection verified — ${providerName} (${engineName}) is healthy & reachable.`, "success");
      } else {
        showToast("No reachable AI provider key detected — running in Local Summary Mode.", "error");
      }
    } catch {
      showToast("Failed to reach AI status endpoint.", "error");
    } finally {
      setTestingAiKey(false);
    }
  };

  const handleIntegrationAction = async (name: string, action: "toggle" | "sync") => {
    setBusyIntegration(`${name}-${action}`);
    try {
      const res = await fetch(`${API_URL}/api/settings/integrations`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, action }),
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.integrations)) {
          setIntegrations(data.integrations);
        }
        showToast(
          action === "sync"
            ? `Synchronized live telemetry with ${name}.`
            : `Updated connection status for ${name}.`,
          "success"
        );
      }
    } catch {
      showToast(`Failed to update ${name}.`, "error");
    } finally {
      setBusyIntegration(null);
    }
  };

  const handleSyncAllIntegrations = async () => {
    setSyncingAll(true);
    try {
      const res = await fetch(`${API_URL}/api/settings/integrations/sync-all`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.integrations)) {
          setIntegrations(data.integrations);
        }
        showToast(`Synchronized ${data.synced ?? connectedCount} connected connector(s).`, "success");
      }
    } catch {
      showToast("Failed to batch-sync connectors.", "error");
    } finally {
      setSyncingAll(false);
    }
  };

  const toggleScope = (scope: string) => {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? (prev.length > 1 ? prev.filter((s) => s !== scope) : prev) : [...prev, scope]
    );
  };

  const handleGenerateToken = (e: React.FormEvent) => {
    e.preventDefault();
    const label = newTokenLabel.trim() || `CI/CD Pipeline Key #${apiTokens.length + 1}`;
    const randomHex = Array.from({ length: 24 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
    const fullToken = `sx_live_${randomHex}`;
    const prefix = `sx_live_${randomHex.slice(0, 6)}••••••••••${randomHex.slice(-4)}`;
    const newItem: ApiTokenItem = {
      id: `tok-${Date.now()}`,
      label,
      prefix,
      token: fullToken,
      scopes: [...selectedScopes],
      created: "Just now",
      lastUsed: "Never",
    };
    persistTokens([newItem, ...apiTokens]);
    setLatestCreatedToken({ label, token: fullToken });
    setNewTokenLabel("");
    showToast(`Generated scoped API token "${label}". Copy it now — secret shown once.`, "success");
  };

  const handleRevokeToken = (id: string, label: string) => {
    persistTokens(apiTokens.filter((t) => t.id !== id));
    showToast(`Revoked API token "${label}".`, "info");
  };

  const handleTriggerWebhookTest = async () => {
    setTestingWebhook(true);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/webhook`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pusher: { email: userProfile.email },
          ref: "refs/heads/main",
          head_commit: { id: "9677d11", message: "Manual webhook verification from Settings" },
        }),
      });
      const now = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      if (res.ok) {
        setWebhookLastResult({
          ok: true,
          message: `HTTP ${res.status} OK — CI/CD pipeline trigger recorded`,
          timestamp: now,
        });
        showToast("Test CI/CD webhook dispatched! Pipeline scan recorded.", "success");
      } else {
        setWebhookLastResult({
          ok: false,
          message: `HTTP ${res.status} — Webhook test rejected`,
          timestamp: now,
        });
        showToast("Webhook test returned an error.", "error");
      }
    } catch {
      const now = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      setWebhookLastResult({
        ok: false,
        message: "Connection failed while dispatching test webhook",
        timestamp: now,
      });
      showToast("Failed to trigger test webhook.", "error");
    } finally {
      setTestingWebhook(false);
    }
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editName.trim()) return;
    setSavingProfile(true);
    try {
      const res = await fetch(`${API_URL}/api/auth/profile`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: editName.trim() }),
      });
      if (res.ok) {
        const data = await res.json();
        setUserProfile((prev) => ({ ...prev, name: data.user.name }));
        if (typeof window !== "undefined") {
          const existing = localStorage.getItem("sentinelx_user");
          const parsed = existing ? JSON.parse(existing) : {};
          localStorage.setItem("sentinelx_user", JSON.stringify({ ...parsed, name: data.user.name }));
          window.dispatchEvent(new CustomEvent("sentinelx-user-updated"));
        }
        showToast("Operator display identity updated across workspace.", "success");
      }
    } catch {
      showToast("Failed to update operator profile.", "error");
    } finally {
      setSavingProfile(false);
    }
  };

  const handleSavePreferences = async (nextPolicies?: AlertPolicies) => {
    const payload = nextPolicies ?? prefs;
    setSavingPrefs(true);
    try {
      const res = await fetch(`${API_URL}/api/settings/policies`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.policies) setPrefs(data.policies as AlertPolicies);
        showToast("Security & notification policies saved to control plane.", "success");
      } else {
        showToast("Could not persist policies on server.", "error");
      }
    } catch {
      showToast("Failed to update alerting policies.", "error");
    } finally {
      setSavingPrefs(false);
    }
  };

  const query = integrationSearch.trim().toLowerCase();
  const filteredIntegrations = integrations.filter((item) => {
    if (integrationFilter !== "All" && item.status !== integrationFilter) return false;
    if (!query) return true;
    return [item.name, item.category || "", item.account || "", item.region || ""].some((v) =>
      v.toLowerCase().includes(query)
    );
  });

  const webhookEndpoint = `${API_URL}/api/devsecops/webhook`;
  const curlSnippet = `curl -X POST "${webhookEndpoint}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"ref":"refs/heads/main","pusher":{"email":"${userProfile.email}"},"head_commit":{"id":"HEAD","message":"CI security scan"}}'`;
  const githubYamlSnippet = `- name: Trigger SentinelX DevSecOps Audit\n  run: |\n    curl -fsSL -X POST "${webhookEndpoint}" \\\n      -H "Content-Type: application/json" \\\n      -d '{"ref":"refs/heads/main","pusher":{"email":"\${{ github.actor }}@users.noreply.github.com"}}'`;

  const detectedProviders = aiConfig.available_providers || [];
  const baseProviders = ["Groq", "Google Gemini", "xAI Grok", "OpenAI"];
  const providerChain = [...detectedProviders, ...baseProviders.filter((p) => !detectedProviders.includes(p))].map(
    (name) => ({
      name,
      detected: detectedProviders.includes(name),
      active: aiConfig.configured && aiConfig.provider === name,
    })
  );

  /* ---------------- Modular Section Blocks ---------------- */

  const aiCopilotCard = (
    <SpotlightCard accent="amber" className="w-full">
      <div className="relative z-10 px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-slate-50 via-white to-amber-50/30 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-xl bg-amber-50 border border-amber-200 flex items-center justify-center shrink-0">
            <Sparkles className="w-4 h-4 text-amber-600" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-gray-900">AI Copilot & Multi-Provider LLM Engine</h2>
            <p className="text-[11px] text-muted">
              Automatic key failover across Groq, Google Gemini, xAI Grok & OpenAI before Local Summary fallback
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={handleVerifyAiConnection}
          disabled={testingAiKey}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-gray-200 bg-white hover:bg-gray-50 hover:border-blue-300 text-gray-700 transition-all shadow-2xs disabled:opacity-50"
        >
          <Activity className={`w-3.5 h-3.5 text-primary ${testingAiKey ? "animate-spin" : ""}`} />
          {testingAiKey ? "Verifying..." : "Test Live Connection"}
        </button>
      </div>

      <div className="relative z-10 p-5 space-y-5">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 bg-slate-50/80 border border-slate-200/80 rounded-xl p-3.5 text-xs">
          <div>
            <span className="text-[11px] text-muted block">Active Provider Status</span>
            <span
              className={`inline-flex items-center gap-1.5 font-bold mt-1 ${
                aiConfig.configured ? "text-emerald-700" : "text-amber-700"
              }`}
            >
              {aiConfig.configured ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  {formatAiBadgeLabel(aiConfig)}
                </>
              ) : (
                <>
                  <AlertCircle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                  Local Summary Mode
                </>
              )}
            </span>
          </div>
          <div>
            <span className="text-[11px] text-muted block">Active Key (Masked)</span>
            <span className="font-mono font-semibold text-gray-800 mt-1 block truncate">{aiConfig.masked_key}</span>
          </div>
          <div>
            <span className="text-[11px] text-muted block">Inference Engine</span>
            <span className="font-mono font-semibold text-indigo-700 mt-1 block truncate">{aiConfig.engine}</span>
          </div>
        </div>

        {/* Failover Order Preview */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-[11px]">
            <span className="font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-primary" /> Provider Failover Chain
            </span>
            <span className="text-muted">
              {(aiConfig.available_providers?.length || 0) > 0
                ? `${aiConfig.available_providers?.length} configured key(s) detected`
                : "No live cloud API key active"}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {providerChain.map((item, idx) => (
              <div key={item.name} className="flex items-center gap-1.5">
                <span
                  className={`inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-1 rounded-lg border ${
                    item.active
                      ? "bg-emerald-50 text-emerald-700 border-emerald-200 shadow-2xs"
                      : item.detected
                      ? "bg-blue-50 text-blue-700 border-blue-200"
                      : "bg-gray-50 text-gray-500 border-gray-200"
                  }`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      item.active ? "bg-emerald-500 animate-pulse" : item.detected ? "bg-blue-500" : "bg-gray-300"
                    }`}
                  />
                  {item.name}
                  {item.active && <span className="text-[9px] uppercase font-bold opacity-80">• Primary</span>}
                </span>
                {idx < providerChain.length - 1 && <ArrowRight className="w-3 h-3 text-gray-400" />}
              </div>
            ))}
            <ArrowRight className="w-3 h-3 text-gray-400" />
            <span
              className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2.5 py-1 rounded-lg border ${
                !aiConfig.configured
                  ? "bg-amber-50 text-amber-800 border-amber-300"
                  : "bg-slate-50 text-slate-600 border-slate-200"
              }`}
            >
              Local Summary Fallback
            </span>
          </div>
        </div>

        {/* Runtime Key Updater */}
        <form onSubmit={handleUpdateAiKey} className="space-y-2.5 pt-1 border-t border-gray-100">
          <label className="block text-xs font-semibold text-gray-700">
            Configure Runtime Provider Key (
            <code className="px-1 py-0.5 rounded bg-slate-100 text-indigo-700 font-mono">GROQ</code> /{" "}
            <code className="px-1 py-0.5 rounded bg-slate-100 text-indigo-700 font-mono">GEMINI</code> /{" "}
            <code className="px-1 py-0.5 rounded bg-slate-100 text-indigo-700 font-mono">XAI</code> /{" "}
            <code className="px-1 py-0.5 rounded bg-slate-100 text-indigo-700 font-mono">OPENAI</code>)
          </label>
          <div className="flex flex-col sm:flex-row gap-2.5">
            <div className="relative flex-1">
              <input
                type={showKeyInput ? "text" : "password"}
                value={newAiKey}
                onChange={(e) => setNewAiKey(e.target.value)}
                placeholder="Paste Groq (gsk_...), AI Studio (AIza...), Vertex (AQ...), xAI (xai-...), or OpenAI (sk-...) key"
                className="w-full pl-3.5 pr-9 py-2 text-xs font-mono bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/30 focus:bg-white transition-colors text-gray-900"
              />
              <button
                type="button"
                onClick={() => setShowKeyInput((v) => !v)}
                aria-label={showKeyInput ? "Hide key" : "Reveal key"}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-700"
              >
                {showKeyInput ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <button
              type="submit"
              disabled={!newAiKey.trim() || savingAiKey}
              className="px-4 py-2 bg-primary hover:bg-blue-700 text-white rounded-lg text-xs font-semibold transition-all shadow-2xs disabled:opacity-50 shrink-0"
            >
              {savingAiKey ? "Validating..." : "Save & Verify Key"}
            </button>
          </div>
          <p className="text-[11px] text-muted">
            Keys are routed automatically by prefix without overwriting secondary backup providers in runtime failover.
          </p>
        </form>
      </div>
    </SpotlightCard>
  );

  const aiPreferencesSideCard = (
    <SpotlightCard accent="indigo" className="p-5 space-y-4">
      <div className="flex items-center gap-2.5">
        <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200 flex items-center justify-center">
          <Sliders className="w-4 h-4 text-indigo-600" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-gray-900">Default Copilot Brief Style</h3>
          <p className="text-[11px] text-muted">Applied automatically when opening AI Assistant</p>
        </div>
      </div>

      <div className="space-y-2">
        {[
          {
            id: "deep" as const,
            title: "Deep Technical Analysis",
            desc: "Full mitigation configs, CLI verification steps & MITRE ATT&CK mapping",
          },
          {
            id: "executive" as const,
            title: "Executive Security Brief",
            desc: "Risk posture summary, business impact & prioritized action plan",
          },
          {
            id: "concise" as const,
            title: "Concise Triage",
            desc: "High-signal bullet remediation for fast SOC response",
          },
        ].map((modeOpt) => {
          const active = defaultAssistantMode === modeOpt.id;
          return (
            <button
              key={modeOpt.id}
              type="button"
              onClick={() => handleAssistantModeChange(modeOpt.id)}
              className={`w-full text-left p-3 rounded-xl border transition-all ${
                active
                  ? "bg-indigo-50/80 border-indigo-300 shadow-2xs"
                  : "bg-slate-50/60 border-gray-200 hover:bg-white hover:border-gray-300"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className={`text-xs font-bold ${active ? "text-indigo-800" : "text-gray-900"}`}>
                  {modeOpt.title}
                </span>
                {active && (
                  <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-indigo-600 text-white">
                    Default
                  </span>
                )}
              </div>
              <p className="text-[11px] text-muted mt-1">{modeOpt.desc}</p>
            </button>
          );
        })}
      </div>

      <Link
        href="/assistant"
        className="w-full inline-flex items-center justify-center gap-2 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold transition-colors"
      >
        Launch AI Copilot <ArrowRight className="w-3.5 h-3.5" />
      </Link>
    </SpotlightCard>
  );

  const integrationsCard = (
    <SpotlightCard accent="blue" className="w-full">
      <div className="relative z-10 px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-slate-50 via-white to-blue-50/30 flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center shrink-0">
              <Cloud className="w-4 h-4 text-blue-600" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-gray-900">Cloud CSPM & DevSecOps Connectors</h2>
              <p className="text-[11px] text-muted">
                Active telemetry streams for cloud posture checks, container scanning, and incident alerting
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
              {connectedCount} / {integrations.length || 5} Active
            </span>
            <button
              type="button"
              onClick={handleSyncAllIntegrations}
              disabled={syncingAll || connectedCount === 0}
              className="flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold bg-white border border-gray-200 hover:bg-gray-50 hover:border-blue-300 text-gray-700 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-primary ${syncingAll ? "animate-spin" : ""}`} />
              {syncingAll ? "Syncing All..." : "Sync All Active"}
            </button>
          </div>
        </div>

        {/* Search & Filter Row */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <div className="relative flex-1 max-w-sm">
            <Search className="w-3.5 h-3.5 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={integrationSearch}
              onChange={(e) => setIntegrationSearch(e.target.value)}
              placeholder="Filter connectors by name, region, account..."
              className="w-full pl-8 pr-7 py-1.5 text-xs bg-white border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/25 text-gray-900"
            />
            {integrationSearch && (
              <button
                type="button"
                onClick={() => setIntegrationSearch("")}
                aria-label="Clear search"
                className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-700"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <div className="inline-flex items-center gap-1 bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-[11px] font-semibold self-start sm:self-auto">
            {(["All", "Connected", "Disconnected"] as const).map((statusOpt) => (
              <button
                key={statusOpt}
                type="button"
                onClick={() => setIntegrationFilter(statusOpt)}
                className={`px-2.5 py-1 rounded-md transition-all ${
                  integrationFilter === statusOpt
                    ? "bg-white text-primary shadow-2xs"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                {statusOpt}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="relative z-10 divide-y divide-gray-100">
        {filteredIntegrations.length === 0 ? (
          <div className="p-8 text-center text-xs text-muted">
            No connectors match the current filter criteria.
          </div>
        ) : (
          filteredIntegrations.map((int, i) => {
            const isConnected = int.status === "Connected";
            const isSyncing = busyIntegration === `${int.name}-sync`;
            const isToggling = busyIntegration === `${int.name}-toggle`;
            const badge = getProviderMonogram(int);
            return (
              <div
                key={int.id || i}
                className="p-4 sm:px-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-50/70 transition-colors"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <div
                    className={`w-10 h-10 rounded-xl border font-mono text-[11px] font-bold flex items-center justify-center shrink-0 ${badge.badgeClass}`}
                  >
                    {badge.code}
                  </div>
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-sm font-semibold text-gray-900">{int.name}</h3>
                      {int.category && (
                        <span className="text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                          {int.category}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2.5 text-xs text-muted flex-wrap">
                      {int.account && (
                        <span className="font-mono text-[11px] text-gray-600 bg-gray-100 px-1.5 py-0.5 rounded truncate max-w-[230px]">
                          {int.account}
                        </span>
                      )}
                      {int.region && <span>Region: {int.region}</span>}
                      <span>• Last sync: {int.last_sync}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2.5 self-end sm:self-center shrink-0">
                  {isConnected ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                      Connected
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-gray-100 text-gray-600 border border-gray-200">
                      <XCircle className="w-3.5 h-3.5 text-gray-400" /> Disconnected
                    </span>
                  )}

                  {isConnected && (
                    <button
                      type="button"
                      onClick={() => handleIntegrationAction(int.name, "sync")}
                      disabled={isSyncing}
                      title="Sync telemetry now"
                      className="p-1.5 rounded-lg border border-gray-200 text-gray-600 hover:text-gray-900 hover:bg-gray-100 transition-colors disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? "animate-spin text-primary" : ""}`} />
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => handleIntegrationAction(int.name, "toggle")}
                    disabled={isToggling}
                    className={`px-3 py-1.5 text-xs font-semibold rounded-lg border transition-colors ${
                      isConnected
                        ? "border-rose-200 text-rose-600 hover:bg-rose-50"
                        : "border-blue-200 bg-blue-50/50 text-blue-700 hover:bg-blue-100"
                    }`}
                  >
                    {isToggling ? "Updating..." : isConnected ? "Disconnect" : "Connect"}
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </SpotlightCard>
  );

  const apiWebhooksCard = (
    <SpotlightCard accent="indigo" className="w-full">
      <div className="relative z-10 px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-slate-50 via-white to-indigo-50/30 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-xl bg-indigo-50 border border-indigo-200 flex items-center justify-center shrink-0">
            <Key className="w-4 h-4 text-indigo-600" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-gray-900">API Tokens & GitHub CI/CD Webhook</h2>
            <p className="text-[11px] text-muted">
              Authenticate external scanners, GitHub Actions workflows, and automated telemetry ingestion
            </p>
          </div>
        </div>
        <span className="text-[11px] font-semibold px-2.5 py-0.5 rounded-full bg-indigo-50 text-indigo-700 border border-indigo-200 shrink-0">
          {apiTokens.length} Scoped Key(s)
        </span>
      </div>

      <div className="relative z-10 p-5 space-y-6">
        {/* Webhook Endpoint Box */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/90 space-y-3">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <span className="text-xs font-bold text-gray-800 flex items-center gap-1.5">
              <Webhook className="w-4 h-4 text-primary" />
              GitHub Push Webhook Endpoint
            </span>
            <button
              type="button"
              onClick={handleTriggerWebhookTest}
              disabled={testingWebhook}
              className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-lg bg-white border border-gray-200 hover:bg-gray-100 hover:border-blue-300 text-gray-700 transition-colors disabled:opacity-50"
            >
              <Zap className={`w-3.5 h-3.5 text-primary ${testingWebhook ? "animate-pulse" : ""}`} />
              {testingWebhook ? "Dispatching..." : "Trigger Test Scan"}
            </button>
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 px-3 py-2 rounded-lg bg-white border border-gray-200 text-xs font-mono text-gray-800 overflow-x-auto">
              {webhookEndpoint}
            </code>
            <button
              type="button"
              onClick={() => copyText(webhookEndpoint, "webhook-url")}
              className="px-3 py-2 rounded-lg bg-white border border-gray-200 hover:bg-gray-100 text-xs font-semibold text-gray-700 flex items-center gap-1.5 shrink-0"
            >
              {copiedId === "webhook-url" ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span className="text-emerald-700">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy URL</span>
                </>
              )}
            </button>
          </div>
          {webhookLastResult && (
            <div
              className={`flex items-center justify-between gap-2 px-3 py-2 rounded-lg border text-[11px] font-medium ${
                webhookLastResult.ok
                  ? "bg-emerald-50 border-emerald-200 text-emerald-800"
                  : "bg-rose-50 border-rose-200 text-rose-800"
              }`}
            >
              <span className="flex items-center gap-1.5">
                {webhookLastResult.ok ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                ) : (
                  <AlertCircle className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                )}
                {webhookLastResult.message}
              </span>
              <span className="font-mono opacity-75">{webhookLastResult.timestamp}</span>
            </div>
          )}
        </div>

        {/* One-time reveal banner after generating key */}
        {latestCreatedToken && (
          <div className="p-3.5 rounded-xl bg-emerald-50/90 border border-emerald-200 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-bold text-emerald-900 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                New Token Created: {latestCreatedToken.label}
              </span>
              <button
                type="button"
                onClick={() => setLatestCreatedToken(null)}
                className="text-[11px] font-semibold text-emerald-700 hover:underline"
              >
                Done
              </button>
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 px-2.5 py-1.5 rounded bg-white border border-emerald-200 font-mono text-xs text-emerald-950 overflow-x-auto">
                {latestCreatedToken.token}
              </code>
              <button
                type="button"
                onClick={() => copyText(latestCreatedToken.token, "latest-secret-token")}
                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold flex items-center gap-1.5 shrink-0"
              >
                {copiedId === "latest-secret-token" ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedId === "latest-secret-token" ? "Copied" : "Copy Secret"}
              </button>
            </div>
          </div>
        )}

        {/* Generate New Token Form with Scope Selector */}
        <form onSubmit={handleGenerateToken} className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-2.5">
            <input
              type="text"
              value={newTokenLabel}
              onChange={(e) => setNewTokenLabel(e.target.value)}
              placeholder="Token description (e.g. Production Kubernetes Agent)"
              className="flex-1 px-3.5 py-2 text-xs bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/30 text-gray-900"
            />
            <button
              type="submit"
              className="bg-primary hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors flex items-center justify-center gap-1.5 shrink-0"
            >
              <Plus className="w-4 h-4" />
              Generate New API Key
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-semibold text-muted mr-1">Token Scopes:</span>
            {ALL_TOKEN_SCOPES.map((scope) => {
              const selected = selectedScopes.includes(scope);
              return (
                <button
                  key={scope}
                  type="button"
                  onClick={() => toggleScope(scope)}
                  className={`text-[11px] font-mono px-2 py-0.5 rounded-md border transition-colors ${
                    selected
                      ? "bg-indigo-600 text-white border-indigo-600"
                      : "bg-slate-50 text-slate-600 border-slate-200 hover:border-indigo-300"
                  }`}
                >
                  {selected ? "✓ " : "+ "}
                  {scope}
                </button>
              );
            })}
          </div>
        </form>

        {/* Active Tokens List */}
        <div className="space-y-2.5">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted">Active Scoped Tokens</h3>
          <div className="divide-y divide-gray-100 border border-gray-200 rounded-xl overflow-hidden">
            {apiTokens.length === 0 ? (
              <div className="p-6 text-center text-xs text-muted bg-white">
                No active API tokens. Generate one above to authenticate CI/CD runners.
              </div>
            ) : (
              apiTokens.map((item) => (
                <div
                  key={item.id}
                  className="p-3.5 bg-white hover:bg-slate-50/70 flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-colors"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-gray-900">{item.label}</span>
                      {item.scopes.map((scope) => (
                        <span
                          key={scope}
                          className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200/70"
                        >
                          {scope}
                        </span>
                      ))}
                    </div>
                    <div className="flex items-center gap-3 text-[11px] text-muted flex-wrap">
                      <code className="font-mono text-gray-700 bg-gray-100 px-1.5 py-0.5 rounded">
                        {item.token || item.prefix}
                      </code>
                      <span>Created: {item.created}</span>
                      <span>• Last used: {item.lastUsed}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
                    <button
                      type="button"
                      onClick={() => copyText(item.token || item.prefix, item.id)}
                      className="px-2.5 py-1 text-xs font-medium rounded-md border border-gray-200 hover:bg-gray-100 text-gray-700 flex items-center gap-1"
                    >
                      {copiedId === item.id ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-600" />
                          <span className="text-emerald-700">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleRevokeToken(item.id, item.label)}
                      className="p-1.5 text-rose-600 hover:bg-rose-50 rounded-md border border-transparent hover:border-rose-200 transition-colors"
                      title="Revoke token"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </SpotlightCard>
  );

  const webhookSnippetsCard = (
    <SpotlightCard accent="blue" className="p-5 space-y-4">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center">
            <Terminal className="w-4 h-4 text-slate-700" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-gray-900">Webhook Integration Snippet</h3>
            <p className="text-[11px] text-muted">Drop directly into terminal or GitHub Actions</p>
          </div>
        </div>
      </div>

      <div className="inline-flex items-center gap-1 bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-[11px] font-semibold">
        <button
          type="button"
          onClick={() => setSnippetTab("curl")}
          className={`px-2.5 py-1 rounded-md transition-all ${
            snippetTab === "curl" ? "bg-white text-primary shadow-2xs" : "text-slate-600 hover:text-slate-900"
          }`}
        >
          cURL
        </button>
        <button
          type="button"
          onClick={() => setSnippetTab("github")}
          className={`px-2.5 py-1 rounded-md transition-all ${
            snippetTab === "github" ? "bg-white text-primary shadow-2xs" : "text-slate-600 hover:text-slate-900"
          }`}
        >
          GitHub Actions YAML
        </button>
      </div>

      <pre className="p-3.5 rounded-xl bg-slate-950 text-slate-100 text-[11px] font-mono overflow-x-auto leading-relaxed border border-slate-800">
        {snippetTab === "curl" ? curlSnippet : githubYamlSnippet}
      </pre>

      <button
        type="button"
        onClick={() => copyText(snippetTab === "curl" ? curlSnippet : githubYamlSnippet, `snippet-${snippetTab}`)}
        className="w-full py-2 px-3 rounded-lg bg-gray-900 hover:bg-gray-800 text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors"
      >
        {copiedId === `snippet-${snippetTab}` ? (
          <>
            <Check className="w-3.5 h-3.5 text-emerald-400" /> Copied Snippet
          </>
        ) : (
          <>
            <Copy className="w-3.5 h-3.5" /> Copy {snippetTab === "curl" ? "cURL Command" : "Workflow Step"}
          </>
        )}
      </button>
    </SpotlightCard>
  );

  const operatorProfileCard = (
    <SpotlightCard accent="emerald" className="w-full">
      <div className="relative z-10 px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-slate-50 via-white to-emerald-50/30 flex items-center gap-2.5">
        <div className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center shrink-0">
          <UserIcon className="w-4 h-4 text-emerald-600" />
        </div>
        <div>
          <h2 className="text-sm font-bold text-gray-900">Operator Profile</h2>
          <p className="text-[11px] text-muted">Authenticated SOC identity & active session</p>
        </div>
      </div>

      <form onSubmit={handleSaveProfile} className="relative z-10 p-5 space-y-4">
        <div>
          <label className="block text-[11px] text-muted mb-1 uppercase font-semibold">Display Name</label>
          <input
            type="text"
            value={editName}
            onChange={(e) => setEditName(e.target.value)}
            className="w-full bg-gray-50 border border-gray-300 rounded-lg px-3 py-2 text-xs font-medium text-gray-900 focus:outline-none focus:ring-2 focus:ring-primary/30 focus:bg-white transition-colors"
          />
        </div>
        <div>
          <label className="block text-[11px] text-muted mb-1 uppercase font-semibold">Email Address</label>
          <input
            type="email"
            disabled
            value={userProfile.email}
            className="w-full bg-gray-100 border border-gray-200 rounded-lg px-3 py-2 text-xs font-mono text-gray-600"
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-[11px] text-muted mb-1 uppercase font-semibold">Clearance Role</label>
            <div className="bg-gray-100 border border-gray-200 rounded-lg px-3 py-2 text-xs font-semibold text-gray-700 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
              <span className="truncate">Super Admin</span>
            </div>
          </div>
          <div>
            <label className="block text-[11px] text-muted mb-1 uppercase font-semibold">Active Sessions</label>
            <div className="bg-gray-100 border border-gray-200 rounded-lg px-3 py-2 text-xs font-mono font-semibold text-gray-700">
              {userProfile.active_sessions} Bearer Token(s)
            </div>
          </div>
        </div>

        <button
          type="submit"
          disabled={savingProfile}
          className="w-full bg-gray-900 hover:bg-gray-800 text-white font-semibold text-xs px-4 py-2.5 rounded-lg transition-colors disabled:opacity-50"
        >
          {savingProfile ? "Saving Profile..." : "Update Operator Profile"}
        </button>
      </form>
    </SpotlightCard>
  );

  const alertPoliciesCard = (
    <SpotlightCard accent="rose" className="w-full">
      <div className="relative z-10 px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-slate-50 via-white to-rose-50/30 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-xl bg-rose-50 border border-rose-200 flex items-center justify-center shrink-0">
            <Bell className="w-4 h-4 text-rose-600" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-gray-900">Alerting & Detection Policies</h2>
            <p className="text-[11px] text-muted">SOC notification routing and IDS automation</p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => {
            setPrefs(DEFAULT_POLICIES);
            void handleSavePreferences(DEFAULT_POLICIES);
          }}
          title="Restore recommended security defaults"
          className="text-[11px] font-semibold text-muted hover:text-gray-900 inline-flex items-center gap-1 px-2 py-1 rounded-md hover:bg-gray-100 transition-colors"
        >
          <RotateCcw className="w-3 h-3" /> Reset
        </button>
      </div>

      <div className="relative z-10 p-5 space-y-2.5">
        {[
          {
            key: "emailCritical" as const,
            title: "Critical & High Email Dispatch",
            desc: "Immediate notification on CRITICAL or HIGH findings",
          },
          {
            key: "slackWebhook" as const,
            title: "Slack #secops-critical-alerts",
            desc: "Stream real-time IDS & audit events to Slack",
          },
          {
            key: "autoAlertIds" as const,
            title: "Auto-Escalate ML IDS Detections",
            desc: "Automatically open Alert tickets when RF-IDS confidence > 85%",
          },
          {
            key: "strictCspmDrift" as const,
            title: "Continuous CSPM Drift Detection",
            desc: "Flag non-compliant AWS S3, IAM, and RDS resources",
          },
          {
            key: "weeklyDigest" as const,
            title: "Weekly Executive Posture Digest",
            desc: "Send PDF summary of risk trends every Monday",
          },
        ].map((item) => (
          <div
            key={item.key}
            className="flex items-center justify-between gap-3 p-2.5 rounded-xl hover:bg-slate-50 border border-transparent hover:border-gray-200 transition-all"
          >
            <div className="min-w-0">
              <div className="text-xs font-semibold text-gray-900">{item.title}</div>
              <div className="text-[11px] text-muted">{item.desc}</div>
            </div>
            <ToggleSwitch
              label={item.title}
              checked={prefs[item.key]}
              onChange={(checked) => setPrefs((prev) => ({ ...prev, [item.key]: checked }))}
            />
          </div>
        ))}

        <button
          type="button"
          onClick={() => handleSavePreferences()}
          disabled={savingPrefs}
          className="mt-2 w-full bg-primary hover:bg-blue-700 text-white font-semibold text-xs px-4 py-2.5 rounded-lg transition-colors disabled:opacity-50"
        >
          {savingPrefs ? "Saving Policies..." : "Save Alerting Policies"}
        </button>
      </div>
    </SpotlightCard>
  );

  const architectureReferenceCard = (
    <SpotlightCard accent="blue" className="w-full">
      <div className="relative z-10 px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-slate-50 via-white to-blue-50/30 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center shrink-0">
            <Shield className="w-4 h-4 text-blue-600" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-gray-900">Security Telemetry Architecture</h2>
            <p className="text-[11px] text-muted">Unified verification pipeline</p>
          </div>
        </div>
        <span className="text-[10px] font-mono font-semibold px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 shrink-0">
          Zero-Hallucination
        </span>
      </div>

      <div className="relative z-10 p-5 space-y-3.5 bg-white">
        <p className="text-xs text-slate-600 leading-relaxed">
          SentinelX correlates live Random Forest IDS classifications, 8-stage DevSecOps audits, and Cloud CSPM drift checks into a verified evidence context for your AI Copilot.
        </p>
        <div className="pt-1 flex flex-wrap items-center gap-3 text-xs border-t border-gray-100">
          <Link
            href="/assistant"
            className="inline-flex items-center gap-1 font-semibold text-blue-600 hover:text-blue-800 transition-colors pt-2"
          >
            Open AI Copilot <ExternalLink className="w-3 h-3" />
          </Link>
          <span className="text-gray-300 pt-2">•</span>
          <Link
            href="/devsecops"
            className="inline-flex items-center gap-1 font-semibold text-emerald-600 hover:text-emerald-800 transition-colors pt-2"
          >
            Launch Audit <ExternalLink className="w-3 h-3" />
          </Link>
          <span className="text-gray-300 pt-2">•</span>
          <Link
            href="/monitoring"
            className="inline-flex items-center gap-1 font-semibold text-indigo-600 hover:text-indigo-800 transition-colors pt-2"
          >
            System Health <ExternalLink className="w-3 h-3" />
          </Link>
        </div>
      </div>
    </SpotlightCard>
  );

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16 animate-fade-in">
      {/* Header Banner Card with Cursor-Tracking Spotlight */}
      <SpotlightCard accent="blue" className="p-6">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3.5 min-w-0">
            <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0 shadow-inner group-hover:scale-105 group-hover:rotate-45 transition-transform duration-500">
              <Settings className="w-6 h-6 text-primary" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2.5 flex-wrap">
                <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-gray-900">
                  Platform Control & Settings
                </h1>
                <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  Control Plane Live
                </span>
                <span className="text-[11px] font-semibold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200">
                  SentinelX v2.4 Enterprise
                </span>
              </div>
              <p className="text-xs text-muted mt-1 leading-relaxed">
                Manage multi-provider AI Copilot keys, cloud CSPM connectors, scoped API tokens, webhooks, and SOC policies
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start md:self-center shrink-0">
            <button
              type="button"
              onClick={handleSyncAllIntegrations}
              disabled={syncingAll || connectedCount === 0}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-700 bg-white hover:bg-gray-50 border border-gray-200 rounded-lg transition-all shadow-2xs disabled:opacity-50"
            >
              <Cloud className="w-3.5 h-3.5 text-blue-600" />
              {syncingAll ? "Syncing..." : "Sync Connectors"}
            </button>
            <button
              type="button"
              onClick={loadSettings}
              className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-gray-700 bg-gray-50 hover:bg-gray-100 border border-gray-200 rounded-lg transition-all shadow-2xs"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-primary" : ""}`} />
              Refresh Status
            </button>
          </div>
        </div>
      </SpotlightCard>

      {/* Top Status KPI Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="animate-slide-up stagger-1 opacity-0">
          <SpotlightCard accent="amber" hoverLift className="p-4 h-full">
            <div className="relative z-10 flex items-start justify-between gap-2">
              <div className="min-w-0">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">AI Copilot Engine</span>
                <div className="mt-1.5 flex items-center gap-2">
                  <span
                    className={`inline-flex items-center gap-1.5 text-xs font-bold px-2.5 py-0.5 rounded-full border ${
                      aiConfig.configured
                        ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                        : "bg-amber-50 text-amber-800 border-amber-300"
                    }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        aiConfig.configured ? "bg-emerald-500 animate-pulse" : "bg-amber-500"
                      }`}
                    />
                    {formatAiBadgeLabel(aiConfig)}
                  </span>
                </div>
                <p className="text-[11px] text-muted mt-1.5 font-mono truncate max-w-[190px]">{aiConfig.engine}</p>
              </div>
              <div className="w-9 h-9 rounded-lg bg-amber-50 border border-amber-200/70 flex items-center justify-center shrink-0 group-hover:scale-110 transition-transform">
                <Sparkles className="w-4 h-4 text-amber-600" />
              </div>
            </div>
          </SpotlightCard>
        </div>

        <div className="animate-slide-up stagger-2 opacity-0">
          <SpotlightCard accent="blue" hoverLift className="p-4 h-full">
            <div className="relative z-10 flex items-start justify-between gap-2">
              <div className="min-w-0 flex-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">Cloud & CI Connectors</span>
                <div className="mt-1.5 text-lg font-bold text-gray-900">
                  {connectedCount}{" "}
                  <span className="text-xs font-normal text-muted">/ {integrations.length || 5} Connected</span>
                </div>
                <div className="mt-2 h-1.5 w-full rounded-full bg-slate-100 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-blue-500 to-emerald-500 rounded-full transition-all duration-500"
                    style={{ width: `${connectorPct}%` }}
                  />
                </div>
              </div>
              <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-200/70 flex items-center justify-center shrink-0 group-hover:scale-110 transition-transform">
                <Cloud className="w-4 h-4 text-blue-600" />
              </div>
            </div>
          </SpotlightCard>
        </div>

        <div className="animate-slide-up stagger-3 opacity-0">
          <SpotlightCard accent="indigo" hoverLift className="p-4 h-full">
            <div className="relative z-10 flex items-start justify-between gap-2">
              <div className="min-w-0">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">ML Intrusion Engine</span>
                <div className="mt-1.5 text-sm font-bold text-gray-900 flex items-center gap-1.5 flex-wrap">
                  {mlEngine.name} v{mlEngine.version}
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-semibold">
                    {mlEngine.accuracy}% ACC
                  </span>
                </div>
                <Link
                  href="/threats"
                  className="text-[11px] font-semibold text-indigo-600 hover:text-indigo-800 inline-flex items-center gap-1 mt-1.5"
                >
                  Inspect Model Telemetry <ArrowRight className="w-3 h-3" />
                </Link>
              </div>
              <div className="w-9 h-9 rounded-lg bg-indigo-50 border border-indigo-200/70 flex items-center justify-center shrink-0 group-hover:scale-110 transition-transform">
                <Cpu className="w-4 h-4 text-indigo-600" />
              </div>
            </div>
          </SpotlightCard>
        </div>

        <div className="animate-slide-up stagger-4 opacity-0">
          <SpotlightCard accent="emerald" hoverLift className="p-4 h-full">
            <div className="relative z-10 flex items-start justify-between gap-2">
              <div className="min-w-0">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">Authenticated Operator</span>
                <div className="mt-1.5 text-sm font-bold text-gray-900 truncate max-w-[180px]">{userProfile.name}</div>
                <p className="text-[11px] text-muted mt-1 truncate max-w-[180px] font-mono">
                  {userProfile.email} • {userProfile.active_sessions}{" "}
                  {userProfile.active_sessions === 1 ? "session" : "sessions"}
                </p>
              </div>
              <div className="w-9 h-9 rounded-lg bg-emerald-50 border border-emerald-200/70 flex items-center justify-center shrink-0 group-hover:scale-110 transition-transform">
                <Shield className="w-4 h-4 text-emerald-600" />
              </div>
            </div>
          </SpotlightCard>
        </div>
      </div>

      {/* Category Filter Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto bg-white border border-gray-200 rounded-2xl p-1.5 shadow-xs">
        {[
          { id: "overview" as const, label: "All Settings", icon: Settings, badge: null },
          {
            id: "ai" as const,
            label: "AI Copilot & Failover",
            icon: Sparkles,
            badge: aiConfig.configured ? aiConfig.provider || "Live" : "Local",
          },
          {
            id: "integrations" as const,
            label: "Cloud & CI Connectors",
            icon: Cloud,
            badge: `${connectedCount}/${integrations.length || 5}`,
          },
          {
            id: "api" as const,
            label: "API Keys & Webhooks",
            icon: Key,
            badge: String(apiTokens.length),
          },
          {
            id: "profile" as const,
            label: "Operator & Policies",
            icon: UserIcon,
            badge: `${enabledPoliciesCount}/5`,
          },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all shrink-0 ${
                isActive
                  ? "bg-primary text-white shadow-xs"
                  : "text-gray-600 hover:text-gray-900 hover:bg-gray-100/80"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
              {tab.badge && (
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-full font-bold ${
                    isActive ? "bg-white/20 text-white" : "bg-slate-100 text-slate-700"
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Focused or Bento Main Workspace */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
          <div className="lg:col-span-2 space-y-6">
            {aiCopilotCard}
            {integrationsCard}
            {apiWebhooksCard}
          </div>
          <div className="space-y-6">
            {operatorProfileCard}
            {alertPoliciesCard}
            {architectureReferenceCard}
          </div>
        </div>
      )}

      {activeTab === "ai" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
          <div className="lg:col-span-2 space-y-6">{aiCopilotCard}</div>
          <div className="space-y-6">
            {aiPreferencesSideCard}
            {architectureReferenceCard}
          </div>
        </div>
      )}

      {activeTab === "integrations" && <div className="space-y-6">{integrationsCard}</div>}

      {activeTab === "api" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
          <div className="lg:col-span-2 space-y-6">{apiWebhooksCard}</div>
          <div className="space-y-6">{webhookSnippetsCard}</div>
        </div>
      )}

      {activeTab === "profile" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          <div className="space-y-6">
            {operatorProfileCard}
            {architectureReferenceCard}
          </div>
          <div className="space-y-6">{alertPoliciesCard}</div>
        </div>
      )}

      {/* Floating Non-Shifting Toast Notification */}
      {toast && (
        <div
          role="status"
          aria-live="polite"
          className={`fixed bottom-5 right-5 z-50 max-w-md flex items-center justify-between gap-3 px-4 py-3 rounded-xl border text-xs font-medium shadow-lg animate-slide-in-right ${
            toast.type === "success"
              ? "bg-emerald-50 border-emerald-200 text-emerald-900"
              : toast.type === "error"
              ? "bg-rose-50 border-rose-200 text-rose-900"
              : "bg-blue-50 border-blue-200 text-blue-900"
          }`}
        >
          <div className="flex items-center gap-2">
            {toast.type === "success" ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            ) : toast.type === "error" ? (
              <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
            ) : (
              <Sparkles className="w-4 h-4 text-blue-600 shrink-0" />
            )}
            <span>{toast.message}</span>
          </div>
          <button
            type="button"
            onClick={() => setToast(null)}
            className="text-[11px] font-semibold underline opacity-80 hover:opacity-100 shrink-0"
          >
            Dismiss
          </button>
        </div>
      )}
    </div>
  );
}
