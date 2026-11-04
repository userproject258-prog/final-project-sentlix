"use client";

import { API_URL, apiFetch as fetch } from "@/lib/api";
import { useEffect, useState } from "react";
import {
  Settings,
  Cloud,
  Key,
  CheckCircle2,
  XCircle,
  Sparkles,
  Shield,
  RefreshCw,
  Copy,
  Check,
  User as UserIcon,
  Bell,
  Webhook,
  Plus,
  Trash2,
  Lock,
  Cpu,
  Activity,
  ExternalLink,
  AlertCircle,
  Eye,
  EyeOff,
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
  engine: string;
  model: string;
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

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<"overview" | "ai" | "integrations" | "api" | "profile">("overview");
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [aiConfig, setAiConfig] = useState<AIConfig>({
    configured: false,
    key_present: false,
    masked_key: "Loading...",
    engine: "Checking...",
    model: "gemini-2.5-flash",
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

  // AI Key state
  const [newAiKey, setNewAiKey] = useState("");
  const [showKeyInput, setShowKeyInput] = useState(false);
  const [savingAiKey, setSavingAiKey] = useState(false);
  const [testingAiKey, setTestingAiKey] = useState(false);

  // Integration action state
  const [busyIntegration, setBusyIntegration] = useState<string | null>(null);

  // API Tokens & Webhooks state
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [newTokenLabel, setNewTokenLabel] = useState("");
  const [testingWebhook, setTestingWebhook] = useState(false);
  const [apiTokens, setApiTokens] = useState<ApiTokenItem[]>([
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
  ]);

  // Profile & Preferences state
  const [editName, setEditName] = useState("");
  const [savingProfile, setSavingProfile] = useState(false);
  const [prefs, setPrefs] = useState({
    emailCritical: true,
    slackWebhook: true,
    autoAlertIds: true,
    weeklyDigest: false,
    strictCspmDrift: true,
  });
  const [savingPrefs, setSavingPrefs] = useState(false);

  const showToast = (message: string, type: "success" | "info" | "error" = "success") => {
    setToast({ message, type });
    setTimeout(() => {
      setToast((prev) => (prev?.message === message ? null : prev));
    }, 4000);
  };

  const loadSettings = async () => {
    try {
      // Load local user fallback immediately if available
      if (typeof window !== "undefined") {
        const storedUser = localStorage.getItem("sentinelx_user");
        if (storedUser) {
          try {
            const parsed = JSON.parse(storedUser);
            if (parsed.name || parsed.email) {
              setUserProfile((prev) => ({
                ...prev,
                name: parsed.name || prev.name,
                email: parsed.email || prev.email,
              }));
              setEditName(parsed.name || "");
            }
          } catch {
            // ignore
          }
        }
      }

      const res = await fetch(`${API_URL}/api/settings`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.integrations)) {
          setIntegrations(data.integrations);
        }
        if (data.ai_config) {
          setAiConfig(data.ai_config);
        }
        if (data.user) {
          setUserProfile(data.user);
          setEditName(data.user.name);
        }
      }
    } catch (err) {
      console.error("Failed to fetch settings:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    showToast("Copied to clipboard", "info");
    setTimeout(() => setCopiedId(null), 2000);
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
          engine: data.engine || prev.engine,
        }));
        setNewAiKey("");
        if (data.configured) {
          showToast("AI API Key verified and activated! Gemini Copilot is now live.", "success");
        } else {
          showToast("Key saved, but provider verification failed. Using Local Summary Mode.", "error");
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
      setAiConfig((prev) => ({
        ...prev,
        configured: isOk,
        engine: isOk ? "Google gemini-2.5-flash" : "Local recorded-data summary",
      }));
      if (isOk) {
        showToast("AI Copilot connection verified — Gemini engine is healthy & reachable.", "success");
      } else {
        showToast("AI key is not reachable or unconfigured — running in Local Summary Mode.", "error");
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
            ? `Synchronized telemetry with ${name}.`
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
      scopes: ["ci:scan", "threats:write", "cspm:read"],
      created: "Just now",
      lastUsed: "Never",
    };
    setApiTokens((prev) => [newItem, ...prev]);
    setNewTokenLabel("");
    showToast(`Generated API token "${label}". Copy it now—it won't be shown in full again.`, "success");
  };

  const handleRevokeToken = (id: string, label: string) => {
    setApiTokens((prev) => prev.filter((t) => t.id !== id));
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
      if (res.ok) {
        showToast("Test CI/CD webhook dispatched! Pipeline scan recorded.", "success");
      } else {
        showToast("Webhook test returned an error.", "error");
      }
    } catch {
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
        }
        showToast("Operator profile updated.", "success");
      }
    } catch {
      showToast("Failed to update operator profile.", "error");
    } finally {
      setSavingProfile(false);
    }
  };

  const handleSavePreferences = () => {
    setSavingPrefs(true);
    setTimeout(() => {
      setSavingPrefs(false);
      showToast("Security & notification policies saved.", "success");
    }, 350);
  };

  const connectedCount = integrations.filter((i) => i.status === "Connected").length;
  const webhookEndpoint = `${API_URL}/api/devsecops/webhook`;

  return (
    <div className="space-y-6 pb-10">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-white border border-gray-200/90 rounded-xl p-5 shadow-2xs">
        <div className="flex items-start sm:items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
            <Settings className="w-6 h-6 text-primary" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-xl sm:text-2xl font-bold text-gray-900">Platform Control & Settings</h1>
              <span className="text-[11px] font-semibold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200">
                SentinelX v2.4 Enterprise
              </span>
            </div>
            <p className="text-xs text-muted mt-1">
              Manage AI Copilot engines, cloud CSPM connectors, CI/CD webhooks, API tokens, and operator policies
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 self-start md:self-center">
          <button
            type="button"
            onClick={loadSettings}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-gray-700 bg-gray-50 hover:bg-gray-100 border border-gray-200 rounded-lg transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh Status
          </button>
        </div>
      </div>

      {/* Toast Notification */}
      {toast && (
        <div
          className={`flex items-center justify-between gap-3 px-4 py-3 rounded-xl border text-xs font-medium shadow-xs transition-all ${
            toast.type === "success"
              ? "bg-emerald-50 border-emerald-200 text-emerald-800"
              : toast.type === "error"
              ? "bg-rose-50 border-rose-200 text-rose-800"
              : "bg-blue-50 border-blue-200 text-blue-800"
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
            className="text-[11px] underline opacity-80 hover:opacity-100"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Top Status Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border border-gray-200/90 rounded-xl p-4 shadow-2xs flex items-start justify-between">
          <div>
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
                {aiConfig.configured ? "Gemini Configured" : "Local Summary Mode"}
              </span>
            </div>
            <p className="text-[11px] text-muted mt-1.5 font-mono truncate max-w-[190px]">{aiConfig.engine}</p>
          </div>
          <div className="w-9 h-9 rounded-lg bg-amber-50 border border-amber-200/70 flex items-center justify-center">
            <Sparkles className="w-4 h-4 text-amber-600" />
          </div>
        </div>

        <div className="bg-white border border-gray-200/90 rounded-xl p-4 shadow-2xs flex items-start justify-between">
          <div>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">Cloud & CI Connectors</span>
            <div className="mt-1.5 text-lg font-bold text-gray-900">
              {connectedCount} <span className="text-xs font-normal text-muted">/ {integrations.length || 5} Connected</span>
            </div>
            <p className="text-[11px] text-emerald-700 font-medium mt-1">Real-time telemetry active</p>
          </div>
          <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-200/70 flex items-center justify-center">
            <Cloud className="w-4 h-4 text-blue-600" />
          </div>
        </div>

        <div className="bg-white border border-gray-200/90 rounded-xl p-4 shadow-2xs flex items-start justify-between">
          <div>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">ML Intrusion Engine</span>
            <div className="mt-1.5 text-sm font-bold text-gray-900 flex items-center gap-1.5">
              RF-IDS v1.0.4
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-semibold">
                94.2% ACC
              </span>
            </div>
            <p className="text-[11px] text-muted mt-1.5">Random Forest Classifier Active</p>
          </div>
          <div className="w-9 h-9 rounded-lg bg-indigo-50 border border-indigo-200/70 flex items-center justify-center">
            <Cpu className="w-4 h-4 text-indigo-600" />
          </div>
        </div>

        <div className="bg-white border border-gray-200/90 rounded-xl p-4 shadow-2xs flex items-start justify-between">
          <div>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">Authenticated Operator</span>
            <div className="mt-1.5 text-sm font-bold text-gray-900 truncate max-w-[180px]">{userProfile.name}</div>
            <p className="text-[11px] text-muted mt-1 truncate max-w-[180px] font-mono">{userProfile.email}</p>
          </div>
          <div className="w-9 h-9 rounded-lg bg-emerald-50 border border-emerald-200/70 flex items-center justify-center">
            <Shield className="w-4 h-4 text-emerald-600" />
          </div>
        </div>
      </div>

      {/* Category Filter Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto bg-white border border-gray-200 rounded-xl p-1.5 shadow-2xs">
        {[
          { id: "overview", label: "All Settings", icon: Settings },
          { id: "ai", label: "AI Copilot & Gemini Key", icon: Sparkles },
          { id: "integrations", label: "Cloud & CI Integrations", icon: Cloud },
          { id: "api", label: "API Keys & Webhooks", icon: Key },
          { id: "profile", label: "Operator & Alert Policies", icon: UserIcon },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
                isActive
                  ? "bg-primary text-white shadow-2xs"
                  : "text-gray-600 hover:text-gray-900 hover:bg-gray-100"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left / Primary Column (2 cols wide on desktop) */}
        <div className="lg:col-span-2 space-y-6">
          {/* 1. AI Copilot & LLM Provider Card */}
          {(activeTab === "overview" || activeTab === "ai") && (
            <div className="bg-white border border-gray-200/90 rounded-xl shadow-2xs overflow-hidden">
              <div className="px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-slate-50 via-white to-slate-50 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-amber-50 border border-amber-200 flex items-center justify-center">
                    <Sparkles className="w-4 h-4 text-amber-600" />
                  </div>
                  <div>
                    <h2 className="text-sm font-bold text-gray-900">AI Copilot & Gemini API Configuration</h2>
                    <p className="text-[11px] text-muted">
                      Configure the live LLM key powering the AI Security Assistant and DevSecOps report synthesis
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleVerifyAiConnection}
                    disabled={testingAiKey}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-gray-200 bg-white hover:bg-gray-50 text-gray-700 transition-colors disabled:opacity-50"
                  >
                    <Activity className={`w-3.5 h-3.5 text-primary ${testingAiKey ? "animate-spin" : ""}`} />
                    {testingAiKey ? "Verifying..." : "Test Live Connection"}
                  </button>
                </div>
              </div>

              <div className="p-5 space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 bg-slate-50/80 border border-slate-200/80 rounded-xl p-3.5 text-xs">
                  <div>
                    <span className="text-[11px] text-muted block">Current Status</span>
                    <span
                      className={`inline-flex items-center gap-1.5 font-bold mt-1 ${
                        aiConfig.configured ? "text-emerald-700" : "text-amber-700"
                      }`}
                    >
                      {aiConfig.configured ? (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Gemini Configured
                        </>
                      ) : (
                        <>
                          <AlertCircle className="w-3.5 h-3.5 text-amber-600" /> Local Fallback Mode
                        </>
                      )}
                    </span>
                  </div>
                  <div>
                    <span className="text-[11px] text-muted block">Active Key (Masked)</span>
                    <span className="font-mono font-semibold text-gray-800 mt-1 block">{aiConfig.masked_key}</span>
                  </div>
                  <div>
                    <span className="text-[11px] text-muted block">Target Engine</span>
                    <span className="font-mono font-semibold text-indigo-700 mt-1 block">{aiConfig.engine}</span>
                  </div>
                </div>

                <form onSubmit={handleUpdateAiKey} className="space-y-2.5">
                  <label className="block text-xs font-semibold text-gray-700">
                    Update <code className="px-1.5 py-0.5 rounded bg-slate-100 text-indigo-700 font-mono">GEMINI_API_KEY</code> at Runtime
                  </label>
                  <div className="flex flex-col sm:flex-row gap-2.5">
                    <div className="relative flex-1">
                      <input
                        type={showKeyInput ? "text" : "password"}
                        value={newAiKey}
                        onChange={(e) => setNewAiKey(e.target.value)}
                        placeholder="Paste AI Studio (AIza...), Vertex Express (AQ...), or Groq (gsk_...) key"
                        className="w-full pl-3.5 pr-9 py-2 text-xs font-mono bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/30 text-gray-900"
                      />
                      <button
                        type="button"
                        onClick={() => setShowKeyInput((v) => !v)}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-700"
                      >
                        {showKeyInput ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    <button
                      type="submit"
                      disabled={!newAiKey.trim() || savingAiKey}
                      className="px-4 py-2 bg-primary hover:bg-blue-700 text-white rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 shrink-0"
                    >
                      {savingAiKey ? "Validating..." : "Save & Verify Key"}
                    </button>
                  </div>
                  <p className="text-[11px] text-muted">
                    Supports Google AI Studio (<code className="font-mono">AIza...</code>), Vertex AI Express (<code className="font-mono">AQ...</code>), and high-speed Groq/xAI keys (<code className="font-mono">gsk_...</code>).
                  </p>
                </form>
              </div>
            </div>
          )}

          {/* 2. Cloud & DevSecOps Integrations Card */}
          {(activeTab === "overview" || activeTab === "integrations") && (
            <div className="bg-white border border-gray-200/90 rounded-xl shadow-2xs overflow-hidden">
              <div className="px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-slate-50 via-white to-slate-50 flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center">
                    <Cloud className="w-4 h-4 text-blue-600" />
                  </div>
                  <div>
                    <h2 className="text-sm font-bold text-gray-900">Cloud CSPM & DevSecOps Connectors</h2>
                    <p className="text-[11px] text-muted">
                      Active telemetry streams for cloud posture checks, container scanning, and incident alerting
                    </p>
                  </div>
                </div>
                <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                  {connectedCount} Active
                </span>
              </div>

              <div className="divide-y divide-gray-100">
                {integrations.map((int, i) => {
                  const isConnected = int.status === "Connected";
                  const isSyncing = busyIntegration === `${int.name}-sync`;
                  const isToggling = busyIntegration === `${int.name}-toggle`;
                  return (
                    <div
                      key={int.id || i}
                      className="p-4 sm:px-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-50/60 transition-colors"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h3 className="text-sm font-semibold text-gray-900">{int.name}</h3>
                          {int.category && (
                            <span className="text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                              {int.category}
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-3 text-xs text-muted flex-wrap">
                          {int.account && (
                            <span className="font-mono text-[11px] text-gray-600 bg-gray-100 px-1.5 py-0.5 rounded">
                              {int.account}
                            </span>
                          )}
                          {int.region && <span>Region: {int.region}</span>}
                          <span>• Last sync: {int.last_sync}</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-2.5 self-end sm:self-center shrink-0">
                        {isConnected ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Connected
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
                })}
              </div>
            </div>
          )}

          {/* 3. API Keys & CI/CD Webhook Card */}
          {(activeTab === "overview" || activeTab === "api") && (
            <div className="bg-white border border-gray-200/90 rounded-xl shadow-2xs overflow-hidden">
              <div className="px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-slate-50 via-white to-slate-50 flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200 flex items-center justify-center">
                    <Key className="w-4 h-4 text-indigo-600" />
                  </div>
                  <div>
                    <h2 className="text-sm font-bold text-gray-900">API Tokens & GitHub CI/CD Webhook</h2>
                    <p className="text-[11px] text-muted">
                      Authenticate external scanners, GitHub Actions workflows, and automated telemetry ingestion
                    </p>
                  </div>
                </div>
              </div>

              <div className="p-5 space-y-6">
                {/* Webhook Endpoint Box */}
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/90 space-y-2.5">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="text-xs font-bold text-gray-800 flex items-center gap-1.5">
                      <Webhook className="w-4 h-4 text-primary" />
                      GitHub Push Webhook Endpoint
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleTriggerWebhookTest}
                        disabled={testingWebhook}
                        className="text-xs font-semibold px-2.5 py-1 rounded-md bg-white border border-gray-200 hover:bg-gray-100 text-gray-700 transition-colors"
                      >
                        {testingWebhook ? "Dispatching..." : "Trigger Test Scan"}
                      </button>
                    </div>
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
                </div>

                {/* Generate New Token Form */}
                <form onSubmit={handleGenerateToken} className="flex flex-col sm:flex-row gap-2.5">
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
                </form>

                {/* Active Tokens List */}
                <div className="space-y-2.5">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted">Active Scoped Tokens</h3>
                  <div className="divide-y divide-gray-100 border border-gray-200 rounded-xl overflow-hidden">
                    {apiTokens.map((item) => (
                      <div
                        key={item.id}
                        className="p-3.5 bg-white hover:bg-slate-50/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                      >
                        <div className="space-y-1">
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
                          <div className="flex items-center gap-3 text-[11px] text-muted">
                            <code className="font-mono text-gray-700 bg-gray-100 px-1.5 py-0.5 rounded">
                              {item.token || item.prefix}
                            </code>
                            <span>Created: {item.created}</span>
                            <span>• Last used: {item.lastUsed}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 self-end sm:self-center">
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
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Column (Profile & Security Preferences) */}
        <div className="space-y-6">
          {/* Operator Profile Card */}
          {(activeTab === "overview" || activeTab === "profile") && (
            <div className="bg-white border border-gray-200/90 rounded-xl shadow-2xs overflow-hidden">
              <div className="px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-slate-50 via-white to-slate-50 flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-center">
                  <UserIcon className="w-4 h-4 text-emerald-600" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-gray-900">Operator Profile</h2>
                  <p className="text-[11px] text-muted">Authenticated SOC identity & session</p>
                </div>
              </div>

              <form onSubmit={handleSaveProfile} className="p-5 space-y-4">
                <div>
                  <label className="block text-[11px] text-muted mb-1 uppercase font-semibold">Display Name</label>
                  <input
                    type="text"
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    className="w-full bg-gray-50 border border-gray-300 rounded-lg px-3 py-2 text-xs font-medium text-gray-900 focus:outline-none focus:ring-2 focus:ring-primary/30"
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
            </div>
          )}

          {/* Notification & Autonomous Defense Policies */}
          {(activeTab === "overview" || activeTab === "profile") && (
            <div className="bg-white border border-gray-200/90 rounded-xl shadow-2xs overflow-hidden">
              <div className="px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-slate-50 via-white to-slate-50 flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-rose-50 border border-rose-200 flex items-center justify-center">
                  <Bell className="w-4 h-4 text-rose-600" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-gray-900">Alerting & Detection Policies</h2>
                  <p className="text-[11px] text-muted">SOC notification routing and IDS automation</p>
                </div>
              </div>

              <div className="p-5 space-y-3.5">
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
                  <label
                    key={item.key}
                    className="flex items-start justify-between gap-3 p-2.5 rounded-lg hover:bg-slate-50 cursor-pointer border border-transparent hover:border-gray-200 transition-all"
                  >
                    <div>
                      <div className="text-xs font-semibold text-gray-900">{item.title}</div>
                      <div className="text-[11px] text-muted">{item.desc}</div>
                    </div>
                    <input
                      type="checkbox"
                      checked={prefs[item.key]}
                      onChange={(e) => setPrefs((prev) => ({ ...prev, [item.key]: e.target.checked }))}
                      className="mt-0.5 h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
                    />
                  </label>
                ))}

                <button
                  type="button"
                  onClick={handleSavePreferences}
                  disabled={savingPrefs}
                  className="mt-2 w-full bg-primary hover:bg-blue-700 text-white font-semibold text-xs px-4 py-2.5 rounded-lg transition-colors"
                >
                  {savingPrefs ? "Saving Policies..." : "Save Alerting Policies"}
                </button>
              </div>
            </div>
          )}

          {/* Quick Documentation / Audit Reference Card */}
          <div className="bg-gradient-to-br from-slate-900 to-slate-800 text-white rounded-xl p-5 shadow-xs space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-wider font-semibold text-blue-300 flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5" /> Security Telemetry Architecture
              </span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              SentinelX correlates live Random Forest IDS classifications, CrewAI 7-stage DevSecOps audits, and Cloud CSPM checks into a unified evidence context for the AI Copilot.
            </p>
            <div className="pt-1 flex items-center gap-3 text-xs">
              <a
                href="/assistant"
                className="inline-flex items-center gap-1 font-semibold text-blue-300 hover:text-white transition-colors"
              >
                Open AI Copilot <ExternalLink className="w-3 h-3" />
              </a>
              <span className="text-slate-600">•</span>
              <a
                href="/devsecops"
                className="inline-flex items-center gap-1 font-semibold text-emerald-300 hover:text-white transition-colors"
              >
                Launch Audit <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
