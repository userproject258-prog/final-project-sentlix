"use client";

import { API_URL, apiFetch as fetch } from "@/lib/api";

import { useState, useRef, useEffect, useCallback } from "react";
import { Bot, User, Send, Loader2, Sparkles, Shield, Terminal, Copy, Check, RotateCcw } from "lucide-react";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  engine?: string;
}

const WELCOME_MESSAGE: Message = {
  id: "1",
  role: "assistant",
  content: "Hello! I am **SentinelX AI**, your Principal Security Operations & CSPM Copilot.\n\nAsk me to prioritize recorded vulnerabilities, correlate attacking IPs with **MITRE ATT&CK**, or draft production-ready **Terraform, Nginx, WAF, and CLI** remediations grounded in your live telemetry.",
  engine: "SentinelX Security Copilot"
};

export default function AssistantPage() {
  const [messages, setMessages] = useState<Message[]>([WELCOME_MESSAGE]);
  const [input, setInput] = useState("");
  const [responseMode, setResponseMode] = useState<"deep" | "executive" | "concise">("deep");
  const [isLoading, setIsLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesRef = useRef<Message[]>([WELCOME_MESSAGE]);
  const messageIdRef = useRef(1);
  const autoQueryHandledRef = useRef(false);

  const [keyStatus, setKeyStatus] = useState<{ configured: boolean; provider?: string } | null>(null);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  const handleCardMouseMove = (e: React.MouseEvent<HTMLElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    e.currentTarget.style.setProperty("--mouse-x", `${e.clientX - rect.left}px`);
    e.currentTarget.style.setProperty("--mouse-y", `${e.clientY - rect.top}px`);
  };

  useEffect(() => {
    fetch(`${API_URL}/api/assistant/status`)
      .then(res => res.json())
      .then(data => {
        setKeyStatus({
          configured: !!data.gemini_api_key_configured,
          provider: typeof data.provider === "string" ? data.provider : undefined,
        });
      })
      .catch(() => setKeyStatus({ configured: false, provider: "Local Summary Mode" }));
  }, []);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const sendPrompt = useCallback(async (promptText: string, modeOverride?: "deep" | "executive" | "concise") => {
    const trimmed = promptText.trim();
    if (!trimmed) return;

    messageIdRef.current += 1;
    const userMsg: Message = { id: `msg-${messageIdRef.current}`, role: "user", content: trimmed };
    const priorHistory = messagesRef.current
      .filter(m => m.id !== "1")
      .slice(-8)
      .map(m => ({ role: m.role, content: m.content.slice(0, 4000) }));

    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);

    try {
      const response = await fetch(`${API_URL}/api/assistant/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          prompt: trimmed,
          history: priorHistory,
          response_mode: modeOverride ?? responseMode,
        }),
      });
      if (!response.ok) throw new Error("Assistant request failed");
      const data = await response.json();
      if (typeof data.api_key_configured === "boolean") {
        setKeyStatus({
          configured: data.api_key_configured,
          provider: data.api_key_configured
            ? (typeof data.provider === "string" ? data.provider : undefined)
            : "Local Summary Mode",
        });
      }

      messageIdRef.current += 1;
      setMessages(prev => [...prev, {
        id: `msg-${messageIdRef.current}`,
        role: "assistant",
        content: data.response || "No response received.",
        engine: data.engine
      }]);
    } catch (error) {
      console.error(error);
      messageIdRef.current += 1;
      setMessages(prev => [...prev, {
        id: `msg-${messageIdRef.current}`,
        role: "assistant",
        content: "⚠️ Failed to communicate with SentinelX AI assistant API backend."
      }]);
    } finally {
      setIsLoading(false);
    }
  }, [responseMode]);

  useEffect(() => {
    if (autoQueryHandledRef.current || typeof window === "undefined") return;
    const q = new URLSearchParams(window.location.search).get("q");
    if (q && q.trim()) {
      autoQueryHandledRef.current = true;
      window.history.replaceState(null, "", window.location.pathname);
      void sendPrompt(q.trim());
    }
  }, [sendPrompt]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isLoading) void sendPrompt(input);
  };

  const handleResetChat = () => {
    if (isLoading) return;
    setMessages([WELCOME_MESSAGE]);
  };

  const quickPrompts = [
    { label: "Remediate Top Findings", query: "Prioritize the top open Critical and High audit findings and generate exact configuration fixes (Nginx/CSP/HSTS/Terraform) with verification commands." },
    { label: "Block Attacker IPs", query: "Correlate the top attacking source IPs from recent threat detections, map them to MITRE ATT&CK techniques, and generate firewall/WAF blocklist rules." },
    { label: "Safe Verification Tests", query: "Provide safe, non-destructive verification commands to validate the recorded audit candidate vulnerabilities." },
    { label: "Environment Briefing", query: "Provide an executive security briefing covering threats, alerts, cloud findings, and DevSecOps audit observations." },
    { label: "CI/CD Pipeline Risks", query: "Review recent CI/CD pipeline scan statuses and recommend concrete DevSecOps gate improvements." },
  ];

  const renderInlineContent = (text: string, keyPrefix: string, isUser: boolean = false) => {
    const tokens = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
    return tokens.map((token, idx) => {
      if (token.startsWith("`") && token.endsWith("`") && token.length > 2) {
        const inner = token.slice(1, -1);
        return (
          <code
            key={`${keyPrefix}-code-${idx}`}
            className={`px-1.5 py-0.5 mx-0.5 rounded font-mono text-[12px] border ${
              isUser
                ? "bg-white/15 text-white border-white/20"
                : "bg-slate-100 text-indigo-700 border-slate-200/80"
            }`}
          >
            {inner}
          </code>
        );
      }
      if (token.startsWith("**") && token.endsWith("**") && token.length > 4) {
        const inner = token.slice(2, -2);
        return (
          <strong
            key={`${keyPrefix}-bold-${idx}`}
            className={`font-semibold ${isUser ? "text-white" : "text-gray-900"}`}
          >
            {inner}
          </strong>
        );
      }
      const badgeMatch = !isUser && token.trim().match(/^(CRITICAL|HIGH|MEDIUM|LOW|OPEN\/ACTIVE|OPEN|ACTIVE|PASS|FAIL)$/i);
      if (badgeMatch) {
        const val = badgeMatch[1].toUpperCase();
        const badgeStyles: Record<string, string> = {
          CRITICAL: "bg-red-100 text-red-800 border-red-200",
          HIGH: "bg-orange-100 text-orange-800 border-orange-200",
          MEDIUM: "bg-amber-100 text-amber-800 border-amber-200",
          LOW: "bg-blue-50 text-blue-700 border-blue-200",
          "OPEN/ACTIVE": "bg-rose-50 text-rose-700 border-rose-200",
          OPEN: "bg-rose-50 text-rose-700 border-rose-200",
          ACTIVE: "bg-emerald-50 text-emerald-700 border-emerald-200",
          PASS: "bg-emerald-50 text-emerald-700 border-emerald-200",
          FAIL: "bg-red-100 text-red-800 border-red-200",
        };
        return (
          <span
            key={`${keyPrefix}-badge-${idx}`}
            className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-bold tracking-wide border ${
              badgeStyles[val] || "bg-gray-100 text-gray-700 border-gray-200"
            }`}
          >
            {token.trim()}
          </span>
        );
      }
      return <span key={`${keyPrefix}-txt-${idx}`}>{token}</span>;
    });
  };

  const isTableSeparator = (line: string) => {
    const trimmed = line.trim();
    if (!trimmed.startsWith("|")) return false;
    const cells = trimmed
      .replace(/^\||\|$/g, "")
      .split("|")
      .map((c) => c.trim());
    return cells.length > 0 && cells.every((c) => /^:?-{2,}:?$/.test(c));
  };

  const parseTableRow = (line: string) => {
    const trimmed = line.trim().replace(/^\|/, "").replace(/\|$/, "");
    return trimmed.split("|").map((c) => c.trim());
  };

  const renderMarkdownBlock = (blockText: string, blockIdx: number, isUser: boolean) => {
    // Normalize spaced-out markdown table rows (e.g. blank lines between | rows |)
    const rawLines = blockText.split("\n");
    const lines: string[] = [];
    for (let i = 0; i < rawLines.length; i++) {
      const curr = rawLines[i];
      if (!curr.trim()) {
        const prevNonEmpty = lines.length > 0 ? lines[lines.length - 1].trim() : "";
        let nextNonEmpty = "";
        for (let j = i + 1; j < rawLines.length; j++) {
          if (rawLines[j].trim()) {
            nextNonEmpty = rawLines[j].trim();
            break;
          }
        }
        if (prevNonEmpty.startsWith("|") && nextNonEmpty.startsWith("|")) {
          continue; // Collapse blank line inside a markdown table
        }
      }
      lines.push(curr);
    }

    const elements: React.ReactNode[] = [];
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];
      const trimmed = line.trim();

      if (!trimmed) {
        elements.push(<div key={`sp-${blockIdx}-${i}`} className="h-2" />);
        i++;
        continue;
      }

      // Horizontal Rule
      if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
        elements.push(
          <hr
            key={`hr-${blockIdx}-${i}`}
            className={`my-4 border-t ${isUser ? "border-white/20" : "border-gray-200"}`}
          />
        );
        i++;
        continue;
      }

      // Markdown Table
      if (trimmed.startsWith("|") && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
        const headers = parseTableRow(trimmed);
        const colCount = Math.max(headers.length, 1);
        i += 2; // Skip header and separator
        const rows: string[][] = [];
        while (i < lines.length && lines[i].trim().startsWith("|")) {
          if (!isTableSeparator(lines[i])) {
            rows.push(parseTableRow(lines[i]));
          }
          i++;
        }

        elements.push(
          <div
            key={`tbl-${blockIdx}-${i}`}
            className="my-3.5 overflow-x-auto rounded-xl border border-gray-200 shadow-2xs bg-white"
          >
            <table className="w-full text-left border-collapse text-xs md:text-[13px]">
              <thead>
                <tr className="bg-slate-50/90 border-b border-gray-200 text-gray-700">
                  {headers.map((h, hIdx) => (
                    <th
                      key={`th-${hIdx}`}
                      className="py-2.5 px-3.5 font-semibold tracking-tight text-gray-800 whitespace-nowrap"
                    >
                      {renderInlineContent(h, `th-${blockIdx}-${i}-${hIdx}`, false)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {rows.map((row, rIdx) => (
                  <tr
                    key={`tr-${rIdx}`}
                    className="hover:bg-slate-50/60 transition-colors align-top"
                  >
                    {row.map((cell, cIdx) => {
                      const spanCols =
                        row.length < colCount && cIdx === row.length - 1
                          ? colCount - cIdx
                          : 1;
                      return (
                        <td
                          key={`td-${cIdx}`}
                          colSpan={spanCols > 1 ? spanCols : undefined}
                          className={`py-2.5 px-3.5 text-gray-700 leading-relaxed ${
                            cIdx === 0 ? "font-medium text-gray-900 whitespace-nowrap" : ""
                          }`}
                        >
                          {renderInlineContent(cell, `td-${blockIdx}-${rIdx}-${cIdx}`, false)}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
        continue;
      }

      // Headings
      const headingMatch = trimmed.match(/^(#{1,4})\s+(.*)$/);
      if (headingMatch) {
        const level = headingMatch[1].length;
        const text = headingMatch[2];
        if (level === 1) {
          elements.push(
            <h1
              key={`h1-${blockIdx}-${i}`}
              className={`text-lg font-bold mt-4 mb-2 ${isUser ? "text-white" : "text-gray-900"}`}
            >
              {renderInlineContent(text, `h1-${blockIdx}-${i}`, isUser)}
            </h1>
          );
        } else if (level === 2) {
          elements.push(
            <h2
              key={`h2-${blockIdx}-${i}`}
              className={`text-[15px] font-bold mt-4 mb-2 pb-1.5 border-b flex items-center gap-2 ${
                isUser
                  ? "text-white border-white/20"
                  : "text-slate-900 border-slate-200/80"
              }`}
            >
              <span className="w-1.5 h-4 rounded-full bg-primary inline-block shrink-0" />
              <span>{renderInlineContent(text, `h2-${blockIdx}-${i}`, isUser)}</span>
            </h2>
          );
        } else if (level === 3) {
          elements.push(
            <h3
              key={`h3-${blockIdx}-${i}`}
              className={`text-sm font-bold mt-3 mb-1.5 ${isUser ? "text-white" : "text-gray-900"}`}
            >
              {renderInlineContent(text, `h3-${blockIdx}-${i}`, isUser)}
            </h3>
          );
        } else {
          elements.push(
            <h4
              key={`h4-${blockIdx}-${i}`}
              className={`text-xs font-semibold uppercase tracking-wider mt-2.5 mb-1 ${
                isUser ? "text-white/90" : "text-gray-700"
              }`}
            >
              {renderInlineContent(text, `h4-${blockIdx}-${i}`, isUser)}
            </h4>
          );
        }
        i++;
        continue;
      }

      // Unordered List
      if (/^[-*•]\s+/.test(trimmed)) {
        const items: string[] = [];
        while (i < lines.length && /^[-*•]\s+/.test(lines[i].trim())) {
          items.push(lines[i].trim().replace(/^[-*•]\s+/, ""));
          i++;
        }
        elements.push(
          <ul key={`ul-${blockIdx}-${i}`} className="my-2 space-y-1.5 pl-4 list-disc marker:text-primary">
            {items.map((item, idx) => (
              <li
                key={`li-${idx}`}
                className={`text-sm leading-relaxed ${isUser ? "text-white" : "text-gray-700"}`}
              >
                {renderInlineContent(item, `ul-${blockIdx}-${i}-${idx}`, isUser)}
              </li>
            ))}
          </ul>
        );
        continue;
      }

      // Ordered List
      if (/^\d+\.\s+/.test(trimmed)) {
        const items: string[] = [];
        while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) {
          items.push(lines[i].trim().replace(/^\d+\.\s+/, ""));
          i++;
        }
        elements.push(
          <ol key={`ol-${blockIdx}-${i}`} className="my-2 space-y-1.5 pl-5 list-decimal marker:font-semibold marker:text-primary">
            {items.map((item, idx) => (
              <li
                key={`oli-${idx}`}
                className={`text-sm leading-relaxed ${isUser ? "text-white" : "text-gray-700"}`}
              >
                {renderInlineContent(item, `ol-${blockIdx}-${i}-${idx}`, isUser)}
              </li>
            ))}
          </ol>
        );
        continue;
      }

      // Blockquote
      if (trimmed.startsWith(">")) {
        const quoteText = trimmed.replace(/^>\s*/, "");
        elements.push(
          <blockquote
            key={`bq-${blockIdx}-${i}`}
            className={`my-2.5 pl-3.5 py-1 border-l-3 italic text-sm ${
              isUser
                ? "border-white/50 text-white/90"
                : "border-primary/60 bg-slate-50/70 text-gray-700 rounded-r-md"
            }`}
          >
            {renderInlineContent(quoteText, `bq-${blockIdx}-${i}`, isUser)}
          </blockquote>
        );
        i++;
        continue;
      }

      // Regular Paragraph
      elements.push(
        <p
          key={`p-${blockIdx}-${i}`}
          className={`mb-2 text-sm leading-relaxed ${isUser ? "text-white" : "text-gray-700"}`}
        >
          {renderInlineContent(line, `p-${blockIdx}-${i}`, isUser)}
        </p>
      );
      i++;
    }

    return <div key={blockIdx}>{elements}</div>;
  };

  const renderMessageContent = (content: string, isUser: boolean = false) => {
    const parts = content.split(/(```[\s\S]*?```)/g);

    return parts.map((part, index) => {
      if (part.startsWith("```") && part.endsWith("```")) {
        const lines = part.split("\n");
        const lang = lines[0].replace("```", "").trim() || "code";
        const code = lines.slice(1, -1).join("\n");

        return (
          <div
            key={index}
            className="my-3.5 rounded-xl overflow-hidden border border-gray-800 bg-[#0d1117] text-gray-200 shadow-xs"
          >
            <div className="flex items-center justify-between px-3.5 py-2 bg-[#161b22] border-b border-gray-800 text-xs font-mono text-gray-400">
              <span className="flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-blue-400" />
                {lang}
              </span>
              <button
                type="button"
                onClick={() => copyToClipboard(code, index)}
                className="flex items-center gap-1 hover:text-white transition-colors"
              >
                {copiedIndex === index ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-3.5 text-xs md:text-sm font-mono overflow-x-auto leading-relaxed text-emerald-300">
              <code>{code}</code>
            </pre>
          </div>
        );
      }

      return renderMarkdownBlock(part, index, isUser);
    });
  };

  return (
    <div
      onMouseMove={handleCardMouseMove}
      className="relative group flex flex-col h-[calc(100vh-8rem)] max-w-5xl mx-auto bg-surface border border-border hover:border-blue-400/60 rounded-2xl shadow-xs hover:shadow-lg hover:shadow-blue-500/5 transition-all duration-300 overflow-hidden"
    >
      {/* Cursor Spotlight Glow */}
      <div
        className="pointer-events-none absolute -inset-px rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 z-0"
        style={{
          background:
            "radial-gradient(420px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(37, 99, 235, 0.05), transparent 80%)",
        }}
      />
      {/* Top Animated Accent Bar */}
      <div className="absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent via-blue-500 to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center z-20" />

      {/* Header */}
      <div className="relative z-10 px-5 py-4 border-b border-border bg-white flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-10 h-10 bg-primary/10 border border-primary/20 rounded-xl flex items-center justify-center shrink-0 group-hover:scale-105 group-hover:-rotate-6 transition-transform duration-300">
            <Bot className="w-5 h-5 text-primary" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="font-bold text-foreground">SentinelX AI Copilot</h1>
              <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1 whitespace-nowrap">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                Connected
              </span>
            </div>
            <p className="text-xs text-muted mt-0.5">
              Principal telemetry analysis, MITRE threat correlation & production remediation drafting
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {/* Response Mode Selector */}
          <div className="inline-flex items-center bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-[11px] font-medium">
            {[
              { id: "deep" as const, label: "Deep Technical" },
              { id: "executive" as const, label: "Executive Brief" },
              { id: "concise" as const, label: "Concise" },
            ].map((modeOpt) => (
              <button
                key={modeOpt.id}
                type="button"
                onClick={() => setResponseMode(modeOpt.id)}
                className={`px-2.5 py-1 rounded-md transition-all whitespace-nowrap ${
                  responseMode === modeOpt.id
                    ? "bg-white text-primary font-semibold shadow-2xs"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                {modeOpt.label}
              </button>
            ))}
          </div>

          {keyStatus !== null && (
            <div className={`flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-lg border whitespace-nowrap ${
              keyStatus.configured
                ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                : "bg-amber-50 text-amber-800 border-amber-300"
            }`}>
              <Sparkles className={`w-3.5 h-3.5 ${keyStatus.configured ? "text-emerald-600" : "text-amber-600"}`} />
              <span>
                {keyStatus.configured
                  ? (keyStatus.provider && keyStatus.provider !== "Local Summary Mode"
                      ? `${keyStatus.provider} Active`
                      : "AI Engine Active")
                  : "Local Summary Mode"}
              </span>
            </div>
          )}

          {messages.length > 1 && (
            <button
              type="button"
              onClick={handleResetChat}
              disabled={isLoading}
              title="Reset conversation"
              className="inline-flex items-center gap-1 text-xs font-medium text-slate-600 hover:text-slate-900 bg-white border border-border hover:bg-slate-50 rounded-lg px-2.5 py-1 transition-all"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">New Chat</span>
            </button>
          )}
        </div>
      </div>

      <div className="relative z-10 px-5 py-2 text-[11px] text-muted border-b border-border bg-slate-50/70 flex flex-wrap items-center justify-between gap-2">
        <span>Grounded in recorded audit findings, CSPM checks, threat streams, alerts, and CI/CD runs.</span>
        <span className="hidden sm:inline-flex items-center gap-1 font-medium text-slate-600">
          <Shield className="w-3 h-3 text-primary" /> Telemetry Context Active
        </span>
      </div>

      {/* Messages Area */}
      <div className="relative z-10 flex-1 overflow-y-auto p-5 space-y-5 bg-gray-50/50">
        {messages.map((msg) => (
          <div key={msg.id} className={`flex gap-3.5 ${msg.role === "user" ? "flex-row-reverse" : "flex-row"}`}>
            <div className={`w-8 h-8 shrink-0 rounded-full flex items-center justify-center shadow-xs ${
              msg.role === "user" ? "bg-gray-800 text-white" : "bg-primary text-white"
            }`}>
              {msg.role === "user" ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
            </div>

            <div className={`max-w-[92%] md:max-w-[88%] rounded-2xl px-5 py-4 shadow-xs transition-all duration-200 ${
              msg.role === "user"
                ? "bg-primary text-white rounded-tr-none"
                : "bg-white border border-gray-200/90 hover:border-blue-300/70 text-gray-800 rounded-tl-none"
            }`}>
              {renderMessageContent(msg.content, msg.role === "user")}
              {msg.engine && (
                <div className="mt-3 pt-2.5 border-t border-gray-100 flex items-center justify-between gap-2 text-[11px] text-muted">
                  <span className="flex items-center gap-1.5 font-medium text-slate-500">
                    <Sparkles className="w-3.5 h-3.5 text-amber-500" />
                    <span>Powered by {msg.engine}</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(msg.content, Number(msg.id.replace(/\D/g, "")) || 999)}
                    className="flex items-center gap-1 text-slate-400 hover:text-slate-700 transition-colors"
                  >
                    {copiedIndex === (Number(msg.id.replace(/\D/g, "")) || 999) ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-500" />
                        <span className="text-emerald-600">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copy report</span>
                      </>
                    )}
                  </button>
                </div>
              )}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex gap-3.5 flex-row">
            <div className="w-8 h-8 shrink-0 rounded-full flex items-center justify-center bg-primary text-white">
              <Bot className="w-4 h-4" />
            </div>
            <div className="bg-white border border-gray-200 rounded-2xl rounded-tl-none px-5 py-3 shadow-xs flex items-center gap-2.5">
              <Loader2 className="w-4 h-4 text-primary animate-spin" />
              <span className="text-xs font-medium text-muted">
                Correlating telemetry, attacker indicators & crafting {responseMode} remediation...
              </span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Prompts Bar */}
      <div className="relative z-10 px-4 py-2.5 bg-white border-t border-border flex items-center gap-2 overflow-x-auto text-xs">
        <span className="text-muted shrink-0 flex items-center gap-1 font-medium">
          <Sparkles className="w-3.5 h-3.5 text-primary" /> Playbooks:
        </span>
        {quickPrompts.map((qp, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => void sendPrompt(qp.query)}
            disabled={isLoading}
            className="shrink-0 px-3 py-1 rounded-full bg-slate-50 hover:bg-blue-50 hover:text-primary hover:border-blue-200 text-gray-700 transition-all border border-gray-200 font-medium"
          >
            {qp.label}
          </button>
        ))}
      </div>

      {/* Input Form */}
      <div className="relative z-10 p-4 bg-white border-t border-border">
        <form onSubmit={handleSubmit} className="flex items-end gap-2.5">
          <textarea
            rows={1}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                if (input.trim() && !isLoading) void sendPrompt(input);
              }
            }}
            placeholder="Ask about active threats, audit observations, or draft Nginx / Terraform / WAF remediations (Shift+Enter for newline)..."
            className="flex-1 resize-none px-4 py-2.5 bg-gray-50 border border-gray-300 rounded-xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary text-foreground text-sm max-h-32 transition-all"
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={!input.trim() || isLoading}
            className="bg-primary hover:bg-blue-700 hover:scale-[1.02] text-white px-5 py-2.5 rounded-xl font-semibold text-sm transition-all disabled:opacity-50 flex items-center gap-2 shrink-0 shadow-xs"
          >
            <Send className="w-4 h-4" />
            <span>Send</span>
          </button>
        </form>
      </div>
    </div>
  );
}
