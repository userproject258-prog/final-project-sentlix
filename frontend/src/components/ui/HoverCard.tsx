"use client";

import type { ReactNode } from "react";

export type HoverAccent = "blue" | "emerald" | "indigo" | "amber" | "rose" | "violet" | "cyan";

export const HOVER_ACCENTS: Record<
  HoverAccent,
  { border: string; glow: string; bar: string; shadow: string; tileGlow: string }
> = {
  blue: {
    border: "hover:border-blue-400/80",
    glow: "rgba(37, 99, 235, 0.08)",
    tileGlow: "rgba(37, 99, 235, 0.11)",
    bar: "via-blue-500",
    shadow: "hover:shadow-blue-500/10",
  },
  emerald: {
    border: "hover:border-emerald-400/80",
    glow: "rgba(16, 185, 129, 0.08)",
    tileGlow: "rgba(16, 185, 129, 0.11)",
    bar: "via-emerald-500",
    shadow: "hover:shadow-emerald-500/10",
  },
  indigo: {
    border: "hover:border-indigo-400/80",
    glow: "rgba(99, 102, 241, 0.08)",
    tileGlow: "rgba(99, 102, 241, 0.11)",
    bar: "via-indigo-500",
    shadow: "hover:shadow-indigo-500/10",
  },
  amber: {
    border: "hover:border-amber-400/80",
    glow: "rgba(245, 158, 11, 0.09)",
    tileGlow: "rgba(245, 158, 11, 0.12)",
    bar: "via-amber-500",
    shadow: "hover:shadow-amber-500/10",
  },
  rose: {
    border: "hover:border-rose-400/80",
    glow: "rgba(225, 29, 72, 0.08)",
    tileGlow: "rgba(225, 29, 72, 0.11)",
    bar: "via-rose-500",
    shadow: "hover:shadow-rose-500/10",
  },
  violet: {
    border: "hover:border-violet-400/80",
    glow: "rgba(139, 92, 246, 0.08)",
    tileGlow: "rgba(139, 92, 246, 0.11)",
    bar: "via-violet-500",
    shadow: "hover:shadow-violet-500/10",
  },
  cyan: {
    border: "hover:border-cyan-400/80",
    glow: "rgba(6, 182, 212, 0.08)",
    tileGlow: "rgba(6, 182, 212, 0.11)",
    bar: "via-cyan-500",
    shadow: "hover:shadow-cyan-500/10",
  },
};

export function handleSpotlightMove(e: React.MouseEvent<HTMLElement>) {
  const rect = e.currentTarget.getBoundingClientRect();
  e.currentTarget.style.setProperty("--mouse-x", `${e.clientX - rect.left}px`);
  e.currentTarget.style.setProperty("--mouse-y", `${e.clientY - rect.top}px`);
}

export function HoverCard({
  accent = "blue",
  as = "section",
  className = "",
  ariaLabel,
  ariaLabelledBy,
  children,
}: {
  accent?: HoverAccent;
  as?: "div" | "section" | "aside";
  className?: string;
  ariaLabel?: string;
  ariaLabelledBy?: string;
  children: ReactNode;
}) {
  const palette = HOVER_ACCENTS[accent];
  const Tag = as;

  return (
    <Tag
      onMouseMove={handleSpotlightMove}
      aria-label={ariaLabel}
      aria-labelledby={ariaLabelledBy}
      className={`relative overflow-hidden group bg-white border border-border ${palette.border} rounded-lg shadow-xs hover:shadow-lg ${palette.shadow} hover:-translate-y-0.5 transition-all duration-300 ease-out ${className}`}
    >
      <div
        className="pointer-events-none absolute -inset-px rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{
          background: `radial-gradient(340px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), ${palette.glow}, transparent 80%)`,
        }}
      />
      <div
        className={`pointer-events-none absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent ${palette.bar} to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center z-20`}
      />
      <div className="relative z-10 flex flex-col flex-1 h-full">{children}</div>
    </Tag>
  );
}

export function HoverTileOverlay({ accent = "blue" }: { accent?: HoverAccent }) {
  const palette = HOVER_ACCENTS[accent];
  return (
    <>
      <div
        className="pointer-events-none absolute -inset-px opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{
          background: `radial-gradient(200px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), ${palette.tileGlow}, transparent 80%)`,
        }}
      />
      <div
        className={`pointer-events-none absolute top-0 inset-x-0 h-[2.5px] bg-gradient-to-r from-transparent ${palette.bar} to-transparent scale-x-0 group-hover:scale-x-100 transition-transform duration-300 ease-out origin-center z-20`}
      />
    </>
  );
}
