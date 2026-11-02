"use client";

import { useEffect, useState } from "react";
import { Menu, X } from "lucide-react";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";

export function AppShell({ children }: { children: React.ReactNode }) {
  const [menuOpen, setMenuOpen] = useState(false);
  useEffect(() => {
    if (!menuOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") setMenuOpen(false); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [menuOpen]);
  return (
    <div className="flex h-screen w-full bg-background overflow-hidden">
      <div className="hidden md:block"><Sidebar /></div>
      {menuOpen && (
        <div className="fixed inset-0 z-50 flex md:hidden">
          <button aria-label="Close navigation" className="absolute inset-0 bg-slate-950/50" onClick={() => setMenuOpen(false)} />
          <div className="relative h-full shadow-xl"><Sidebar onNavigate={() => setMenuOpen(false)} /></div>
          <button aria-label="Close navigation" className="relative m-3 self-start rounded-md bg-white p-2 text-slate-800" onClick={() => setMenuOpen(false)}><X className="h-5 w-5" /></button>
        </div>
      )}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <div className="flex items-center border-b border-border">
          <button aria-label="Open navigation" aria-expanded={menuOpen} className="ml-3 rounded-md p-2 text-foreground hover:bg-slate-100 md:hidden" onClick={() => setMenuOpen(true)}><Menu className="h-5 w-5" /></button>
          <div className="min-w-0 flex-1"><Topbar /></div>
        </div>
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 animate-fade-in">
          {children}
        </main>
      </div>
    </div>
  );
}
