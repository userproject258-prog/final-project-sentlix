"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useSyncExternalStore } from "react";
import { Bell, User, LogOut } from "lucide-react";
import { API_URL, apiFetch } from "@/lib/api";

function subscribeUser(callback: () => void) {
  window.addEventListener("storage", callback);
  return () => window.removeEventListener("storage", callback);
}

function getStoredUserName() {
  try {
    const stored = localStorage.getItem("sentinelx_user");
    if (stored) {
      const u = JSON.parse(stored);
      if (u.name) return u.name as string;
    }
  } catch {
    // Ignore parse errors
  }
  return "SecOps Analyst";
}

function getServerUserName() {
  return "SecOps Analyst";
}

export function Topbar() {
  const router = useRouter();
  const userName = useSyncExternalStore(subscribeUser, getStoredUserName, getServerUserName);

  const handleLogout = async () => {
    try { await apiFetch(`${API_URL}/api/auth/logout`, { method: "POST" }); } catch { /* Clear local session even if offline. */ }
    localStorage.removeItem("sentinelx_token");
    localStorage.removeItem("sentinelx_user");
    router.replace("/login");
  };

  return (
    <header className="h-14 bg-surface flex items-center justify-between px-3 sm:px-6 flex-shrink-0">
      <p className="text-sm font-semibold text-foreground">Security workspace</p>
      
      <div className="flex items-center gap-4">
        <Link href="/alerts" aria-label="View alerts" className="relative p-2 text-muted hover:text-foreground transition-colors" title="Alerts">
          <Bell className="w-5 h-5" />
        </Link>
        
        <div className="flex items-center gap-2 border-l border-border pl-4">
          <Link href="/settings" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
            <div className="w-8 h-8 rounded-full bg-primary/10 border-sentinel flex items-center justify-center text-primary font-medium text-sm">
              <User className="w-4 h-4" />
            </div>
            <span className="text-xs font-semibold text-foreground hidden sm:inline">{userName}</span>
          </Link>

          <button 
            onClick={handleLogout} 
            title="Sign out"
            className="p-1.5 text-muted hover:text-red-600 rounded-md hover:bg-red-50 transition-colors ml-1"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
}

