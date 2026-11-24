"use client";

import { useEffect, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";
import { AppShell } from "@/components/layout/AppShell";
import { Loader2 } from "lucide-react";
import { API_URL, apiFetch } from "@/lib/api";

function subscribeToken(callback: () => void) {
  window.addEventListener("storage", callback);
  return () => window.removeEventListener("storage", callback);
}

function getClientHasToken(): boolean {
  try {
    return Boolean(localStorage.getItem("sentinelx_token"));
  } catch {
    return false;
  }
}

function getServerHasToken(): boolean {
  return false;
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const hasToken = useSyncExternalStore(subscribeToken, getClientHasToken, getServerHasToken);

  useEffect(() => {
    if (!hasToken) {
      router.replace("/login");
      return;
    }

    // Validate session in the background without blocking dashboard rendering or initial data fetch.
    // If the session is invalid/expired, apiFetch clears localStorage and redirects to /login on 401.
    void apiFetch(`${API_URL}/api/auth/me`).catch(() => {
      // Offline / transient network errors shouldn't trap the user behind a permanent spinner
    });
  }, [hasToken, router]);

  if (!hasToken) {
    return (
      <div className="h-screen w-screen flex flex-col items-center justify-center bg-background text-foreground gap-3">
        <Loader2 className="w-6 h-6 text-primary animate-spin" />
        <p className="text-xs text-muted font-medium">Redirecting to sign in...</p>
      </div>
    );
  }

  return <AppShell>{children}</AppShell>;
}
