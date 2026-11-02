const rawApiUrl = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").trim().replace(/\/+$/, "");

// If deployed on railway or modern web with https, upgrade http to https to prevent mixed content blocking
export const API_URL = (
  typeof window !== "undefined" && window.location.protocol === "https:" && rawApiUrl.startsWith("http://") && !rawApiUrl.includes("localhost")
    ? rawApiUrl.replace("http://", "https://")
    : rawApiUrl
);

export const WS_URL = process.env.NEXT_PUBLIC_WS_URL || (
  API_URL.startsWith("https://") 
    ? API_URL.replace("https://", "wss://") + "/ws/live"
    : API_URL.replace("http://", "ws://") + "/ws/live"
);

export async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const token = typeof window === "undefined" ? null : localStorage.getItem("sentinelx_token");
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await globalThis.fetch(input, { ...init, headers });
  if (response.status === 401 && typeof window !== "undefined") {
    localStorage.removeItem("sentinelx_token");
    localStorage.removeItem("sentinelx_user");
    window.location.replace("/login");
  }
  return response;
}

export function websocketProtocols(): string[] {
  const token = typeof window === "undefined" ? null : localStorage.getItem("sentinelx_token");
  return token ? ["bearer", token] : [];
}

