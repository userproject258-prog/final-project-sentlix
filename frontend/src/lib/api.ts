const rawApiUrl = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").trim().replace(/\/+$/, "");

export const API_URL =
  typeof window !== "undefined" &&
  window.location.protocol === "https:" &&
  rawApiUrl.startsWith("http://") &&
  !rawApiUrl.includes("localhost")
    ? rawApiUrl.replace("http://", "https://")
    : rawApiUrl;

export const WS_URL =
  process.env.NEXT_PUBLIC_WS_URL ||
  (API_URL.startsWith("https://")
    ? API_URL.replace("https://", "wss://") + "/ws/live"
    : API_URL.replace("http://", "ws://") + "/ws/live");

interface CacheEntry {
  value: unknown;
  storedAt: number;
}

const responseCache = new Map<string, CacheEntry>();
const inFlightPrefetches = new Map<string, Promise<unknown>>();
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;

export function getCachedData<T>(key: string, maxAgeMs = DEFAULT_CACHE_TTL_MS): T | null {
  const entry = responseCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.storedAt > maxAgeMs) {
    responseCache.delete(key);
    return null;
  }
  return entry.value as T;
}

export function setCachedData(key: string, value: unknown): void {
  responseCache.set(key, { value, storedAt: Date.now() });
}

export function clearApiCache(): void {
  responseCache.clear();
  inFlightPrefetches.clear();
}

export async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const token = typeof window === "undefined" ? null : localStorage.getItem("sentinelx_token");
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await globalThis.fetch(input, { ...init, headers });
  if (response.status === 401 && typeof window !== "undefined") {
    clearApiCache();
    localStorage.removeItem("sentinelx_token");
    localStorage.removeItem("sentinelx_user");
    window.location.replace("/login");
  }
  return response;
}

export function prefetchEndpoint(path: string): Promise<unknown> | null {
  if (typeof window === "undefined") return null;
  const existing = inFlightPrefetches.get(path);
  if (existing) return existing;
  const task = apiFetch(`${API_URL}${path}`)
    .then((res) => (res.ok ? res.json() : null))
    .then((json) => {
      if (json !== null) setCachedData(path, json);
      return json;
    })
    .catch(() => null)
    .finally(() => {
      inFlightPrefetches.delete(path);
    });
  inFlightPrefetches.set(path, task);
  return task;
}

export function websocketProtocols(): string[] {
  const token = typeof window === "undefined" ? null : localStorage.getItem("sentinelx_token");
  return token ? ["bearer", token] : [];
}
