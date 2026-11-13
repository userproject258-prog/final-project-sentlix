from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, List, Dict, Any, Optional, Tuple
import hashlib
import requests
import re
import time
import uuid
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


# ── Input Schema ─────────────────────────────────────────────────────────────

class DeepEndpointDiscoveryInput(BaseModel):
    """Input schema for the Deep Endpoint and Directory Discovery Tool."""
    base_url: str = Field(
        ...,
        description=(
            "The base URL of the target to probe (e.g. https://example.com). "
            "Must include the scheme (http:// or https://)."
        ),
    )


# ── Target Paths ──────────────────────────────────────────────────────────────

ADMIN_PATHS: List[str] = [
    "/admin", "/administrator", "/admin/login", "/admin/dashboard",
    "/wp-admin", "/cpanel", "/phpmyadmin", "/adminer", "/wp-json/wp/v2/users",
]

API_PATHS: List[str] = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/users", "/api/admin",
    "/graphql", "/swagger", "/swagger-ui.html", "/api-docs",
    "/openapi.json", "/swagger.json", "/docs", "/v1/api-docs", "/v2/api-docs",
    "/api/health",
]

SENSITIVE_CONFIG_PATHS: List[str] = [
    "/.env", "/.env.local", "/.env.production", "/config.php", "/web.config", "/phpinfo.php",
    "/.git/config", "/.git/HEAD", "/config.json", "/package.json",
    "/.htaccess", "/backup.zip", "/dump.sql", "/database.sql",
    "/server-status", "/server-info", "/actuator/env", "/actuator/health",
    "/actuator/heapdump", "/.DS_Store",
]

CLOUD_DEVOPS_PATHS: List[str] = [
    "/docker-compose.yml", "/Dockerfile", "/.dockerenv",
    "/terraform.tfstate", "/.kube/config", "/metrics", "/prometheus",
    "/debug/pprof/", "/_profiler", "/__debug__/",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
]

AUTH_PATHS: List[str] = [
    "/login", "/signin", "/register", "/signup", "/forgot-password",
    "/reset-password", "/logout", "/auth", "/oauth", "/oauth/token",
    "/token", "/refresh", "/sso",
]

PUBLIC_CORE_PATHS: List[str] = [
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/health", "/status", "/ping", "/version",
]

STANDARD_PATHS: List[str] = (
    ADMIN_PATHS[:6] + API_PATHS[:10] + SENSITIVE_CONFIG_PATHS[:12] + AUTH_PATHS[:6] + PUBLIC_CORE_PATHS
)

ALL_DEEP_PATHS: List[str] = list(dict.fromkeys(
    ADMIN_PATHS + API_PATHS + SENSITIVE_CONFIG_PATHS + CLOUD_DEVOPS_PATHS + AUTH_PATHS + PUBLIC_CORE_PATHS
))

CRITICAL_PATTERNS = [
    ".env", ".git", "phpinfo", "backup", "dump.sql", "database.sql",
    "actuator/env", "actuator/heapdump", "config.json", "web.config",
    "terraform.tfstate", ".kube/config", "docker-compose",
]

# Secret patterns to check inside client-side JS bundles
JS_SECRET_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CRITICAL"),
    ("Google Cloud / Maps API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "HIGH"),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "CRITICAL"),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "CRITICAL"),
    ("Slack Webhook / Token", re.compile(r"\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b"), "HIGH"),
    ("Embedded JWT Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{12,}\.[A-Za-z0-9_\-]{12,}\.[A-Za-z0-9_\-]{10,}\b"), "MEDIUM"),
]

JS_API_ROUTE_PATTERN = re.compile(r"""["'](/api/v?\d*/[a-zA-Z0-9_\-/{}]+|/v[123]/[a-zA-Z0-9_\-/{}]+)["']""")


# ── Helpers & Baseline Verification ───────────────────────────────────────────

def _mask_secret(val: str) -> str:
    if len(val) <= 10:
        return "*" * len(val)
    return f"{val[:5]}...{val[-4:]}"


def _probe_soft404_baseline(base_url: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """Probe a guaranteed nonexistent path to detect SPA catch-all / custom 200 OK 404 responses."""
    canary_path = f"/__sentinelx_canary_404_{uuid.uuid4().hex[:10]}"
    url = f"{base_url.rstrip('/')}{canary_path}"
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SentinelX-DeepScanner/2.0)"},
        )
        body_prefix = resp.text[:512].strip().lower()
        return {
            "status": resp.status_code,
            "size": len(resp.content),
            "content_type": resp.headers.get("Content-Type", "").split(";")[0].strip().lower(),
            "body_hash": hashlib.sha256(body_prefix.encode("utf-8", errors="ignore")).hexdigest(),
            "is_html": "<html" in body_prefix or "<!doctype html" in body_prefix,
        }
    except Exception:
        return None


def _validate_content_signature(path: str, status: Optional[int], content_type: str, body_sample: str) -> bool:
    """
    Verify that a 200 OK response for a sensitive/structured file matches expected file semantics
    rather than an HTML SPA fallback or generic error page.
    """
    if status != 200:
        return True
    p = path.lower()
    ct = content_type.lower()
    sample = body_sample.strip()
    sample_lower = sample.lower()
    looks_like_html = "<html" in sample_lower[:400] or "<!doctype html" in sample_lower[:400] or "text/html" in ct

    if any(ext in p for ext in [".env", ".git/", ".sql", ".yml", "dockerfile", "terraform.tfstate", ".kube/config", "robots.txt", ".htaccess", ".ds_store"]):
        if looks_like_html:
            return False
        if ".git/head" in p and ("ref:" not in sample_lower and not re.match(r"^[0-9a-f]{40}", sample_lower)):
            return False
        if ".git/config" in p and "[core]" not in sample_lower and "[remote" not in sample_lower:
            return False
        if ".env" in p and "=" not in sample:
            return False
        if "terraform.tfstate" in p and "terraform_version" not in sample_lower:
            return False
        if ".yml" in p and ":" not in sample:
            return False

    if any(ext in p for ext in ["openapi.json", "swagger.json", "package.json", "config.json", "jwks.json", "openid-configuration", "actuator/"]):
        if looks_like_html:
            return False
        if not (sample.startswith("{") or sample.startswith("[")):
            return False

    if "phpinfo.php" in p and "php version" not in sample_lower:
        return False

    if "sitemap.xml" in p and "<urlset" not in sample_lower and "<sitemapindex" not in sample_lower:
        return False

    return True


def _classify_status(status: Optional[int], is_soft_404: bool = False) -> str:
    if status is None:
        return "Connection Failed"
    if is_soft_404:
        return f"Soft-404 / Catch-All ({status})"
    if status == 200:
        return "Exposed (200 OK)"
    if status == 201:
        return "Created (201)"
    if status in (301, 302, 303, 307, 308):
        return f"Redirected ({status})"
    if status == 401:
        return "Unauthorized (401)"
    if status == 403:
        return "Forbidden (403)"
    if status == 404:
        return "Not Found (404)"
    if status == 405:
        return "Method Not Allowed (405)"
    if status == 429:
        return "Rate Limited (429)"
    if status >= 500:
        return f"Server Error ({status})"
    return f"HTTP {status}"


def _assess_risk(path: str, status: Optional[int], verified_content: bool = True, is_soft_404: bool = False) -> str:
    if status is None or is_soft_404 or not verified_content:
        return "Info"
    path_lower = path.lower()

    if status == 200 and any(pat in path_lower for pat in CRITICAL_PATTERNS):
        return "Critical"

    if status == 200 and any(p in path_lower for p in ["/admin", "/wp-admin", "/phpmyadmin", "/adminer", "/actuator", "/_profiler", "/__debug__"]):
        return "High"

    if status == 200 and any(p in path_lower for p in ["/swagger", "/openapi.json", "/swagger.json", "/api-docs", "/graphql", "/metrics", "/prometheus", "/debug/pprof", "/wp-json/wp/v2/users"]):
        return "Medium"

    if status == 403 and any(p in path_lower for p in ["/admin", "/.git", "/.env", "/cpanel", "/actuator"]):
        return "Medium"

    if status == 200:
        return "Low"

    return "Info"


def _probe_single(
    base_url: str,
    path: str,
    baseline: Optional[Dict[str, Any]] = None,
    timeout: float = 6.0,
) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    start_time = time.time()
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            },
        )
        latency_ms = int((time.time() - start_time) * 1000)
        content_type = resp.headers.get("Content-Type", "—").split(";")[0].strip()
        location = resp.headers.get("Location", "—")
        server = resp.headers.get("Server", "—")
        body_sample = resp.text[:1024] if resp.text else ""
        body_prefix = body_sample[:512].strip().lower()
        body_hash = hashlib.sha256(body_prefix.encode("utf-8", errors="ignore")).hexdigest()

        is_soft_404 = False
        if baseline and resp.status_code == baseline["status"] and baseline["status"] == 200:
            size_delta = abs(len(resp.content) - baseline["size"])
            if body_hash == baseline["body_hash"] or (size_delta <= 48 and baseline["is_html"] and "<html" in body_prefix):
                is_soft_404 = True

        verified_content = _validate_content_signature(path, resp.status_code, content_type, body_sample)
        if not verified_content and resp.status_code == 200:
            is_soft_404 = True

        return {
            "path": path,
            "url": url,
            "status": resp.status_code,
            "classification": _classify_status(resp.status_code, is_soft_404=is_soft_404),
            "size": len(resp.content),
            "latency_ms": latency_ms,
            "content_type": content_type,
            "location": location,
            "server": server,
            "risk": _assess_risk(path, resp.status_code, verified_content=verified_content, is_soft_404=is_soft_404),
            "verified": verified_content and not is_soft_404,
            "is_soft_404": is_soft_404,
            "error": None,
        }
    except requests.exceptions.Timeout:
        return {
            "path": path,
            "url": url,
            "status": None,
            "classification": "Request Timeout",
            "size": 0,
            "latency_ms": int((time.time() - start_time) * 1000),
            "content_type": "—",
            "location": "—",
            "server": "—",
            "risk": "Low",
            "verified": False,
            "is_soft_404": False,
            "error": "Timeout after 6s",
        }
    except Exception as e:
        return {
            "path": path,
            "url": url,
            "status": None,
            "classification": "Connection Error",
            "size": 0,
            "latency_ms": int((time.time() - start_time) * 1000),
            "content_type": "—",
            "location": "—",
            "server": "—",
            "risk": "Low",
            "verified": False,
            "is_soft_404": False,
            "error": str(e)[:60],
        }


def _extract_robots_paths(base_url: str) -> List[str]:
    discovered = []
    try:
        url = f"{base_url.rstrip('/')}/robots.txt"
        resp = requests.get(url, timeout=5, verify=False)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        target_p = parts[1].strip()
                        if target_p and target_p.startswith("/") and "*" not in target_p and target_p not in discovered:
                            discovered.append(target_p)
    except Exception:
        pass
    return discovered[:20]


def _extract_sitemap_paths(base_url: str) -> List[str]:
    discovered = []
    try:
        url = f"{base_url.rstrip('/')}/sitemap.xml"
        resp = requests.get(url, timeout=5, verify=False)
        if resp.status_code == 200 and "<loc>" in resp.text.lower():
            base_host = urlparse(base_url).netloc.lower()
            locs = re.findall(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", resp.text, re.IGNORECASE)
            for loc in locs:
                parsed = urlparse(loc)
                if parsed.netloc.lower() == base_host and parsed.path and parsed.path not in discovered:
                    discovered.append(parsed.path)
    except Exception:
        pass
    return discovered[:15]


def _extract_js_bundles(base_url: str) -> List[Dict[str, str]]:
    js_records: List[Dict[str, str]] = []
    try:
        resp = requests.get(base_url, timeout=8, verify=False)
        if resp.status_code == 200:
            pattern = r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
            matches = re.findall(pattern, resp.text, re.IGNORECASE)
            seen = set()
            base_domain = urlparse(base_url).netloc.lower()
            for m in matches:
                m = m.strip()
                if not m or m in seen:
                    continue
                seen.add(m)

                full_url = urljoin(base_url, m)
                js_domain = urlparse(full_url).netloc.lower()
                is_internal = (base_domain in js_domain or js_domain in base_domain or not js_domain)

                filename = full_url.split("/")[-1].split("?")[0]
                if any(x in filename.lower() for x in ["vendor", "chunk-vendors", "npm", "libs"]):
                    b_type = "Vendor / Dependency"
                elif any(x in filename.lower() for x in ["app", "main", "bundle", "index", "_app"]):
                    b_type = "Core Application Bundle"
                elif any(x in filename.lower() for x in ["gtm", "analytics", "pixel", "tracking"]):
                    b_type = "Telemetry & Analytics"
                else:
                    b_type = "Client Script"

                js_records.append({
                    "url": full_url,
                    "filename": filename or "script.js",
                    "origin": "Internal" if is_internal else "Third-Party / CDN",
                    "type": b_type,
                })
    except Exception:
        pass
    return js_records[:25]


def _inspect_js_bundles(js_bundles: List[Dict[str, str]]) -> Tuple[List[Dict[str, str]], List[str]]:
    """Inspect internal JS bundles (bounded) for leaked API keys/tokens and hidden API paths."""
    secret_hits: List[Dict[str, str]] = []
    discovered_api_routes: List[str] = []
    internal_bundles = [b for b in js_bundles if b["origin"] == "Internal"][:5]

    for bundle in internal_bundles:
        try:
            resp = requests.get(bundle["url"], timeout=4, verify=False)
            if resp.status_code != 200 or not resp.text:
                continue
            body = resp.text[:400000]  # Bound inspection to first 400KB per bundle

            for label, pattern, sev in JS_SECRET_PATTERNS:
                matches = pattern.findall(body)
                if matches:
                    sample = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    secret_hits.append({
                        "file": bundle["filename"],
                        "url": bundle["url"],
                        "secret_type": label,
                        "masked_sample": _mask_secret(sample),
                        "severity": sev,
                    })

            for route in JS_API_ROUTE_PATTERN.findall(body):
                if route not in discovered_api_routes and len(route) < 80:
                    discovered_api_routes.append(route)
        except Exception:
            continue

    return secret_hits[:10], discovered_api_routes[:20]


# ── Report Generation ─────────────────────────────────────────────────────────

def _format_table(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "| Endpoint Path | HTTP Status | Classification | Latency | Size | Content-Type / Redirect | Risk Level |\n|---|---|---|---|---|---|---|\n| _No endpoints identified in this category_ | — | — | — | — | — | Info |\n"

    out = [
        "| Endpoint Path | HTTP Status | Classification | Latency | Size | Content-Type / Redirect | Risk Level |",
        "|---|---|---|---|---|---|---|"
    ]
    for r in rows:
        status_code = str(r["status"]) if r["status"] is not None else "ERR"
        extra = r["location"] if r["location"] != "—" else (r["content_type"] if r["content_type"] != "—" else r["error"] or "—")
        if len(extra) > 40:
            extra = extra[:37] + "..."
        out.append(
            f"| `{r['path']}` | `{status_code}` | {r['classification']} | `{r['latency_ms']}ms` | `{r['size']} B` | `{extra}` | {r['risk']} |"
        )
    return "\n".join(out)


def _build_discovery_report(
    base_url: str,
    depth: str,
    all_results: List[Dict[str, Any]],
    js_bundles: List[Dict[str, str]],
    robots_paths: List[str],
    sitemap_paths: List[str],
    js_secrets: List[Dict[str, str]],
    js_routes: List[str],
    baseline: Optional[Dict[str, Any]],
) -> str:
    admin_results = [r for r in all_results if r["path"] in ADMIN_PATHS or any(p in r["path"].lower() for p in ["admin", "cpanel", "phpmyadmin", "wp-json"])]
    api_results = [r for r in all_results if r["path"] in API_PATHS or any(p in r["path"].lower() for p in ["api", "graphql", "swagger", "docs", "metrics", "openid"])]
    config_results = [r for r in all_results if r["path"] in SENSITIVE_CONFIG_PATHS or r["path"] in CLOUD_DEVOPS_PATHS or any(p in r["path"].lower() for p in [".env", ".git", "backup", "sql", "config", "docker", "terraform", ".kube"])]
    auth_results = [r for r in all_results if r["path"] in AUTH_PATHS or any(p in r["path"].lower() for p in ["login", "auth", "token", "signup"])]

    total_probed = len(all_results)
    exposed_200 = sum(1 for r in all_results if r["status"] == 200 and not r.get("is_soft_404"))
    soft_404_count = sum(1 for r in all_results if r.get("is_soft_404"))
    redirects_3xx = sum(1 for r in all_results if r["status"] in (301, 302, 303, 307, 308))
    forbidden_403 = sum(1 for r in all_results if r["status"] == 403)
    critical_exposures = [r for r in all_results if r["risk"] in ("Critical", "High") and r["status"] == 200 and r.get("verified")]

    sections = []
    sections.append("# Deep Endpoint & Directory Discovery Audit")
    sections.append(f"**Target System Base URL:** `{base_url}` | **Scan Depth:** `{depth.upper()}`\n")

    sections.append("## Endpoint Discovery Overview\n")
    sections.append("| Discovery Metric | Quantitative Result | Security Interpretation | Status |")
    sections.append("|---|---|---|---|")
    sections.append(f"| Total Route Paths Probed | `{total_probed}` Target Vectors | Comprehensive surface enumeration ({depth} profile) | Configured |")
    sections.append(f"| Verified Accessible (200 OK) | `{exposed_200}` Active Endpoints | Publicly reachable routes verified against soft-404 baseline | {'Warning' if exposed_200 > 15 else 'Normal'} |")
    if baseline and baseline.get("status") == 200:
        sections.append(f"| Soft-404 / Catch-All Filtered | `{soft_404_count}` SPA Fallbacks | Eliminated false-positive 200 OK HTML catch-all responses | Guarded |")
    sections.append(f"| Access Restricted (403 Forbidden) | `{forbidden_403}` Routes Protected | Endpoint discovered but perimeter access denied | Protected |")
    sections.append(f"| Route Redirects (3xx Series) | `{redirects_3xx}` Routed Endpoints | Path forwarded to canonical or auth location | Routed |")
    sections.append(f"| High / Critical Exposures | `{len(critical_exposures)}` Verified Endpoints | Sensitive config/admin files confirmed readable | {'Critical' if len(critical_exposures) > 0 else 'Clean'} |")
    sections.append(f"| Discovered JavaScript Bundles | `{len(js_bundles)}` Client Script Files | Front-end assets analyzed for leaked secrets & API paths | Cataloged |")
    if js_secrets:
        sections.append(f"| Client-Side JS Secret Signals | `{len(js_secrets)}` Pattern Hits | Potential tokens or API keys found inside static bundles | Critical |")
    if robots_paths or sitemap_paths:
        sections.append(f"| Crawler Route Hints | `{len(robots_paths)}` robots / `{len(sitemap_paths)}` sitemap | Additional application paths discovered dynamically | Analyzed |")

    sections.append("\n## Sensitive Files & Configuration Exposures\n")
    if critical_exposures:
        sections.append("> Critical Alert: One or more sensitive configuration files, VCS trees, or administrative portals were verified accessible without authentication.\n")
    sections.append(_format_table(config_results))

    sections.append("\n## Administrative Portals & Control Consoles\n")
    sections.append(_format_table(admin_results))

    sections.append("\n## API Routes & Service Gateways\n")
    sections.append(_format_table(api_results))

    sections.append("\n## Authentication & Session Management Routes\n")
    sections.append(_format_table(auth_results))

    sections.append("\n## Discovered JavaScript Assets & Secrets Analysis\n")
    if js_bundles:
        sections.append("| Bundle Identifier | Origin Type | Classification | Asset Source URL |")
        sections.append("|---|---|---|---|")
        for js in js_bundles:
            sections.append(f"| `{js['filename']}` | {js['origin']} | {js['type']} | `{js['url']}` |")
    else:
        sections.append("| Bundle Identifier | Origin Type | Classification | Asset Source URL |\n|---|---|---|---|\n| _No script bundles detected on target root_ | — | — | — |")

    if js_secrets:
        sections.append("\n### Client-Side Secret & Token Disclosures\n")
        sections.append("| Script File | Secret Classification | Redacted Sample | Severity | Bundle URL |")
        sections.append("|---|---|---|---|---|")
        for s in js_secrets:
            sections.append(f"| `{s['file']}` | {s['secret_type']} | `{s['masked_sample']}` | {s['severity']} | `{s['url']}` |")

    if js_routes:
        sections.append("\n### Hidden API Paths Extracted from JS Bundles\n")
        sections.append(", ".join(f"`{r}`" for r in js_routes))

    sections.append("\n## Endpoint Hardening Action Items\n")
    sections.append("| Finding Focus | Risk Level | Target Route / Vector | Remediation Strategy |")
    sections.append("|---|---|---|---|")
    if critical_exposures:
        for ce in critical_exposures:
            sections.append(f"| Exposed Sensitive Asset | {ce['risk']} | `{ce['path']}` | Restrict web server access immediately via Nginx/Apache configuration or WAF block rule. |")
    else:
        sections.append("| Configuration Hardening | Low | `/.env`, `/.git`, `/backup.zip` | Confirm web server denies all dotfiles and backup extensions at root directory. |")
    if js_secrets:
        sections.append("| Client-Side Secret Exposure | High | JS Bundles | Move API keys/secrets to backend environment variables and rotate affected credentials. |")
    sections.append("| Administrative Perimeter | Medium | `/admin`, `/wp-admin` | Enforce multi-factor authentication, IP allowlisting, or VPN gateway requirement. |")
    sections.append("| API Documentation Gate | Low | `/swagger`, `/openapi.json` | Restrict public swagger/OpenAPI UI availability in production environments. |")

    return "\n".join(sections)


# ── Tool Class ────────────────────────────────────────────────────────────────

class DeepEndpointDirectoryDiscoveryTool(BaseTool):
    """
    Probes target base URL for common sensitive endpoints, configuration
    files, admin panels, cloud/DevOps telemetry routes, and JavaScript secrets.
    Includes soft-404 baseline filtering to prevent false positives on SPA targets.
    """

    name: str = "Deep Endpoint and Directory Discovery Tool"
    description: str = (
        "Accepts a base URL and performs high-performance concurrent discovery of "
        "sensitive endpoints, admin panels, API routes, config files, robots.txt/sitemap.xml directives, "
        "and client-side JavaScript secret analysis with soft-404 elimination."
    )
    args_schema: Type[BaseModel] = DeepEndpointDiscoveryInput

    def inspect(self, base_url: str, depth: str = "deep") -> Tuple[str, List[Dict[str, str]]]:
        """Execute concurrent endpoint discovery probe and return report + structured findings."""
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"
        base_url = base_url.rstrip("/")

        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        # 1. Soft-404 baseline calibration
        baseline = _probe_soft404_baseline(base_url)

        # 2. Extract dynamic route hints
        robots_paths = _extract_robots_paths(base_url)
        sitemap_paths = _extract_sitemap_paths(base_url) if depth != "standard" else []

        base_dictionary = STANDARD_PATHS if depth == "standard" else ALL_DEEP_PATHS
        all_paths_to_probe = list(dict.fromkeys(base_dictionary + robots_paths + sitemap_paths))

        # 3. Concurrent probing
        workers = 10 if depth == "standard" else 16
        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_path = {
                executor.submit(_probe_single, base_url, path, baseline): path
                for path in all_paths_to_probe
            }
            for future in as_completed(future_to_path):
                try:
                    results.append(future.result())
                except Exception:
                    path = future_to_path[future]
                    results.append({
                        "path": path,
                        "url": f"{base_url}{path}",
                        "status": None,
                        "classification": "Scan Error",
                        "size": 0,
                        "latency_ms": 0,
                        "content_type": "—",
                        "location": "—",
                        "server": "—",
                        "risk": "Low",
                        "verified": False,
                        "is_soft_404": False,
                        "error": "Thread execution error",
                    })

        # 4. Extract JS bundles and inspect internal bundles in deep/aggressive modes
        js_bundles = _extract_js_bundles(base_url)
        js_secrets: List[Dict[str, str]] = []
        js_routes: List[str] = []
        if depth != "standard" and js_bundles:
            js_secrets, js_routes = _inspect_js_bundles(js_bundles)

        report = _build_discovery_report(
            base_url, depth, results, js_bundles, robots_paths, sitemap_paths, js_secrets, js_routes, baseline
        )

        findings: List[Dict[str, str]] = []
        seen_titles = set()
        for r in results:
            if r["status"] == 200 and r.get("verified") and r["risk"] in ("Critical", "High", "Medium"):
                title = f"Exposed endpoint {r['path']} ({r['risk']})"
                if title not in seen_titles:
                    seen_titles.add(title)
                    findings.append({
                        "target": r["url"],
                        "title": title,
                        "severity": r["risk"].upper(),
                        "evidence": f"GET {r['url']} returned verified HTTP 200 ({r['size']} bytes, {r['content_type']}).",
                        "recommendation": f"Restrict public access to {r['path']} via server rules, authentication, or WAF policies.",
                    })

        for secret in js_secrets:
            title = f"Client-side {secret['secret_type']} exposure in {secret['file']}"
            if title not in seen_titles:
                seen_titles.add(title)
                findings.append({
                    "target": secret["url"],
                    "title": title,
                    "severity": secret["severity"],
                    "evidence": f"Redacted match `{secret['masked_sample']}` found in JavaScript bundle {secret['file']}.",
                    "recommendation": "Remove embedded secrets from frontend bundles, move to server-side secrets, and rotate keys.",
                })

        return report, findings

    def _run(self, base_url: str) -> str:
        return self.inspect(base_url, depth="deep")[0]
