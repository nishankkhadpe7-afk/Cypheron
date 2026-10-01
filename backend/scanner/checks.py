"""Individual security checks.

Every check takes a ScanContext and returns a list of Findings.
Passive checks only look at what the site already sends back to a normal
visitor. Active checks (exposed files) request extra paths and are only run
when the user confirms they own or are authorised to test the target.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .findings import Finding, passed

OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"


@dataclass
class ScanContext:
    url: str                    # URL the user entered (normalised)
    response: httpx.Response    # response after following redirects
    client: httpx.AsyncClient
    html: str = ""

    @property
    def final_url(self) -> str:
        return str(self.response.url)

    @property
    def is_https(self) -> bool:
        return self.final_url.startswith("https://")

    @property
    def host(self) -> str:
        return urlparse(self.final_url).hostname or ""

    @property
    def headers(self) -> httpx.Headers:
        return self.response.headers


# ---------------------------------------------------------------- headers
async def check_security_headers(ctx: ScanContext) -> list[Finding]:
    h = ctx.headers
    out: list[Finding] = []
    cat = "headers"

    csp = h.get("content-security-policy")
    if not csp:
        out.append(Finding(
            "header.csp.missing", "Missing Content-Security-Policy", cat, "medium",
            "The response does not set a Content-Security-Policy header.",
            "Without CSP, any injected script runs with full privileges, so an XSS bug is easier to exploit.",
            "Define a Content-Security-Policy that allows scripts only from trusted origins, e.g. "
            "\"default-src 'self'; object-src 'none'; frame-ancestors 'self'\".",
            references=[MDN + "Content-Security-Policy"]))
    else:
        weak = [d for d in ("'unsafe-inline'", "'unsafe-eval'") if d in csp]
        if weak:
            out.append(Finding(
                "header.csp.weak", "Weak Content-Security-Policy", cat, "low",
                f"CSP is present but allows {', '.join(sorted(set(weak)))}.",
                "Unsafe keywords re-enable inline or eval'd script, which removes much of CSP's XSS protection.",
                "Replace 'unsafe-inline' with nonces or hashes and remove 'unsafe-eval'.",
                evidence=csp[:300]))
        else:
            out.append(passed("header.csp.ok", "Content-Security-Policy present", cat, csp[:300]))

    if ctx.is_https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            out.append(Finding(
                "header.hsts.missing", "Missing Strict-Transport-Security (HSTS)", cat, "medium",
                "The HTTPS response does not set HSTS.",
                "Browsers may still try plain HTTP first, which allows SSL-stripping attacks on public networks.",
                "Add \"Strict-Transport-Security: max-age=31536000; includeSubDomains\".",
                references=[MDN + "Strict-Transport-Security"]))
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            age = int(m.group(1)) if m else 0
            if age < 15552000:  # 180 days
                out.append(Finding(
                    "header.hsts.short", "HSTS max-age is too short", cat, "low",
                    f"HSTS max-age is {age} seconds (under 180 days).",
                    "A short max-age means protection lapses quickly for returning visitors.",
                    "Use max-age of at least 31536000 (one year).", evidence=hsts))
            else:
                out.append(passed("header.hsts.ok", "HSTS enabled", cat, hsts))

    xfo = h.get("x-frame-options")
    if xfo or (csp and "frame-ancestors" in csp):
        out.append(passed("header.xfo.ok", "Clickjacking protection present", cat, xfo or "CSP frame-ancestors"))
    else:
        out.append(Finding(
            "header.xfo.missing", "Missing clickjacking protection (X-Frame-Options)", cat, "low",
            "Neither X-Frame-Options nor CSP frame-ancestors is set.",
            "Other sites can embed this page in an invisible frame and trick users into clicking buttons.",
            "Set \"X-Frame-Options: DENY\" or CSP \"frame-ancestors 'self'\".",
            references=[MDN + "X-Frame-Options"]))

    if (h.get("x-content-type-options") or "").lower() == "nosniff":
        out.append(passed("header.xcto.ok", "X-Content-Type-Options: nosniff", cat))
    else:
        out.append(Finding(
            "header.xcto.missing", "Missing X-Content-Type-Options", cat, "low",
            "The response does not set \"X-Content-Type-Options: nosniff\".",
            "Browsers may guess content types, which can turn an uploaded file into executable script.",
            "Add \"X-Content-Type-Options: nosniff\".", references=[MDN + "X-Content-Type-Options"]))

    if h.get("referrer-policy"):
        out.append(passed("header.referrer.ok", "Referrer-Policy present", cat, h.get("referrer-policy")))
    else:
        out.append(Finding(
            "header.referrer.missing", "Missing Referrer-Policy", cat, "low",
            "No Referrer-Policy header is set.",
            "Full URLs, which can include tokens or IDs, may leak to third-party sites via the Referer header.",
            "Add \"Referrer-Policy: strict-origin-when-cross-origin\".", references=[MDN + "Referrer-Policy"]))

    if h.get("permissions-policy"):
        out.append(passed("header.permissions.ok", "Permissions-Policy present", cat))
    else:
        out.append(Finding(
            "header.permissions.missing", "Missing Permissions-Policy", cat, "info",
            "No Permissions-Policy header restricts powerful browser features.",
            "Embedded or injected content can request camera, microphone or location access.",
            "Add a Permissions-Policy, e.g. \"camera=(), microphone=(), geolocation=()\".",
            references=[OWASP_HEADERS]))
    return out


# ------------------------------------------------------ HTTPS / transport
async def check_https(ctx: ScanContext) -> list[Finding]:
    cat = "transport"
    out: list[Finding] = []
    parsed = urlparse(ctx.url)

    if ctx.is_https:
        out.append(passed("transport.https.ok", "Site is served over HTTPS", cat, ctx.final_url))
        # Does plain HTTP redirect to HTTPS?
        if parsed.port in (None, 443):
            http_url = f"http://{ctx.host}{parsed.path or '/'}"
            try:
                r = await ctx.client.get(http_url, follow_redirects=True)
                if str(r.url).startswith("https://"):
                    out.append(passed("transport.redirect.ok", "HTTP redirects to HTTPS", cat, f"{http_url} → {r.url}"))
                else:
                    out.append(Finding(
                        "transport.redirect.missing", "HTTP does not redirect to HTTPS", cat, "medium",
                        "The site still answers over plain HTTP without redirecting.",
                        "Visitors who type the address without https:// get an unencrypted page.",
                        "Redirect all HTTP requests to HTTPS with a 301.", evidence=http_url))
            except httpx.HTTPError:
                out.append(passed("transport.redirect.ok", "Plain HTTP is not served", cat))
        return out

    # Target is HTTP. Is HTTPS available at all?
    https_url = ctx.final_url.replace("http://", "https://", 1)
    try:
        await ctx.client.get(https_url, follow_redirects=True)
        out.append(Finding(
            "transport.redirect.missing", "HTTPS available but not enforced", cat, "medium",
            "The site answers on HTTPS but the HTTP version does not redirect to it.",
            "Visitors on HTTP send cookies and form data unencrypted.",
            "Redirect all HTTP traffic to HTTPS and enable HSTS.", evidence=ctx.final_url))
    except httpx.HTTPError:
        out.append(Finding(
            "transport.https.missing", "Site is not served over HTTPS", cat, "high",
            "The site is only reachable over unencrypted HTTP.",
            "Anyone on the same network can read or modify pages, passwords and cookies in transit.",
            "Install a TLS certificate (Let's Encrypt is free) and redirect HTTP to HTTPS.",
            evidence=ctx.final_url))
    return out


def _tls_probe(host: str, port: int) -> dict:
    """Blocking TLS handshake; run in a thread."""
    info: dict = {}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                info["version"] = s.version()
                info["cipher"] = s.cipher()[0] if s.cipher() else None
                info["not_after"] = cert.get("notAfter")
                info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
    except ssl.SSLCertVerificationError as e:
        info["verify_error"] = e.verify_message or str(e)
    except (OSError, ssl.SSLError) as e:
        info["error"] = str(e)

    # Legacy protocol support (only testable if local OpenSSL still allows it).
    info["legacy"] = []
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.minimum_version = ver
            c.maximum_version = ver
            with socket.create_connection((host, port), timeout=5) as sock:
                with c.wrap_socket(sock, server_hostname=host):
                    info["legacy"].append(name)
        except Exception:
            pass
    return info


async def check_tls(ctx: ScanContext) -> list[Finding]:
    if not ctx.is_https:
        return []
    cat = "transport"
    out: list[Finding] = []
    port = urlparse(ctx.final_url).port or 443
    info = await asyncio.to_thread(_tls_probe, ctx.host, port)

    if "verify_error" in info:
        out.append(Finding(
            "tls.cert.invalid", "TLS certificate is not trusted", "transport", "high",
            f"Certificate verification failed: {info['verify_error']}.",
            "Browsers show a warning, and users who click through can't tell a real site from an attacker's.",
            "Use a certificate from a trusted CA that matches the hostname (e.g. Let's Encrypt)."))
        return out
    if "error" in info:
        return out

    try:
        expires = datetime.strptime(info["not_after"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        if days < 0:
            out.append(Finding("tls.cert.expired", "TLS certificate has expired", cat, "high",
                               f"Certificate expired {-days} days ago.", "Browsers block the site with a warning.",
                               "Renew the certificate and automate renewal."))
        elif days < 15:
            out.append(Finding("tls.cert.expiring", "TLS certificate expires soon", cat, "medium",
                               f"Certificate expires in {days} days.", "The site will break when it expires.",
                               "Renew now and set up automatic renewal (e.g. certbot)."))
        else:
            out.append(passed("tls.cert.ok", "Valid TLS certificate", cat,
                              f"Expires in {days} days · issuer {info['issuer'].get('organizationName', '?')}"))
    except (KeyError, ValueError, TypeError):
        pass

    if info.get("version") in ("TLSv1.3", "TLSv1.2"):
        out.append(passed("tls.version.ok", f"Modern TLS negotiated ({info['version']})", cat, info.get("cipher")))
    if info.get("legacy"):
        out.append(Finding(
            "tls.legacy", "Legacy TLS versions enabled", cat, "medium",
            f"The server still accepts {', '.join(info['legacy'])}.",
            "TLS 1.0/1.1 have known weaknesses and are deprecated by all major browsers.",
            "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3."))
    return out


# ----------------------------------------------------------------- cookies
SESSION_HINTS = ("sess", "sid", "auth", "token", "jwt", "login")


async def check_cookies(ctx: ScanContext) -> list[Finding]:
    cat = "cookies"
    raw = ctx.response.headers.get_list("set-cookie")
    # also collect from redirect history
    for r in ctx.response.history:
        raw += r.headers.get_list("set-cookie")
    if not raw:
        return []

    out: list[Finding] = []
    for line in raw:
        name = line.split("=", 1)[0].strip()
        lower = line.lower()
        attrs = [a.strip() for a in lower.split(";")[1:]]
        is_session = any(k in name.lower() for k in SESSION_HINTS)
        problems = []
        if ctx.is_https and "secure" not in attrs:
            problems.append("Secure")
        if "httponly" not in attrs:
            problems.append("HttpOnly")
        if not any(a.startswith("samesite") for a in attrs):
            problems.append("SameSite")
        if not problems:
            out.append(passed(f"cookie.{name}.ok", f"Cookie '{name}' has secure flags", cat))
            continue
        sev = "medium" if is_session and ("HttpOnly" in problems or "Secure" in problems) else "low"
        out.append(Finding(
            f"cookie.{name}.flags", f"Cookie '{name}' missing {', '.join(problems)}", cat, sev,
            f"The cookie '{name}' is set without: {', '.join(problems)}.",
            "Without HttpOnly, scripts (including injected ones) can read it; without Secure it can travel over HTTP; "
            "without SameSite it is sent on cross-site requests, which helps CSRF.",
            f"Set the cookie with \"; Secure; HttpOnly; SameSite=Lax\".",
            evidence=line[:200], references=[MDN + "Set-Cookie"]))
    return out


# -------------------------------------------------------------------- CORS
async def check_cors(ctx: ScanContext) -> list[Finding]:
    cat = "cors"
    probe_origin = "https://cypheron-probe.example"
    try:
        r = await ctx.client.get(ctx.final_url, headers={"Origin": probe_origin})
    except httpx.HTTPError:
        return []
    acao = r.headers.get("access-control-allow-origin")
    acac = (r.headers.get("access-control-allow-credentials") or "").lower() == "true"
    if not acao:
        return [passed("cors.ok", "No permissive CORS policy", cat)]
    if acao == probe_origin and acac:
        return [Finding(
            "cors.reflect.credentials", "CORS reflects any origin with credentials", cat, "high",
            "The server copies the request's Origin into Access-Control-Allow-Origin and allows credentials.",
            "Any website a logged-in user visits can read this site's authenticated responses.",
            "Only allow an explicit list of trusted origins; never reflect arbitrary Origin values with credentials.",
            evidence=f"Origin: {probe_origin} → ACAO: {acao}, ACAC: true")]
    if acao == probe_origin:
        return [Finding(
            "cors.reflect", "CORS reflects arbitrary origins", cat, "medium",
            "The server echoes any Origin in Access-Control-Allow-Origin.",
            "Any site can read responses from this origin (without cookies).",
            "Use an allow-list of trusted origins.", evidence=f"ACAO: {acao}")]
    if acao == "*":
        return [Finding(
            "cors.wildcard", "CORS allows all origins (*)", cat, "info",
            "Access-Control-Allow-Origin is '*'.",
            "Fine for public data, but risky if this endpoint returns anything private.",
            "Restrict to known origins if responses contain user data.", evidence="ACAO: *")]
    return [passed("cors.ok", "CORS restricted to specific origin", cat, acao)]


# ------------------------------------------------ page content & forms
CSRF_NAMES = re.compile(r"csrf|xsrf|_token|authenticity|nonce|__requestverification", re.I)


async def check_content(ctx: ScanContext) -> list[Finding]:
    if "html" not in (ctx.headers.get("content-type") or ""):
        return []
    soup = BeautifulSoup(ctx.html, "html.parser")
    out: list[Finding] = []

    # Forms
    for i, form in enumerate(soup.find_all("form")):
        action = urljoin(ctx.final_url, form.get("action") or ctx.final_url)
        method = (form.get("method") or "get").lower()
        has_pw = form.find("input", {"type": "password"}) is not None
        label = form.get("id") or form.get("name") or f"#{i + 1}"

        if has_pw and action.startswith("http://"):
            out.append(Finding(
                f"form.{label}.insecure_password", f"Password form '{label}' submits over HTTP", "content", "high",
                "A form with a password field sends its data to an unencrypted URL.",
                "Passwords are visible to anyone on the network path.",
                "Serve the page and the form action over HTTPS.", evidence=f"action={action}"))
        if has_pw and method == "get":
            out.append(Finding(
                f"form.{label}.password_get", f"Password form '{label}' uses GET", "content", "medium",
                "The login form submits with GET, putting the password in the URL.",
                "URLs end up in browser history, server logs and Referer headers.",
                "Use method=\"post\" for forms with credentials."))
        if method == "post":
            hidden = [inp.get("name", "") for inp in form.find_all("input", {"type": "hidden"})]
            if not any(CSRF_NAMES.search(n or "") for n in hidden):
                out.append(Finding(
                    f"form.{label}.csrf", f"Form '{label}' has no visible CSRF token", "content", "low",
                    "This POST form has no hidden field that looks like an anti-CSRF token.",
                    "If the server doesn't protect it another way, other sites can submit it on a user's behalf.",
                    "Add a per-session CSRF token, or rely on SameSite cookies plus Origin checks.",
                    evidence=f"POST {action} · hidden fields: {hidden or 'none'}"))
            else:
                out.append(passed(f"form.{label}.csrf.ok", f"Form '{label}' has a CSRF token", "content"))

    # Mixed content on HTTPS pages
    if ctx.is_https:
        active, passive = [], []
        for tag, attr in (("script", "src"), ("iframe", "src"), ("link", "href")):
            for el in soup.find_all(tag):
                v = el.get(attr) or ""
                if v.startswith("http://"):
                    active.append(v)
        for el in soup.find_all(["img", "audio", "video", "source"]):
            v = el.get("src") or ""
            if v.startswith("http://"):
                passive.append(v)
        if active:
            out.append(Finding(
                "content.mixed.active", "Mixed content: scripts/styles loaded over HTTP", "content", "medium",
                f"{len(active)} script, frame or stylesheet URL(s) use plain HTTP on an HTTPS page.",
                "An attacker on the network can swap these files and take over the page.",
                "Load every resource over HTTPS.", evidence=", ".join(active[:3])))
        if passive:
            out.append(Finding(
                "content.mixed.passive", "Mixed content: images/media over HTTP", "content", "low",
                f"{len(passive)} image or media URL(s) use plain HTTP.",
                "They can be altered in transit and weaken the page's security indicator.",
                "Load media over HTTPS.", evidence=", ".join(passive[:3])))
    return out


# --------------------------------------------- tech fingerprint / disclosure
VERSION_RE = re.compile(r"\d+\.\d+")
JS_LIB_RE = re.compile(r"(jquery|bootstrap|angular|vue|react|lodash)[.-]?v?(\d+\.\d+(?:\.\d+)?)", re.I)


async def check_disclosure(ctx: ScanContext) -> list[Finding]:
    cat = "disclosure"
    out: list[Finding] = []
    tech: list[str] = []

    for header in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        v = ctx.headers.get(header)
        if not v:
            continue
        tech.append(v)
        if VERSION_RE.search(v):
            out.append(Finding(
                f"disclosure.{header}", f"Version disclosed in {header.title()} header", cat, "low",
                f"The {header} header reveals exact software versions: {v}.",
                "Attackers can match the version to known CVEs without any probing.",
                f"Remove or genericise the {header} header (e.g. server_tokens off in nginx, "
                f"ServerTokens Prod in Apache, expose_php=Off in PHP).", evidence=f"{header}: {v}"))

    if ctx.html:
        soup = BeautifulSoup(ctx.html, "html.parser")
        gen = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
        if gen and gen.get("content"):
            tech.append(gen["content"])
            if VERSION_RE.search(gen["content"]):
                out.append(Finding(
                    "disclosure.generator", "CMS version disclosed in meta generator", cat, "low",
                    f"The page advertises: {gen['content']}.",
                    "Reveals the exact CMS version, which narrows down applicable exploits.",
                    "Remove the generator meta tag.", evidence=gen["content"]))
        for s in soup.find_all("script", src=True):
            m = JS_LIB_RE.search(s["src"])
            if m:
                tech.append(f"{m.group(1)} {m.group(2)}")

    if tech:
        out.append(Finding(
            "fingerprint", "Detected technologies", cat, "info",
            "Technologies identified from headers and page source.",
            evidence=" · ".join(dict.fromkeys(tech))))
    return out


# -------------------------------------- ACTIVE: exposed files (consent only)
SENSITIVE_PATHS = [
    # path, severity, title, validator(text) -> bool
    ("/.git/HEAD", "critical", "Git repository exposed", lambda t: t.strip().startswith("ref:")),
    ("/.env", "critical", "Environment file (.env) exposed",
     lambda t: bool(re.search(r"^[A-Z_][A-Z0-9_]*\s*=", t, re.M)) and "<html" not in t.lower()),
    ("/.DS_Store", "low", "macOS .DS_Store file exposed", lambda t: t.startswith("\x00\x00\x00\x01Bud1") or "Bud1" in t[:16]),
    ("/phpinfo.php", "medium", "phpinfo() page exposed", lambda t: "phpinfo()" in t or "PHP Version" in t),
    ("/server-status", "medium", "Apache server-status exposed", lambda t: "Apache Server Status" in t),
    ("/backup.zip", "high", "Backup archive exposed", lambda t: t.startswith("PK")),
    ("/.htpasswd", "high", ".htpasswd file exposed", lambda t: bool(re.search(r"^\w+:\$", t, re.M))),
]
LISTING_PATHS = ["/uploads/", "/backup/", "/files/", "/images/"]


async def check_exposed_files(ctx: ScanContext) -> list[Finding]:
    cat = "exposure"
    base = f"{urlparse(ctx.final_url).scheme}://{urlparse(ctx.final_url).netloc}"
    out: list[Finding] = []

    async def fetch(path):
        try:
            return path, await ctx.client.get(base + path, follow_redirects=False)
        except httpx.HTTPError:
            return path, None

    results = await asyncio.gather(*(fetch(p) for p, *_ in SENSITIVE_PATHS), *(fetch(p) for p in LISTING_PATHS))
    by_path = dict(results)

    for path, sev, title, valid in SENSITIVE_PATHS:
        r = by_path.get(path)
        if r is None or r.status_code != 200:
            continue
        text = r.content[:4096].decode("latin-1")
        if valid(text):
            out.append(Finding(
                f"exposure{path}", title, cat, sev,
                f"{path} is publicly downloadable.",
                "Leaks source code, credentials or server internals that attackers can use directly.",
                f"Block access to {path} in the web server config and remove it from the web root. "
                "Rotate any secrets it contained.", evidence=f"GET {base}{path} → 200"))

    for path in LISTING_PATHS:
        r = by_path.get(path)
        if r is not None and r.status_code == 200 and re.search(r"<title>\s*Index of", r.text, re.I):
            out.append(Finding(
                f"exposure.listing{path}", f"Directory listing enabled at {path}", cat, "medium",
                "The server lists every file in this directory.",
                "Attackers can browse and download files that were never meant to be linked.",
                "Disable directory indexes (Options -Indexes in Apache, autoindex off in nginx).",
                evidence=f"GET {base}{path} → Index of"))

    if not out:
        out.append(passed("exposure.ok", "No common sensitive files exposed", cat,
                          f"Checked {len(SENSITIVE_PATHS) + len(LISTING_PATHS)} paths"))
    return out


PASSIVE_CHECKS = [
    ("Security headers", check_security_headers),
    ("HTTPS & redirects", check_https),
    ("SSL/TLS certificate", check_tls),
    ("Cookie flags", check_cookies),
    ("CORS policy", check_cors),
    ("Forms & page content", check_content),
    ("Technology fingerprint", check_disclosure),
]
ACTIVE_CHECKS = [
    ("Exposed files & directories", check_exposed_files),
]
