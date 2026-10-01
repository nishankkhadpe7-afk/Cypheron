"""VulnShop — a deliberately insecure local site for demoing Cypheron.

Run:  python demo_target.py            vulnerable version  (http://localhost:8081)
      python demo_target.py --fixed    same site after applying Cypheron's fixes
Scan: http://localhost:8081 with "active checks" ticked, then rescan the fixed
version to show the score improve.

Never deploy this anywhere public.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXED = "--fixed" in sys.argv

PAGE = b"""<!doctype html>
<html><head>
<meta name="generator" content="WordPress 5.2.1">
<title>VulnShop - Login</title>
<script src="/static/jquery-1.12.4.min.js"></script>
</head><body>
<h1>VulnShop</h1>
<form id="login" method="post" action="/login">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input name="username"> <input type="password" name="password">
  <button>Sign in</button>
</form>
<form id="newsletter" method="post" action="/subscribe">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input name="email"><button>Subscribe</button>
</form>
</body></html>"""

FILES = {
    "/.git/HEAD": (b"ref: refs/heads/main\n", "text/plain"),
    "/.env": (b"APP_ENV=production\nDB_PASSWORD=supersecret123\nSTRIPE_KEY=sk_test_xxx\n", "text/plain"),
    "/uploads/": (b"<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1>"
                  b"<a href='invoice-2024.pdf'>invoice-2024.pdf</a></body></html>", "text/html"),
}


def render_page():
    page = PAGE
    if FIXED:
        page = page.replace(b'<meta name="generator" content="WordPress 5.2.1">\n', b"")
        return page.replace(b"{csrf}", b"9f8e7d6c5b4a")
    # vulnerable version: strip the CSRF fields entirely
    return b"\n".join(l for l in page.split(b"\n") if b"csrf_token" not in l)


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache" if FIXED else "Apache/2.4.29 (Ubuntu)"
    sys_version = ""

    def _common(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        if FIXED:
            self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header("Set-Cookie", "PHPSESSID=abc123def456; path=/; HttpOnly; SameSite=Lax")
        else:
            self.send_header("X-Powered-By", "PHP/5.6.40")
            self.send_header("Set-Cookie", "PHPSESSID=abc123def456; path=/")
            origin = self.headers.get("Origin")
            if origin:  # classic CORS misconfig: reflect any origin with credentials
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            return self._common(200, "text/html; charset=utf-8", render_page())
        if path in FILES and not FIXED:
            body, ctype = FILES[path]
            return self._common(200, ctype, body)
        self._common(404, "text/html", b"<h1>404 Not Found</h1>")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"VulnShop ({'FIXED' if FIXED else 'VULNERABLE'}) on http://localhost:8081  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", 8081), Handler).serve_forever()
