#!/usr/bin/env python3
"""Experimental static server and a loopback-only SearXNG search proxy."""
import ipaddress
import json
import os
import re
import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone
from html import unescape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parent / "public"
PORT = int(os.environ.get("PORT", "8080"))
SEARXNG_URL = os.environ.get("SEARXNG_URL", "http://127.0.0.1:8888").rstrip("/")
PUBLIC_ORIGIN = os.environ.get(
    "PUBLIC_ORIGIN", "https://ai-test.make-cph-great-again.community"
).rstrip("/")
ALLOWED_ORIGINS = {
    PUBLIC_ORIGIN, f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"
}
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/websearch.css": ("websearch.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/worker.js": ("worker.js", "text/javascript; charset=utf-8"),
    "/models.js": ("models.js", "text/javascript; charset=utf-8"),
    "/models.css": ("models.css", "text/css; charset=utf-8"),
    "/workspace.css": ("workspace.css", "text/css; charset=utf-8"),
    "/openclaw-install.js": ("openclaw-install.js", "text/javascript; charset=utf-8"),
    "/openclaw-client.js": ("openclaw-client.js", "text/javascript; charset=utf-8"),
    "/local-memory.js": ("local-memory.js", "text/javascript; charset=utf-8"),
    "/chat-policy.js": ("chat-policy.js", "text/javascript; charset=utf-8"),
    "/mesh-controller.js": ("mesh-controller.js", "text/javascript; charset=utf-8"),
    "/mesh-worker.js": ("mesh-worker.js", "text/javascript; charset=utf-8"),
    "/mesh-protocol.js": ("mesh-protocol.js", "text/javascript; charset=utf-8"),
    "/mesh-discovery.js": ("mesh-discovery.js", "text/javascript; charset=utf-8"),
    "/mesh-discovery-client.js": ("mesh-discovery-client.js", "text/javascript; charset=utf-8"),
    "/vendor/mesh-crypto.js": ("vendor/mesh-crypto.js", "text/javascript; charset=utf-8"),
    "/vendor/mesh-crypto-LICENSE.txt": ("vendor/mesh-crypto-LICENSE.txt", "text/plain; charset=utf-8"),
    "/vendor/mesh-crypto-provenance.json": ("vendor/mesh-crypto-provenance.json", "application/json"),
    "/relay-controller.js": ("relay-controller.js", "text/javascript; charset=utf-8"),
    "/relay-worker.js": ("relay-worker.js", "text/javascript; charset=utf-8"),
    "/relay-protocol.js": ("relay-protocol.js", "text/javascript; charset=utf-8"),
    "/relay-ui.js": ("relay-ui.js", "text/javascript; charset=utf-8"),
    "/relay-map.js": ("relay-map.js", "text/javascript; charset=utf-8"),
    "/relay.css": ("relay.css", "text/css; charset=utf-8"),
    "/assets/earth-land.json": ("assets/earth-land.json", "application/json"),
    "/assets/earth-land.LICENSE.txt": ("assets/earth-land.LICENSE.txt", "text/plain; charset=utf-8"),
    "/assets/cypher-horizon.png": ("assets/cypher-horizon.png", "image/png"),
}
# Aggregate limits for this single server process, not per-user limits.
SEARCHES_PER_MINUTE = 20
SEARCH_SLOTS = threading.BoundedSemaphore(2)
RATE_LOCK = threading.Lock()
RECENT = deque()


def check_backend():
    u = urlsplit(SEARXNG_URL)
    if (u.scheme != "http" or u.hostname != "127.0.0.1" or
            u.username or u.password or u.path or u.query or u.fragment):
        raise ValueError("SEARXNG_URL must be http://127.0.0.1:PORT")
    if not u.port:
        raise ValueError("SEARXNG_URL must include a port")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Do not forward this internal request through environment proxy settings.
UPSTREAM = build_opener(ProxyHandler({}), NoRedirect())


def clean(value, limit):
    if not isinstance(value, str):
        return ""
    text = re.sub(r"<[^>]*>", " ", unescape(value[:10000]))
    text = "".join(c for c in text if c.isprintable() or c.isspace())
    return " ".join(text.split())[:limit]


def public_link(value):
    if not isinstance(value, str) or len(value) > 2000:
        return None
    if any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
        return None
    try:
        u = urlsplit(value)
        host = (u.hostname or "").lower()
        if u.scheme not in ("http", "https") or not host or u.username or u.password:
            return None
        if u.port not in (None, 80, 443):
            return None
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            return None
        try:
            if not ipaddress.ip_address(host).is_global:
                return None
        except ValueError:
            if "." not in host:
                return None
        return urlunsplit((u.scheme, u.netloc, u.path, u.query, "")), host
    except ValueError:
        return None


def search_web(query, time_range, language="en"):
    params = {
        "q": query, "format": "json", "categories": "general",
        "language": language, "safesearch": "1", "pageno": "1",
    }
    if time_range:
        params["time_range"] = time_range
    req = Request(
        SEARXNG_URL + "/search", data=urlencode(params).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"}, method="POST",
    )
    with UPSTREAM.open(req, timeout=20) as response:
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("Oversized search response")
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("Unexpected search response")
    results, seen = [], set()
    for row in data["results"][:50]:
        if not isinstance(row, dict):
            continue
        link = public_link(row.get("url"))
        snippet = clean(row.get("content"), 1200)
        if not link or not snippet or link[0] in seen:
            continue
        seen.add(link[0])
        results.append({
            "title": clean(row.get("title"), 200) or link[1],
            "url": link[0], "domain": link[1], "snippet": snippet,
            "published": clean(row.get("publishedDate"), 80),
        })
        if len(results) == 5:
            break
    warnings = []
    failures = data.get("unresponsive_engines", [])
    if isinstance(failures, list):
        for item in failures[:6]:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                warnings.append(f"{clean(item[0], 40)}: {clean(item[1], 120)}")
    return {
        "ok": True, "query": query, "language": language,
        "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "results": results, "warnings": warnings,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "BrowserLLMLab"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format, *args):
        # Do not write questions or request bodies to application access logs.
        pass

    def send_bytes(self, code, body, mime):
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        if code == 429:
            self.send_header("Retry-After", "60")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def send_json(self, code, data):
        self.send_bytes(code, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                        "application/json; charset=utf-8")

    def fail(self, code, message):
        self.send_json(code, {"ok": False, "error": message})

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            return self.send_json(200, {"ok": True, "inference": "browser",
                                       "version": "models-v1", "workspace": "cypher-v5"})
        if path not in STATIC:
            return self.fail(404, "Not found")
        filename, mime = STATIC[path]
        try:
            body = (ROOT / filename).read_bytes()
        except OSError:
            return self.fail(500, "Static file unavailable")
        self.send_bytes(200, body, mime)

    do_HEAD = do_GET

    def do_POST(self):
        if self.path != "/api/search":
            return self.fail(404, "Not found")
        origin = self.headers.get("Origin")
        if origin and origin not in ALLOWED_ORIGINS:
            return self.fail(403, "Origin not allowed")
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return self.fail(403, "Cross-site requests are not allowed")
        if self.headers.get_content_type() != "application/json":
            return self.fail(415, "Use application/json")
        if self.headers.get("Transfer-Encoding"):
            return self.fail(400, "Transfer-Encoding is not supported")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 8192:
                return self.fail(413, "Request body must be 1-8192 bytes")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError()
            query, time_range = data.get("q"), data.get("time_range", "")
            if not isinstance(query, str) or not isinstance(time_range, str):
                raise ValueError()
            query = query.strip()
            if not 1 <= len(query) <= 400 or len(query.encode("utf-8")) > 1200:
                raise ValueError()
            if time_range not in ("", "day", "month", "year"):
                raise ValueError()
            language = data.get("language", "ja" if re.search(r"[\u3040-\u30ff\u3400-\u9fff]", query) else "en")
            if language not in ("ja", "en"):
                return self.fail(400, "Invalid language: use ja or en")
        except (ValueError, UnicodeError, socket.timeout):
            return self.fail(400, "Invalid query: use 1-400 characters and at most 1200 UTF-8 bytes")
        with RATE_LOCK:
            now = time.monotonic()
            while RECENT and now - RECENT[0] >= 60:
                RECENT.popleft()
            allowed = len(RECENT) < SEARCHES_PER_MINUTE
            if allowed:
                RECENT.append(now)
        if not allowed:
            return self.fail(429, "Shared search limit reached: 20 requests per minute")
        if not SEARCH_SLOTS.acquire(blocking=False):
            return self.fail(503, "Search is busy. Please try again shortly")
        try:
            self.send_json(200, search_web(query, time_range, language))
        except HTTPError as error:
            self.fail(502, f"SearXNG returned HTTP {error.code}; check its configuration and logs")
        except (URLError, OSError, ValueError):
            self.fail(502, "Search backend unavailable or invalid response; check SearXNG logs")
        finally:
            SEARCH_SLOTS.release()


if __name__ == "__main__":
    check_backend()
    with ThreadingHTTPServer(("127.0.0.1", PORT), Handler) as server:
        print(f"Browser LLM Lab: http://127.0.0.1:{PORT} / models-v1", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
