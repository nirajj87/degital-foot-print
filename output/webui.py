"""Dashboard: python main.py --web

On a live server, set WEB_TOKEN and bind behind nginx. Do not expose
an open scanner to the internet without the token.
"""
from __future__ import annotations

import html
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from config import CONFIG


def start_web(out_dir: str, run_scan, host=None, port=None, token=None):
    host = host or CONFIG.get("WEB_HOST") or "127.0.0.1"
    port = int(port or CONFIG.get("WEB_PORT") or 8765)
    token = token if token is not None else CONFIG.get("WEB_TOKEN")
    public = host not in ("127.0.0.1", "localhost", "::1")
    if public and not token:
        raise SystemExit("WEB_TOKEN is required when binding a public interface (0.0.0.0).")

    last_scan = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            print("%s - %s" % (self.address_string(), fmt % args))

        def _authed(self, given: str | None) -> bool:
            if not token:
                return True
            return (given or "") == token

        def _page(self, body: str, code=200):
            page = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>Digital Footprint Analyzer</title>
<style>
body{{font-family:Segoe UI,sans-serif;background:#f8fafc;margin:0;color:#101828}}
main{{max-width:720px;margin:40px auto;padding:0 20px 48px}}
input,button{{font-size:16px;padding:8px 10px}}
input{{width:100%;max-width:420px;box-sizing:border-box}}
button{{background:#175cd3;color:#fff;border:0;border-radius:6px;padding:8px 16px}}
.muted{{color:#667085}}
label{{display:block;margin:12px 0 4px;font-size:14px}}
</style></head><body><main>{body}</main></body></html>"""
            data = page.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _form(self, extra=""):
            token_field = ""
            if token:
                token_field = '<label>Access token</label><p><input name="token" type="password" required/></p>'
            self._page(
                f"""
<h1>Digital Footprint Analyzer</h1>
<p class="muted">Scan only your own email, phone, username, or domain — or accounts you have written permission to assess. Public sources only.</p>
{extra}
<form method="post" action="/scan">
  <label>Target</label>
  <p><input name="target" placeholder="you@example.com / +91... / github:user / example.com" required/></p>
  {token_field}
  <p><button type="submit">Scan</button></p>
</form>
<p class="muted">Read USER_MANUAL.md for CLI, API keys, and live-server setup.</p>
"""
            )

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path.startswith("/report/"):
                name = os.path.basename(path[8:])
                full = os.path.join(out_dir, name)
                if not name.endswith(".html") or not os.path.isfile(full):
                    return self._page("<p>Report not found.</p>", 404)
                with open(full, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            self._form()

        def do_POST(self):
            if self.path.split("?", 1)[0] != "/scan":
                return self._page("<p>Not found</p>", 404)
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            fields = parse_qs(raw)
            target = (fields.get("target") or [""])[0].strip()
            given = (fields.get("token") or [""])[0].strip()
            if not self._authed(given):
                return self._form("<p class='muted'>Invalid access token.</p>")
            if not target:
                return self._form("<p class='muted'>Enter a target.</p>")
            ip = self.client_address[0]
            now = time.time()
            if now - last_scan.get(ip, 0) < 20:
                return self._form("<p class='muted'>Wait a few seconds before the next scan.</p>")
            last_scan[ip] = now
            try:
                report = run_scan(target)
                html_name = os.path.basename(report["html_path"])
            except Exception as e:
                return self._page(f"<p>Scan failed: {html.escape(str(e))}</p>", 500)
            self.send_response(302)
            self.send_header("Location", f"/report/{html_name}")
            self.end_headers()

    print(f"Dashboard: http://{host}:{port}")
    if token:
        print("Access token is required.")
    if public:
        print("Public bind — put nginx + HTTPS in front of this process.")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
