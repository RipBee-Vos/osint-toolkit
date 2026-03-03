#!/usr/bin/env python3
"""Simple GUI for self_audit.py (allowlist-only)."""

from __future__ import annotations
import html
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "self_audit_outputs"
PORT = 8770


def run_self_audit(url: str, allowlist: str, outdir: str) -> tuple[int, str]:
    cmd = [
        "python3",
        str(ROOT / "self_audit.py"),
        url,
        "--allowlist",
        allowlist,
        "--outdir",
        outdir,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    output = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    return p.returncode, output.strip()


def list_reports() -> list[str]:
    if not OUT.exists():
        return []
    return sorted([p.name for p in OUT.iterdir() if p.suffix in {".md", ".json", ".csv"}], reverse=True)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/file":
            qs = urllib.parse.parse_qs(parsed.query)
            name = (qs.get("name", [""])[0]).strip()
            target = (OUT / name).resolve()
            if not str(target).startswith(str(OUT.resolve())) or not target.exists():
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not found")
                return
            content = target.read_bytes()
            ctype = "text/plain; charset=utf-8"
            if target.suffix == ".json":
                ctype = "application/json; charset=utf-8"
            elif target.suffix == ".csv":
                ctype = "text/csv; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(content)
            return

        reports = "".join(
            f"<li><a href='/file?name={urllib.parse.quote(name)}' target='_blank'>{html.escape(name)}</a></li>"
            for name in list_reports()
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        body = f"""
<!doctype html>
<html><head><meta charset='utf-8'><title>Self Audit GUI</title></head>
<body style='font-family:Arial;max-width:900px;margin:24px auto'>
  <h1>Self-OSINT Audit GUI</h1>
  <p>For your own profiles only (allowlist enforced).</p>
  <form method='post' action='/run' style='display:grid;gap:8px;max-width:700px'>
    <label>Profile URL <input name='url' placeholder='https://www.linkedin.com/in/your-handle/' required /></label>
    <label>Allowlist file <input name='allowlist' value='my_profiles.txt' /></label>
    <label>Output dir <input name='outdir' value='self_audit_outputs' /></label>
    <button type='submit'>Run Self Audit</button>
  </form>
  <h2>Latest Reports</h2>
  <ul>{reports or '<li>No reports yet</li>'}</ul>
</body></html>
"""
        self.wfile.write(body.encode("utf-8"))

    def do_POST(self):
        if self.path != "/run":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        data = urllib.parse.parse_qs(raw)
        url = data.get("url", [""])[0].strip()
        allowlist = data.get("allowlist", ["my_profiles.txt"])[0].strip() or "my_profiles.txt"
        outdir = data.get("outdir", ["self_audit_outputs"])[0].strip() or "self_audit_outputs"

        rc, output = run_self_audit(url, allowlist, outdir)
        status = "PASS" if rc == 0 else f"FAIL (rc={rc})"

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        body = f"""
<!doctype html>
<html><head><meta charset='utf-8'><title>Run Result</title></head>
<body style='font-family:Arial;max-width:900px;margin:24px auto'>
  <h1>Run Result: {status}</h1>
  <pre style='white-space:pre-wrap;background:#f5f5f5;padding:12px;border-radius:8px'>{html.escape(output)}</pre>
  <p><a href='/'>Back</a></p>
</body></html>
"""
        self.wfile.write(body.encode("utf-8"))


def main():
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Self-audit GUI running at http://127.0.0.1:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
