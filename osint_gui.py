#!/usr/bin/env python3
"""Minimal local web GUI for osint.py (no third-party deps)."""

from __future__ import annotations
import html
import json
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "outputs"
PORT = 8765


def run_scan(target: str, scope: str, outdir: str, no_enrich: bool, max_subdomains: int) -> tuple[int, str]:
    cmd = [
        "python3",
        str(ROOT / "osint.py"),
        target,
        "--scope",
        scope,
        "--outdir",
        outdir,
        "--max-subdomains",
        str(max_subdomains),
    ]
    if no_enrich:
        cmd.append("--no-enrich")

    p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    output = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    return p.returncode, output.strip()


def list_reports() -> list[str]:
    if not OUT.exists():
        return []
    files = sorted([p.name for p in OUT.iterdir() if p.suffix in {".md", ".html", ".json", ".csv"}])
    return files


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
            if target.suffix == ".html":
                ctype = "text/html; charset=utf-8"
            elif target.suffix == ".json":
                ctype = "application/json; charset=utf-8"
            elif target.suffix == ".csv":
                ctype = "text/csv; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(content)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        reports = "".join(
            f"<li><a href='/file?name={urllib.parse.quote(name)}' target='_blank'>{html.escape(name)}</a></li>"
            for name in list_reports()
        )
        body = f"""
<!doctype html>
<html><head><meta charset='utf-8'><title>OSINT Toolkit GUI</title></head>
<body style='font-family:Arial;max-width:900px;margin:24px auto'>
  <h1>OSINT Toolkit GUI</h1>
  <form method='post' action='/run' style='display:grid;gap:8px;max-width:600px'>
    <label>Target <input name='target' placeholder='example.com' required /></label>
    <label>Scope file <input name='scope' value='scope.txt' /></label>
    <label>Output dir <input name='outdir' value='outputs' /></label>
    <label>Max subdomains <input name='max_subdomains' type='number' value='100' min='1' max='1000' /></label>
    <label><input name='no_enrich' type='checkbox' checked /> No enrichment</label>
    <button type='submit'>Run Scan</button>
  </form>
  <h2>Reports</h2>
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

        target = data.get("target", [""])[0].strip()
        scope = data.get("scope", ["scope.txt"])[0].strip() or "scope.txt"
        outdir = data.get("outdir", ["outputs"])[0].strip() or "outputs"
        no_enrich = "no_enrich" in data
        try:
            max_subdomains = int(data.get("max_subdomains", ["100"])[0])
        except ValueError:
            max_subdomains = 100

        rc, output = run_scan(target, scope, outdir, no_enrich, max_subdomains)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        status = "PASS" if rc == 0 else f"FAIL (rc={rc})"
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
    print(f"GUI running at http://127.0.0.1:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
