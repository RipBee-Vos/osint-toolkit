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
PEOPLE_OUT = ROOT / "people_search_outputs"
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
    report_files: list[str] = []
    for base in [OUT, PEOPLE_OUT]:
        if not base.exists():
            continue
        report_files.extend(
            [f"{base.name}/{p.name}" for p in base.iterdir() if p.suffix in {".md", ".json", ".csv"}]
        )
    return sorted(report_files, reverse=True)


def run_people_search(name: str, location: str, company: str, username: str, outdir: str) -> tuple[int, str]:
    cmd = ["python3", str(ROOT / "people_search.py"), name, "--outdir", outdir]
    if location:
        cmd.extend(["--location", location])
    if company:
        cmd.extend(["--company", company])
    if username:
        cmd.extend(["--username", username])
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    output = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    return p.returncode, output.strip()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/file":
            qs = urllib.parse.parse_qs(parsed.query)
            name = (qs.get("name", [""])[0]).strip()
            if "/" not in name:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not found")
                return
            folder, filename = name.split("/", 1)
            base = ROOT / folder
            if base not in [OUT, PEOPLE_OUT]:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not found")
                return
            target = (base / filename).resolve()
            if not str(target).startswith(str(base.resolve())) or not target.exists():
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
  <p>Use for authorized and legal investigations only.</p>
  <form method='post' action='/run' style='display:grid;gap:8px;max-width:700px'>
    <h2>Self profile audit (allowlist enforced)</h2>
    <label>Profile URL <input name='url' placeholder='https://www.linkedin.com/in/your-handle/' required /></label>
    <label>Allowlist file <input name='allowlist' value='my_profiles.txt' /></label>
    <label>Output dir <input name='outdir' value='self_audit_outputs' /></label>
    <button type='submit'>Run Self Audit</button>
  </form>

  <form method='post' action='/people-search' style='display:grid;gap:8px;max-width:700px;margin-top:24px'>
    <h2>People search query generator (no scraping)</h2>
    <label>Name <input name='name' placeholder='Jane Doe' required /></label>
    <label>Location <input name='location' placeholder='Austin, TX' /></label>
    <label>Company/School <input name='company' placeholder='Example Corp' /></label>
    <label>Username <input name='username' placeholder='janedoe123' /></label>
    <label>Output dir <input name='outdir' value='people_search_outputs' /></label>
    <button type='submit'>Generate Search Links</button>
  </form>
  <h2>Latest Reports</h2>
  <ul>{reports or '<li>No reports yet</li>'}</ul>
</body></html>
"""
        self.wfile.write(body.encode("utf-8"))

    def do_POST(self):
        if self.path not in {"/run", "/people-search"}:
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        data = urllib.parse.parse_qs(raw)
        if self.path == "/run":
            url = data.get("url", [""])[0].strip()
            allowlist = data.get("allowlist", ["my_profiles.txt"])[0].strip() or "my_profiles.txt"
            outdir = data.get("outdir", ["self_audit_outputs"])[0].strip() or "self_audit_outputs"
            rc, output = run_self_audit(url, allowlist, outdir)
        else:
            name = data.get("name", [""])[0].strip()
            location = data.get("location", [""])[0].strip()
            company = data.get("company", [""])[0].strip()
            username = data.get("username", [""])[0].strip()
            outdir = data.get("outdir", ["people_search_outputs"])[0].strip() or "people_search_outputs"
            rc, output = run_people_search(name, location, company, username, outdir)
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
