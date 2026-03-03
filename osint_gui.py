#!/usr/bin/env python3
"""Minimal local web GUI for osint.py (no third-party deps)."""

from __future__ import annotations

import datetime as _dt
import html
import json
import re
import subprocess
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "outputs"
PORT = 8765

MAX_TEXT = 200
MAX_NOTES = 2000

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def _clamp(s: str, n: int) -> str:
    return (s or "").strip()[:n]


def _now_run_id() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _safe_int(value: str, default: int, min_v: int, max_v: int) -> int:
    try:
        v = int(value)
    except Exception:
        return default
    return max(min_v, min(max_v, v))


def _parse_lines(raw: str, max_items: int = 25, max_each: int = MAX_TEXT) -> list[str]:
    if not raw:
        return []
    parts = [p.strip() for p in raw.replace("\r", "").split("\n")]
    parts = [p for p in parts if p]
    parts = parts[:max_items]
    return [_clamp(p, max_each) for p in parts]


def _validate_target(target_kind: str, target: str) -> tuple[bool, str]:
    target_kind = (target_kind or "").strip()
    target = (target or "").strip()

    if not target:
        return False, "Target is required."

    if target_kind == "domain":
        if not DOMAIN_RE.match(target):
            return False, "Target does not look like a valid domain (example.com)."

    if target_kind not in {"domain", "person", "username", "email"}:
        return False, "Unknown target type."

    return True, ""


def _build_target_details(form: dict[str, list[str]], target_kind: str, target: str) -> dict:
    def get(k: str, n: int = MAX_TEXT) -> str:
        return _clamp(form.get(k, [""])[0], n)

    details: dict = {
        "target_kind": target_kind,
        "target": target,
        "name": get("name"),
        "aliases": _parse_lines(form.get("aliases", [""])[0]),
        "location": {
            "city": get("loc_city"),
            "state_region": get("loc_state"),
            "country": get("loc_country"),
        },
        "usernames": _parse_lines(form.get("usernames", [""])[0]),
        "emails": _parse_lines(form.get("emails", [""])[0]),
        "phones": _parse_lines(form.get("phones", [""])[0]),
        "social": {
            "linkedin": get("social_linkedin"),
            "github": get("social_github"),
            "x": get("social_x"),
            "facebook": get("social_facebook"),
            "instagram": get("social_instagram"),
            "tiktok": get("social_tiktok"),
            "reddit": get("social_reddit"),
            "website": get("social_website"),
            "other": _parse_lines(form.get("social_other", [""])[0]),
        },
        "notes": get("notes", MAX_NOTES),
    }

    # Drop empty location keys
    details["location"] = {k: v for k, v in details["location"].items() if v}
    # Drop empty social keys (keep "other" only if not empty)
    details["social"] = {k: v for k, v in details["social"].items() if v}

    return details


def run_scan(
    target: str,
    scope: str,
    outdir: str,
    no_enrich: bool,
    max_subdomains: int,
    target_kind: str,
    details_path: str | None,
) -> tuple[int, str]:
    cmd = [
        sys.executable,
        str(ROOT / "osint.py"),
        target,
        "--scope",
        scope,
        "--outdir",
        outdir,
        "--max-subdomains",
        str(max_subdomains),
    ]

    # Optional flags (requires osint.py support)
    if target_kind:
        cmd.extend(["--target-kind", target_kind])
    if details_path:
        cmd.extend(["--target-details", details_path])

    if no_enrich:
        cmd.append("--no-enrich")

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    except FileNotFoundError as exc:
        return 1, f"Unable to start scan process: {exc}"

    output = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    return p.returncode, output.strip()


def list_reports() -> list[str]:
    if not OUT.exists():
        return []
    exts = {".md", ".html", ".json", ".csv", ".txt", ".log"}
    files: list[str] = []
    for p in OUT.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            files.append(str(p.relative_to(OUT)))
    return sorted(files)


def _page(title: str, body: str) -> bytes:
    doc = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
</head>
<body style="font-family:Arial, sans-serif; max-width: 980px; margin: 24px auto; padding: 0 12px;">
{body}
</body>
</html>
"""
    return doc.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/file":
            qs = urllib.parse.parse_qs(parsed.query)
            name = (qs.get("name", [""])[0]).strip()

            out_root = OUT.resolve()
            target = (OUT / name).resolve()

            # Prevent traversal and only serve files under outputs/
            if not str(target).startswith(str(out_root)) or not target.exists() or not target.is_file():
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

        reports = "".join(
            f"<li><a href='/file?name={urllib.parse.quote(name)}' target='_blank'>{html.escape(name)}</a></li>"
            for name in list_reports()
        )

        body = f"""
<h1>OSINT Toolkit GUI</h1>

<form method="post" action="/run" style="display:grid; gap:12px; max-width: 820px; padding: 12px; border: 1px solid #ddd; border-radius: 10px;">
  <fieldset style="border: 1px solid #eee; border-radius: 10px; padding: 12px;">
    <legend style="padding: 0 6px;">Target</legend>

    <label style="display:block; margin-bottom:8px;">
      Target type
      <select name="target_kind" style="width: 100%; padding: 8px;">
        <option value="domain" selected>Domain</option>
        <option value="person">Person</option>
        <option value="username">Username</option>
        <option value="email">Email</option>
      </select>
    </label>

    <label style="display:block;">
      Target value
      <input name="target" placeholder="example.com or Jane Doe or handle" required style="width: 100%; padding: 8px;" />
    </label>
  </fieldset>

  <fieldset style="border: 1px solid #eee; border-radius: 10px; padding: 12px;">
    <legend style="padding: 0 6px;">More details (optional)</legend>

    <label style="display:block;">
      Name
      <input name="name" placeholder="Full name" style="width: 100%; padding: 8px;" />
    </label>

    <label style="display:block;">
      Aliases (one per line)
      <textarea name="aliases" rows="3" placeholder="Nicknames, alternate spellings" style="width: 100%; padding: 8px;"></textarea>
    </label>

    <div style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px;">
      <label>City <input name="loc_city" style="width: 100%; padding: 8px;" /></label>
      <label>State/Region <input name="loc_state" style="width: 100%; padding: 8px;" /></label>
      <label>Country <input name="loc_country" style="width: 100%; padding: 8px;" /></label>
    </div>

    <label style="display:block;">
      Usernames (one per line)
      <textarea name="usernames" rows="3" placeholder="Known handles" style="width: 100%; padding: 8px;"></textarea>
    </label>

    <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px;">
      <label>Emails (one per line)
        <textarea name="emails" rows="3" style="width: 100%; padding: 8px;"></textarea>
      </label>
      <label>Phones (one per line)
        <textarea name="phones" rows="3" style="width: 100%; padding: 8px;"></textarea>
      </label>
    </div>

    <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px;">
      <label>LinkedIn <input name="social_linkedin" placeholder="profile URL or handle" style="width: 100%; padding: 8px;" /></label>
      <label>GitHub <input name="social_github" placeholder="username or URL" style="width: 100%; padding: 8px;" /></label>
      <label>X <input name="social_x" placeholder="handle or URL" style="width: 100%; padding: 8px;" /></label>
      <label>Facebook <input name="social_facebook" placeholder="URL" style="width: 100%; padding: 8px;" /></label>
      <label>Instagram <input name="social_instagram" placeholder="handle or URL" style="width: 100%; padding: 8px;" /></label>
      <label>TikTok <input name="social_tiktok" placeholder="handle or URL" style="width: 100%; padding: 8px;" /></label>
      <label>Reddit <input name="social_reddit" placeholder="u/username" style="width: 100%; padding: 8px;" /></label>
      <label>Website <input name="social_website" placeholder="https://..." style="width: 100%; padding: 8px;" /></label>
    </div>

    <label style="display:block;">
      Other social links (one per line)
      <textarea name="social_other" rows="3" placeholder="Other profile URLs" style="width: 100%; padding: 8px;"></textarea>
    </label>

    <label style="display:block;">
      Notes
      <textarea name="notes" rows="4" placeholder="Anything else that could help narrow results" style="width: 100%; padding: 8px;"></textarea>
    </label>
  </fieldset>

  <fieldset style="border: 1px solid #eee; border-radius: 10px; padding: 12px;">
    <legend style="padding: 0 6px;">Scan settings</legend>

    <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px;">
      <label>Scope file <input name="scope" value="scope.txt" style="width: 100%; padding: 8px;" /></label>
      <label>Output dir <input name="outdir" value="outputs" style="width: 100%; padding: 8px;" /></label>
    </div>

    <label style="display:block;">
      Max subdomains
      <input name="max_subdomains" type="number" value="100" min="1" max="1000" style="width: 100%; padding: 8px;" />
    </label>

    <label style="display:block; margin-top: 6px;">
      <input name="no_enrich" type="checkbox" checked /> No enrichment
    </label>
  </fieldset>

  <button type="submit" style="padding: 10px 14px; border-radius: 10px; border: 1px solid #333; background: #fff; cursor: pointer;">
    Run Scan
  </button>
</form>

<h2 style="margin-top: 24px;">Reports</h2>
<ul>
  {reports or "<li>No reports yet</li>"}
</ul>
"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(_page("OSINT Toolkit GUI", body))

    def do_POST(self):
        if self.path != "/run":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        data = urllib.parse.parse_qs(raw)

        target_kind = _clamp(data.get("target_kind", ["domain"])[0], 20) or "domain"
        target = _clamp(data.get("target", [""])[0], 253)

        ok, msg = _validate_target(target_kind, target)
        if not ok:
            body = f"""
<h1>Run Result: FAIL</h1>
<p style="color:#b00020;"><b>Validation error:</b> {html.escape(msg)}</p>
<p><a href="/">Back</a></p>
"""
            self.send_response(400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(_page("Run Result", body))
            return

        scope = _clamp(data.get("scope", ["scope.txt"])[0], 200) or "scope.txt"
        outdir_root = _clamp(data.get("outdir", ["outputs"])[0], 200) or "outputs"
        no_enrich = "no_enrich" in data
        max_subdomains = _safe_int(data.get("max_subdomains", ["100"])[0], default=100, min_v=1, max_v=1000)

        run_id = _now_run_id()
        run_dir = (ROOT / outdir_root / run_id).resolve()
        run_dir.mkdir(parents=True, exist_ok=True)

        details = _build_target_details(data, target_kind, target)
        details_path = run_dir / "target_details.json"
        details_path.write_text(json.dumps(details, indent=2, ensure_ascii=False), encoding="utf-8")

        rc, output = run_scan(
            target=target,
            scope=scope,
            outdir=str(run_dir),
            no_enrich=no_enrich,
            max_subdomains=max_subdomains,
            target_kind=target_kind,
            details_path=str(details_path),
        )

        status = "PASS" if rc == 0 else f"FAIL (rc={rc})"

        # Link to the details JSON from the outputs root
        rel_details = str(details_path.relative_to(OUT)) if OUT in details_path.parents else str(details_path.name)

        body = f"""
<h1>Run Result: {html.escape(status)}</h1>
<p><b>Run folder:</b> {html.escape(str(run_dir.relative_to(ROOT)))}</p>
<p><b>Target details:</b> <a href="/file?name={urllib.parse.quote(rel_details)}" target="_blank">target_details.json</a></p>
<pre style="white-space:pre-wrap; background:#f5f5f5; padding:12px; border-radius:10px; border:1px solid #ddd;">{html.escape(output or "(no output)")}</pre>
<p><a href="/">Back</a></p>
"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(_page("Run Result", body))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"GUI running at http://127.0.0.1:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
