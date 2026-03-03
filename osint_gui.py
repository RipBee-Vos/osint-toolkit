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
    target_kind = (target_kind or "").strip().lower()
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

    details["location"] = {k: v for k, v in details["location"].items() if v}
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
    blanket_pivots: bool,
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

    if target_kind:
        cmd.extend(["--target-kind", target_kind])
    if details_path:
        cmd.extend(["--target-details", details_path])

    if blanket_pivots:
        cmd.append("--blanket-pivots")

    if no_enrich:
        cmd.append("--no-enrich")

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    except FileNotFoundError as exc:
        return 1, f"Unable to start scan process: {exc}"

    output = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    return p.returncode, output.strip()


def list_reports() -> list[dict]:
    if not OUT.exists():
        return []
    runs: list[dict] = []
    for run_dir in [p for p in OUT.iterdir() if p.is_dir()]:
        files = [f for f in sorted(run_dir.iterdir()) if f.is_file()]
        rel_files = [str(f.relative_to(OUT)) for f in files]
        ts = run_dir.stat().st_mtime
        runs.append({"run_id": run_dir.name, "mtime": ts, "files": rel_files})
    runs.sort(key=lambda x: x["mtime"], reverse=True)
    return runs


def _guess_run_outputs(run_dir: Path, target_kind: str, target_value: str) -> list[Path]:
    candidates: list[Path] = []

    td = run_dir / "target_details.json"
    if td.exists():
        candidates.append(td)

    if target_kind in {"person", "username", "email"}:
        for name in (
            "seed.html",
            "seed.md",
            "seed.json",
            "seed.findings.csv",
            "seed.pivots.json",
            "seed.pivots.csv",
            "seed.pivots.txt",
            "batch.findings.csv",
        ):
            p = run_dir / name
            if p.exists():
                candidates.append(p)
        return candidates

    stem = (target_value or "").replace("*", "wildcard").replace("/", "_").replace(":", "_")

    for name in (
        f"{stem}.html",
        f"{stem}.md",
        f"{stem}.json",
        f"{stem}.findings.csv",
        f"{stem}.pivots.json",
        f"{stem}.pivots.csv",
        f"{stem}.pivots.txt",
        "batch.findings.csv",
    ):
        p = run_dir / name
        if p.exists():
            candidates.append(p)

    if not candidates:
        for p in sorted(run_dir.glob("*")):
            if p.is_file():
                candidates.append(p)

    return candidates


def _page(title: str, body: str) -> bytes:
    style = """
<style>
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; font-family: Inter, Segoe UI, Arial, sans-serif; background: #f3f5f8; color: #17212f; }
.container { max-width: 1100px; margin: 0 auto; padding: 24px 16px 40px; }
.header { background: #fff; border: 1px solid #dce2ea; border-radius: 14px; padding: 18px; box-shadow: 0 5px 20px rgba(20, 31, 45, 0.07); }
.subtitle { margin: 6px 0 0; color: #4a5b72; }
.notice { margin-top: 10px; padding: 10px 12px; border-radius: 10px; background: #fff8e6; border: 1px solid #f3dd9a; color: #5f4700; font-size: 14px; }
.card { margin-top: 16px; background: #fff; border: 1px solid #dce2ea; border-radius: 14px; padding: 16px; box-shadow: 0 4px 14px rgba(20, 31, 45, 0.05); }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.stack { display: grid; gap: 10px; }
label { display: grid; gap: 6px; font-weight: 600; font-size: 14px; }
input, select, textarea { width: 100%; border: 1px solid #c8d1de; border-radius: 10px; padding: 10px; font: inherit; background: #fff; }
input:focus, select:focus, textarea:focus, button:focus { outline: 2px solid #4f7cff; outline-offset: 1px; }
details { border: 1px solid #e4e9f1; border-radius: 10px; padding: 10px; background: #fafbfd; }
summary { cursor: pointer; font-weight: 600; }
button { border: 0; border-radius: 10px; background: #1f5eff; color: #fff; padding: 11px 16px; cursor: pointer; font-weight: 700; box-shadow: 0 5px 14px rgba(31, 94, 255, 0.25); }
button:hover { background: #184bd0; }
.badge { display: inline-block; padding: 4px 9px; border-radius: 999px; font-weight: 700; font-size: 12px; }
.badge.pass { background: #e7f8ee; color: #1e7a41; border: 1px solid #a8e2bf; }
.badge.fail { background: #fdeceb; color: #a1261b; border: 1px solid #f4b6b1; }
@media (max-width: 820px) { .grid { grid-template-columns: 1fr; } }
</style>
"""
    doc = f"""<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>{html.escape(title)}</title>
  {style}
</head>
<body>
<div class=\"container\">{body}</div>
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

        run_items = []
        for run in list_reports()[:10]:
            files = "".join(
                f"<li><a href='/file?name={urllib.parse.quote(name)}' target='_blank'>{html.escape(Path(name).name)}</a></li>"
                for name in run["files"]
                if Path(name).name.endswith((".html", ".md", ".json", ".csv", ".txt"))
            )
            run_items.append(
                f"<details><summary>{html.escape(run['run_id'])}</summary>"
                f"<ul>{files or '<li>No files</li>'}</ul></details>"
            )

        body = f"""
<div class="header">
  <h1>OSINT Toolkit GUI</h1>
  <p class="subtitle">Local-only interface for authorized passive recon and seed + manual pivots workflows.</p>
  <div class="notice">Safety: scope required for domain mode.</div>
</div>

<form method="post" action="/run" class="card stack" id="scan-form">
  <div class="grid">
    <label>Target type
      <select name="target_kind" id="target_kind">
        <option value="domain" selected>Domain</option>
        <option value="person">Person</option>
        <option value="username">Username</option>
        <option value="email">Email</option>
      </select>
    </label>
    <label>Target value
      <input name="target" placeholder="example.com or Jane Doe or handle" required />
    </label>
  </div>

  <details open>
    <summary>Scan settings</summary>
    <div class="grid" style="margin-top:10px;">
      <label>Scope file <input name="scope" value="scope.txt" /></label>
      <label>Output dir <input name="outdir" value="outputs" /></label>
    </div>
    <div id="domain-settings" class="grid" style="margin-top:10px;">
      <label>Max subdomains
        <input name="max_subdomains" type="number" value="100" min="1" max="1000" />
      </label>
      <label style="align-self:end;">
        <span><input name="no_enrich" type="checkbox" checked /> No enrichment (domain mode)</span>
      </label>
    </div>
    <label id="pivot-setting" style="margin-top:10px;">
      <span><input name="blanket_pivots" type="checkbox" checked /> Blanket pivots (seed modes)</span>
    </label>
  </details>

  <details id="seed-details" open>
    <summary>More details (optional)</summary>
    <div class="stack" style="margin-top:10px;">
      <label>Name <input name="name" placeholder="Full name" /></label>
      <label>Aliases (one per line)<textarea name="aliases" rows="3"></textarea></label>
      <div class="grid">
        <label>City <input name="loc_city" /></label>
        <label>State/Region <input name="loc_state" /></label>
      </div>
      <label>Country <input name="loc_country" /></label>
      <label>Usernames (one per line)<textarea name="usernames" rows="3"></textarea></label>
      <div class="grid">
        <label>Emails (one per line)<textarea name="emails" rows="3"></textarea></label>
        <label>Phones (one per line)<textarea name="phones" rows="3"></textarea></label>
      </div>
      <div class="grid">
        <label>LinkedIn <input name="social_linkedin" /></label>
        <label>GitHub <input name="social_github" /></label>
        <label>X <input name="social_x" /></label>
        <label>Facebook <input name="social_facebook" /></label>
        <label>Instagram <input name="social_instagram" /></label>
        <label>TikTok <input name="social_tiktok" /></label>
        <label>Reddit <input name="social_reddit" /></label>
        <label>Website <input name="social_website" /></label>
      </div>
      <label>Other social links (one per line)<textarea name="social_other" rows="3"></textarea></label>
      <label>Notes<textarea name="notes" rows="4"></textarea></label>
    </div>
  </details>

  <button type="submit">Run Scan</button>
</form>

<div class="card">
  <h2>Recent Runs</h2>
  {''.join(run_items) or '<p>No runs yet</p>'}
</div>

<script>
(function() {{
  const targetKind = document.getElementById('target_kind');
  const seedDetails = document.getElementById('seed-details');
  const domainSettings = document.getElementById('domain-settings');
  const pivotSetting = document.getElementById('pivot-setting');
  const blanket = document.querySelector('input[name="blanket_pivots"]');
  const noEnrich = document.querySelector('input[name="no_enrich"]');
  const maxSubdomains = document.querySelector('input[name="max_subdomains"]');

  function syncView() {{
    const isDomain = targetKind.value === 'domain';
    seedDetails.style.display = isDomain ? 'none' : 'block';
    domainSettings.style.display = isDomain ? 'grid' : 'none';
    pivotSetting.style.display = isDomain ? 'none' : 'block';
    blanket.disabled = isDomain;
    noEnrich.disabled = !isDomain;
    maxSubdomains.disabled = !isDomain;
  }}

  targetKind.addEventListener('change', syncView);
  syncView();
}})();
</script>
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

        target_kind = _clamp(data.get("target_kind", ["domain"])[0], 20).lower() or "domain"
        target = _clamp(data.get("target", [""])[0], 253)

        ok, msg = _validate_target(target_kind, target)
        if not ok:
            body = f"""
<h1>Run Result <span class='badge fail'>FAIL</span></h1>
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
        blanket_pivots = "blanket_pivots" in data
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
            blanket_pivots=blanket_pivots,
        )

        is_ok = rc == 0
        badge = "<span class='badge pass'>PASS</span>" if is_ok else f"<span class='badge fail'>FAIL (rc={rc})</span>"
        rel_details = str(details_path.relative_to(OUT)) if OUT in details_path.parents else str(details_path.name)

        produced = _guess_run_outputs(run_dir, target_kind, target)
        def pick(ext: str) -> str | None:
            for p in produced:
                if p.suffix == ext:
                    rel = str(p.relative_to(OUT)) if OUT in p.parents else p.name
                    return f"<a href='/file?name={urllib.parse.quote(rel)}' target='_blank'>{html.escape(p.name)}</a>"
            return None

        primary = pick('.html') or pick('.md') or pick('.json') or "No primary artifact found"
        links = []
        for p in produced:
            rel = str(p.relative_to(OUT)) if OUT in p.parents else p.name
            links.append(f"<li><a href='/file?name={urllib.parse.quote(rel)}' target='_blank'>{html.escape(p.name)}</a></li>")
        produced_html = "<ul>" + "".join(links) + "</ul>" if links else "<p><i>No outputs found in the run folder.</i></p>"

        body = f"""
<div class="card">
  <h1>Run Result {badge}</h1>
  <p><b>Run folder:</b> {html.escape(str(run_dir.relative_to(ROOT)))}</p>
  <p><b>Target details:</b> <a href="/file?name={urllib.parse.quote(rel_details)}" target="_blank">target_details.json</a></p>
  <p><b>Primary artifact:</b> {primary}</p>
</div>
<div class="card">
  <h2>Generated Reports</h2>
  {produced_html}
</div>
<div class="card">
  <details>
    <summary>Runtime output</summary>
    <pre style="white-space:pre-wrap; background:#f6f8fb; padding:12px; border-radius:10px; border:1px solid #dbe3ef;">{html.escape(output or '(no output)')}</pre>
  </details>
  <p><a href="/">Back</a></p>
</div>
"""
        self.send_response(200 if is_ok else 500)
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
