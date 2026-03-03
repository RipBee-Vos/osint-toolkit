#!/usr/bin/env python3
"""Minimal local web GUI for osint.py (no third-party deps)."""

from __future__ import annotations
import datetime as dt
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
MAX_FIELD_LEN = 2000
MAX_NOTES_LEN = 20000


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")


def clamp_text(value: str, max_len: int = MAX_FIELD_LEN) -> str:
    return value.strip()[:max_len]


def split_lines(value: str, max_items: int = 200, max_item_len: int = 200) -> list[str]:
    items = []
    for line in value.splitlines():
        cleaned = line.strip()
        if cleaned:
            items.append(cleaned[:max_item_len])
        if len(items) >= max_items:
            break
    return items


def resolve_outdir(outdir: str) -> Path:
    selected = clamp_text(outdir, 200) or "outputs"
    candidate = (ROOT / selected).resolve()
    if not str(candidate).startswith(str(ROOT.resolve())):
        return OUT
    return candidate


def run_scan(
    target: str,
    target_kind: str,
    scope: str,
    run_dir: Path,
    no_enrich: bool,
    max_subdomains: int,
    target_details_path: Path,
) -> tuple[int, str, str]:
    cmd = [
        sys.executable,
        str(ROOT / "osint.py"),
        target,
        "--scope",
        scope,
        "--outdir",
        str(run_dir),
        "--max-subdomains",
        str(max_subdomains),
        "--target-kind",
        target_kind,
        "--target-details",
        str(target_details_path),
    ]
    if no_enrich:
        cmd.append("--no-enrich")

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    except FileNotFoundError as exc:
        return 1, f"Unable to start scan process: {exc}", ""
    output = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    return p.returncode, output.strip(), " ".join(urllib.parse.quote(part, safe="/:._-") for part in cmd)


def list_reports() -> list[str]:
    if not OUT.exists():
        return []
    suffixes = {".md", ".html", ".json", ".csv", ".txt", ".log"}
    files = sorted(str(p.relative_to(OUT)) for p in OUT.rglob("*") if p.is_file() and p.suffix.lower() in suffixes)
    return files


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/file":
            qs = urllib.parse.parse_qs(parsed.query)
            name = (qs.get("name", [""])[0]).strip()
            target = (OUT / name).resolve()
            if not name or not str(target).startswith(str(OUT.resolve())) or not target.exists() or not target.is_file():
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
  <form method='post' action='/run' style='display:grid;gap:8px;max-width:700px'>
    <label>Target type
      <select name='target_kind'>
        <option value='domain' selected>domain</option>
        <option value='person'>person</option>
        <option value='username'>username</option>
        <option value='email'>email</option>
      </select>
    </label>
    <label>Target value <input name='target' placeholder='example.com' required /></label>
    <label>Name <input name='name' /></label>
    <label>Aliases (one per line)<br><textarea name='aliases' rows='3'></textarea></label>
    <fieldset style='border:1px solid #ddd;padding:10px'>
      <legend>Location</legend>
      <label>City <input name='location_city' /></label><br>
      <label>State/Region <input name='location_state_region' /></label><br>
      <label>Country <input name='location_country' /></label>
    </fieldset>
    <label>Usernames (one per line)<br><textarea name='usernames' rows='3'></textarea></label>
    <label>Emails (one per line)<br><textarea name='emails' rows='3'></textarea></label>
    <label>Phones (one per line)<br><textarea name='phones' rows='3'></textarea></label>
    <fieldset style='border:1px solid #ddd;padding:10px'>
      <legend>Social links/handles</legend>
      <label>LinkedIn <input name='social_linkedin' /></label><br>
      <label>GitHub <input name='social_github' /></label><br>
      <label>X <input name='social_x' /></label><br>
      <label>Facebook <input name='social_facebook' /></label><br>
      <label>Instagram <input name='social_instagram' /></label><br>
      <label>TikTok <input name='social_tiktok' /></label><br>
      <label>Reddit <input name='social_reddit' /></label><br>
      <label>Website <input name='social_website' /></label><br>
      <label>Other social links (one per line)<br><textarea name='social_other' rows='3'></textarea></label>
    </fieldset>
    <label>Notes<br><textarea name='notes' rows='4'></textarea></label>

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

        target_kind = clamp_text(data.get("target_kind", ["domain"])[0], 20).lower() or "domain"
        if target_kind not in {"domain", "person", "username", "email"}:
            target_kind = "domain"

        target = clamp_text(data.get("target", [""])[0], 300)
        scope = clamp_text(data.get("scope", ["scope.txt"])[0], 300) or "scope.txt"
        outdir = clamp_text(data.get("outdir", ["outputs"])[0], 300) or "outputs"
        no_enrich = "no_enrich" in data
        try:
            max_subdomains = int(data.get("max_subdomains", ["100"])[0])
        except ValueError:
            max_subdomains = 100
        max_subdomains = max(1, min(max_subdomains, 5000))

        if not target:
            rc, output = 2, "Target is required"
            run_dir = resolve_outdir(outdir)
            command_str = ""
        elif target_kind == "domain" and not DOMAIN_RE.match(target):
            rc, output = 2, "Invalid domain format for target_kind=domain"
            run_dir = resolve_outdir(outdir)
            command_str = ""
        else:
            chosen_outdir = resolve_outdir(outdir)
            run_id = dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            run_dir = chosen_outdir / run_id
            suffix = 1
            while run_dir.exists():
                suffix += 1
                run_dir = chosen_outdir / f"{run_id}_{suffix}"
            run_dir.mkdir(parents=True, exist_ok=True)

            details = {
                "target_kind": target_kind,
                "target": target,
                "name": clamp_text(data.get("name", [""])[0], 300),
                "aliases": split_lines(data.get("aliases", [""])[0]),
                "location": {
                    "city": clamp_text(data.get("location_city", [""])[0], 200),
                    "state_region": clamp_text(data.get("location_state_region", [""])[0], 200),
                    "country": clamp_text(data.get("location_country", [""])[0], 200),
                },
                "usernames": split_lines(data.get("usernames", [""])[0]),
                "emails": split_lines(data.get("emails", [""])[0]),
                "phones": split_lines(data.get("phones", [""])[0]),
                "social": {
                    "linkedin": clamp_text(data.get("social_linkedin", [""])[0], 500),
                    "github": clamp_text(data.get("social_github", [""])[0], 500),
                    "x": clamp_text(data.get("social_x", [""])[0], 500),
                    "facebook": clamp_text(data.get("social_facebook", [""])[0], 500),
                    "instagram": clamp_text(data.get("social_instagram", [""])[0], 500),
                    "tiktok": clamp_text(data.get("social_tiktok", [""])[0], 500),
                    "reddit": clamp_text(data.get("social_reddit", [""])[0], 500),
                    "website": clamp_text(data.get("social_website", [""])[0], 500),
                    "other": split_lines(data.get("social_other", [""])[0], max_items=200, max_item_len=500),
                },
                "notes": clamp_text(data.get("notes", [""])[0], MAX_NOTES_LEN),
            }
            details_path = run_dir / "target_details.json"
            details_path.write_text(json.dumps(details, indent=2), encoding="utf-8")

            rc, output, command_str = run_scan(target, target_kind, scope, run_dir, no_enrich, max_subdomains, details_path)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        status = "PASS" if rc == 0 else f"FAIL (rc={rc})"
        run_rel = run_dir.relative_to(ROOT) if str(run_dir).startswith(str(ROOT.resolve())) else run_dir
        details_rel = None
        details_path = run_dir / "target_details.json"
        if details_path.exists() and str(details_path.resolve()).startswith(str(OUT.resolve())):
            details_rel = details_path.relative_to(OUT)

        details_link = (
            f"<p>Target details: <a href='/file?name={urllib.parse.quote(str(details_rel))}' target='_blank'>target_details.json</a></p>"
            if details_rel
            else ""
        )

        body = f"""
<!doctype html>
<html><head><meta charset='utf-8'><title>Run Result</title></head>
<body style='font-family:Arial;max-width:900px;margin:24px auto'>
  <h1>Run Result: {status}</h1>
  <p>Run folder: <code>{html.escape(str(run_rel))}</code></p>
  {details_link}
  <p>Command: <code>{html.escape(command_str)}</code></p>
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
