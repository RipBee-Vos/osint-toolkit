#!/usr/bin/env python3
"""
Self-OSINT audit helper (consent-based, allowlist-only).

Purpose:
- Audit your OWN public profile exposure.
- Not for searching other people.
"""

from __future__ import annotations
import argparse
import csv
import datetime as dt
import json
import re
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path

UA = "Self-OSINT-Audit/1.0"


def load_allowlist(path: Path) -> set[str]:
    allowed = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        allowed.add(line)
    return allowed


def get_html(url: str, timeout: int = 12) -> tuple[int | None, dict, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status = getattr(r, "status", None)
            headers = dict(r.headers)
            html = r.read(300000).decode("utf-8", errors="replace")
            return status, headers, html
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(300000).decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, dict(e.headers or {}), body
    except Exception:
        return None, {}, ""


def title_from_html(text: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()


def meta_description(text: str) -> str | None:
    m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', text, re.I)
    return m.group(1).strip() if m else None


def simple_findings(url: str, headers: dict, html: str) -> list[dict]:
    findings = []
    title = title_from_html(html) or ""
    desc = meta_description(html) or ""

    if "X-Robots-Tag" not in headers:
        findings.append({
            "id": "robots_tag_missing",
            "severity": "info",
            "evidence": "X-Robots-Tag header not present",
            "recommendation": "Consider robots/indexing strategy for non-essential pages",
        })

    if any(tok in (title + " " + desc).lower() for tok in ["email", "phone", "address"]):
        findings.append({
            "id": "possible_contact_keywords_public",
            "severity": "low",
            "evidence": "Public metadata may contain contact-related keywords",
            "recommendation": "Review profile headline/about for oversharing",
        })

    csp = headers.get("Content-Security-Policy")
    if not csp:
        findings.append({
            "id": "csp_not_observed",
            "severity": "info",
            "evidence": "Content-Security-Policy header not observed",
            "recommendation": "Platform-controlled; note as informational only",
        })

    return findings


def to_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["url", "id", "severity", "evidence", "recommendation"])
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main() -> int:
    p = argparse.ArgumentParser(description="Self-OSINT profile audit (allowlist required)")
    p.add_argument("url", help="Your own profile URL (must be in allowlist)")
    p.add_argument("--allowlist", default="my_profiles.txt")
    p.add_argument("--outdir", default="self_audit_outputs")
    args = p.parse_args()

    allow_path = Path(args.allowlist)
    if not allow_path.exists():
        print(f"[!] Allowlist not found: {allow_path}")
        return 2

    url = args.url.strip()
    allowed = load_allowlist(allow_path)
    if url not in allowed:
        print("[!] URL not in allowlist. Add your own profile URL to my_profiles.txt first.")
        return 3

    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme.startswith("http"):
        print("[!] URL must be http/https")
        return 4

    status, headers, html = get_html(url)
    title = title_from_html(html)
    desc = meta_description(html)
    findings = simple_findings(url, headers, html)
    if status == 999:
        findings.append({
            "id": "platform_request_blocked",
            "severity": "info",
            "evidence": "HTTP 999 request denied by platform anti-automation controls",
            "recommendation": "Use manual browser review for this platform and treat automated fetch as limited",
        })

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = re.sub(r"[^a-zA-Z0-9._-]", "_", parsed.netloc + parsed.path)

    report = {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "mode": "self-audit",
        "url": url,
        "status": status,
        "title": title,
        "meta_description": desc,
        "headers_sample": {k: headers[k] for k in ["Content-Security-Policy", "X-Robots-Tag", "Server"] if k in headers},
        "findings": findings,
        "note": "Consent-based self-audit only. Do not use for third-party profile lookup.",
    }

    json_path = outdir / f"{stem}.{stamp}.json"
    md_path = outdir / f"{stem}.{stamp}.md"
    csv_path = outdir / f"{stem}.{stamp}.findings.csv"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    md_lines = [
        f"# Self-OSINT Audit\n",
        f"- Generated: {report['generated_at']}",
        f"- URL: {url}",
        f"- HTTP status: {status}",
        f"- Title: {title}",
        "",
        "## Findings",
    ]
    if findings:
        for f in findings:
            md_lines.append(f"- [{f['severity'].upper()}] {f['id']}: {f['evidence']}")
            md_lines.append(f"  - Recommendation: {f['recommendation']}")
    else:
        md_lines.append("- No findings generated.")

    md_lines += ["", "## Guardrail", "- This mode is allowlist-only for your own profiles."]
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    csv_rows = [{"url": url, **f} for f in findings]
    to_csv(csv_path, csv_rows)

    print(f"[+] JSON: {json_path}")
    print(f"[+] Markdown: {md_path}")
    print(f"[+] CSV: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
