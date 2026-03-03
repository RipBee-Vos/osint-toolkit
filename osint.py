#!/usr/bin/env python3
"""
Ethical OSINT Toolkit (authorized use only)

- Passive recon only
- Scope-restricted (targets must be in scope file)
- Outputs JSON + Markdown summary
"""

from __future__ import annotations
import argparse
import datetime as dt
import json
import re
import socket
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path

USER_AGENT = "Ethical-OSINT-Toolkit/1.0"
CRT_SH = "https://crt.sh/?q={query}&output=json"
RDAP_HINT = "https://rdap.org/domain/{domain}"


def http_get(url: str, timeout: int = 12) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def load_scope(scope_file: Path) -> set[str]:
    allowed = set()
    for line in scope_file.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        allowed.add(line)
    return allowed


def is_in_scope(target: str, scope: set[str]) -> bool:
    t = target.lower().strip()
    if t in scope:
        return True
    # allow subdomains when root domain is in scope
    return any(t == s or t.endswith("." + s) for s in scope)


def dns_lookup(domain: str) -> dict:
    out = {"A": [], "AAAA": [], "NS": [], "MX": [], "TXT": []}

    try:
        infos = socket.getaddrinfo(domain, None)
        for item in infos:
            addr = item[4][0]
            if ":" in addr:
                out["AAAA"].append(addr)
            else:
                out["A"].append(addr)
    except Exception:
        pass

    # NS / MX / TXT via DNS-over-HTTPS (Google)
    for rtype in ["NS", "MX", "TXT"]:
        try:
            url = f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type={rtype}"
            data = json.loads(http_get(url))
            for ans in data.get("Answer", []):
                out[rtype].append(ans.get("data", ""))
        except Exception:
            pass

    for k in out:
        out[k] = sorted(set(out[k]))
    return out


def rdap_lookup(domain: str) -> dict:
    out = {"source": RDAP_HINT.format(domain=domain), "status": "unknown", "raw": None}
    try:
        data = json.loads(http_get(out["source"]))
        out["status"] = "ok"
        out["raw"] = {
            "ldhName": data.get("ldhName"),
            "status": data.get("status"),
            "events": data.get("events"),
            "nameservers": data.get("nameservers"),
        }
    except Exception as e:
        out["status"] = f"error: {e}"
    return out


def passive_subdomains(domain: str, max_items: int = 100) -> list[str]:
    query = urllib.parse.quote(f"%.{domain}")
    url = CRT_SH.format(query=query)
    found = set()
    try:
        raw = http_get(url)
        data = json.loads(raw)
        for row in data:
            name_val = row.get("name_value", "")
            for candidate in name_val.splitlines():
                c = candidate.strip().lower().replace("*.", "")
                if c.endswith("." + domain) or c == domain:
                    found.add(c)
    except Exception:
        return []
    return sorted(found)[:max_items]


def http_fingerprint(host: str) -> dict:
    result = {"url": None, "status": None, "headers": {}, "title": None, "tls": {}}
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=10) as r:
                html = r.read(250000).decode("utf-8", errors="replace")
                result["url"] = url
                result["status"] = r.status
                result["headers"] = dict(r.headers)
                m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
                if m:
                    result["title"] = re.sub(r"\s+", " ", m.group(1)).strip()
                break
        except Exception:
            continue

    # TLS metadata
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["tls"] = {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "subjectAltName": cert.get("subjectAltName"),
                }
    except Exception:
        pass

    return result


def build_markdown(report: dict) -> str:
    lines = []
    lines.append(f"# OSINT Report: {report['target']}")
    lines.append("")
    lines.append(f"- Generated: {report['generated_at']}")
    lines.append(f"- Scope check: {report['scope_check']}")
    lines.append("")
    lines.append("## DNS")
    for k, v in report["dns"].items():
        lines.append(f"- {k}: {', '.join(v) if v else 'None'}")
    lines.append("")
    lines.append("## RDAP")
    lines.append(f"- Status: {report['rdap']['status']}")
    lines.append(f"- Source: {report['rdap']['source']}")
    lines.append("")
    lines.append("## Passive Subdomains (crt.sh)")
    subs = report.get("subdomains", [])
    lines.append(f"- Count: {len(subs)}")
    for s in subs[:25]:
        lines.append(f"  - {s}")
    if len(subs) > 25:
        lines.append(f"  - ... (+{len(subs)-25} more)")
    lines.append("")
    lines.append("## HTTP/TLS Fingerprint")
    http = report.get("http", {})
    lines.append(f"- URL: {http.get('url')}")
    lines.append(f"- Status: {http.get('status')}")
    lines.append(f"- Title: {http.get('title')}")
    hdrs = http.get("headers", {})
    for hk in ["Server", "X-Powered-By", "Strict-Transport-Security", "Content-Security-Policy"]:
        if hk in hdrs:
            lines.append(f"- {hk}: {hdrs.get(hk)}")
    lines.append("")
    lines.append("## Ethics & Limits")
    lines.append("- Passive recon only; no exploitation attempted.")
    lines.append("- Data quality may vary by source and time.")
    lines.append("- Use only on assets you are authorized to assess.")
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description="Ethical OSINT toolkit (authorized scope only)")
    p.add_argument("target", help="Domain to assess (e.g., example.com)")
    p.add_argument("--scope", default="scope.txt", help="Path to allowed scope file")
    p.add_argument("--outdir", default="outputs", help="Output directory")
    p.add_argument("--max-subdomains", type=int, default=100)
    args = p.parse_args()

    target = args.target.lower().strip()
    scope_path = Path(args.scope)
    if not scope_path.exists():
        print(f"[!] Scope file not found: {scope_path}", file=sys.stderr)
        return 2

    scope = load_scope(scope_path)
    if not is_in_scope(target, scope):
        print(f"[!] Target '{target}' is out of scope. Update {scope_path} first.", file=sys.stderr)
        return 3

    report = {
        "target": target,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "scope_check": "PASS",
        "dns": dns_lookup(target),
        "rdap": rdap_lookup(target),
        "subdomains": passive_subdomains(target, args.max_subdomains),
        "http": http_fingerprint(target),
    }

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stem = target.replace("*", "wildcard").replace("/", "_")
    json_path = outdir / f"{stem}.json"
    md_path = outdir / f"{stem}.md"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(build_markdown(report), encoding="utf-8")

    print(f"[+] JSON report: {json_path}")
    print(f"[+] Markdown report: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
