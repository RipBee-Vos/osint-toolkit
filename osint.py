#!/usr/bin/env python3
"""
Ethical OSINT Toolkit (authorized use only)

- Passive recon only
- Scope-restricted (targets must be in scope file)
- Supports allow/deny, wildcard domains, CIDR/IP entries
- Outputs JSON + Markdown + CSV summary
"""

from __future__ import annotations
import argparse
import csv
import datetime as dt
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path

USER_AGENT = "Ethical-OSINT-Toolkit/1.2"
CRT_SH = "https://crt.sh/?q={query}&output=json"
RDAP_HINT = "https://rdap.org/domain/{domain}"
SHODAN_HOST_API = "https://api.shodan.io/shodan/host/{target}?key={key}"
CENSYS_HOST_API = "https://search.censys.io/api/v2/hosts/{target}"


def http_get(url: str, timeout: int = 12, headers: dict | None = None) -> str:
    hdr = {"User-Agent": USER_AGENT}
    if headers:
        hdr.update(headers)
    req = urllib.request.Request(url, headers=hdr)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def normalize_target(value: str) -> str:
    v = value.strip().lower()
    if "://" in v:
        v = urllib.parse.urlparse(v).hostname or v
    return v.rstrip(".")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_scope_entry(line: str) -> tuple[str, str]:
    entry = line.strip().lower()
    mode = "allow"
    if entry.startswith("allow:"):
        entry = entry.split(":", 1)[1].strip()
    elif entry.startswith("deny:"):
        mode = "deny"
        entry = entry.split(":", 1)[1].strip()
    return mode, entry


def load_scope(scope_file: Path) -> dict:
    parsed = {
        "allow_domains": set(),
        "allow_wildcards": set(),
        "allow_ips": set(),
        "allow_cidrs": [],
        "deny_domains": set(),
        "deny_wildcards": set(),
        "deny_ips": set(),
        "deny_cidrs": [],
        "raw": [],
    }

    for raw_line in scope_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        mode, entry = parse_scope_entry(line)
        bucket = "allow" if mode == "allow" else "deny"
        parsed["raw"].append({"mode": bucket, "entry": entry})

        try:
            net = ipaddress.ip_network(entry, strict=False)
            parsed[f"{bucket}_cidrs"].append(net)
            continue
        except ValueError:
            pass

        if is_ip(entry):
            parsed[f"{bucket}_ips"].add(entry)
            continue

        if entry.startswith("*."):
            parsed[f"{bucket}_wildcards"].add(entry[2:])
        else:
            parsed[f"{bucket}_domains"].add(entry)

    return parsed


def domain_matches(host: str, domains: set[str], wildcards: set[str]) -> bool:
    if host in domains:
        return True
    if any(host == d or host.endswith("." + d) for d in domains):
        return True
    if any(host.endswith("." + w) for w in wildcards):
        return True
    return False


def target_in_networks(target: str, cidrs, ips: set[str]) -> bool:
    if is_ip(target):
        if target in ips:
            return True
        ip_obj = ipaddress.ip_address(target)
        return any(ip_obj in n for n in cidrs)

    resolved = set()
    try:
        infos = socket.getaddrinfo(target, None)
        for item in infos:
            resolved.add(item[4][0])
    except Exception:
        return False

    for addr in resolved:
        if addr in ips:
            return True
        try:
            ip_obj = ipaddress.ip_address(addr)
            if any(ip_obj in n for n in cidrs):
                return True
        except ValueError:
            continue
    return False


def is_in_scope(target: str, scope: dict) -> tuple[bool, str]:
    t = normalize_target(target)

    deny_hit = (
        domain_matches(t, scope["deny_domains"], scope["deny_wildcards"])
        or target_in_networks(t, scope["deny_cidrs"], scope["deny_ips"])
    )
    if deny_hit:
        return False, "DENY rule matched"

    allow_hit = (
        domain_matches(t, scope["allow_domains"], scope["allow_wildcards"])
        or target_in_networks(t, scope["allow_cidrs"], scope["allow_ips"])
    )
    if allow_hit:
        return True, "ALLOW rule matched"

    return False, "No ALLOW rule matched"


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


def resolve_ips(target: str) -> list[str]:
    if is_ip(target):
        return [target]
    ips = set()
    try:
        infos = socket.getaddrinfo(target, None)
        for item in infos:
            ips.add(item[4][0])
    except Exception:
        pass
    return sorted(ips)


def shodan_enrich(target: str) -> dict:
    key = os.getenv("SHODAN_API_KEY")
    if not key:
        return {"status": "skipped (no SHODAN_API_KEY)"}

    ips = resolve_ips(target)
    if not ips:
        return {"status": "skipped (no resolvable ip)"}

    results = []
    for ip in ips[:3]:
        try:
            url = SHODAN_HOST_API.format(target=ip, key=urllib.parse.quote(key))
            data = json.loads(http_get(url, timeout=15))
            results.append(
                {
                    "ip": ip,
                    "org": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "tags": data.get("tags", []),
                }
            )
        except Exception as e:
            results.append({"ip": ip, "error": str(e)})
    return {"status": "ok", "hosts": results}


def censys_enrich(target: str) -> dict:
    api_id = os.getenv("CENSYS_API_ID")
    api_secret = os.getenv("CENSYS_API_SECRET")
    if not api_id or not api_secret:
        return {"status": "skipped (no CENSYS_API_ID/CENSYS_API_SECRET)"}

    ips = resolve_ips(target)
    if not ips:
        return {"status": "skipped (no resolvable ip)"}

    basic = f"{api_id}:{api_secret}".encode("utf-8")
    import base64

    auth = base64.b64encode(basic).decode("utf-8")
    headers = {"Authorization": f"Basic {auth}"}

    results = []
    for ip in ips[:3]:
        try:
            url = CENSYS_HOST_API.format(target=ip)
            data = json.loads(http_get(url, timeout=15, headers=headers))
            d = data.get("result", {})
            services = d.get("services", [])
            results.append(
                {
                    "ip": ip,
                    "services_count": len(services),
                    "services_sample": [
                        {"port": s.get("port"), "service_name": s.get("service_name")}
                        for s in services[:10]
                    ],
                }
            )
        except Exception as e:
            results.append({"ip": ip, "error": str(e)})
    return {"status": "ok", "hosts": results}


def compute_findings(report: dict) -> list[dict]:
    findings = []
    hdrs = report.get("http", {}).get("headers", {})

    if report.get("http", {}).get("url", "").startswith("http://"):
        findings.append(
            {
                "id": "http_no_tls",
                "severity": "medium",
                "evidence": "Site responded over HTTP",
                "recommendation": "Prefer HTTPS-only with HSTS",
            }
        )

    if hdrs and "Strict-Transport-Security" not in hdrs:
        findings.append(
            {
                "id": "missing_hsts",
                "severity": "low",
                "evidence": "HSTS header not observed",
                "recommendation": "Add Strict-Transport-Security header",
            }
        )

    if hdrs.get("Server"):
        findings.append(
            {
                "id": "server_banner_exposed",
                "severity": "info",
                "evidence": f"Server header present: {hdrs.get('Server')}",
                "recommendation": "Reduce banner detail where possible",
            }
        )

    if hdrs.get("X-Powered-By"):
        findings.append(
            {
                "id": "powered_by_exposed",
                "severity": "low",
                "evidence": f"X-Powered-By present: {hdrs.get('X-Powered-By')}",
                "recommendation": "Suppress framework/version disclosure",
            }
        )

    if report.get("subdomains") and len(report["subdomains"]) > 50:
        findings.append(
            {
                "id": "large_subdomain_surface",
                "severity": "info",
                "evidence": f"{len(report['subdomains'])} passive subdomains discovered",
                "recommendation": "Review external attack surface and stale DNS entries",
            }
        )

    return findings


def build_markdown(report: dict) -> str:
    lines = []
    lines.append(f"# OSINT Report: {report['target']}")
    lines.append("")
    lines.append(f"- Generated: {report['generated_at']}")
    lines.append(f"- Scope check: {report['scope_check']}")
    lines.append(f"- Scope reason: {report.get('scope_reason')}")
    lines.append("")

    lines.append("## Findings")
    findings = report.get("findings", [])
    if not findings:
        lines.append("- No notable passive findings generated.")
    else:
        for f in findings:
            lines.append(f"- [{f['severity'].upper()}] {f['id']}: {f['evidence']}")
            lines.append(f"  - Recommendation: {f['recommendation']}")
    lines.append("")

    lines.append("## DNS")
    for k, v in report.get("dns", {}).items():
        lines.append(f"- {k}: {', '.join(v) if v else 'None'}")
    lines.append("")

    lines.append("## RDAP")
    lines.append(f"- Status: {report.get('rdap', {}).get('status')}")
    lines.append(f"- Source: {report.get('rdap', {}).get('source')}")
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

    lines.append("## Enrichment")
    lines.append(f"- Shodan: {report.get('enrichment', {}).get('shodan', {}).get('status')}")
    lines.append(f"- Censys: {report.get('enrichment', {}).get('censys', {}).get('status')}")
    lines.append("")

    lines.append("## Ethics & Limits")
    lines.append("- Passive recon only; no exploitation attempted.")
    lines.append("- Data quality may vary by source and time.")
    lines.append("- Use only on assets you are authorized to assess.")
    return "\n".join(lines) + "\n"


def write_findings_csv(path: Path, target: str, findings: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["target", "id", "severity", "evidence", "recommendation"])
        w.writeheader()
        for item in findings:
            row = {"target": target, **item}
            w.writerow(row)


def main() -> int:
    p = argparse.ArgumentParser(description="Ethical OSINT toolkit (authorized scope only)")
    p.add_argument("target", help="Domain/IP/URL to assess")
    p.add_argument("--scope", default="scope.txt", help="Path to allowed scope file")
    p.add_argument("--outdir", default="outputs", help="Output directory")
    p.add_argument("--max-subdomains", type=int, default=100)
    p.add_argument("--no-enrich", action="store_true", help="Skip Shodan/Censys enrichment")
    args = p.parse_args()

    target = normalize_target(args.target)
    scope_path = Path(args.scope)
    if not scope_path.exists():
        print(f"[!] Scope file not found: {scope_path}", file=sys.stderr)
        return 2

    scope = load_scope(scope_path)
    in_scope, reason = is_in_scope(target, scope)
    if not in_scope:
        print(f"[!] Target '{target}' is out of scope ({reason}). Update {scope_path} first.", file=sys.stderr)
        return 3

    report = {
        "target": target,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "scope_check": "PASS",
        "scope_reason": reason,
        "dns": dns_lookup(target) if not is_ip(target) else {},
        "rdap": rdap_lookup(target) if not is_ip(target) else {"status": "skipped (ip target)", "source": None, "raw": None},
        "subdomains": passive_subdomains(target, args.max_subdomains) if not is_ip(target) else [],
        "http": http_fingerprint(target),
    }

    if args.no_enrich:
        enrichment = {
            "shodan": {"status": "skipped (--no-enrich)"},
            "censys": {"status": "skipped (--no-enrich)"},
        }
    else:
        enrichment = {
            "shodan": shodan_enrich(target),
            "censys": censys_enrich(target),
        }

    report["enrichment"] = enrichment
    report["findings"] = compute_findings(report)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stem = target.replace("*", "wildcard").replace("/", "_").replace(":", "_")
    json_path = outdir / f"{stem}.json"
    md_path = outdir / f"{stem}.md"
    csv_path = outdir / f"{stem}.findings.csv"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(build_markdown(report), encoding="utf-8")
    write_findings_csv(csv_path, target, report["findings"])

    print(f"[+] JSON report: {json_path}")
    print(f"[+] Markdown report: {md_path}")
    print(f"[+] Findings CSV: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
