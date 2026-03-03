#!/usr/bin/env python3
"""
Ethical OSINT Toolkit (authorized use only)

- Passive recon only
- Scope-restricted (targets must be in scope file)
- Supports allow/deny, wildcard domains, CIDR/IP entries
- Outputs JSON + Markdown + CSV + HTML
- Supports batch mode and delta comparison
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

USER_AGENT = "Ethical-OSINT-Toolkit/1.3"
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
        "allow_domains": set(), "allow_wildcards": set(), "allow_ips": set(), "allow_cidrs": [],
        "deny_domains": set(), "deny_wildcards": set(), "deny_ips": set(), "deny_cidrs": [],
    }
    for raw_line in scope_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        mode, entry = parse_scope_entry(line)
        bucket = "allow" if mode == "allow" else "deny"
        try:
            parsed[f"{bucket}_cidrs"].append(ipaddress.ip_network(entry, strict=False))
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
        for item in socket.getaddrinfo(target, None):
            resolved.add(item[4][0])
    except Exception:
        return False

    for addr in resolved:
        if addr in ips:
            return True
        try:
            if any(ipaddress.ip_address(addr) in n for n in cidrs):
                return True
        except ValueError:
            continue
    return False


def is_in_scope(target: str, scope: dict) -> tuple[bool, str]:
    t = normalize_target(target)
    deny_hit = domain_matches(t, scope["deny_domains"], scope["deny_wildcards"]) or target_in_networks(t, scope["deny_cidrs"], scope["deny_ips"])
    if deny_hit:
        return False, "DENY rule matched"
    allow_hit = domain_matches(t, scope["allow_domains"], scope["allow_wildcards"]) or target_in_networks(t, scope["allow_cidrs"], scope["allow_ips"])
    if allow_hit:
        return True, "ALLOW rule matched"
    return False, "No ALLOW rule matched"


def dns_lookup(domain: str) -> dict:
    out = {"A": [], "AAAA": [], "NS": [], "MX": [], "TXT": []}
    try:
        for item in socket.getaddrinfo(domain, None):
            addr = item[4][0]
            (out["AAAA"] if ":" in addr else out["A"]).append(addr)
    except Exception:
        pass
    for rtype in ["NS", "MX", "TXT"]:
        try:
            data = json.loads(http_get(f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type={rtype}"))
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
        out["raw"] = {"ldhName": data.get("ldhName"), "status": data.get("status"), "events": data.get("events"), "nameservers": data.get("nameservers")}
    except Exception as e:
        out["status"] = f"error: {e}"
    return out


def passive_subdomains(domain: str, max_items: int = 100) -> list[str]:
    found = set()
    try:
        raw = http_get(CRT_SH.format(query=urllib.parse.quote(f"%.{domain}")))
        for row in json.loads(raw):
            for candidate in row.get("name_value", "").splitlines():
                c = candidate.strip().lower().replace("*.", "")
                if c.endswith("." + domain) or c == domain:
                    found.add(c)
    except Exception:
        return []
    return sorted(found)[:max_items]


def http_fingerprint(host: str) -> dict:
    result = {"url": None, "status": None, "headers": {}, "title": None, "tls": {}}
    for scheme in ["https", "http"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}", headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=10) as r:
                html = r.read(250000).decode("utf-8", errors="replace")
                result["url"], result["status"], result["headers"] = f"{scheme}://{host}", r.status, dict(r.headers)
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
                result["tls"] = {"subject": cert.get("subject"), "issuer": cert.get("issuer"), "notBefore": cert.get("notBefore"), "notAfter": cert.get("notAfter"), "subjectAltName": cert.get("subjectAltName")}
    except Exception:
        pass
    return result


def resolve_ips(target: str) -> list[str]:
    if is_ip(target):
        return [target]
    ips = set()
    try:
        for item in socket.getaddrinfo(target, None):
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
    hosts = []
    for ip in ips[:3]:
        try:
            data = json.loads(http_get(SHODAN_HOST_API.format(target=ip, key=urllib.parse.quote(key)), timeout=15))
            hosts.append({"ip": ip, "org": data.get("org"), "os": data.get("os"), "ports": data.get("ports", []), "tags": data.get("tags", [])})
        except Exception as e:
            hosts.append({"ip": ip, "error": str(e)})
    return {"status": "ok", "hosts": hosts}


def censys_enrich(target: str) -> dict:
    api_id, api_secret = os.getenv("CENSYS_API_ID"), os.getenv("CENSYS_API_SECRET")
    if not api_id or not api_secret:
        return {"status": "skipped (no CENSYS_API_ID/CENSYS_API_SECRET)"}
    ips = resolve_ips(target)
    if not ips:
        return {"status": "skipped (no resolvable ip)"}
    import base64
    headers = {"Authorization": f"Basic {base64.b64encode(f'{api_id}:{api_secret}'.encode()).decode()}"}
    hosts = []
    for ip in ips[:3]:
        try:
            data = json.loads(http_get(CENSYS_HOST_API.format(target=ip), timeout=15, headers=headers))
            services = data.get("result", {}).get("services", [])
            hosts.append({"ip": ip, "services_count": len(services), "services_sample": [{"port": s.get("port"), "service_name": s.get("service_name")} for s in services[:10]]})
        except Exception as e:
            hosts.append({"ip": ip, "error": str(e)})
    return {"status": "ok", "hosts": hosts}


def confidence_for_finding(fid: str, report: dict) -> str:
    if fid in {"missing_hsts", "server_banner_exposed", "powered_by_exposed", "http_no_tls"}:
        return "high" if report.get("http", {}).get("headers") or report.get("http", {}).get("url") else "low"
    if fid == "large_subdomain_surface":
        return "medium"
    return "low"


def compute_findings(report: dict) -> list[dict]:
    findings = []
    hdrs = report.get("http", {}).get("headers", {})
    if report.get("http", {}).get("url", "").startswith("http://"):
        findings.append({"id": "http_no_tls", "severity": "medium", "evidence": "Site responded over HTTP", "recommendation": "Prefer HTTPS-only with HSTS"})
    if hdrs and "Strict-Transport-Security" not in hdrs:
        findings.append({"id": "missing_hsts", "severity": "low", "evidence": "HSTS header not observed", "recommendation": "Add Strict-Transport-Security header"})
    if hdrs.get("Server"):
        findings.append({"id": "server_banner_exposed", "severity": "info", "evidence": f"Server header present: {hdrs.get('Server')}", "recommendation": "Reduce banner detail where possible"})
    if hdrs.get("X-Powered-By"):
        findings.append({"id": "powered_by_exposed", "severity": "low", "evidence": f"X-Powered-By present: {hdrs.get('X-Powered-By')}", "recommendation": "Suppress framework/version disclosure"})
    if report.get("subdomains") and len(report["subdomains"]) > 50:
        findings.append({"id": "large_subdomain_surface", "severity": "info", "evidence": f"{len(report['subdomains'])} passive subdomains discovered", "recommendation": "Review external surface and stale DNS entries"})
    for f in findings:
        f["confidence"] = confidence_for_finding(f["id"], report)
    return findings


def compare_findings(current: list[dict], baseline: list[dict]) -> dict:
    ck = {(f["id"], f.get("evidence", "")): f for f in current}
    bk = {(f["id"], f.get("evidence", "")): f for f in baseline}
    new_keys = sorted(set(ck) - set(bk))
    rem_keys = sorted(set(bk) - set(ck))
    return {"new": [ck[k] for k in new_keys], "removed": [bk[k] for k in rem_keys], "changed": []}


def build_markdown(report: dict) -> str:
    lines = [f"# OSINT Report: {report['target']}", "", f"- Generated: {report['generated_at']}", f"- Scope check: {report['scope_check']}", f"- Scope reason: {report.get('scope_reason')}", "", "## Findings"]
    findings = report.get("findings", [])
    if not findings:
        lines.append("- No notable passive findings generated.")
    else:
        for f in findings:
            lines.append(f"- [{f['severity'].upper()}|{f['confidence'].upper()}] {f['id']}: {f['evidence']}")
            lines.append(f"  - Recommendation: {f['recommendation']}")
    delta = report.get("delta")
    if delta:
        lines += ["", "## Delta (vs baseline)", f"- New findings: {len(delta.get('new', []))}", f"- Removed findings: {len(delta.get('removed', []))}"]
    return "\n".join(lines) + "\n"


def build_html(report: dict) -> str:
    badge = {"info": "#6b7280", "low": "#1d4ed8", "medium": "#d97706", "high": "#b91c1c"}
    rows = []
    for f in report.get("findings", []):
        color = badge.get(f["severity"], "#374151")
        rows.append(f"<tr><td><span style='background:{color};color:#fff;padding:2px 8px;border-radius:10px'>{f['severity']}</span></td><td>{f['confidence']}</td><td>{f['id']}</td><td>{f['evidence']}</td><td>{f['recommendation']}</td></tr>")
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>OSINT Report {report['target']}</title></head><body style='font-family:Arial,sans-serif;max-width:1000px;margin:24px auto'>
<h1>OSINT Report: {report['target']}</h1>
<p><b>Generated:</b> {report['generated_at']}<br><b>Scope:</b> {report['scope_check']} ({report.get('scope_reason')})</p>
<h2>Findings</h2>
<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;width:100%'><thead><tr><th>Severity</th><th>Confidence</th><th>ID</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="5">No findings</td></tr>'}</tbody></table>
</body></html>"""


def write_findings_csv(path: Path, target: str, findings: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["target", "id", "severity", "confidence", "evidence", "recommendation"])
        w.writeheader()
        for item in findings:
            w.writerow({"target": target, **item})


def run_target(target: str, args, scope: dict) -> tuple[int, dict | None]:
    in_scope, reason = is_in_scope(target, scope)
    if not in_scope:
        print(f"[!] Target '{target}' is out of scope ({reason}).", file=sys.stderr)
        return 3, None

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
    report["enrichment"] = {"shodan": {"status": "skipped (--no-enrich)"}, "censys": {"status": "skipped (--no-enrich)"}} if args.no_enrich else {"shodan": shodan_enrich(target), "censys": censys_enrich(target)}
    report["findings"] = compute_findings(report)

    if args.baseline_dir:
        base = Path(args.baseline_dir) / f"{target.replace('*','wildcard').replace('/','_').replace(':','_')}.json"
        if base.exists():
            try:
                old = json.loads(base.read_text(encoding="utf-8"))
                report["delta"] = compare_findings(report["findings"], old.get("findings", []))
            except Exception:
                report["delta"] = {"new": [], "removed": [], "changed": []}

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stem = target.replace("*", "wildcard").replace("/", "_").replace(":", "_")

    (outdir / f"{stem}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (outdir / f"{stem}.md").write_text(build_markdown(report), encoding="utf-8")
    (outdir / f"{stem}.html").write_text(build_html(report), encoding="utf-8")
    write_findings_csv(outdir / f"{stem}.findings.csv", target, report["findings"])

    print(f"[+] Wrote reports for {target}")
    return 0, report


def load_targets(args) -> list[str]:
    targets = []
    if args.target:
        targets.append(normalize_target(args.target))
    if args.targets_file:
        for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(normalize_target(line))
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def write_batch_csv(outdir: Path, reports: list[dict]) -> None:
    path = outdir / "batch.findings.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["target", "id", "severity", "confidence", "evidence", "recommendation"])
        w.writeheader()
        for r in reports:
            for item in r.get("findings", []):
                w.writerow({"target": r["target"], **item})


def main() -> int:
    p = argparse.ArgumentParser(description="Ethical OSINT toolkit (authorized scope only)")
    p.add_argument("target", nargs="?", help="Domain/IP/URL to assess")
    p.add_argument("--targets-file", help="File with one target per line")
    p.add_argument("--scope", default="scope.txt", help="Path to allowed scope file")
    p.add_argument("--outdir", default="outputs", help="Output directory")
    p.add_argument("--baseline-dir", help="Previous outputs dir for delta mode")
    p.add_argument("--max-subdomains", type=int, default=100)
    p.add_argument("--no-enrich", action="store_true", help="Skip Shodan/Censys enrichment")
    args = p.parse_args()

    if not args.target and not args.targets_file:
        print("[!] Provide target or --targets-file", file=sys.stderr)
        return 2

    scope_path = Path(args.scope)
    if not scope_path.exists():
        print(f"[!] Scope file not found: {scope_path}", file=sys.stderr)
        return 2
    scope = load_scope(scope_path)

    targets = load_targets(args)
    reports, failed = [], 0
    for t in targets:
        rc, report = run_target(t, args, scope)
        if rc == 0 and report:
            reports.append(report)
        else:
            failed += 1

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    if len(reports) > 1:
        write_batch_csv(outdir, reports)
        print(f"[+] Batch CSV: {outdir / 'batch.findings.csv'}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
