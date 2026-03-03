#!/usr/bin/env python3
"""
Ethical OSINT Toolkit (authorized use only)

- Passive recon only (domain mode)
- Scope-restricted for domain/IP targets (targets must be in scope file)
- Supports allow/deny, wildcard domains, CIDR/IP entries
- Outputs JSON + Markdown + CSV + HTML
- Supports batch mode and delta comparison

GUI support:
- --target-kind: domain|person|username|email
- --target-details: path to JSON file with extra target context

PERSON/USERNAME/EMAIL modes are "seed + pivots" only:
- No scraping
- No automated collection from social networks
- Generates validation results, canonical URLs, and search pivots for manual use
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
import urllib.error
from pathlib import Path

USER_AGENT = "Ethical-OSINT-Toolkit/1.5"
REPORT_VERSION = "1.1"
TOOL_NAME = "Ethical OSINT Toolkit"
CRT_SH = "https://crt.sh/?q={query}&output=json"
RDAP_HINT = "https://rdap.org/domain/{domain}"
SHODAN_HOST_API = "https://api.shodan.io/shodan/host/{target}?key={key}"
CENSYS_HOST_API = "https://search.censys.io/api/v2/hosts/{target}"

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}$")
E164_LIKE_RE = re.compile(r"^\+?[0-9][0-9\-\s().]{6,}$")
URL_RE = re.compile(r"^https?://", re.I)
DOMAIN_LIKE_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)

HANDLE_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
GITHUB_RE = re.compile(r"^[A-Za-z0-9-]{1,39}$")
REDDIT_RE = re.compile(r"^[A-Za-z0-9_-]{3,20}$")

# ---------------------------
# Pivot/search helpers
# ---------------------------

SEARCH_ENGINES = {
    "google": "https://www.google.com/search?q={q}",
    "bing": "https://www.bing.com/search?q={q}",
    "duckduckgo": "https://duckduckgo.com/?q={q}",
}

DATA_BROKER_SITES = [
    "whitepages.com",
    "spokeo.com",
    "beenverified.com",
    "intelius.com",
    "radaris.com",
    "mylife.com",
    "truthfinder.com",
    "fastpeoplesearch.com",
    "peoplefinders.com",
]

PUBLIC_RECORDS_SITES = [
    "opencorporates.com",
    "sec.gov",
    "justia.com",
    "courtlistener.com",
    "patents.google.com",
]

CODE_REPO_SITES = [
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "pypi.org",
    "npmjs.com",
]

MEDIA_SITES = [
    "news.google.com",
    "medium.com",
    "substack.com",
    "stackoverflow.com",
    "reddit.com",
]


def _engine_links(query: str) -> dict:
    q = urllib.parse.quote((query or "").strip())
    return {k: v.format(q=q) for k, v in SEARCH_ENGINES.items()} if q else {}


def _pivot(category: str, label: str, query: str, basis: list[str] | None = None) -> dict:
    query = (query or "").strip()
    return {
        "category": category,
        "label": label,
        "query": query,
        "links": _engine_links(query),
        "basis": basis or [],
    }


def _nonempty_str_list(v: object, limit: int = 50) -> list[str]:
    if not isinstance(v, list):
        return []
    out = []
    for item in v:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        if len(out) >= limit:
            break
    return out


def identity_confidence(details: dict) -> dict:
    """
    Heuristic seed-quality score (0-100). This does NOT assert identity.
    It estimates how strong your seeds are for manual pivoting.
    """
    name = (details.get("name") or "").strip()
    aliases = _nonempty_str_list(details.get("aliases"), 25)

    loc = details.get("location") or {}
    city = (loc.get("city") or "").strip()
    state = (loc.get("state_region") or "").strip()
    country = (loc.get("country") or "").strip()

    usernames = _nonempty_str_list(details.get("usernames"), 25)
    emails = _nonempty_str_list(details.get("emails"), 25)
    phones = _nonempty_str_list(details.get("phones"), 25)

    social = details.get("social") or {}
    social_count = 0
    if isinstance(social, dict):
        social_count = sum(1 for _, v in social.items() if isinstance(v, str) and v.strip())

    score = 0
    reasons: list[str] = []

    if name:
        score += 20
        reasons.append("Name present (+20)")
    if aliases:
        add = min(10, 2 * len(aliases))
        score += add
        reasons.append(f"Aliases present (+{add})")
    if any([city, state, country]):
        score += 10
        reasons.append("Location present (+10)")
    if usernames:
        add = min(20, 3 * len(usernames))
        score += add
        reasons.append(f"Usernames present (+{add})")
    if emails:
        add = min(20, 5 * len(emails))
        score += add
        reasons.append(f"Emails present (+{add})")
    if phones:
        add = min(10, 5 * len(phones))
        score += add
        reasons.append(f"Phones present (+{add})")
    if social_count:
        add = min(10, 2 * social_count)
        score += add
        reasons.append(f"Explicit social fields present (+{add})")

    score = max(0, min(100, score))

    band = "low"
    if score >= 70:
        band = "high"
    elif score >= 40:
        band = "medium"

    return {
        "score": score,
        "band": band,
        "reasons": reasons,
        "note": "This reflects seed richness for manual OSINT pivoting, not a verified identity match.",
    }


def export_pivots(outdir: Path, stem: str, pivots: list[dict]) -> None:
    """
    Writes:
      - <stem>.pivots.json
      - <stem>.pivots.csv
      - <stem>.pivots.txt   (one query per line)
    """
    if not pivots:
        return

    payload = {"pivots": pivots}
    (outdir / f"{stem}.pivots.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    with (outdir / f"{stem}.pivots.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["category", "label", "query", "google", "bing", "duckduckgo", "basis"],
        )
        w.writeheader()
        for it in pivots:
            links = it.get("links") or {}
            w.writerow(
                {
                    "category": it.get("category", ""),
                    "label": it.get("label", ""),
                    "query": it.get("query", ""),
                    "google": links.get("google", ""),
                    "bing": links.get("bing", ""),
                    "duckduckgo": links.get("duckduckgo", ""),
                    "basis": ",".join(it.get("basis") or []),
                }
            )

    lines = [(it.get("query") or "").strip() for it in pivots if (it.get("query") or "").strip()]
    (outdir / f"{stem}.pivots.txt").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def http_get(url: str, timeout: int = 12, headers: dict | None = None) -> dict:
    hdr = {"User-Agent": USER_AGENT}
    if headers:
        hdr.update(headers)
    req = urllib.request.Request(url, headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {
                "ok": True,
                "url": url,
                "status": getattr(r, "status", None),
                "text": r.read().decode("utf-8", errors="replace"),
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        return {
            "ok": False,
            "url": url,
            "status": exc.code,
            "text": exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else "",
            "error": {"type": "http_error", "message": f"HTTP {exc.code}"},
        }
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, socket.timeout):
            err_type = "timeout"
            msg = "request timed out"
        elif isinstance(reason, socket.gaierror):
            err_type = "dns_error"
            msg = f"dns failure: {reason}"
        else:
            err_type = "network_error"
            msg = str(reason)
        return {
            "ok": False,
            "url": url,
            "status": None,
            "text": "",
            "error": {"type": err_type, "message": msg},
        }
    except socket.timeout:
        return {
            "ok": False,
            "url": url,
            "status": None,
            "text": "",
            "error": {"type": "timeout", "message": "request timed out"},
        }
    except Exception as exc:
        return {
            "ok": False,
            "url": url,
            "status": None,
            "text": "",
            "error": {"type": "unknown_error", "message": str(exc)},
        }


def normalize_target(value: str) -> str:
    v = (value or "").strip().lower()
    if "://" in v:
        v = urllib.parse.urlparse(v).hostname or v
    return v.rstrip(".")


def normalize_domain_for_match(value: str) -> str:
    v = normalize_target(value)
    if v.startswith("*."):
        v = v[2:]
    return v.rstrip(".")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------
# Scope logic (domain/ip mode)
# ---------------------------

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
    }
    for raw_line in scope_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        mode, entry = parse_scope_entry(line)
        entry = normalize_domain_for_match(entry)
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
    """Return True when host matches configured domain scope rules.

    Semantics:
    - "example.com" matches "example.com" and any subdomain.
    - "*.example.com" also matches "example.com" and any subdomain.
    - Trailing dots are ignored during matching.
    """
    host_n = normalize_domain_for_match(host)
    if not host_n:
        return False

    norm_domains = {normalize_domain_for_match(d) for d in domains if d}
    norm_wildcards = {normalize_domain_for_match(w) for w in wildcards if w}

    if any(host_n == d or host_n.endswith("." + d) for d in norm_domains):
        return True
    if any(host_n == w or host_n.endswith("." + w) for w in norm_wildcards):
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
    deny_hit = domain_matches(t, scope["deny_domains"], scope["deny_wildcards"]) or target_in_networks(
        t, scope["deny_cidrs"], scope["deny_ips"]
    )
    if deny_hit:
        return False, "DENY rule matched"
    allow_hit = domain_matches(t, scope["allow_domains"], scope["allow_wildcards"]) or target_in_networks(
        t, scope["allow_cidrs"], scope["allow_ips"]
    )
    if allow_hit:
        return True, "ALLOW rule matched"
    return False, "No ALLOW rule matched"


# ---------------------------
# Domain recon (existing)
# ---------------------------

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
            resp = http_get(f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type={rtype}")
            if not resp.get("ok"):
                continue
            data = json.loads(resp.get("text") or "{}")
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
        resp = http_get(out["source"])
        if not resp.get("ok"):
            err = resp.get("error") or {}
            out["status"] = f"error: {err.get('type','request_failed')} ({err.get('message','unknown')})"
            return out
        data = json.loads(resp.get("text") or "{}")
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
    found = set()
    try:
        resp = http_get(CRT_SH.format(query=urllib.parse.quote(f"%.{domain}")))
        if not resp.get("ok"):
            return []
        for row in json.loads(resp.get("text") or "[]"):
            for candidate in row.get("name_value", "").splitlines():
                c = candidate.strip().lower().replace("*.", "")
                if c.endswith("." + domain) or c == domain:
                    found.add(c)
    except Exception:
        return []
    return sorted(found)[:max_items]


def http_fingerprint(host: str) -> dict:
    result = {"url": None, "status": None, "headers": {}, "title": None, "tls": {"status": "skipped: https request did not succeed"}}
    https_ok = False
    for scheme in ["https", "http"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}", headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=10) as r:
                html_doc = r.read(250000).decode("utf-8", errors="replace")
                result["url"], result["status"], result["headers"] = f"{scheme}://{host}", r.status, dict(r.headers)
                m = re.search(r"<title[^>]*>(.*?)</title>", html_doc, re.I | re.S)
                if m:
                    result["title"] = re.sub(r"\s+", " ", m.group(1)).strip()
                if scheme == "https":
                    https_ok = True
                break
        except Exception:
            continue

    if not https_ok:
        return result

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["tls"] = {
                    "status": "ok",
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "subjectAltName": cert.get("subjectAltName"),
                }
    except Exception as exc:
        result["tls"] = {"status": f"error: {exc}"}
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
            resp = http_get(SHODAN_HOST_API.format(target=ip, key=urllib.parse.quote(key)), timeout=15)
            if not resp.get("ok"):
                err = resp.get("error") or {}
                hosts.append({"ip": ip, "error": f"{err.get('type','request_failed')}: {err.get('message','unknown')}"})
                continue
            data = json.loads(resp.get("text") or "{}")
            hosts.append(
                {
                    "ip": ip,
                    "org": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "tags": data.get("tags", []),
                }
            )
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
            resp = http_get(CENSYS_HOST_API.format(target=ip), timeout=15, headers=headers)
            if not resp.get("ok"):
                err = resp.get("error") or {}
                hosts.append({"ip": ip, "error": f"{err.get('type','request_failed')}: {err.get('message','unknown')}"})
                continue
            data = json.loads(resp.get("text") or "{}")
            services = data.get("result", {}).get("services", [])
            hosts.append(
                {
                    "ip": ip,
                    "services_count": len(services),
                    "services_sample": [{"port": s.get("port"), "service_name": s.get("service_name")} for s in services[:10]],
                }
            )
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
    if (report.get("http", {}).get("url") or "").startswith("http://"):
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


# ---------------------------
# Seed + pivots (person mode)
# ---------------------------

def _strip_handle(v: str) -> str:
    v = (v or "").strip()
    if v.startswith("@"):
        v = v[1:]
    return v


def validate_email(email: str) -> dict:
    e = (email or "").strip()
    if not e:
        return {"ok": False, "reason": "empty"}
    if not EMAIL_RE.match(e):
        return {"ok": False, "reason": "format"}
    domain = e.split("@", 1)[1].lower()
    if not DOMAIN_LIKE_RE.match(domain):
        return {"ok": False, "reason": "domain looks invalid"}
    return {"ok": True, "reason": "ok"}


def validate_phone(phone: str) -> dict:
    p = (phone or "").strip()
    if not p:
        return {"ok": False, "reason": "empty"}
    if not E164_LIKE_RE.match(p):
        return {"ok": False, "reason": "format"}
    digits = re.sub(r"\D", "", p)
    if len(digits) < 7 or len(digits) > 15:
        return {"ok": False, "reason": "digit length"}
    return {"ok": True, "reason": "ok"}


def validate_url(url: str) -> dict:
    u = (url or "").strip()
    if not u:
        return {"ok": False, "reason": "empty"}
    if not URL_RE.match(u):
        return {"ok": False, "reason": "must start with http:// or https://"}
    try:
        p = urllib.parse.urlparse(u)
        if not p.scheme or not p.netloc:
            return {"ok": False, "reason": "parse"}
    except Exception:
        return {"ok": False, "reason": "parse"}
    return {"ok": True, "reason": "ok"}


def validate_username(kind: str, handle: str) -> dict:
    h = _strip_handle(handle)
    if not h:
        return {"ok": False, "reason": "empty"}
    if kind == "github":
        if not GITHUB_RE.match(h):
            return {"ok": False, "reason": "github format"}
        return {"ok": True, "reason": "ok"}
    if kind == "reddit":
        if not REDDIT_RE.match(h):
            return {"ok": False, "reason": "reddit format"}
        return {"ok": True, "reason": "ok"}
    if not HANDLE_RE.match(h):
        return {"ok": False, "reason": "format"}
    return {"ok": True, "reason": "ok"}


def _canonical_profiles(details: dict) -> dict:
    social = (details.get("social") or {}).copy()
    usernames = details.get("usernames") or []

    def canon(platform: str, value: str) -> str | None:
        v = (value or "").strip()
        if not v:
            return None
        if URL_RE.match(v):
            return v
        h = _strip_handle(v)
        if platform == "github":
            return f"https://github.com/{h}"
        if platform == "linkedin":
            return f"https://www.linkedin.com/in/{h}"
        if platform == "x":
            return f"https://x.com/{h}"
        if platform == "instagram":
            return f"https://www.instagram.com/{h}/"
        if platform == "tiktok":
            return f"https://www.tiktok.com/@{h}"
        if platform == "facebook":
            return f"https://www.facebook.com/{h}"
        if platform == "reddit":
            h2 = h[2:] if h.lower().startswith("u/") else h
            return f"https://www.reddit.com/user/{h2}/"
        return None

    out: dict[str, object] = {}

    for key in ["linkedin", "github", "x", "facebook", "instagram", "tiktok", "reddit", "website"]:
        v = social.get(key)
        c = canon(key, v) if v else None
        if c:
            out[key] = c

    maybe = []
    for u in usernames[:25]:
        u = _strip_handle(u)
        if not u:
            continue
        maybe.append(
            {
                "handle": u,
                "github": f"https://github.com/{u}",
                "x": f"https://x.com/{u}",
                "reddit": f"https://www.reddit.com/user/{u}/",
                "instagram": f"https://www.instagram.com/{u}/",
            }
        )
    if maybe:
        out["_derived_from_usernames"] = maybe

    return out


def _platform_sites() -> list[tuple[str, str]]:
    return [
        ("LinkedIn", "linkedin.com"),
        ("GitHub", "github.com"),
        ("X", "x.com"),
        ("Twitter legacy", "twitter.com"),
        ("Facebook", "facebook.com"),
        ("Instagram", "instagram.com"),
        ("TikTok", "tiktok.com"),
        ("Reddit", "reddit.com"),
        ("YouTube", "youtube.com"),
        ("Medium", "medium.com"),
        ("StackOverflow", "stackoverflow.com"),
        ("StackExchange", "stackexchange.com"),
        ("Keybase", "keybase.io"),
        ("About.me", "about.me"),
        ("Linktree", "linktr.ee"),
        ("SoundCloud", "soundcloud.com"),
        ("Twitch", "twitch.tv"),
        ("Pinterest", "pinterest.com"),
        ("GitLab", "gitlab.com"),
        ("Bitbucket", "bitbucket.org"),
        ("HackerOne", "hackerone.com"),
        ("Bugcrowd", "bugcrowd.com"),
        ("ResearchGate", "researchgate.net"),
        ("ORCID", "orcid.org"),
        ("Academia", "academia.edu"),
        ("Pastebin", "pastebin.com"),
        ("Flickr", "flickr.com"),
        ("Vimeo", "vimeo.com"),
        ("Slideshare", "slideshare.net"),
        ("Substack", "substack.com"),
    ]


def _build_pivots(details: dict, blanket: bool) -> list[dict]:
    name = (details.get("name") or details.get("target") or "").strip()
    aliases = _nonempty_str_list(details.get("aliases"), 25)
    loc = details.get("location") or {}
    city = (loc.get("city") or "").strip()
    state = (loc.get("state_region") or "").strip()
    country = (loc.get("country") or "").strip()
    usernames = _nonempty_str_list(details.get("usernames"), 25)
    emails = _nonempty_str_list(details.get("emails"), 25)
    phones = _nonempty_str_list(details.get("phones"), 25)
    social = details.get("social") or {}

    where = " ".join([x for x in [city, state, country] if x]).strip()
    pivots: list[dict] = []

    # General
    if name:
        pivots.append(_pivot("general", "Name exact", f"\"{name}\"", basis=["name"]))
        if where:
            pivots.append(_pivot("general", "Name + location", f"\"{name}\" \"{where}\"", basis=["name", "location"]))
        pivots.append(_pivot("general", "Email mentions (manual)", f"\"{name}\" \"@\"", basis=["name"]))

    for a in aliases[:10]:
        pivots.append(_pivot("general", "Alias exact", f"\"{a}\"", basis=["alias"]))
        if where:
            pivots.append(_pivot("general", "Alias + location", f"\"{a}\" \"{where}\"", basis=["alias", "location"]))

    for u in usernames[:20]:
        u2 = _strip_handle(u)
        if not u2:
            continue
        pivots.append(_pivot("general", "Username exact", f"\"{u2}\"", basis=["username"]))

    for e in emails[:15]:
        pivots.append(_pivot("general", "Email exact", f"\"{e}\"", basis=["email"]))
        if blanket:
            pivots.append(
                _pivot(
                    "general",
                    "Email leaks/mentions (manual)",
                    f"\"{e}\" site:pastebin.com OR site:github.com OR site:gitlab.com",
                    basis=["email"],
                )
            )

    for p in phones[:10]:
        pivots.append(_pivot("general", "Phone exact", f"\"{p}\"", basis=["phone"]))

    # Social
    if name:
        pivots.append(_pivot("social", "LinkedIn (name)", f"\"{name}\" site:linkedin.com/in", basis=["name"]))
        pivots.append(_pivot("social", "GitHub (name)", f"\"{name}\" site:github.com", basis=["name"]))
        pivots.append(_pivot("social", "Reddit (name)", f"\"{name}\" site:reddit.com", basis=["name"]))
        pivots.append(_pivot("social", "X/Twitter (name)", f"\"{name}\" site:x.com OR site:twitter.com", basis=["name"]))

        if blanket:
            for label, site in _platform_sites():
                pivots.append(_pivot("social", f"{label} (name)", f"\"{name}\" site:{site}", basis=["name"]))
                if where:
                    pivots.append(_pivot("social", f"{label} (name+where)", f"\"{name}\" \"{where}\" site:{site}", basis=["name", "location"]))

    for u in usernames[:20]:
        u2 = _strip_handle(u)
        if not u2:
            continue
        pivots.append(_pivot("social", "Username + GitHub", f"\"{u2}\" site:github.com", basis=["username"]))
        pivots.append(_pivot("social", "Username + LinkedIn", f"\"{u2}\" site:linkedin.com", basis=["username"]))
        pivots.append(_pivot("social", "Username + Reddit", f"\"{u2}\" site:reddit.com", basis=["username"]))
        pivots.append(_pivot("social", "Username + X/Twitter", f"\"{u2}\" site:x.com OR site:twitter.com", basis=["username"]))

        if blanket:
            for label, site in _platform_sites():
                pivots.append(_pivot("social", f"{label} (username)", f"\"{u2}\" site:{site}", basis=["username"]))

    # Provided socials -> treat as general pivots (manual validation)
    if isinstance(social, dict):
        for k, v in social.items():
            if not v:
                continue
            if isinstance(v, str) and v.strip():
                pivots.append(_pivot("social", f"Provided social ({k})", f"\"{v.strip()}\"", basis=["provided_link"]))
            if isinstance(v, list):
                for item in v[:10]:
                    if isinstance(item, str) and item.strip():
                        pivots.append(_pivot("social", f"Provided social ({k})", f"\"{item.strip()}\"", basis=["provided_link"]))

    # Brokers (manual)
    if name:
        for site in DATA_BROKER_SITES:
            if where:
                pivots.append(_pivot("brokers", f"Broker search ({site})", f"\"{name}\" \"{where}\" site:{site}", basis=["name", "location"]))
            else:
                pivots.append(_pivot("brokers", f"Broker search ({site})", f"\"{name}\" site:{site}", basis=["name"]))

    # Public records (manual)
    if name:
        for site in PUBLIC_RECORDS_SITES:
            q = f"\"{name}\" site:{site}"
            if where:
                q = f"\"{name}\" \"{where}\" site:{site}"
            pivots.append(_pivot("public_records", f"Public records ({site})", q, basis=["name", "location"] if where else ["name"]))

    # Code repos (manual)
    if name:
        pivots.append(_pivot("code_repos", "Code mentions (name) on GitHub", f"\"{name}\" site:github.com", basis=["name"]))
    for u in usernames[:20]:
        u2 = _strip_handle(u)
        if not u2:
            continue
        for site in CODE_REPO_SITES:
            pivots.append(_pivot("code_repos", f"Handle on {site}", f"\"{u2}\" site:{site}", basis=["username"]))

    # Media mentions (manual)
    if name:
        for site in MEDIA_SITES:
            q = f"\"{name}\" site:{site}"
            if where:
                q = f"\"{name}\" \"{where}\" site:{site}"
            pivots.append(_pivot("media_mentions", f"Mentions ({site})", q, basis=["name", "location"] if where else ["name"]))

    # Extra blanket pivots (general)
    if blanket and name:
        pivots.append(_pivot("general", "Profile directory pivot", f"\"{name}\" \"profile\" \"about\"", basis=["name"]))
        pivots.append(_pivot("general", "Resume/CV pivot", f"\"{name}\" (resume OR cv OR \"curriculum vitae\")", basis=["name"]))
        pivots.append(_pivot("general", "Email domain pivot (manual)", f"\"{name}\" \"@\" \"mail\"", basis=["name"]))

    # Deduplicate by query
    seen = set()
    uniq = []
    for it in pivots:
        q = (it.get("query") or "").strip()
        if q and q not in seen:
            seen.add(q)
            uniq.append(it)
    return uniq


def _seed_findings_from_validation(validation: dict) -> list[dict]:
    findings = []

    def add(sev: str, fid: str, evidence: str, rec: str) -> None:
        findings.append({"id": fid, "severity": sev, "confidence": "high", "evidence": evidence, "recommendation": rec})

    for e, res in (validation.get("emails") or {}).items():
        if not res.get("ok"):
            add("low", "invalid_email", f"Email seed looks invalid: {e} ({res.get('reason')})", "Fix the seed or remove it.")
    for p, res in (validation.get("phones") or {}).items():
        if not res.get("ok"):
            add("low", "invalid_phone", f"Phone seed looks invalid: {p} ({res.get('reason')})", "Fix the seed or remove it.")
    for u, res in (validation.get("usernames_generic") or {}).items():
        if not res.get("ok"):
            add("info", "odd_username", f"Username seed looks unusual: {u} ({res.get('reason')})", "Double-check the handle format.")
    for k, res in (validation.get("urls") or {}).items():
        if not res.get("ok"):
            add("low", "invalid_url", f"URL seed looks invalid for {k}: {res.get('reason')}", "Fix the URL to include http(s):// and a valid host.")

    return findings


def build_seed_report(target: str, args, run_id: str) -> dict:
    details = getattr(args, "target_details_data", {}) or {}
    details.setdefault("target_kind", getattr(args, "target_kind", "person"))
    details.setdefault("target", target)

    emails = details.get("emails") or []
    phones = details.get("phones") or []
    usernames = details.get("usernames") or []
    social = details.get("social") or {}

    validation = {
        "emails": {e: validate_email(e) for e in emails[:50] if isinstance(e, str) and e.strip()},
        "phones": {p: validate_phone(p) for p in phones[:50] if isinstance(p, str) and p.strip()},
        "usernames_generic": {u: validate_username("generic", u) for u in usernames[:50] if isinstance(u, str) and u.strip()},
        "urls": {},
        "usernames_platform": {},
    }

    for key in ["linkedin", "github", "x", "facebook", "instagram", "tiktok", "reddit", "website"]:
        v = social.get(key)
        if not v:
            continue
        if isinstance(v, str) and v.strip():
            if URL_RE.match(v.strip()):
                validation["urls"][key] = validate_url(v.strip())
            else:
                platform = key if key in {"github", "reddit"} else "generic"
                validation["usernames_platform"][f"{key}:{v.strip()}"] = validate_username(platform, v.strip())

    canonical = _canonical_profiles(details)
    pivots = _build_pivots(details, blanket=getattr(args, "blanket_pivots", False))
    confidence = identity_confidence(details)

    report = {
        **report_metadata(run_id),
        "target": target,
        "target_kind": getattr(args, "target_kind", "person"),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope_result": "N/A",
        "scope_note": "seed+pivots mode, no automated recon",
        "scope_check": "PASS",
        "scope_reason": "seed+pivots mode (no automated network recon; manual pivots only)",
        "details": details,
        "identity_confidence": confidence,
        "canonical_profiles": canonical,
        "validation": validation,
        "pivots": pivots,
        "data_broker_pivots": [p for p in pivots if p.get("category") == "brokers"],
        "enrichment": {"status": "skipped (seed+pivots)"},
        "findings": [],
    }

    report["findings"].extend(_seed_findings_from_validation(validation))
    if not report["findings"]:
        report["findings"].append(
            {
                "id": "seed_ok",
                "severity": "info",
                "confidence": "high",
                "evidence": "Seed details loaded; no format issues flagged.",
                "recommendation": "Use pivots manually and validate ownership/authorization before taking action.",
            }
        )

    return report


# ---------------------------
# Rendering
# ---------------------------

def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_markdown(report: dict) -> str:
    lines = [
        f"# OSINT Report: {report.get('target', 'unknown')}",
        "",
        f"- Generated: {report.get('generated_at')}",
        f"- Scope check: {report.get('scope_check')}",
        f"- Scope reason: {report.get('scope_reason')}",
        f"- Target kind: {report.get('target_kind', 'domain')}",
        "",
    ]

    details = report.get("details")
    if details:
        lines += ["## Target Details (seed)", "```json", json.dumps(details, indent=2, ensure_ascii=False), "```", ""]

    if report.get("identity_confidence"):
        lines += ["## Identity Confidence (seed quality)", "```json", json.dumps(report["identity_confidence"], indent=2, ensure_ascii=False), "```", ""]

    if report.get("canonical_profiles"):
        lines += ["## Canonical Profiles (derived)", "```json", json.dumps(report["canonical_profiles"], indent=2, ensure_ascii=False), "```", ""]

    if report.get("validation"):
        lines += ["## Validation (format checks only)", "```json", json.dumps(report["validation"], indent=2, ensure_ascii=False), "```", ""]

    pivots = report.get("pivots") or []
    if pivots:
        lines += ["## Search Pivots (manual)", ""]
        order = ["social", "brokers", "public_records", "code_repos", "media_mentions", "general"]
        for cat in order:
            items = [p for p in pivots if p.get("category") == cat]
            if not items:
                continue
            lines.append(f"### {cat.replace('_', ' ').title()}")
            for it in items:
                lines.append(f"- **{it.get('label','pivot')}**: `{it.get('query','')}`")
            lines.append("")

    lines.append("## Findings")
    findings = report.get("findings", [])
    if not findings:
        lines.append("- No notable passive findings generated.")
    else:
        for f in findings:
            lines.append(f"- [{f['severity'].upper()}|{f.get('confidence','LOW').upper()}] {f['id']}: {f['evidence']}")
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
        rows.append(
            "<tr>"
            f"<td><span style='background:{color};color:#fff;padding:2px 8px;border-radius:10px'>{html_escape(f['severity'])}</span></td>"
            f"<td>{html_escape(str(f.get('confidence','')))}</td>"
            f"<td>{html_escape(f['id'])}</td>"
            f"<td>{html_escape(f['evidence'])}</td>"
            f"<td>{html_escape(f['recommendation'])}</td>"
            "</tr>"
        )

    def block(title: str, obj: object) -> str:
        return (
            f"<h2>{html_escape(title)}</h2>"
            f"<pre style='white-space:pre-wrap;background:#f5f5f5;padding:12px;border-radius:10px;border:1px solid #ddd;'>"
            f"{html_escape(json.dumps(obj, indent=2, ensure_ascii=False))}"
            f"</pre>"
        )

    pivots_html = ""
    pivots = report.get("pivots") or []
    if pivots:
        order = ["social", "brokers", "public_records", "code_repos", "media_mentions", "general"]
        sections = []
        for cat in order:
            items = [p for p in pivots if p.get("category") == cat]
            if not items:
                continue

            tr = []
            for it in items:
                q = it.get("query", "")
                label = it.get("label", "pivot")
                links = it.get("links") or {}
                g = links.get("google", "")
                b = links.get("bing", "")
                d = links.get("duckduckgo", "")
                g_link = f'<a href="{g}" target="_blank">Google</a> ' if g else ""
                b_link = f'<a href="{b}" target="_blank">Bing</a> ' if b else ""
                d_link = f'<a href="{d}" target="_blank">DDG</a>' if d else ""
                tr.append(
                    "<tr>"
                    f"<td>{html_escape(label)}</td>"
                    f"<td><code>{html_escape(q)}</code></td>"
                    f"<td>{g_link}{b_link}{d_link}</td>"
                    "</tr>"
                )

            sections.append(
                f"<h3>{html_escape(cat.replace('_', ' ').title())}</h3>"
                "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;width:100%'>"
                "<thead><tr><th>Label</th><th>Query</th><th>Links</th></tr></thead>"
                f"<tbody>{''.join(tr)}</tbody>"
                "</table>"
            )

        pivots_html = "<h2>Search Pivots (manual)</h2>" + "".join(sections)

    details_block = block("Target Details (seed)", report["details"]) if report.get("details") else ""
    confidence_block = block("Identity Confidence (seed quality)", report["identity_confidence"]) if report.get("identity_confidence") else ""
    canon_block = block("Canonical Profiles (derived)", report["canonical_profiles"]) if report.get("canonical_profiles") else ""
    validation_block = block("Validation (format checks only)", report["validation"]) if report.get("validation") else ""

    return f"""<!doctype html><html><head><meta charset='utf-8'><title>OSINT Report {html_escape(report.get('target','unknown'))}</title></head>
<body style='font-family:Arial,sans-serif;max-width:1000px;margin:24px auto'>
<h1>OSINT Report: {html_escape(report.get('target','unknown'))}</h1>
<p><b>Generated:</b> {html_escape(str(report.get('generated_at')))}<br>
<b>Scope:</b> {html_escape(str(report.get('scope_check')))} ({html_escape(str(report.get('scope_reason')))} )<br>
<b>Target kind:</b> {html_escape(str(report.get('target_kind','domain')))}</p>
{details_block}
{confidence_block}
{canon_block}
{validation_block}
{pivots_html}
<h2>Findings</h2>
<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;width:100%'>
<thead><tr><th>Severity</th><th>Confidence</th><th>ID</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="5">No findings</td></tr>'}</tbody>
</table>
</body></html>"""


def write_findings_csv(path: Path, target: str, findings: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["target", "id", "severity", "confidence", "evidence", "recommendation"])
        w.writeheader()
        for item in findings:
            w.writerow({"target": target, **item})


def write_report_bundle(outdir: Path, stem: str, report: dict) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / f"{stem}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (outdir / f"{stem}.md").write_text(build_markdown(report), encoding="utf-8")
    (outdir / f"{stem}.html").write_text(build_html(report), encoding="utf-8")
    write_findings_csv(outdir / f"{stem}.findings.csv", report.get("target", "unknown"), report.get("findings", []))

    # NEW: Search All Pivots export
    if report.get("pivots"):
        export_pivots(outdir, stem, report["pivots"])


def report_metadata(run_id: str) -> dict:
    return {
        "tool_name": TOOL_NAME,
        "tool_version": USER_AGENT.split("/", 1)[1] if "/" in USER_AGENT else USER_AGENT,
        "report_version": REPORT_VERSION,
        "run_id": run_id,
    }


# ---------------------------
# Execution
# ---------------------------

def run_target(target: str, args, scope: dict, run_id: str) -> tuple[int, dict | None]:
    target_kind = getattr(args, "target_kind", "domain")

    if target_kind in {"person", "username", "email"}:
        report = build_seed_report(target, args, run_id)
        outdir = Path(args.outdir)
        write_report_bundle(outdir, "seed", report)
        print(f"[+] Wrote seed+pivots reports for {target}")
        return 0, report

    in_scope, reason = is_in_scope(target, scope)
    if not in_scope:
        print(f"[!] Target '{target}' is out of scope ({reason}).", file=sys.stderr)
        return 3, None

    report = {
        **report_metadata(run_id),
        "target": target,
        "target_kind": "domain",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope_result": "PASS",
        "scope_note": reason,
        "scope_check": "PASS",
        "scope_reason": reason,
        "dns": dns_lookup(target) if not is_ip(target) else {},
        "rdap": rdap_lookup(target) if not is_ip(target) else {"status": "skipped (ip target)", "source": None, "raw": None},
        "subdomains": passive_subdomains(target, args.max_subdomains) if not is_ip(target) else [],
        "http": http_fingerprint(target),
    }

    report["enrichment"] = (
        {"shodan": {"status": "skipped (--no-enrich)"}, "censys": {"status": "skipped (--no-enrich)"}}
        if args.no_enrich
        else {"shodan": shodan_enrich(target), "censys": censys_enrich(target)}
    )

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
    stem = target.replace("*", "wildcard").replace("/", "_").replace(":", "_")
    write_report_bundle(outdir, stem, report)

    print(f"[+] Wrote reports for {target}")
    return 0, report


def load_targets(args) -> list[str]:
    targets = []
    if args.target:
        if getattr(args, "target_kind", "domain") == "domain":
            targets.append(normalize_target(args.target))
        else:
            targets.append((args.target or "").strip())

    if args.targets_file:
        for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                if getattr(args, "target_kind", "domain") == "domain":
                    targets.append(normalize_target(line))
                else:
                    targets.append(line)

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
                w.writerow({"target": r.get("target", "unknown"), **item})


def main() -> int:
    p = argparse.ArgumentParser(description="Ethical OSINT toolkit (authorized scope only)")
    p.add_argument("target", nargs="?", help="Domain/IP/URL to assess (or seed target in person mode)")
    p.add_argument("--targets-file", help="File with one target per line")
    p.add_argument("--scope", default="scope.txt", help="Path to allowed scope file")
    p.add_argument("--outdir", default="outputs", help="Output directory")
    p.add_argument("--baseline-dir", help="Previous outputs dir for delta mode")
    p.add_argument("--max-subdomains", type=int, default=100)
    p.add_argument("--no-enrich", action="store_true", help="Skip Shodan/Censys enrichment")

    p.add_argument("--target-kind", choices=["domain", "person", "username", "email"], default="domain", help="Type of target being scanned")
    p.add_argument("--target-details", help="Path to JSON file containing additional structured target data")
    p.add_argument("--blanket-pivots", action="store_true", help="Seed modes only: generate broad manual pivots across many public platforms")

    args = p.parse_args()

    args.target_details_data = {}
    if args.target_details:
        try:
            args.target_details_data = json.loads(Path(args.target_details).read_text(encoding="utf-8"))
            print(f"[+] Loaded target details: {args.target_details}")
        except Exception as e:
            print(f"[!] Failed to load target details: {e}", file=sys.stderr)

    if not args.target and not args.targets_file:
        print("[!] Provide target or --targets-file", file=sys.stderr)
        return 2

    scope = {}
    if args.target_kind == "domain":
        scope_path = Path(args.scope)
        if not scope_path.exists():
            print(f"[!] Scope file not found: {scope_path}", file=sys.stderr)
            return 2
        scope = load_scope(scope_path)

    targets = load_targets(args)
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    reports, failed = [], 0
    for t in targets:
        rc, report = run_target(t, args, scope, run_id)
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
