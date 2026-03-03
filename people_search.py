#!/usr/bin/env python3
"""Consent-first people search helper (query generator only)."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import urllib.parse
from pathlib import Path


DEFAULT_SITES = [
    "linkedin.com/in",
    "github.com",
    "x.com",
    "twitter.com",
    "facebook.com",
    "instagram.com",
]


def slugify(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", value.strip())


def build_query(name: str, location: str | None, company: str | None, username: str | None) -> str:
    parts = [f'"{name.strip()}"']
    if location:
        parts.append(f'"{location.strip()}"')
    if company:
        parts.append(f'"{company.strip()}"')
    if username:
        parts.append(f'"{username.strip()}"')
    return " ".join(parts)


def build_urls(query: str, sites: list[str]) -> dict[str, str]:
    encoded = urllib.parse.quote_plus(query)
    scoped_google = [f"site:{site}" for site in sites]
    scoped_bing = [f"site:{site}" for site in sites]
    google_query = f"{query} ({' OR '.join(scoped_google)})"
    bing_query = f"{query} ({' OR '.join(scoped_bing)})"

    return {
        "google_general": f"https://www.google.com/search?q={encoded}",
        "bing_general": f"https://www.bing.com/search?q={encoded}",
        "google_scoped": "https://www.google.com/search?q=" + urllib.parse.quote_plus(google_query),
        "bing_scoped": "https://www.bing.com/search?q=" + urllib.parse.quote_plus(bing_query),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate legal/ethical people-search query links (no scraping)."
    )
    parser.add_argument("name", help="Person name to search for")
    parser.add_argument("--location", help="Optional city/state/country filter")
    parser.add_argument("--company", help="Optional company/school filter")
    parser.add_argument("--username", help="Optional known handle/username")
    parser.add_argument(
        "--sites",
        default=",".join(DEFAULT_SITES),
        help="Comma-separated domains for scoped searches",
    )
    parser.add_argument("--outdir", default="people_search_outputs")
    args = parser.parse_args()

    sites = [s.strip() for s in args.sites.split(",") if s.strip()]
    query = build_query(args.name, args.location, args.company, args.username)
    urls = build_urls(query, sites)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = slugify(args.name)

    report = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": "people-search-query-generator",
        "ethics": "Use only for lawful, authorized, and consent-based investigations.",
        "inputs": {
            "name": args.name,
            "location": args.location,
            "company": args.company,
            "username": args.username,
            "sites": sites,
        },
        "query": query,
        "links": urls,
    }

    json_path = outdir / f"{stem}.{stamp}.json"
    md_path = outdir / f"{stem}.{stamp}.md"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    md = [
        "# People Search Query Pack",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Name: {args.name}",
        f"- Query: `{query}`",
        "",
        "## Search Links",
    ]
    for key, value in urls.items():
        md.append(f"- **{key}**: {value}")

    md += [
        "",
        "## Guardrails",
        "- No scraping is performed by this tool.",
        "- Confirm legal authority and purpose before use.",
    ]
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"[+] JSON: {json_path}")
    print(f"[+] Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
