# Ethical OSINT Toolkit (Portfolio Edition)

A **passive, scope-limited** OSINT script for cybersecurity students and defenders.

## What this is
- Recon helper for authorized targets only
- Produces recruiter-friendly artifacts (`.json` + `.md` reports)
- Designed for portfolio use and methodology demonstration

## What this is NOT
- Not a doxxing/stalking tool
- Not an exploitation framework
- Not for unauthorized testing

## Features
- Scope enforcement via `scope.txt` (hard stop when out-of-scope)
- Allow/deny rules, wildcard domains, IPs, and CIDR ranges
- DNS collection (A/AAAA/NS/MX/TXT)
- RDAP metadata lookup
- Passive subdomain discovery (crt.sh)
- HTTP header/title fingerprint
- TLS certificate metadata
- Severity-tagged findings (`info`/`low`/`medium`) + confidence scoring (`low`/`medium`/`high`)
- Output formats: JSON + Markdown + HTML + CSV findings
- Batch mode (`--targets-file`) + combined batch CSV
- Delta mode (`--baseline-dir`) to show new/removed findings
- Optional enrichment: Shodan + Censys (via environment variables)

## Usage
```bash
python3 osint.py example.com --scope scope.txt --outdir outputs
```

## Local GUI
```bash
python3 osint_gui.py
```
Then open: `http://127.0.0.1:8765`

## FastAPI Case Runner (authorized org/assets only)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-fastapi.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Open: `http://127.0.0.1:8000`

Optional:
```bash
python3 osint.py example.com --max-subdomains 200
python3 osint.py https://portal.example.com --scope scope.txt
python3 osint.py 203.0.113.10 --scope scope.txt
python3 osint.py example.com --no-enrich
python3 osint.py --targets-file targets.txt --scope scope.txt --outdir outputs
python3 osint.py example.com --baseline-dir previous_outputs --outdir outputs
```

## Scope file format (`scope.txt`)
One rule per line. Default mode is `allow:`.

```txt
# Allow root domain (+ all subdomains)
example.com

# Explicit wildcard (apex + subdomains)
allow:*.corp.example

# Allow an IP or CIDR
allow:203.0.113.10
allow:203.0.113.0/24

# Deny takes priority over allow
deny:admin.example.com
deny:203.0.113.66
```

Rules supported:
- Domains (apex + subdomains)
- Wildcards (`*.domain.tld`)
- IPv4/IPv6
- CIDR blocks
- `allow:` / `deny:` prefixes (`deny` always wins)


## Scope semantics
- Domain mode enforces scope rules from `scope.txt`.
- `example.com` matches the apex and all subdomains.
- `*.example.com` also matches the apex and all subdomains.
- `deny:` rules always win over `allow:` rules.
- Trailing dots are normalized during matching.

## GUI usage
- Run `python3 osint_gui.py` and open `http://127.0.0.1:8765`.
- Domain target type keeps scope and domain scan controls visible.
- Person, username, and email target types keep seed fields and manual pivot options visible.
- GUI writes each run to `outputs/<run_id>/` with JSON, Markdown, HTML, findings CSV, pivots exports, and `target_details.json`.

## Local sample data and ignore suggestions
- Sample targets file: `examples/targets.sample.txt`.
- Sample target details: `examples/target_details.sample.json`.
- Keep local artifacts out of git with:
  - `outputs/`
  - `.venv/`
  - `*.local.*`
  - `targets.local.txt`

## Output
- `outputs/<target>.json` — machine-readable full report
- `outputs/<target>.md` — human-readable summary
- `outputs/<target>.html` — recruiter-friendly visual report
- `outputs/<target>.findings.csv` — severity/confidence findings table
- `outputs/batch.findings.csv` — combined findings from batch mode

## Optional Enrichment (API keys)
Set environment variables to enable passive enrichment:

```bash
export SHODAN_API_KEY="..."
export CENSYS_API_ID="..."
export CENSYS_API_SECRET="..."
```

If keys are missing, enrichment is skipped safely and reported in output.

## Ethics / Legal
Use only on systems and domains you own or have explicit written permission to test.

## Suggested portfolio framing
Include in your repo:
1. Assessment objective
2. Scope and authorization statement
3. Methodology (passive only)
4. Findings with confidence levels
5. Limitations and next steps

## Ethics-first portfolio bundle (included)
- `program_scope.md` — authorization + rules-of-engagement template
- `blue_team_playbook.md` — monthly external-surface workflow
- `demo_targets.txt` — safe sample targets for screenshots/demo runs

## Demo mode (safe examples)
```bash
python3 osint.py --targets-file demo_targets.txt --scope scope.txt --outdir outputs --no-enrich
```

## One-command portfolio demo
```bash
chmod +x run_portfolio_demo.sh
./run_portfolio_demo.sh
```
Generates:
- `PORTFOLIO_SUMMARY.md`
- `outputs_demo/` artifacts (JSON/MD/HTML/CSV)

## Bug-bounty safe scope import
Prepare `assets.txt` from program in-scope assets (one per line), then import:
```bash
python3 import_scope.py assets.txt scope.txt
```

## Self-OSINT mode (your own profiles only)
1. Add your own URLs to `my_profiles.txt`
2. Run:
```bash
python3 self_audit.py "https://www.linkedin.com/in/your-handle/" --allowlist my_profiles.txt
```
Outputs are written to `self_audit_outputs/` (JSON + Markdown + CSV).

### Easy GUI for self-audit
```bash
python3 self_audit_gui.py
```
Open: `http://127.0.0.1:8770`

## People search mode (query links, no scraping)
Generate legal/ethical search links for public profile discovery:

```bash
python3 people_search.py "Jane Doe" --location "Austin, TX" --company "Example Corp"
```

Outputs are written to `people_search_outputs/` (JSON + Markdown with search URLs).
