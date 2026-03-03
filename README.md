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
- DNS collection (A/AAAA/NS/MX/TXT)
- RDAP metadata lookup
- Passive subdomain discovery (crt.sh)
- HTTP header/title fingerprint
- TLS certificate metadata

## Usage
```bash
python3 osint.py example.com --scope scope.txt --outdir outputs
```

Optional:
```bash
python3 osint.py example.com --max-subdomains 200
```

## Scope file format (`scope.txt`)
One entry per line:
```txt
# Allowed targets only
example.com
example.org
```

Subdomains are automatically permitted when the root domain is listed.

## Output
- `outputs/<target>.json` — machine-readable full report
- `outputs/<target>.md` — human-readable summary

## Ethics / Legal
Use only on systems and domains you own or have explicit written permission to test.

## Suggested portfolio framing
Include in your repo:
1. Assessment objective
2. Scope and authorization statement
3. Methodology (passive only)
4. Findings with confidence levels
5. Limitations and next steps
