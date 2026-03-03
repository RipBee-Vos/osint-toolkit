# OSINT Report: example.com

- Generated: 2026-03-03T00:58:39.325538Z
- Scope check: PASS

## DNS
- A: 104.18.26.120, 104.18.27.120
- AAAA: 2606:4700::6812:1a78, 2606:4700::6812:1b78
- NS: elliott.ns.cloudflare.com., hera.ns.cloudflare.com.
- MX: 0 .
- TXT: _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9, v=spf1 -all

## RDAP
- Status: ok
- Source: https://rdap.org/domain/example.com

## Passive Subdomains (crt.sh)
- Count: 6
  - dev.example.com
  - example.com
  - m.example.com
  - products.example.com
  - support.example.com
  - www.example.com

## HTTP/TLS Fingerprint
- URL: https://example.com
- Status: 200
- Title: Example Domain
- Server: cloudflare

## Ethics & Limits
- Passive recon only; no exploitation attempted.
- Data quality may vary by source and time.
- Use only on assets you are authorized to assess.
