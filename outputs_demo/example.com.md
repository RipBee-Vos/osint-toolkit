# OSINT Report: example.com

- Generated: 2026-03-03T01:56:16.892104+00:00
- Scope check: PASS
- Scope reason: ALLOW rule matched

## Findings
- [LOW|HIGH] missing_hsts: HSTS header not observed
  - Recommendation: Add Strict-Transport-Security header
- [INFO|HIGH] server_banner_exposed: Server header present: cloudflare
  - Recommendation: Reduce banner detail where possible
