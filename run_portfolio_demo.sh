#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

OUTDIR="outputs_demo"
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

python3 osint.py --targets-file demo_targets.txt --scope scope.txt --outdir "$OUTDIR" --no-enrich

python3 - <<'PY'
from pathlib import Path
import json
from datetime import datetime, UTC

out = Path("outputs_demo")
reports = sorted(out.glob("*.json"))
findings = []
for p in reports:
    data = json.loads(p.read_text(encoding="utf-8"))
    for f in data.get("findings", []):
        findings.append((data.get("target"), f.get("severity"), f.get("confidence"), f.get("id")))

sev_order = {"medium": 3, "low": 2, "info": 1}
findings.sort(key=lambda x: sev_order.get(x[1], 0), reverse=True)

lines = []
lines.append("# Portfolio Summary")
lines.append("")
lines.append(f"- Generated: {datetime.now(UTC).isoformat()}")
lines.append("- Mode: Demo (safe, passive, no enrichment)")
lines.append(f"- Targets processed: {len(reports)}")
lines.append(f"- Total findings: {len(findings)}")
lines.append("")
lines.append("## Top Findings")
if findings:
    for t, sev, conf, fid in findings[:10]:
        lines.append(f"- [{sev.upper()}|{conf.upper()}] `{fid}` on `{t}`")
else:
    lines.append("- No findings generated in this run.")

lines.append("")
lines.append("## Artifacts")
lines.append("- Per-target JSON/MD/HTML/CSV in `outputs_demo/`")
if (out / "batch.findings.csv").exists():
    lines.append("- Batch CSV: `outputs_demo/batch.findings.csv`")

Path("PORTFOLIO_SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("[+] Wrote PORTFOLIO_SUMMARY.md")
PY

echo "[+] Demo complete"
echo "    - Summary: PORTFOLIO_SUMMARY.md"
echo "    - Artifacts: ${OUTDIR}/"
