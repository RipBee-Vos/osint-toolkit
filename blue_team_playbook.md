# Blue-Team External Surface Playbook

## Monthly Cadence
1. Run batch passive scan on authorized assets
2. Compare with previous baseline (`--baseline-dir`)
3. Triage new findings by severity/confidence
4. Open remediation tasks and assign owners
5. Re-scan after fixes

## Command Set
```bash
python3 osint.py --targets-file targets.txt --scope scope.txt --outdir outputs
python3 osint.py --targets-file targets.txt --scope scope.txt --outdir outputs --baseline-dir previous_outputs
```

## Triage Guidance
- medium: address first (TLS posture, plaintext exposure)
- low: hardening backlog
- info: asset inventory / hygiene

## Evidence Package
- `outputs/*.md` human summaries
- `outputs/*.findings.csv` tracker import
- `outputs/batch.findings.csv` monthly diff worksheet
