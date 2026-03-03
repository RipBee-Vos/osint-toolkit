from __future__ import annotations
import json
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import conn, init_db

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "app" / "templates"
STATIC = ROOT / "app" / "static"

app = FastAPI(title="OSINT Case Runner")
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES))


@app.on_event("startup")
def startup() -> None:
    init_db()


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def run_scan(target: str, scope_file: str, outdir: str, no_enrich: bool = True) -> tuple[int, str]:
    cmd = [
        sys.executable,
        str(ROOT / "osint.py"),
        target,
        "--scope",
        scope_file,
        "--outdir",
        outdir,
    ]
    if no_enrich:
        cmd.append("--no-enrich")
    try:
        p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    except FileNotFoundError as exc:
        return 1, f"Unable to start scan process: {exc}"
    return p.returncode, (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")


def load_findings_json(target: str, outdir: str) -> list[dict]:
    stem = target.replace("*", "wildcard").replace("/", "_").replace(":", "_")
    path = ROOT / outdir / f"{stem}.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("findings", [])


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    with conn() as c:
        rows = c.execute("SELECT * FROM cases ORDER BY id DESC LIMIT 50").fetchall()
    return templates.TemplateResponse("index.html", {"request": request, "cases": rows})


@app.post("/cases/create")
def create_case(
    engagement_id: str = Form(...),
    purpose: str = Form(...),
    target: str = Form(...),
    scope_file: str = Form("scope.txt"),
    outdir: str = Form("outputs"),
):
    ts = now_iso()
    with conn() as c:
        cur = c.execute(
            "INSERT INTO cases(engagement_id,purpose,target,scope_file,outdir,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (engagement_id.strip(), purpose.strip(), target.strip(), scope_file.strip(), outdir.strip(), "created", ts, ts),
        )
        case_id = cur.lastrowid
    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(case_id: int, request: Request):
    with conn() as c:
        case = c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        findings = c.execute("SELECT * FROM findings WHERE case_id=? ORDER BY id DESC", (case_id,)).fetchall()
    return templates.TemplateResponse("case_detail.html", {"request": request, "case": case, "findings": findings})


@app.post("/cases/{case_id}/run")
def run_case(case_id: int):
    with conn() as c:
        case = c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        c.execute("UPDATE cases SET status=?, updated_at=?, error_message=NULL WHERE id=?", ("running", now_iso(), case_id))

    rc, output = run_scan(case["target"], case["scope_file"], case["outdir"], no_enrich=True)

    with conn() as c:
        if rc != 0:
            c.execute(
                "UPDATE cases SET status=?, updated_at=?, error_message=? WHERE id=?",
                ("error", now_iso(), output[-2000:], case_id),
            )
            return RedirectResponse(url=f"/cases/{case_id}", status_code=303)

        findings = load_findings_json(case["target"], case["outdir"])
        c.execute("DELETE FROM findings WHERE case_id=?", (case_id,))
        for f in findings:
            c.execute(
                "INSERT INTO findings(case_id,finding_id,severity,confidence,evidence,recommendation) VALUES (?,?,?,?,?,?)",
                (
                    case_id,
                    f.get("id", "unknown"),
                    f.get("severity", "info"),
                    f.get("confidence", "low"),
                    f.get("evidence", ""),
                    f.get("recommendation", ""),
                ),
            )
        c.execute("UPDATE cases SET status=?, updated_at=? WHERE id=?", ("complete", now_iso(), case_id))

    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)
