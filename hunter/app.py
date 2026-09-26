"""FastAPI entrypoint for the AI Threat Hunter.

Run directly with:
    uvicorn app:app --host 0.0.0.0 --port 8000
or via hunter/Dockerfile / docker-compose.yml.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from config import settings
from llm_engine import ThreatHuntingEngine
from models import Action, ExecEvent, Verdict
from responder import kill_pid

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("cyber_patrol.api")

app = FastAPI(
    title="Cyber Patrol AI Threat Hunter",
    description=(
        "Evaluates eBPF-captured process-execution events against MITRE "
        "ATT&CK and issues severity/action verdicts, with an optional "
        "kill response for high-confidence critical findings."
    ),
    version="1.0.0",
)

# One engine instance per process: the anthropic.Anthropic client
# internally pools HTTP connections, so this is the efficient shape for a
# uvicorn worker handling many requests, not a per-request construction.
engine = ThreatHuntingEngine(settings)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/v1/evaluate", response_model=Verdict)
def evaluate(event: ExecEvent) -> Verdict:
    logger.info("evaluating pid=%s uid=%s comm=%s cmd=%r", event.pid, event.uid, event.comm, event.command_line)

    try:
        verdict = engine.evaluate(event)
    except Exception:
        logger.exception("unexpected failure evaluating pid=%s", event.pid)
        raise HTTPException(status_code=500, detail="threat evaluation failed")

    logger.info(
        "verdict pid=%s severity=%s action=%s technique=%s confidence=%.2f",
        event.pid, verdict.severity, verdict.action, verdict.mitre_technique, verdict.confidence,
    )

    if verdict.action == Action.KILL:
        # Best-effort local response for single-node deployments; the Go
        # broker independently applies the same verdict on its side (see
        # broker/internal/pipeline.Pipeline.evaluate). kill_pid() is
        # idempotent against an already-exited or already-killed process,
        # so both paths running is safe -- see responder.py's module docs
        # for which one actually fires in your topology.
        kill_pid(event.pid, event.comm)

    return verdict


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled exception on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "internal error"})
