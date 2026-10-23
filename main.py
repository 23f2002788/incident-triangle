import hashlib
import json
import os
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from database import (
    get_run, init_db, save_new_run, save_receipt_result,
    get_receipt, update_run_state
)
from planner import create_plan
from state_machine import process_receipt, initial_dispatches
from telemetry import build_trace, new_trace_context

PROFILE = "ga5-incident-agent/v2"
app = FastAPI(title="GA5 Observable Incident Triage", version="2.0.0")


class IncidentRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    profile: str
    runId: str = Field(min_length=8)
    agentName: str
    publicMarker: str
    sensitive: dict[str, Any] = Field(default_factory=dict)
    incident: dict[str, Any]
    toolCatalog: list[dict[str, Any]]
    policy: dict[str, Any]
    traceparent: str | None = None
    tracestate: str | None = None


@app.on_event("startup")
def startup():
    init_db()


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def public_response(state: dict) -> dict:
    # Sensitive input is never stored in the public state or echoed on errors.
    return state


@app.post("/v2/incidents")
async def create_incident(body: IncidentRequest, request: Request):
    data = body.model_dump()
    if data.get("profile") != PROFILE:
        raise HTTPException(status_code=400, detail="Unsupported profile")
    run_id = data["runId"]
    digest = fingerprint(data)
    existing = get_run(run_id)
    if existing:
        if existing["request_hash"] != digest:
            raise HTTPException(status_code=409, detail="runId content conflict")
        return JSONResponse(existing["state"])

    incident = data.get("incident", {})
    allowed = incident.get("allowedRootCauses", [])
    catalog = data.get("toolCatalog", [])
    policy = data.get("policy", {})
    if not allowed or not isinstance(catalog, list):
        raise HTTPException(status_code=422, detail="Invalid incident or tool catalog")

    # The sensitive object is deliberately excluded from the planner payload.
    planner_input = {
        "incident": incident,
        "toolCatalog": catalog,
        "policy": policy,
        "agentName": data.get("agentName", "incident-response"),
    }
    plan = await create_plan(planner_input)
    diagnosis = {
        "rootCause": plan["rootCause"],
        "evidence": plan["evidence"],
    }
    context = new_trace_context(data.get("traceparent"), data.get("tracestate"))
    trace_id = context["trace_id"]
    server_span_id = context["server_span_id"]
    agent_span_id = context["agent_span_id"]

    dispatches = initial_dispatches(
        plan=plan,
        run_id=run_id,
        trace_id=trace_id,
        policy=policy,
        tool_catalog=catalog,
    )
    state = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": diagnosis,
        "dispatches": dispatches,
        "approvals": [],
        "chosenEffect": None,
        "suppressed": [],
        "actionLog": list(dispatches),
        "receiptLog": [],
        "_internal": {
            "request_hash": digest,
            "publicMarker": data.get("publicMarker", ""),
            "trace_id": trace_id,
            "server_span_id": server_span_id,
            "agent_span_id": agent_span_id,
            "tracestate": context.get("tracestate"),
            "incident": incident,
            "policy": policy,
            "toolCatalog": catalog,
            "plan": plan,
            "pending_action_ids": [d["actionId"] for d in dispatches],
            "logical_actions": {},
            "seen_receipts": {},
            "approval_pending": None,
        },
    }
    state["otlp"] = build_trace(state, phase="waiting")
    save_new_run(run_id, digest, state)
    return JSONResponse(public_response(state))


@app.post("/v2/incidents/{run_id}/receipts")
async def receive_receipt(run_id: str, request: Request):
    try:
        receipt = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    if not isinstance(receipt, dict) or not isinstance(receipt.get("receiptId"), str):
        raise HTTPException(status_code=422, detail="Invalid receipt")
    current = get_run(run_id)
    if not current:
        raise HTTPException(status_code=404, detail="Run not found")
    state = current["state"]
    receipt_id = receipt["receiptId"]
    receipt_hash = fingerprint(receipt)
    internal = state["_internal"]
    old = internal["seen_receipts"].get(receipt_id)
    if old:
        if old != receipt_hash:
            raise HTTPException(status_code=409, detail="receiptId content conflict")
        return JSONResponse(state)

    # Only receipt-driven state transitions happen here; no model call.
    updated = process_receipt(state, receipt)
    updated["_internal"]["seen_receipts"][receipt_id] = receipt_hash
    updated["otlp"] = build_trace(updated, phase=updated["status"])
    save_receipt_result(run_id, receipt_id, receipt_hash, updated)
    return JSONResponse(public_response(updated))


@app.get("/v2/incidents/{run_id}")
def read_incident(run_id: str):
    current = get_run(run_id)
    if not current:
        raise HTTPException(status_code=404, detail="Run not found")
    return JSONResponse(public_response(current["state"]))


@app.exception_handler(Exception)
async def safe_error_handler(request: Request, exc: Exception):
    # Avoid echoing request bodies, credentials, or exception strings.
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
