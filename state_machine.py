import hashlib
import json
import uuid
from typing import Any


def uid(prefix="id"):
    return f"{prefix}_{uuid.uuid4().hex}"


def compact_sorted(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(obj):
    return hashlib.sha256(compact_sorted(obj).encode()).hexdigest()


def initial_dispatches(plan, run_id, trace_id, policy, tool_catalog):
    dispatches = []
    for d in plan["diagnostics"]:
        action_id = uid("action")
        call_id = uid("call")
        span_id = uuid.uuid4().hex[:16]
        dispatches.append({
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": d["toolName"],
            "arguments": d.get("arguments", {}),
            "evidence": [plan["evidence"][0]],
            "attempt": 1,
            "traceparent": f"00-{trace_id}-{span_id}-01",
        })
    return dispatches


def process_receipt(state: dict, receipt: dict) -> dict:
    s = json.loads(json.dumps(state))
    internal = s["_internal"]
    pending = {d["actionId"]: d for d in s.get("dispatches", [])}
    outcomes = receipt.get("outcomes", [])
    approvals = receipt.get("approvals", [])
    if outcomes and approvals:
        raise ValueError("Receipt cannot mix outcomes and approvals")

    if outcomes:
        for outcome in outcomes:
            action_id = outcome.get("actionId")
            dispatch = pending.get(action_id)
            if not dispatch:
                raise ValueError("Outcome is not for a pending call")
            if outcome.get("callId") != dispatch["callId"] or outcome.get("attempt") != dispatch["attempt"]:
                raise ValueError("Outcome does not match pending attempt")
            item = {
                "receiptId": receipt["receiptId"],
                "actionId": action_id,
                "callId": dispatch["callId"],
                "attempt": dispatch["attempt"],
                "status": outcome.get("status"),
                "resultClass": outcome.get("resultClass"),
                "nonce": outcome.get("nonce"),
            }
            s["receiptLog"].append(item)
            internal.setdefault("outcome_by_action", {})[action_id] = outcome
            s["dispatches"].remove(dispatch)

            if outcome.get("status") == 503 and dispatch["attempt"] == 1:
                retry = dict(dispatch)
                retry["attempt"] = 2
                span_id = uuid.uuid4().hex[:16]
                retry["traceparent"] = f"00-{internal['trace_id']}-{span_id}-01"
                s["dispatches"].append(retry)
                s["actionLog"].append(retry)
                continue
            if outcome.get("status") == 0 and outcome.get("errorType") == "timeout":
                s["suppressed"].append({
                    "reason": "diagnostic_timeout",
                    "actionId": action_id,
                })

        if s["dispatches"]:
            s["status"] = "waiting"
            return s

        all_outcomes = list(internal.get("outcome_by_action", {}).values())
        timed_out = any(o.get("status") == 0 and o.get("errorType") == "timeout" for o in all_outcomes)
        failed = any(o.get("status") not in (200, 201, 202) for o in all_outcomes)
        if timed_out or failed:
            s["status"] = "failed"
            s["chosenEffect"] = None
            s["dispatches"] = []
            s["approvals"] = []
            return s

        # Select one effect only after successful diagnostic receipts.
        effect = choose_effect(s, all_outcomes)
        if not effect:
            s["status"] = "failed"
            return s
        args = effect.get("arguments", {})
        tool_name = effect["toolName"]
        action_id = uid("action")
        call_id = uid("call")
        if tool_name in set(internal["policy"].get("approvalRequiredFor", [])):
            approval_id = uid("approval")
            s["dispatches"] = []
            s["approvals"] = [{
                "approvalId": approval_id,
                "actionId": action_id,
                "toolName": tool_name,
                "argumentsDigest": sha256_json(args),
            }]
            internal["approval_pending"] = {
                "approvalId": approval_id,
                "actionId": action_id,
                "callId": call_id,
                "toolName": tool_name,
                "arguments": args,
            }
            s["status"] = "waiting"
            return s

        dispatch = make_effect_dispatch(action_id, call_id, tool_name, args, internal["trace_id"])
        s["dispatches"] = [dispatch]
        s["actionLog"].append(dispatch)
        s["chosenEffect"] = tool_name
        return s

    if approvals:
        pending_approval = internal.get("approval_pending")
        if not pending_approval:
            raise ValueError("No approval pending")
        if len(approvals) != 1:
            raise ValueError("Expected one approval")
        a = approvals[0]
        if a.get("approvalId") != pending_approval["approvalId"]:
            raise ValueError("Approval ID mismatch")
        approval_log = {
            "receiptId": receipt["receiptId"],
            "approvalId": a["approvalId"],
            "decision": a.get("decision"),
            "nonce": a.get("nonce"),
        }
        s["receiptLog"].append(approval_log)
        if a.get("decision") != "approved":
            s["status"] = "failed"
            s["approvals"] = []
            s["dispatches"] = []
            internal["approval_pending"] = None
            return s
        p = pending_approval
        dispatch = make_effect_dispatch(
            p["actionId"], p["callId"], p["toolName"], p["arguments"],
            internal["trace_id"], approval_id=p["approvalId"], approval_nonce=a.get("nonce")
        )
        s["approvals"] = []
        s["dispatches"] = [dispatch]
        s["actionLog"].append(dispatch)
        s["chosenEffect"] = p["toolName"]
        internal["approval_pending"] = None
        return s

    raise ValueError("Receipt has no outcomes or approvals")


def choose_effect(state, outcomes):
    internal = state["_internal"]
    incident = internal["incident"]
    catalog = internal["toolCatalog"]
    effect_names = set(internal["policy"].get("effectTools", []))
    # The model does not choose effects. Prefer the catalog's safe, non-destructive effect
    # whose description/inputs best match the incident and diagnosis.
    diagnosis = state["diagnosis"]["rootCause"].lower()
    candidates = [t for t in catalog if t.get("name") in effect_names]
    if not candidates:
        return None
    # Explicit policy: when already at scaling limit, page owner instead of scaling.
    transcript = incident.get("transcript", "").lower()
    at_limit = ("scaling limit" in transcript or "maximum replicas" in transcript or "at capacity limit" in transcript)
    if at_limit:
        page = [t for t in candidates if "page" in t.get("name", "").lower() or "owner" in t.get("name", "").lower()]
        if page:
            return {"toolName": page[0]["name"], "arguments": {}}
        return None
    safe = [t for t in candidates if t.get("name") not in {"rollback_deployment", "disable_feature"}]
    if safe:
        chosen = safe[0]
    else:
        chosen = candidates[0]
    return {"toolName": chosen["name"], "arguments": {}}


def make_effect_dispatch(action_id, call_id, tool_name, arguments, trace_id,
                         approval_id=None, approval_nonce=None):
    span_id = uuid.uuid4().hex[:16]
    d = {
        "actionId": action_id,
        "callId": call_id,
        "phase": "effect",
        "toolName": tool_name,
        "arguments": arguments,
        "evidence": [],
        "attempt": 1,
        "traceparent": f"00-{trace_id}-{span_id}-01",
    }
    if approval_id:
        d["approvalId"] = approval_id
        d["approvalNonce"] = approval_nonce
    return d
