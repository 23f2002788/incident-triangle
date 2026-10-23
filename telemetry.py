import uuid


def hx(n=16):
    return uuid.uuid4().hex[:n]


def new_trace_context(traceparent=None, tracestate=None):
    trace_id = None
    if isinstance(traceparent, str):
        parts = traceparent.split("-")
        if len(parts) == 4 and parts[0] == "00" and len(parts[1]) == 32 and len(parts[2]) == 16:
            try:
                int(parts[1], 16)
                int(parts[2], 16)
                if int(parts[1], 16) and int(parts[2], 16):
                    trace_id = parts[1].lower()
            except ValueError:
                pass
    trace_id = trace_id or hx(32)
    return {
        "trace_id": trace_id,
        "server_span_id": hx(16),
        "agent_span_id": hx(16),
        "tracestate": tracestate if traceparent and trace_id else None,
    }


def span(name, kind, trace_id, span_id, parent_id, attrs=None, status_code=0, links=None):
    return {
        "traceId": trace_id,
        "spanId": span_id,
        "parentSpanId": parent_id or "",
        "name": name,
        "kind": kind,
        "startTimeUnixNano": "0",
        "endTimeUnixNano": "1",
        "attributes": [
            {"key": k, "value": {"stringValue": str(v)}} for k, v in (attrs or {}).items()
        ],
        "status": {"code": status_code},
        **({"links": links} if links else {}),
    }


def build_trace(state, phase="waiting"):
    internal = state["_internal"]
    trace_id = internal["trace_id"]
    server_id = internal["server_span_id"]
    agent_id = internal["agent_span_id"]
    marker = internal.get("publicMarker", "")
    run_id = state["runId"]
    base_attrs = {"ga5.run.id": run_id, "ga5.public.marker": marker}
    spans = [
        span("POST /v2/incidents", 2, trace_id, server_id, "", base_attrs),
        span("invoke_agent incident-response", 1, trace_id, agent_id, server_id, base_attrs),
        span("chat incident-plan", 3, trace_id, hx(16), agent_id, {
            **base_attrs, "gen_ai.operation.name": "chat",
            "gen_ai.request.model": __import__("os").getenv("MODEL_NAME", "gpt-4o-mini"),
        }),
    ]
    action_span_ids = {}
    # Trace only stored dispatches. Do not include arguments/results or transcript.
    for d in state.get("actionLog", []):
        aid = d["actionId"]
        logical_span_id = hx(16)
        action_span_ids.setdefault(aid, logical_span_id)
        spans.append(span(f"execute_tool {d['toolName']}", 1, trace_id, logical_span_id, agent_id, {
            **base_attrs, "ga5.action.id": aid,
            "gen_ai.tool.name": d["toolName"],
            "gen_ai.tool.call.id": d["callId"],
            "gen_ai.operation.name": "execute_tool",
        }))
        receipt = next((r for r in state.get("receiptLog", [])
                        if r.get("actionId") == aid and r.get("attempt") == d.get("attempt")), {})
        span_id = d.get("traceparent", "").split("-")[2] if d.get("traceparent") else hx(16)
        attrs = {
            **base_attrs,
            "ga5.action.id": aid,
            "ga5.attempt": d.get("attempt", 1),
            "ga5.receipt.id": receipt.get("receiptId", ""),
            "ga5.receipt.nonce": receipt.get("nonce", ""),
            "http.request.method": "POST",
            "http.request.resend_count": d.get("attempt", 1) - 1,
            "http.response.status_code": receipt.get("status", 0),
        }
        status = receipt.get("status")
        error_type = "timeout" if receipt.get("errorType") == "timeout" else ("503" if status == 503 else None)
        if error_type:
            attrs["error.type"] = error_type
        spans.append(span(f"POST tool/{d['toolName']}", 3, trace_id, span_id, logical_span_id, attrs,
                          status_code=2 if error_type else 0))
    if len([d for d in state.get("actionLog", []) if d.get("phase") == "diagnostic"]) > 1:
        diagnostic_spans = [
            {"traceId": trace_id, "spanId": action_span_ids[d["actionId"]]}
            for d in state.get("actionLog", []) if d.get("phase") == "diagnostic"
        ]
        spans.append(span("incident.join", 1, trace_id, hx(16), agent_id, base_attrs, links=diagnostic_spans))
    if state.get("approvals") or any("approvalId" in r for r in state.get("receiptLog", [])):
        approval = internal.get("approval_pending") or {}
        spans.append(span("approval_gate", 1, trace_id, hx(16), agent_id, {
            **base_attrs,
            "ga5.approval.id": approval.get("approvalId", ""),
            "ga5.approval.receipt.nonce": next((r.get("nonce", "") for r in state.get("receiptLog", [])
                                                  if "approvalId" in r), ""),
        }))
    return {"resourceSpans": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "ga5-incident-agent"}}
        ]},
        "scopeSpans": [{"scope": {"name": "ga5-incident-agent"}, "spans": spans}]
    }]}
