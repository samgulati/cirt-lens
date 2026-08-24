import json
import logging
import os
import re
import time
import urllib.request

from ..observability import AI_FALLBACKS
from .serializers import serialize_incident

EVENT_ID_RE = re.compile(r"\b(?:AUTH|ENDP|NET|CLOUD|EVT)-\d+\b")
log = logging.getLogger("cirt_lens")


def validate_citations(answer, event_ids):
    cited = sorted(set(EVENT_ID_RE.findall(answer)))
    return bool(cited) and set(cited) <= set(event_ids), cited


def validate_structure(payload, event_ids):
    if not isinstance(payload, dict) or not isinstance(payload.get("claims"), list):
        return {
            "event_ids_valid": False,
            "claims_have_evidence": False,
            "fully_grounded_structure_valid": False,
            "cited_event_ids": [],
        }
    ids = []
    claims_have = bool(payload["claims"]) and all(
        isinstance(c, dict) and c.get("text") and c.get("evidence_ids") for c in payload["claims"]
    )
    for claim in payload["claims"]:
        if isinstance(claim, dict):
            ids.extend(claim.get("evidence_ids", []))
    ids = sorted(set(ids))
    valid = bool(ids) and set(ids) <= set(event_ids)
    return {
        "event_ids_valid": valid,
        "claims_have_evidence": claims_have,
        "fully_grounded_structure_valid": valid and claims_have,
        "cited_event_ids": ids,
    }


def local_result(incident, events, question):
    risky = [e for e in events if e.risk_score > 0]
    q = question.lower()
    claims = [
        {
            "text": f"{e.activity}; detected flags: {', '.join(json.loads(e.risk_flags))}.",
            "evidence_ids": [e.id],
        }
        for e in risky[:8]
    ]
    if "affected" in q or "system" in q:
        summary = f"The evidence affects {incident.primary_user or 'an unconfirmed user'} and {incident.primary_host or 'an unconfirmed host/device'}."
    elif "contain" in q or "recommend" in q:
        summary = (
            "Recommended actions derive from the matched playbook; execution remains simulated."
        )
    elif "why" in q and ("risk" in q or "critical" in q):
        summary = f"Risk is {incident.risk_score}/100 from {json.loads(incident.score_breakdown)}."
    else:
        summary = f"Likely {incident.incident_type.lower()} — deterministic confidence heuristic {incident.confidence_score}/100."
    return {
        "summary": summary,
        "claims": claims,
        "uncertainties": ["The root-cause statement is a hypothesis requiring analyst validation."],
        "recommended_next_steps": [
            "Validate identity and device ownership.",
            "Review adjacent telemetry.",
            "Confirm scope before simulated containment.",
        ],
    }


def render(payload):
    claims = "\n".join(
        f"- {c['text']} Evidence: {', '.join(c['evidence_ids'])}" for c in payload.get("claims", [])
    )
    steps = "\n".join(
        f"{i+1}. {x}" for i, x in enumerate(payload.get("recommended_next_steps", []))
    )
    return f"{payload.get('summary','')}\n\nEvidence-backed claims\n{claims}\n\nUncertainty\n{' '.join(payload.get('uncertainties',[]))}\n\nNext steps\n{steps}"


def local_answer(incident, events, question):
    """Backward-compatible text renderer for callers that do not consume structured AI output."""
    payload = local_result(incident, events, question)
    answer = render(payload)
    if "evidence" in question.lower():
        answer = "Evidence supporting the hypothesis\n\n" + answer
    return answer


def _external(context, question, correction=None):
    prompt = "Return JSON only with summary, claims[{text,evidence_ids}], uncertainties[], recommended_next_steps[]. Every factual claim requires supplied incident event IDs. Never invent evidence."
    if correction:
        prompt += f" Previous output failed: {correction}."
    body = json.dumps(
        {
            "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            "messages": [
                {"role": "system", "content": prompt},
                {
                    "role": "user",
                    "content": f"Context:\n{json.dumps(context)}\nQuestion:{question}",
                },
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
    ).encode()
    req = urllib.request.Request(
        os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/") + "/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(json.loads(response.read())["choices"][0]["message"]["content"])


def investigate(incident, events, question):
    start = time.perf_counter()
    ids = json.loads(incident.event_ids)
    if not os.getenv("OPENAI_API_KEY"):
        payload = local_result(incident, events, question)
        check = validate_structure(payload, ids)
        return {
            "answer": render(payload),
            "structured": payload,
            "mode": "local_deterministic",
            **check,
            "validated": check["fully_grounded_structure_valid"],
            "latency_ms": round((time.perf_counter() - start) * 1000),
        }
    correction = None
    for _ in range(2):
        try:
            payload = _external(serialize_incident(incident, events), question, correction)
            check = validate_structure(payload, ids)
            if check["fully_grounded_structure_valid"]:
                return {
                    "answer": render(payload),
                    "structured": payload,
                    "mode": "openai",
                    **check,
                    "validated": True,
                    "latency_ms": round((time.perf_counter() - start) * 1000),
                }
            correction = "output must be a JSON object with non-empty claims and valid evidence_ids"
        except Exception:
            correction = (
                "output was malformed or the request failed; return the required JSON object"
            )
        log.warning(
            "ai_invalid_evidence",
            extra={"operation": "ai_invalid_evidence", "incident_id": incident.id},
        )
    log.warning(
        "ai_local_fallback", extra={"operation": "ai_local_fallback", "incident_id": incident.id}
    )
    AI_FALLBACKS.inc()
    payload = local_result(incident, events, question)
    check = validate_structure(payload, ids)
    return {
        "answer": render(payload),
        "structured": payload,
        "mode": "local_fallback",
        **check,
        "validated": check["fully_grounded_structure_valid"],
        "latency_ms": round((time.perf_counter() - start) * 1000),
    }
