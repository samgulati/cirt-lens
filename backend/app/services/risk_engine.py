BEHAVIORAL_FLAGS = {
    "IMPOSSIBLE_TRAVEL",
    "MFA_FATIGUE",
    "NEW_DEVICE",
    "UNUSUAL_ADMIN_ACTION",
    "UNUSUAL_EGRESS",
}
THREAT_FLAGS = {"KNOWN_MALICIOUS_IP"}


def severity(score):
    return (
        "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    )


def _asset_impact(events):
    score = 0
    for event in events:
        data = event if isinstance(event, dict) else __import__("json").loads(event.data)
        if data.get("sensitive_resource"):
            score = max(score, 20)
        if data.get("privileged"):
            score = max(score, 15)
        if data.get("event_type") == "CREDENTIAL_STORE_ACCESS":
            score = max(score, 20)
        resource = str(data.get("resource", "")).lower()
        if any(
            x in resource for x in ("securityadmin", "finance-sensitive", "sensitive-analytics")
        ):
            score = max(score, 20)
    return score


def calculate_risk(findings, events=None):
    events = events or []
    flags = {f.flag for f in findings}
    parts = {
        "Detection Strength": min(
            40, sum(min(f.risk_contribution, 12) for f in findings if f.risk_contribution > 0)
        ),
        "Asset / Impact Context": min(20, _asset_impact(events)),
        "Behavioral Anomaly": min(20, 7 * len(flags & BEHAVIORAL_FLAGS)),
        "Threat Intelligence": 20 if flags & THREAT_FLAGS else 0,
    }
    total = sum(parts.values())
    if total > 100:
        overflow = total - 100
        parts["Detection Strength"] -= min(overflow, parts["Detection Strength"])
    return sum(parts.values()), parts


def calculate_confidence(findings, events, cohesion):
    flags = {f.flag for f in findings}
    source_count = len({e.source for e in events})
    evidence_count = len({f.event_id for f in findings})
    breakdown = {
        "Detection Support": min(35, len(flags) * 7),
        "Source Corroboration": min(20, max(0, source_count - 1) * 10),
        "Correlation Cohesion": min(25, round(cohesion * 2.5)),
        "Threat Intelligence": 10 if "KNOWN_MALICIOUS_IP" in flags else 0,
        "Evidence Completeness": min(10, evidence_count * 2),
    }
    return min(100, sum(breakdown.values())), breakdown
