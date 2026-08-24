from collections import defaultdict
from datetime import timedelta

from ..config import settings
from ..schemas.telemetry import (
    AuthenticationEventInput,
    CloudEventInput,
    DetectionFinding,
    EndpointEventInput,
    NetworkEventInput,
    TelemetryInput,
)

MALICIOUS_IPS = {"203.0.113.50", "198.51.100.77", "192.0.2.91"}
RULES = {
    "AUTH-001": (
        "Impossible Travel",
        "1.1",
        "Geography changed inside the configured window.",
        30,
        "behavioral",
    ),
    "AUTH-002": (
        "MFA Request Generation",
        "1.1",
        "Repeated denied MFA requests.",
        25,
        "behavioral",
    ),
    "AUTH-003": (
        "New Device Observation",
        "1.1",
        "Device is absent from trusted baseline.",
        12,
        "behavioral",
    ),
    "ENDP-001": ("Suspicious PowerShell", "1.0", "Suspicious PowerShell pattern.", 30, "execution"),
    "ENDP-002": (
        "Credential Material Access",
        "1.0",
        "OS credential-store access.",
        30,
        "credential_access",
    ),
    "ENDP-003": ("Registry Run Key Persistence", "1.0", "Run-key modification.", 25, "persistence"),
    "NET-001": (
        "Known Demo Threat Destination",
        "1.0",
        "Demo intelligence match.",
        35,
        "threat_intelligence",
    ),
    "NET-002": ("Unusual Egress", "1.0", "Outbound threshold exceeded.", 25, "exfiltration"),
    "NET-003": ("High-volume Data Transfer", "1.1", "Twice egress threshold.", 30, "exfiltration"),
    "CLOUD-001": ("Unusual Administrative Action", "1.0", "Privileged action.", 20, "privilege"),
    "CLOUD-002": ("Sensitive Resource Access", "1.0", "Sensitive resource.", 20, "impact"),
    "CLOUD-003": ("Sensitive Resource Download", "1.0", "Sensitive download.", 20, "collection"),
    "CLOUD-004": (
        "Post-authentication Privileged Action",
        "1.1",
        "Privileged action follows suspicious auth.",
        30,
        "privilege",
    ),
}


def finding(event, rule, flag, risk, reason, **metadata):
    return DetectionFinding(
        event_id=event.id,
        rule_id=rule,
        rule_version=RULES[rule][1],
        flag=flag,
        risk_contribution=risk,
        reason=reason,
        metadata=metadata,
    )


def detect_impossible_travel(events, window_minutes=None):
    window = timedelta(minutes=window_minutes or settings.impossible_travel_window_minutes)
    auth = sorted(
        (e for e in events if isinstance(e, AuthenticationEventInput) and e.result == "SUCCESS"),
        key=lambda e: e.timestamp,
    )
    results = []
    recent: defaultdict[str, list[AuthenticationEventInput]] = defaultdict(list)
    for current in auth:
        candidates = recent[current.user]
        while candidates and current.timestamp - candidates[0].timestamp > window:
            candidates.pop(0)
        for previous in reversed(candidates):
            delta = current.timestamp - previous.timestamp
            if current.country != previous.country and timedelta(0) <= delta <= window:
                minutes = int(delta.total_seconds() / 60)
                reason = f"Successful authentications for {current.user} occurred from {previous.country} and {current.country} within {minutes} minutes."
                results.extend(
                    [
                        finding(
                            previous,
                            "AUTH-001",
                            "IMPOSSIBLE_TRAVEL",
                            0,
                            reason,
                            paired_event_id=current.id,
                            countries=[previous.country, current.country],
                            minutes=minutes,
                        ),
                        finding(
                            current,
                            "AUTH-001",
                            "IMPOSSIBLE_TRAVEL",
                            30,
                            reason,
                            previous_event_id=previous.id,
                            countries=[previous.country, current.country],
                            minutes=minutes,
                        ),
                    ]
                )
                break
        candidates.append(current)
    return results


def detect_mfa_fatigue(events, threshold=None, window_minutes=None):
    threshold = threshold or settings.mfa_fatigue_threshold
    window = timedelta(minutes=window_minutes or settings.mfa_fatigue_window_minutes)
    by_user = defaultdict(list)
    results = []
    for event in sorted(events, key=lambda e: e.timestamp):
        if isinstance(event, AuthenticationEventInput) and event.mfa_result == "DENIED":
            by_user[event.user].append(event)
    for user, denied in by_user.items():
        for index in range(threshold - 1, len(denied)):
            group = denied[index - threshold + 1 : index + 1]
            if group[-1].timestamp - group[0].timestamp <= window:
                reason = f"{threshold} denied MFA prompts for {user} occurred within {int((group[-1].timestamp-group[0].timestamp).total_seconds()/60)+1} minutes."
                for position, event in enumerate(group):
                    results.append(
                        finding(
                            event,
                            "AUTH-002",
                            "MFA_FATIGUE",
                            7 if position == len(group) - 1 else 6,
                            reason,
                            evidence_ids=[e.id for e in group],
                        )
                    )
                break
    return results


def detect_new_devices(events, baseline_devices=None):
    trusted = {user: set(devices) for user, devices in (baseline_devices or {}).items()}
    results = []
    for event in sorted(events, key=lambda e: e.timestamp):
        if isinstance(event, AuthenticationEventInput) and event.device_id not in trusted.get(
            event.user, set()
        ):
            results.append(
                finding(
                    event,
                    "AUTH-003",
                    "NEW_DEVICE",
                    12,
                    f"Device {event.device_id} is not present in the trusted behavioral baseline for {event.user}.",
                    device_id=event.device_id,
                    authentication_result=event.result,
                )
            )
    return results


def detect_powershell(event):
    return (
        isinstance(event, EndpointEventInput)
        and "powershell" in event.process_name.lower()
        and any(
            x in event.command_line.lower() for x in ("-encodedcommand", "iex", "downloadstring")
        )
    )


def detect_malicious_ip(event):
    return isinstance(event, NetworkEventInput) and event.destination_ip in MALICIOUS_IPS


def detect_event_rules(event):
    results = []
    if detect_powershell(event):
        results.append(
            finding(
                event,
                "ENDP-001",
                "SUSPICIOUS_POWERSHELL",
                30,
                "PowerShell executed with a suspicious encoded or download-expression pattern.",
            )
        )
    if isinstance(event, EndpointEventInput):
        if event.event_type.upper() == "CREDENTIAL_STORE_ACCESS":
            results.append(
                finding(
                    event,
                    "ENDP-002",
                    "CREDENTIAL_ACCESS",
                    30,
                    "Structured endpoint telemetry recorded access to OS credential material.",
                )
            )
        if event.event_type.upper() == "RUN_KEY_MODIFICATION":
            results.append(
                finding(
                    event,
                    "ENDP-003",
                    "PERSISTENCE",
                    25,
                    "Structured endpoint telemetry recorded a Registry Run Keys persistence modification.",
                )
            )
    if isinstance(event, NetworkEventInput):
        if detect_malicious_ip(event):
            results.append(
                finding(
                    event,
                    "NET-001",
                    "KNOWN_MALICIOUS_IP",
                    35,
                    f"Destination {event.destination_ip} matched the synthetic documentation-range threat-intelligence set.",
                )
            )
        if event.bytes_sent >= settings.unusual_egress_bytes:
            results.append(
                finding(
                    event,
                    "NET-002",
                    "UNUSUAL_EGRESS",
                    25,
                    f"Outbound transfer of {event.bytes_sent:,} bytes exceeded the {settings.unusual_egress_bytes:,}-byte demo threshold.",
                )
            )
        if event.bytes_sent >= settings.unusual_egress_bytes * 2:
            results.append(
                finding(
                    event,
                    "NET-003",
                    "DATA_EXFILTRATION",
                    30,
                    "Outbound volume was at least twice the unusual-egress threshold; channel semantics remain unclassified.",
                )
            )
    if isinstance(event, CloudEventInput):
        if event.privileged:
            results.append(
                finding(
                    event,
                    "CLOUD-001",
                    "UNUSUAL_ADMIN_ACTION",
                    20,
                    f"Privileged {event.service} action {event.action} was observed.",
                )
            )
        if event.sensitive_resource:
            results.append(
                finding(
                    event,
                    "CLOUD-002",
                    "SENSITIVE_RESOURCE_ACCESS",
                    20,
                    f"Cloud action targeted explicitly sensitive resource {event.resource}.",
                )
            )
            if event.action.lower() in {"downloadobject", "getobject", "download", "export"}:
                results.append(
                    finding(
                        event,
                        "CLOUD-003",
                        "MASS_DOWNLOAD",
                        20,
                        f"A download action targeted sensitive resource {event.resource}.",
                    )
                )
    return results


def detect_temporal_privilege(events, findings):
    # Denied MFA prompts are useful context, but cannot establish an authenticated
    # session. Only successful authentications with a causal anomaly qualify.
    suspicious_ids = {f.event_id for f in findings if f.flag in {"IMPOSSIBLE_TRAVEL", "NEW_DEVICE"}}
    auth = [
        e
        for e in events
        if isinstance(e, AuthenticationEventInput)
        and e.result == "SUCCESS"
        and e.id in suspicious_ids
    ]
    results = []
    window = timedelta(minutes=settings.privileged_action_after_auth_window_minutes)
    for cloud in (e for e in events if isinstance(e, CloudEventInput) and e.privileged):
        prior = [
            e
            for e in auth
            if e.user == cloud.user and timedelta(0) <= cloud.timestamp - e.timestamp <= window
        ]
        if prior:
            closest = max(prior, key=lambda e: e.timestamp)
            minutes = int((cloud.timestamp - closest.timestamp).total_seconds() / 60)
            results.append(
                finding(
                    cloud,
                    "CLOUD-004",
                    "PRIVILEGE_ESCALATION",
                    30,
                    f"Privileged {cloud.service} action occurred {minutes} minutes after suspicious authentication for {cloud.user}.",
                    authentication_evidence_ids=[e.id for e in prior],
                    elapsed_minutes=minutes,
                    privileged_event_id=cloud.id,
                )
            )
    return results


def run_detection(events: list[TelemetryInput], baseline_devices=None):
    results = (
        detect_impossible_travel(events)
        + detect_mfa_fatigue(events)
        + detect_new_devices(events, baseline_devices)
    )
    for event in events:
        results.extend(detect_event_rules(event))
    results.extend(detect_temporal_privilege(events, results))
    return results
