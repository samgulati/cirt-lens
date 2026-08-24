from typing import Any

ATTACK_MAPPING_VERSION = "MITRE ATT&CK Enterprise (verified 2026-08-20; simplified demo mapping)"
MAPPINGS = {
    "SUSPICIOUS_POWERSHELL": (
        "T1059.001",
        "PowerShell",
        "PowerShell executed with an encoded-command or download-expression pattern.",
    ),
    "CREDENTIAL_ACCESS": (
        "T1003",
        "OS Credential Dumping",
        "Structured endpoint telemetry explicitly recorded access to OS credential material.",
    ),
    "PERSISTENCE": (
        "T1547.001",
        "Registry Run Keys / Startup Folder",
        "Structured endpoint telemetry recorded a Registry Run Keys persistence modification.",
    ),
    "IMPOSSIBLE_TRAVEL": (
        "T1078",
        "Valid Accounts",
        "A valid account authenticated across geographically inconsistent locations.",
    ),
    "NEW_DEVICE": (
        "T1078",
        "Valid Accounts",
        "A valid account was used from a device outside its trusted baseline.",
    ),
    "MFA_FATIGUE": (
        "T1621",
        "Multi-Factor Authentication Request Generation",
        "Repeated MFA requests were generated for the same identity inside a short window.",
    ),
}


def map_techniques(findings):
    mapped: dict[str, dict[str, Any]] = {}
    for item in findings:
        if item.flag not in MAPPINGS:
            continue
        tid, name, reason = MAPPINGS[item.flag]
        technique = mapped.setdefault(
            tid,
            {
                "id": tid,
                "name": name,
                "reason": reason,
                "evidence_ids": [],
                "mapping_version": ATTACK_MAPPING_VERSION,
            },
        )
        for event_id in [item.event_id, *item.metadata.get("evidence_ids", [])]:
            if event_id not in technique["evidence_ids"]:
                technique["evidence_ids"].append(event_id)
    return list(mapped.values())
