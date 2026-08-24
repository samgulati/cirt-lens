ACTION_REDUCTIONS = {
    "Revoke active sessions": 12,
    "Force password reset": 10,
    "Block source IP": 8,
    "Isolate host": 20,
    "Kill suspicious process": 8,
    "Block destination": 12,
    "Disable account": 15,
    "Collect forensic snapshot": 0,
    "Preserve evidence": 0,
    "Escalate incident": 0,
}
PLAYBOOKS = [
    {
        "id": "credential",
        "name": "Credential Compromise",
        "description": "Contain account takeover.",
        "conditions": ["IMPOSSIBLE_TRAVEL", "MFA_FATIGUE or NEW_DEVICE"],
        "required_objectives": ["invalidate_session", "secure_identity"],
        "actions": {
            "Revoke active sessions": ["invalidate_session"],
            "Disable account": ["secure_identity"],
            "Force password reset": ["secure_identity"],
            "Block source IP": ["block_known_source"],
            "Escalate incident": [],
        },
    },
    {
        "id": "endpoint",
        "name": "Endpoint Compromise",
        "description": "Contain malicious execution.",
        "conditions": ["SUSPICIOUS_POWERSHELL or CREDENTIAL_ACCESS"],
        "required_objectives": ["isolate_host", "stop_malicious_execution"],
        "actions": {
            "Isolate host": ["isolate_host"],
            "Kill suspicious process": ["stop_malicious_execution"],
            "Block destination": ["block_destination"],
            "Collect forensic snapshot": [],
        },
    },
    {
        "id": "exfiltration",
        "name": "Data Exfiltration",
        "description": "Stop suspicious transfer.",
        "conditions": ["UNUSUAL_EGRESS", "Sensitive resource activity"],
        "required_objectives": ["block_destination", "restrict_identity"],
        "actions": {
            "Block destination": ["block_destination"],
            "Disable account": ["restrict_identity"],
            "Preserve evidence": [],
            "Escalate incident": [],
        },
    },
]


def select_playbook(flags):
    flags = set(flags)
    if "IMPOSSIBLE_TRAVEL" in flags and flags & {"MFA_FATIGUE", "NEW_DEVICE"}:
        return PLAYBOOKS[0]
    if "SUSPICIOUS_POWERSHELL" in flags and flags & {"CREDENTIAL_ACCESS", "KNOWN_MALICIOUS_IP"}:
        return PLAYBOOKS[1]
    if "UNUSUAL_EGRESS" in flags and flags & {
        "SENSITIVE_RESOURCE_ACCESS",
        "MASS_DOWNLOAD",
        "DATA_EXFILTRATION",
    }:
        return PLAYBOOKS[2]


def recommend_playbook(flags):
    selected = select_playbook(flags)
    if not selected:
        return []
    return [
        {
            "action": action,
            "reason": f"Derived {selected['name']} playbook conditions matched.",
            "risk_reduction": (
                "HIGH"
                if ACTION_REDUCTIONS[action] >= 12
                else "MEDIUM" if ACTION_REDUCTIONS[action] > 0 else "NONE"
            ),
            "reduction_points": ACTION_REDUCTIONS[action],
            "objectives": objectives,
            "status": "PENDING",
        }
        for action, objectives in selected["actions"].items()
    ]


def containment_progress(flags, actions):
    playbook = select_playbook(flags)
    if not playbook:
        return {"completed": 0, "required": 0, "objectives": []}
    completed = {
        objective
        for action in actions
        if action.get("status") == "EXECUTED"
        for objective in action.get("objectives", [])
    }
    required = set(playbook["required_objectives"])
    return {
        "completed": len(completed & required),
        "required": len(required),
        "objectives": [
            {"id": x, "complete": x in completed} for x in playbook["required_objectives"]
        ],
    }


def residual_risk(original, actions):
    return max(
        0,
        original
        - sum(
            ACTION_REDUCTIONS.get(a["action"], 0) for a in actions if a.get("status") == "EXECUTED"
        ),
    )
