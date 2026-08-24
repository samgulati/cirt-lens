import random
from datetime import datetime, timedelta

from ..models import Event
from ..schemas.telemetry import (
    AuthenticationEventInput,
    CloudEventInput,
    EndpointEventInput,
    NetworkEventInput,
)
from ..services.pipeline import process_raw_telemetry
from ..services.scenario_generator import generate_raw_scenario

BASELINE_DEVICES = {
    "alice@example.com": {"DEVICE-ALICE-MAC"},
    "devon@example.com": {"DEVICE-DEVON-WIN"},
    "priya@example.com": {"DEVICE-PRIYA-LNX"},
    "marco@example.com": {"DEVICE-MARCO-WIN"},
}


def seed_database(db):
    if db.query(Event).count():
        return
    random.seed(42)
    now = datetime.utcnow()
    users = list(BASELINE_DEVICES)
    hosts = ["ENG-MAC-042", "FIN-WIN-017", "OPS-LNX-008", "HR-WIN-023", "DEV-LNX-031"]
    for i in range(320):
        source = i % 4
        timestamp = now - timedelta(minutes=random.randint(40, 1440))
        user = random.choice(users)
        host = random.choice(hosts)
        ip = f"10.{random.randint(1,50)}.{random.randint(1,250)}.{random.randint(2,250)}"
        common = {"id": f"EVT-{10000+i}", "timestamp": timestamp}
        if source == 0:
            event = AuthenticationEventInput(
                **common,
                user=user,
                source_ip=ip,
                country="India",
                city="Delhi",
                device_id=next(iter(BASELINE_DEVICES[user])),
                result="SUCCESS",
                mfa_result="APPROVED",
                authentication_method="FIDO2",
            )
        elif source == 1:
            event = EndpointEventInput(
                **common,
                hostname=host,
                user=user,
                process_name="trusted-agent",
                parent_process="services.exe",
                command_line="trusted-agent --health",
                process_hash=f"sha256:normal{i:04d}",
                event_type="PROCESS_START",
            )
        elif source == 2:
            event = NetworkEventInput(
                **common,
                source_ip=ip,
                destination_ip="192.0.2.10",
                destination_port=443,
                protocol="HTTPS",
                bytes_sent=2048,
                bytes_received=8192,
                domain="updates.example.test",
                country="India",
                user=user,
                hostname=host,
            )
        else:
            event = CloudEventInput(
                **common,
                user=user,
                source_ip=ip,
                service="ObjectStorage",
                action="ListResources",
                resource="general-documents",
                result="SUCCESS",
                device_id=next(iter(BASELINE_DEVICES[user])),
            )
        process_raw_telemetry(db, [event], BASELINE_DEVICES, correlate=False)
    # Two independently processed chains per type yield 30+ detected events while
    # preserving more than 300 normal background observations.
    kinds = ("credential", "endpoint", "exfiltration") * 2
    for offset, kind in enumerate(kinds):
        process_raw_telemetry(
            db,
            generate_raw_scenario(kind, 1001 + offset, now - timedelta(hours=offset * 2)),
            BASELINE_DEVICES,
        )
