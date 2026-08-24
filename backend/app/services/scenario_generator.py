from datetime import UTC, datetime, timedelta

from ..schemas.telemetry import (
    AuthenticationEventInput,
    CloudEventInput,
    EndpointEventInput,
    NetworkEventInput,
    TelemetryInput,
)


def generate_raw_scenario(kind, sequence, now=None) -> list[TelemetryInput]:
    now = (now or datetime.now(UTC)).replace(tzinfo=None)
    base = now - timedelta(minutes=31)
    n = sequence
    if kind == "credential":
        raw: list[TelemetryInput] = [
            AuthenticationEventInput(
                id=f"AUTH-{n}0",
                timestamp=base,
                user="alice@example.com",
                source_ip="10.10.4.22",
                country="India",
                city="Bangalore",
                device_id="DEVICE-ALICE-MAC",
                result="SUCCESS",
                mfa_result="APPROVED",
                authentication_method="Push MFA",
            ),
            AuthenticationEventInput(
                id=f"AUTH-{n}1",
                timestamp=base + timedelta(minutes=15),
                user="alice@example.com",
                source_ip="203.0.113.50",
                country="Germany",
                city="Frankfurt",
                device_id="DEVICE-NEW-019",
                result="SUCCESS",
                mfa_result="NOT_REQUIRED",
                authentication_method="Password",
            ),
        ]
        for i in range(4):
            raw.append(
                AuthenticationEventInput(
                    id=f"AUTH-{n}{i+2}",
                    timestamp=base + timedelta(minutes=16 + i),
                    user="alice@example.com",
                    source_ip="203.0.113.50",
                    country="Germany",
                    city="Frankfurt",
                    device_id="DEVICE-NEW-019",
                    result="FAILURE",
                    mfa_result="DENIED",
                    authentication_method="Push MFA",
                )
            )
        raw += [
            AuthenticationEventInput(
                id=f"AUTH-{n}6",
                timestamp=base + timedelta(minutes=20),
                user="alice@example.com",
                source_ip="203.0.113.50",
                country="Germany",
                city="Frankfurt",
                device_id="DEVICE-NEW-019",
                result="SUCCESS",
                mfa_result="APPROVED",
                authentication_method="Push MFA",
            ),
            CloudEventInput(
                id=f"CLOUD-{n}7",
                timestamp=base + timedelta(minutes=25),
                user="alice@example.com",
                source_ip="203.0.113.50",
                service="IAM",
                action="UpdatePolicy",
                resource="arn:demo:iam::policy/SecurityAdmin",
                result="SUCCESS",
                privileged=True,
                device_id="DEVICE-NEW-019",
            ),
            CloudEventInput(
                id=f"CLOUD-{n}8",
                timestamp=base + timedelta(minutes=30),
                user="alice@example.com",
                source_ip="203.0.113.50",
                service="ObjectStorage",
                action="DownloadObject",
                resource="demo://finance-sensitive/forecast.csv",
                result="SUCCESS",
                sensitive_resource=True,
                device_id="DEVICE-NEW-019",
            ),
        ]
        return raw
    if kind == "endpoint":
        return [
            EndpointEventInput(
                id=f"ENDP-{n}0",
                timestamp=base,
                hostname="FIN-WIN-017",
                user="devon@example.com",
                process_name="powershell.exe",
                parent_process="winword.exe",
                command_line="powershell.exe -EncodedCommand SYNTHETIC_NOT_EXECUTABLE",
                process_hash="demo-sha256-001",
                event_type="PROCESS_START",
            ),
            EndpointEventInput(
                id=f"ENDP-{n}1",
                timestamp=base + timedelta(minutes=4),
                hostname="FIN-WIN-017",
                user="devon@example.com",
                process_name="demo-tool.exe",
                parent_process="powershell.exe",
                command_line="synthetic credential test",
                process_hash="demo-sha256-002",
                event_type="CREDENTIAL_STORE_ACCESS",
            ),
            NetworkEventInput(
                id=f"NET-{n}2",
                timestamp=base + timedelta(minutes=8),
                source_ip="10.20.5.17",
                destination_ip="203.0.113.50",
                destination_port=443,
                protocol="TLS",
                bytes_sent=24000,
                bytes_received=8000,
                domain="demo-c2.invalid",
                country="Test Range",
                user="devon@example.com",
                hostname="FIN-WIN-017",
            ),
            EndpointEventInput(
                id=f"ENDP-{n}3",
                timestamp=base + timedelta(minutes=14),
                hostname="FIN-WIN-017",
                user="devon@example.com",
                process_name="reg.exe",
                parent_process="powershell.exe",
                command_line="synthetic run-key telemetry",
                process_hash="demo-sha256-003",
                event_type="RUN_KEY_MODIFICATION",
            ),
        ]
    return [
        CloudEventInput(
            id=f"CLOUD-{n}0",
            timestamp=base,
            user="priya@example.com",
            source_ip="198.51.100.22",
            service="AdminConsole",
            action="AssumeAdminRole",
            resource="arn:demo:role/DataAdmin",
            result="SUCCESS",
            privileged=True,
        ),
        CloudEventInput(
            id=f"CLOUD-{n}1",
            timestamp=base + timedelta(minutes=5),
            user="priya@example.com",
            source_ip="198.51.100.22",
            service="ObjectStorage",
            action="ListObjects",
            resource="demo://sensitive-analytics",
            result="SUCCESS",
            sensitive_resource=True,
        ),
        NetworkEventInput(
            id=f"NET-{n}2",
            timestamp=base + timedelta(minutes=12),
            source_ip="10.30.8.8",
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="TLS",
            bytes_sent=650000000,
            bytes_received=12000,
            domain="transfer.invalid",
            country="Test Range",
            user="priya@example.com",
            hostname="OPS-LNX-008",
        ),
        NetworkEventInput(
            id=f"NET-{n}3",
            timestamp=base + timedelta(minutes=20),
            source_ip="10.30.8.8",
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="TLS",
            bytes_sent=1100000000,
            bytes_received=9000,
            domain="transfer.invalid",
            country="Test Range",
            user="priya@example.com",
            hostname="OPS-LNX-008",
        ),
    ]
