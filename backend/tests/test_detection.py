from datetime import timedelta

from app.schemas.telemetry import (
    AuthenticationEventInput,
    CloudEventInput,
    EndpointEventInput,
    NetworkEventInput,
)
from app.services.detection_engine import (
    detect_event_rules,
    detect_impossible_travel,
    detect_malicious_ip,
    detect_mfa_fatigue,
    detect_new_devices,
    detect_powershell,
    detect_temporal_privilege,
)


def auth(i, t, user="alice", country="India", device="known", mfa="APPROVED", result="SUCCESS"):
    return AuthenticationEventInput(
        id=f"AUTH-{i}",
        timestamp=t,
        user=user,
        source_ip="10.0.0.1",
        country=country,
        city="City",
        device_id=device,
        result=result,
        mfa_result=mfa,
        authentication_method="push",
    )


def endpoint(t, command="Write-Output safe", kind="PROCESS_START"):
    return EndpointEventInput(
        id="ENDP-1",
        timestamp=t,
        hostname="H",
        user="u",
        process_name="PoWeRsHeLl.ExE",
        parent_process="p",
        command_line=command,
        process_hash="x",
        event_type=kind,
    )


def network(t, ip="8.8.8.8", size=1):
    return NetworkEventInput(
        id="NET-1",
        timestamp=t,
        source_ip="10.0.0.1",
        destination_ip=ip,
        destination_port=443,
        protocol="TLS",
        bytes_sent=size,
        bytes_received=0,
        country="US",
    )


def test_impossible_travel_positive(now):
    assert detect_impossible_travel(
        [auth(1, now), auth(2, now + timedelta(minutes=20), country="Germany")]
    )


def test_impossible_travel_outside_window(now):
    assert not detect_impossible_travel(
        [auth(1, now), auth(2, now + timedelta(minutes=61), country="Germany")]
    )


def test_impossible_travel_different_users(now):
    assert not detect_impossible_travel(
        [auth(1, now), auth(2, now + timedelta(minutes=10), user="bob", country="Germany")]
    )


def test_impossible_travel_same_country(now):
    assert not detect_impossible_travel([auth(1, now), auth(2, now + timedelta(minutes=10))])


def test_mfa_fatigue_positive(now):
    assert detect_mfa_fatigue(
        [auth(i, now + timedelta(minutes=i), mfa="DENIED", result="FAILURE") for i in range(4)]
    )


def test_mfa_fatigue_only_three(now):
    assert not detect_mfa_fatigue(
        [auth(i, now + timedelta(minutes=i), mfa="DENIED", result="FAILURE") for i in range(3)]
    )


def test_mfa_fatigue_outside_window(now):
    assert not detect_mfa_fatigue(
        [auth(i, now + timedelta(minutes=i * 4), mfa="DENIED", result="FAILURE") for i in range(4)]
    )


def test_suspicious_powershell_case_insensitive(now):
    assert detect_powershell(endpoint(now, "-eNcOdEdCoMmAnD harmless"))


def test_safe_powershell(now):
    assert not detect_powershell(endpoint(now))


def test_hostile_string_is_plain_data(now):
    event = endpoint(now, "-EncodedCommand $(touch /tmp/must-not-exist); `id`")
    findings = detect_event_rules(event)
    assert findings and event.command_line.endswith("`id`")


def test_malicious_ip(now):
    assert detect_malicious_ip(network(now, "203.0.113.50"))


def test_safe_ip(now):
    assert not detect_malicious_ip(network(now))


def test_unusual_egress_threshold(now):
    assert "UNUSUAL_EGRESS" in {f.flag for f in detect_event_rules(network(now, size=500000000))}


def test_sensitive_resource(now):
    event = CloudEventInput(
        id="CLOUD-1",
        timestamp=now,
        user="u",
        source_ip="1.1.1.1",
        service="S3",
        action="DownloadObject",
        resource="sensitive",
        result="SUCCESS",
        sensitive_resource=True,
    )
    assert {"SENSITIVE_RESOURCE_ACCESS", "MASS_DOWNLOAD"} <= {
        f.flag for f in detect_event_rules(event)
    }


def test_new_device_observation_never_pollutes_trusted_baseline(now):
    baseline = {"alice": {"known"}}
    failed = auth(20, now, device="attacker", mfa="DENIED", result="FAILURE")
    succeeded = auth(21, now + timedelta(minutes=5), device="attacker")
    assert detect_new_devices([failed], baseline)
    assert detect_new_devices([succeeded], baseline)
    assert baseline == {"alice": {"known"}}
    assert not detect_new_devices([auth(22, now, device="known")], baseline)


def test_privileged_action_requires_prior_same_user_auth_in_window(now):
    suspicious = auth(30, now, device="attacker")
    auth_findings = detect_new_devices([suspicious], {"alice": {"known"}})

    def cloud(i, when, user="alice"):
        return CloudEventInput(
            id=f"CLOUD-{i}",
            timestamp=when,
            user=user,
            source_ip="10.0.0.1",
            service="IAM",
            action="AddRole",
            resource="role",
            result="SUCCESS",
            privileged=True,
        )

    positive = detect_temporal_privilege(
        [suspicious, cloud(30, now + timedelta(minutes=10))], auth_findings
    )
    assert positive and positive[0].metadata["elapsed_minutes"] == 10
    assert not detect_temporal_privilege(
        [suspicious, cloud(31, now - timedelta(minutes=1))], auth_findings
    )
    assert not detect_temporal_privilege(
        [suspicious, cloud(32, now + timedelta(hours=2))], auth_findings
    )
    assert not detect_temporal_privilege(
        [suspicious, cloud(33, now + timedelta(minutes=10), "bob")], auth_findings
    )
