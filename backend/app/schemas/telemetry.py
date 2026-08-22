from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class RawEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=3, max_length=80)
    timestamp: datetime
    schema_version: Literal["1.0"] = "1.0"

class AuthenticationEventInput(RawEvent):
    telemetry_type: Literal["authentication"] = "authentication"
    user: str
    source_ip: str
    country: str
    city: str
    device_id: str
    result: Literal["SUCCESS", "FAILURE"]
    mfa_result: Literal["APPROVED", "DENIED", "NOT_REQUIRED"]
    authentication_method: str

class EndpointEventInput(RawEvent):
    telemetry_type: Literal["endpoint"] = "endpoint"
    hostname: str
    user: str
    process_name: str
    parent_process: str
    command_line: str
    process_hash: str
    event_type: str
    destination_ip: str | None = None

class NetworkEventInput(RawEvent):
    telemetry_type: Literal["network"] = "network"
    source_ip: str
    destination_ip: str
    destination_port: int = Field(ge=1, le=65535)
    protocol: str
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)
    domain: str | None = None
    country: str
    user: str | None = None
    hostname: str | None = None

class CloudEventInput(RawEvent):
    telemetry_type: Literal["cloud"] = "cloud"
    user: str
    source_ip: str
    service: str
    action: str
    resource: str
    result: Literal["SUCCESS", "FAILURE"]
    privileged: bool = False
    sensitive_resource: bool = False
    device_id: str | None = None

TelemetryInput = AuthenticationEventInput | EndpointEventInput | NetworkEventInput | CloudEventInput

class DetectionFinding(BaseModel):
    event_id: str
    rule_id: str
    rule_version: str = "1.0"
    flag: str
    risk_contribution: int
    reason: str
    metadata: dict = {}
