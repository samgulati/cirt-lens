import os
from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    environment: str = os.getenv("ENVIRONMENT", "development")
    auth_mode: str = os.getenv("AUTH_MODE", "local")
    auth_secret: str = os.getenv("AUTH_SECRET", "local-demo-secret-change-in-production")
    auth_required: bool = os.getenv("AUTH_REQUIRED", "false").lower() == "true"
    default_tenant_id: str = os.getenv("DEFAULT_TENANT_ID", "tenant-demo")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    telemetry_stream: str = os.getenv("TELEMETRY_STREAM", "cirt:telemetry")
    telemetry_dlq: str = os.getenv("TELEMETRY_DLQ", "cirt:telemetry:dlq")
    max_processing_attempts: int = int(os.getenv("MAX_PROCESSING_ATTEMPTS", "3"))
    connector_mode: str = os.getenv("CONNECTOR_MODE", "fake")
    auth0_connector_live: bool = os.getenv("AUTH0_CONNECTOR_LIVE", "false").lower() == "true"
    auth0_allowed_target_users: str = os.getenv("AUTH0_ALLOWED_TARGET_USERS", "")
    auth0_connector_target_user: str = os.getenv("AUTH0_CONNECTOR_TARGET_USER", "")
    auth0_management_client_id: str = os.getenv("AUTH0_MANAGEMENT_CLIENT_ID", "")
    auth0_management_client_secret: str = os.getenv("AUTH0_MANAGEMENT_CLIENT_SECRET", "")
    oidc_issuer: str = os.getenv("OIDC_ISSUER", "")
    oidc_jwks_url: str = os.getenv("OIDC_JWKS_URL", "")
    oidc_audience: str = os.getenv("OIDC_AUDIENCE", "cirt-lens")
    oidc_claim_namespace: str = os.getenv("OIDC_CLAIM_NAMESPACE", "https://github.com/samgulati/cirt-lens")
    otlp_endpoint: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    impossible_travel_window_minutes: int = int(os.getenv("IMPOSSIBLE_TRAVEL_WINDOW_MINUTES", "60"))
    mfa_fatigue_threshold: int = int(os.getenv("MFA_FATIGUE_THRESHOLD", "4"))
    mfa_fatigue_window_minutes: int = int(os.getenv("MFA_FATIGUE_WINDOW_MINUTES", "10"))
    unusual_egress_bytes: int = int(os.getenv("UNUSUAL_EGRESS_BYTES", "500000000"))
    correlation_window_minutes: int = int(os.getenv("CORRELATION_WINDOW_MINUTES", "60"))
    correlation_min_score: int = int(os.getenv("CORRELATION_MIN_SCORE", "5"))
    privileged_action_after_auth_window_minutes: int = int(os.getenv("PRIVILEGED_ACTION_AFTER_AUTH_WINDOW_MINUTES", "60"))
    max_incident_span_minutes: int = int(os.getenv("MAX_INCIDENT_SPAN_MINUTES", "90"))
    min_group_cohesion_score: float = float(os.getenv("MIN_GROUP_COHESION_SCORE", "5"))

settings = Settings()
