from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, Gauge, Histogram, make_asgi_app

from .config import settings

HTTP_LATENCY = Histogram(
    "cirt_http_request_seconds", "HTTP request latency", ["method", "path", "status"]
)
DETECTION_LATENCY = Histogram("cirt_detection_seconds", "Detection processing latency")
CORRELATION_GROUPS = Counter("cirt_correlation_groups_total", "Correlated groups")
AI_FALLBACKS = Counter("cirt_ai_fallback_total", "AI local fallbacks")
ACTIONS = Counter("cirt_response_actions_total", "Response actions", ["action", "status"])
APPROVALS = Counter("cirt_action_approvals_total", "Approval lifecycle transitions", ["status"])
APPROVAL_AGE = Histogram("cirt_action_approval_age_seconds", "Age of approvals when decided")
CONNECTOR_FAILURES = Counter(
    "cirt_connector_failures_total", "Connector failures", ["connector", "code", "retryable"]
)
INGESTION = Counter("cirt_ingestion_jobs_total", "Ingestion jobs", ["status"])
DLQ_DEPTH = Gauge("cirt_ingestion_dlq_depth", "Redis stream DLQ depth")
QUEUE_DEPTH = Gauge("cirt_ingestion_queue_depth", "Redis telemetry stream depth")


def install_observability(app):
    provider = TracerProvider(
        resource=Resource.create(
            {"service.name": "cirt-lens-api", "deployment.environment": settings.environment}
        )
    )
    if settings.otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otlp_endpoint))
        )
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)
    app.mount("/metrics", make_asgi_app())


install_metrics = install_observability
