"""OpenTelemetry bootstrap for HTTP, database, cache, storage, and HTTP clients."""

import logging
import socket

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_provider: TracerProvider | None = None
_configured = False


def configure_tracing(app: FastAPI) -> None:
    """Configure tracing once without making telemetry a startup dependency."""
    global _configured, _provider
    if _configured:
        return
    _configured = True

    exporter_name = settings.OTEL_TRACES_EXPORTER.lower()
    if not settings.OTEL_ENABLED or exporter_name == "none":
        logger.info("OpenTelemetry tracing disabled")
        return

    try:
        resource = Resource.create(
            {
                "service.name": settings.OTEL_SERVICE_NAME or settings.APP_NAME,
                "service.version": settings.APP_VERSION,
                "service.instance.id": socket.gethostname(),
                "deployment.environment.name": settings.OTEL_DEPLOYMENT_ENVIRONMENT,
            }
        )
        provider = TracerProvider(
            resource=resource,
            sampler=ParentBased(TraceIdRatioBased(settings.OTEL_TRACE_SAMPLE_RATIO)),
        )
        if exporter_name == "console":
            exporter = ConsoleSpanExporter()
        elif exporter_name == "otlp":
            exporter = OTLPSpanExporter(
                endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT,
                insecure=settings.OTEL_EXPORTER_OTLP_INSECURE,
            )
        else:
            raise ValueError(
                "OTEL_TRACES_EXPORTER must be one of: otlp, console, none"
            )

        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _provider = provider
    except Exception:
        _provider = None
        logger.exception("OpenTelemetry setup failed; continuing without tracing")
        return

    instrumentors = {
        "FastAPI": lambda: FastAPIInstrumentor.instrument_app(
            app,
            tracer_provider=provider,
            excluded_urls=settings.OTEL_EXCLUDED_URLS,
        ),
        "psycopg": lambda: PsycopgInstrumentor().instrument(
            tracer_provider=provider
        ),
        "Redis": lambda: RedisInstrumentor().instrument(tracer_provider=provider),
        "HTTPX": lambda: HTTPXClientInstrumentor().instrument(
            tracer_provider=provider
        ),
        "botocore": lambda: BotocoreInstrumentor().instrument(
            tracer_provider=provider
        ),
    }
    for name, instrument in instrumentors.items():
        try:
            instrument()
        except Exception:
            logger.exception("Could not enable %s tracing", name)

    logger.info(
        "OpenTelemetry tracing enabled: exporter=%s endpoint=%s sample_ratio=%s",
        exporter_name,
        settings.OTEL_EXPORTER_OTLP_ENDPOINT if exporter_name == "otlp" else "stdout",
        settings.OTEL_TRACE_SAMPLE_RATIO,
    )


def shutdown_tracing() -> None:
    """Flush queued spans during graceful application shutdown."""
    if _provider is not None:
        _provider.shutdown()


def current_trace_id() -> str | None:
    """Return the active W3C trace ID in its canonical 32-character form."""
    context = trace.get_current_span().get_span_context()
    if not context.is_valid:
        return None
    return format(context.trace_id, "032x")
