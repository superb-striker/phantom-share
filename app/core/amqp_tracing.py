"""W3C trace-context propagation across aio-pika message boundaries."""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager

from opentelemetry import propagate, trace
from opentelemetry.trace import SpanKind

tracer = trace.get_tracer("phantom.amqp")


def _carrier(headers: Mapping | None) -> dict[str, str]:
    carrier: dict[str, str] = {}
    for key, value in (headers or {}).items():
        normalized_key = key.decode() if isinstance(key, bytes) else str(key)
        normalized_value = value.decode() if isinstance(value, bytes) else str(value)
        carrier[normalized_key] = normalized_value
    return carrier


def inject_trace_headers(headers: Mapping | None = None) -> dict[str, str]:
    """Copy application headers and inject the active W3C trace context."""
    carrier = _carrier(headers)
    propagate.inject(carrier)
    return carrier


@contextmanager
def message_span(
    name: str,
    *,
    kind: SpanKind,
    destination: str,
    headers: Mapping | None = None,
    operation: str,
) -> Iterator[trace.Span]:
    """Start a messaging span, extracting a remote parent when supplied."""
    parent = propagate.extract(_carrier(headers)) if headers else None
    attributes = {
        "messaging.system": "rabbitmq",
        "messaging.destination.name": destination,
        "messaging.operation.type": operation,
    }
    with tracer.start_as_current_span(
        name,
        context=parent,
        kind=kind,
        attributes=attributes,
        record_exception=True,
        set_status_on_exception=True,
    ) as span:
        yield span
