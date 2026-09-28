from opentelemetry import propagate, trace
from opentelemetry.context import attach, detach
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags, TraceState

from app.core.amqp_tracing import inject_trace_headers


def test_amqp_headers_propagate_w3c_trace_context():
    span_context = SpanContext(
        trace_id=0x1234567890ABCDEF1234567890ABCDEF,
        span_id=0x1234567890ABCDEF,
        is_remote=False,
        trace_flags=TraceFlags.SAMPLED,
        trace_state=TraceState(),
    )
    token = attach(trace.set_span_in_context(NonRecordingSpan(span_context)))
    try:
        headers = inject_trace_headers({"x-retry-attempt": 2})
    finally:
        detach(token)

    extracted = trace.get_current_span(
        propagate.extract(headers)
    ).get_span_context()
    assert headers["x-retry-attempt"] == "2"
    assert extracted.trace_id == span_context.trace_id
    assert extracted.span_id == span_context.span_id
    assert extracted.is_remote is True
