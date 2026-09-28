"""
middleware/audit.py – Starlette middleware that attaches the client IP
to the request state so route handlers can pass it to audit_service.log.
Also adds standard security response headers.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.client_ip import resolve_client_ip
from app.core.tracing import current_trace_id


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request.state.client_ip = resolve_client_ip(
            request.client.host if request.client else None,
            request.headers.get("X-Forwarded-For"),
        )
        trace_id = current_trace_id()
        request.state.trace_id = trace_id
        response = await call_next(request)
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if trace_id:
            response.headers["X-Trace-ID"] = trace_id
        return response
