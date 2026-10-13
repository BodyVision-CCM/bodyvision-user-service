"""Logs JSON (une ligne par événement) avec le traceId de la requête, pour Cloud Logging."""

import json
import logging
import re
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone

trace_id_var: ContextVar[str | None] = ContextVar("trace_id", default=None)

_STD_ATTRS = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_QUIET_PATHS = {"/healthz", "/readyz", "/metrics"}  # sondes : pas de journal d'accès (trop bruyant)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "service": "auth",
            "logger": record.name,
            "message": record.getMessage(),
        }
        if (tid := trace_id_var.get()) is not None:
            payload["traceId"] = tid
        payload.update({k: v for k, v in record.__dict__.items() if k not in _STD_ATTRS})
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # uvicorn installe ses propres handlers : on les remplace pour avoir un seul format JSON.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True


class RequestContextMiddleware:
    """Attribue un traceId à chaque requête (repris de X-Request-ID s'il est valide), le renvoie
    dans l'en-tête de réponse et journalise l'accès. ASGI pur : le traceId reste disponible
    pour les gestionnaires d'erreurs (request.state.trace_id)."""

    def __init__(self, app):
        self.app = app
        self.log = logging.getLogger("access")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = dict(scope["headers"]).get(b"x-request-id", b"").decode("latin-1")
        trace_id = incoming if _VALID_REQUEST_ID.match(incoming) else uuid.uuid4().hex
        scope.setdefault("state", {})["trace_id"] = trace_id
        token = trace_id_var.set(trace_id)
        started = time.perf_counter()
        status = 500

        async def send_with_trace(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message.setdefault("headers", []).append((b"x-request-id", trace_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_with_trace)
        finally:
            if scope["path"] not in _QUIET_PATHS:
                self.log.info(
                    "request",
                    extra={
                        "method": scope["method"],
                        "path": scope["path"],
                        "status": status,
                        "durationMs": round((time.perf_counter() - started) * 1000, 1),
                    },
                )
            trace_id_var.reset(token)
