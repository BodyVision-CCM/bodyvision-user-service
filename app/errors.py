"""Erreurs au format du contrat : {code, message, traceId} (schéma `Error` d'openapi.yaml)."""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger(__name__)


class Error(BaseModel):
    """Schéma `Error` du contrat."""

    code: str = Field(examples=["INVALID_CREDENTIALS"])
    message: str
    traceId: str | None = None


class AppError(Exception):
    def __init__(self, status_code: int, code: str, message: str, headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers
        super().__init__(message)


def unauthorized(code: str, message: str) -> AppError:
    return AppError(401, code, message, headers={"WWW-Authenticate": "Bearer"})


def _response(request: Request, status: int, code: str, message: str, headers=None) -> JSONResponse:
    body = Error(code=code, message=message, traceId=getattr(request.state, "trace_id", None))
    return JSONResponse(status_code=status, content=body.model_dump(exclude_none=True), headers=headers)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError):
        return _response(request, exc.status_code, exc.code, exc.message, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        # On n'inclut jamais la valeur reçue ("input") : elle peut contenir un mot de passe.
        parts = []
        for e in exc.errors():
            loc = ".".join(str(x) for x in e["loc"] if x not in ("body", "query", "path"))
            parts.append(f"{loc}: {e['msg']}" if loc else e["msg"])
        return _response(request, 422, "VALIDATION_ERROR", "; ".join(parts) or "Requête invalide.")

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        codes = {404: ("NOT_FOUND", "Ressource introuvable."), 405: ("METHOD_NOT_ALLOWED", "Méthode non autorisée.")}
        code, message = codes.get(exc.status_code, ("HTTP_ERROR", str(exc.detail)))
        return _response(request, exc.status_code, code, message, getattr(exc, "headers", None))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.exception("unhandled error")  # le détail reste dans les logs, jamais dans la réponse
        return _response(request, 500, "INTERNAL_ERROR", "Erreur interne.")
