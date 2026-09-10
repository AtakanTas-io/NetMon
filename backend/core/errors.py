"""API hata sözleşmesi ve istek izleme yardımcıları."""

from __future__ import annotations

import json
import re
import secrets
from http import HTTPStatus
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

_TRACE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


def ensure_trace_id(request: Request) -> str:
    """Geçerli üst sistem izini koru, aksi halde yeni bir iz kimliği üret."""
    current = getattr(request.state, "trace_id", None)
    if current:
        return str(current)
    incoming = (request.headers.get("X-Trace-ID") or "").strip()
    trace_id = incoming if _TRACE_ID_RE.fullmatch(incoming) else secrets.token_hex(16)
    request.state.trace_id = trace_id
    return trace_id


def error_code_for_status(status_code: int) -> str:
    return {
        400: "BAD_REQUEST",
        401: "AUTHENTICATION_REQUIRED",
        403: "PERMISSION_DENIED",
        404: "NOT_FOUND",
        409: "CONFLICT",
        413: "PAYLOAD_TOO_LARGE",
        422: "VALIDATION_ERROR",
        428: "PASSWORD_CHANGE_REQUIRED",
        429: "RATE_LIMITED",
        503: "SERVICE_UNAVAILABLE",
    }.get(status_code, "INTERNAL_ERROR" if status_code >= 500 else f"HTTP_{status_code}")


def _default_message(status_code: int) -> str:
    if status_code >= 500:
        return "İstek işlenirken beklenmeyen bir hata oluştu."
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return "İstek başarısız oldu."


def error_envelope(
    request: Request,
    status_code: int,
    *,
    code: str | None = None,
    message: str | None = None,
    detail: Any = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Her API hatası için kararlı, izlenebilir ve güvenli yanıt gövdesi üret."""
    public_message = _default_message(status_code) if status_code >= 500 else (message or _default_message(status_code))
    public_detail = None if status_code >= 500 else detail
    payload = dict(extra or {})
    payload.update(
        {
            "code": code if code and _ERROR_CODE_RE.fullmatch(code) else error_code_for_status(status_code),
            "message": public_message,
            "detail": public_detail if public_detail is not None else public_message,
            "trace_id": ensure_trace_id(request),
            # Eski arayüz sürümleri `error` alanını okuyor. Yeni istemciler `message` kullanır.
            "error": public_message,
        }
    )
    return payload


def api_error_response(
    request: Request,
    status_code: int,
    *,
    code: str | None = None,
    message: str | None = None,
    detail: Any = None,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=error_envelope(
            request,
            status_code,
            code=code,
            message=message,
            detail=detail,
            extra=extra,
        ),
        headers={"X-Trace-ID": ensure_trace_id(request)},
    )


async def normalize_error_response(request: Request, response):
    """Eski JSONResponse hata biçimlerini merkezi zarfa dönüştür."""
    if not request.url.path.startswith("/api/") or response.status_code < 400:
        return response
    content_type = response.headers.get("content-type", "").lower()
    if "application/json" not in content_type or not hasattr(response, "body_iterator"):
        return response

    body = b"".join([chunk async for chunk in response.body_iterator])
    try:
        payload = json.loads(body)
    except (TypeError, ValueError, UnicodeDecodeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {"detail": payload}

    raw_detail = payload.get("detail")
    raw_message = payload.get("message") or payload.get("error")
    if not raw_message and isinstance(raw_detail, str):
        raw_message = raw_detail
    code = payload.get("code") if isinstance(payload.get("code"), str) else None
    extra = {
        key: value for key, value in payload.items() if key not in {"code", "message", "detail", "trace_id", "error"}
    }
    headers = dict(response.headers)
    headers.pop("content-length", None)
    headers.pop("content-type", None)
    headers["X-Trace-ID"] = ensure_trace_id(request)
    return JSONResponse(
        status_code=response.status_code,
        content=error_envelope(
            request,
            response.status_code,
            code=code,
            message=str(raw_message) if raw_message is not None else None,
            detail=raw_detail,
            extra=extra,
        ),
        headers=headers,
        background=response.background,
    )
