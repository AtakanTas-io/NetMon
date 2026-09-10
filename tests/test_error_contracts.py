from starlette.requests import Request

from backend.core.errors import ensure_trace_id, error_envelope


def request_with_headers(headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request({"type": "http", "method": "GET", "path": "/api/test", "headers": headers or []})


def test_server_errors_never_expose_internal_details():
    request = request_with_headers()
    payload = error_envelope(
        request,
        500,
        code="INTERNAL_ERROR",
        message="database password=hidden",
        detail={"stack": "private"},
    )

    assert payload["message"] == "İstek işlenirken beklenmeyen bir hata oluştu."
    assert payload["detail"] == payload["message"]
    assert "hidden" not in str(payload)
    assert payload["trace_id"]


def test_invalid_incoming_trace_id_is_replaced():
    request = request_with_headers([(b"x-trace-id", b"invalid trace id with spaces")])
    trace_id = ensure_trace_id(request)

    assert trace_id != "invalid trace id with spaces"
    assert len(trace_id) == 32
