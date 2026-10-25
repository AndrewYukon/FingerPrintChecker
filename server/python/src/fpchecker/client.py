"""HTTP client: one method per OpenAPI operationId (snake_case)."""
from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Mapping, Optional
from urllib.parse import quote, quote_plus, urlsplit

from .errors import FpCheckerApiError

DEFAULT_BASE_URL = "https://api.fpchecker.com"
_MAX_RETRIES = 2
_MAX_DELAY = 10.0
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_USER_AGENT = "fpchecker-python/0.1.0"

Json = Dict[str, Any]
Query = Mapping[str, Any]


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would forward X-Secret-Key to another origin: never follow."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise urllib.error.URLError(f"redirect refused (HTTP {code})")


def _default_opener() -> Any:
    return urllib.request.build_opener(_RefuseRedirect)


def _validate_base_url(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ValueError("FpChecker: base_url must be a string")
    try:
        u = urlsplit(raw)
        host = u.hostname
    except ValueError:
        raise ValueError("FpChecker: base_url is not a valid URL") from None
    if not host:
        raise ValueError("FpChecker: base_url is not a valid URL")
    loopback = host.lower() in _LOOPBACK
    if u.scheme != "https" and not (u.scheme == "http" and loopback):
        raise ValueError("FpChecker: base_url must be https (http only for localhost, 127.0.0.1, [::1])")
    return raw.rstrip("/")


def _enc(value: str) -> str:
    return quote(str(value), safe="")


def _query_string(q: Optional[Query]) -> str:
    if not q:
        return ""
    parts = []
    for k, v in q.items():
        if v is None:
            continue
        s = "true" if v is True else "false" if v is False else str(v)
        parts.append(f"{quote_plus(str(k))}={quote_plus(s)}")
    return "?" + "&".join(parts) if parts else ""


def _error_code(body: Any) -> Optional[str]:
    if not isinstance(body, dict):
        return None
    code = body.get("error")
    if code is None:
        code = body.get("reason")
    return code if isinstance(code, str) else None


def _parse_retry_after(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    v = value.strip()
    return int(v) if re.fullmatch(r"[0-9]{1,9}", v) else None


def _parse_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        return None


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    return isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, (TimeoutError, socket.timeout))


class FpChecker:
    """Server client. ``secret_key`` goes only in the X-Secret-Key header."""

    def __init__(
        self,
        secret_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10,
        *,
        publishable_key: Optional[str] = None,
        opener: Any = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(secret_key, str) or secret_key == "":
            raise TypeError("FpChecker: secret_key is required")
        self._secret_key = secret_key
        self._publishable_key = publishable_key
        self._base_url = _validate_base_url(base_url)
        self._timeout = timeout
        self._opener = opener if opener is not None else _default_opener()
        self._sleep = sleep

    def __repr__(self) -> str:
        return f"FpChecker(base_url={self._base_url!r})"

    # --- operations (method name = snake_case operationId) ---
    def create_intent(self, body: Json) -> Json:
        return self._call("POST", "/v2/intents", body=body)

    def get_challenge(self, query: Query) -> Json:
        return self._call("GET", "/v2/challenge", query=query, publishable=True)

    def identify(self, body: Json) -> Json:
        return self._call("POST", "/v2/identify", body=body, publishable=True)

    def check_eligibility(self, body: Json) -> Json:
        return self._call("POST", "/v1/eligibility", body=body)

    def release_eligibility(self, body: Json) -> Json:
        return self._call("POST", "/v1/eligibility/release", body=body)

    def check_quota(self, body: Json) -> Json:
        return self._call("POST", "/v1/quota", body=body)

    def bind_subject(self, body: Json) -> Json:
        return self._call("POST", "/v1/subjects/bind", body=body)

    def relate_subjects(self, body: Json) -> Json:
        return self._call("POST", "/v1/subjects/relation", body=body)

    def send_feedback(self, body: Json) -> Json:
        return self._call("POST", "/v1/feedback", body=body)

    def get_claim_flags(self, query: Optional[Query] = None) -> Json:
        return self._call("GET", "/v1/claims/flags", query=query)

    def search_events(self, query: Optional[Query] = None) -> Json:
        return self._call("GET", "/v1/events", query=query)

    def get_event(self, event_id: str) -> Json:
        return self._call("GET", f"/v1/events/{_enc(event_id)}")

    def update_event(self, event_id: str, body: Json) -> Json:
        return self._call("PATCH", f"/v1/events/{_enc(event_id)}", body=body)

    def get_visitor(self, visitor_id: str) -> Json:
        return self._call("GET", f"/v1/visitors/{_enc(visitor_id)}")

    def delete_visitor(self, visitor_id: str) -> Json:
        return self._call("DELETE", f"/v1/visitors/{_enc(visitor_id)}")

    def get_health(self) -> Json:
        return self._call("GET", "/health", auth=False)

    def get_status(self) -> Json:
        return self._call("GET", "/status", auth=False)

    # --- transport ---
    def _call(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Query] = None,
        body: Optional[Json] = None,
        publishable: bool = False,
        auth: bool = True,
    ) -> Json:
        url = self._base_url + path + _query_string(query)
        headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
        if publishable:
            if not self._publishable_key:
                raise TypeError("FpChecker: publishable_key is required for this operation")
            headers["X-Publishable-Key"] = self._publishable_key
        elif auth:
            headers["X-Secret-Key"] = self._secret_key
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        max_retries = _MAX_RETRIES if method == "GET" else 0

        attempt = 0
        while True:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            status = 0
            raw = b""
            resp_headers: Any = None
            failure: Optional[BaseException] = None
            try:
                with self._opener.open(req, timeout=self._timeout) as res:
                    status = res.status
                    raw = res.read()
                    resp_headers = res.headers
            except urllib.error.HTTPError as e:
                status = e.code
                resp_headers = e.headers
                try:
                    raw = e.read()
                except (OSError, ValueError):
                    raw = b""
                finally:
                    e.close()
            except (OSError, ValueError) as e:  # URLError, timeouts, http.client errors
                failure = e

            if failure is not None:
                if attempt < max_retries:
                    self._sleep(min(0.5 * 2**attempt, _MAX_DELAY))
                    attempt += 1
                    continue
                code = "timeout" if _is_timeout(failure) else "network_error"
                raise FpCheckerApiError(0, code, None, None) from failure

            parsed = _parse_json(raw)
            if 200 <= status < 300:
                return parsed if parsed is not None else {}

            retry_after = _parse_retry_after(resp_headers.get("Retry-After") if resp_headers else None)
            if (status == 429 or status >= 500) and attempt < max_retries:
                wait = retry_after if retry_after is not None else 0.5 * 2**attempt
                self._sleep(min(wait, _MAX_DELAY))
                attempt += 1
                continue
            raise FpCheckerApiError(status, _error_code(parsed), retry_after, parsed)
