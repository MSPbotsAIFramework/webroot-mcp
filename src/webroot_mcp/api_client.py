import asyncio
from typing import Any

import httpx

from ._json import error_envelope

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_MAX_BACKOFF_SECONDS = 20.0

# One shared connection pool for the process lifetime. No credentials are
# ever stored on it — each WebrootClient instance carries its own
# username/password/client_id/client_secret/parent_keycode, sourced fresh
# per request from the gateway's headers (see server.py's contextvar-based
# credential isolation), so sharing this pool across tenants/requests is
# safe: only the TCP/TLS connections are pooled, never credentials or
# derived tokens.
_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=_TIMEOUT)
    return _http_client


# status_code -> (error code, retryable). status_code 0 means a network/
# connection-level failure (no response at all).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def _classify(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    return "invalid_argument", False


class WebrootError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Webroot Unity API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = _classify(self.status_code)
        return error_envelope(code, self.message, retryable)


def _retry_delay(resp: httpx.Response, attempt: int) -> float:
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            return min(float(retry_after), _MAX_BACKOFF_SECONDS)
        except ValueError:
            pass
    return min(2**attempt, _MAX_BACKOFF_SECONDS)


async def _request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict | None = None,
    data: dict | None = None,
) -> httpx.Response:
    """Shared request helper: connection reuse, timeouts, and bounded
    retry+backoff on 429/5xx (respecting Retry-After). Raises WebrootError
    on a final non-2xx response or network failure; never retries other
    4xx statuses.
    """
    client = _get_http_client()
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = await client.request(method, url, headers=headers, params=params, data=data)
        except httpx.RequestError as e:
            last_exc = e
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(min(2**attempt, _MAX_BACKOFF_SECONDS))
                continue
            raise WebrootError(0, f"{e or type(e).__name__} (url={url})") from e

        if resp.status_code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
            await asyncio.sleep(_retry_delay(resp, attempt))
            continue

        return resp

    # Unreachable in practice (loop always returns or raises above), but
    # keeps type checkers happy and guards against future edits.
    if last_exc:
        raise WebrootError(0, f"{last_exc}") from last_exc
    raise WebrootError(0, "request failed with no response")


def _error_message(resp: httpx.Response) -> str:
    try:
        detail = resp.json()
        if isinstance(detail, dict):
            return str(detail.get("message") or detail.get("error") or detail)
        return str(detail)
    except ValueError:
        return resp.text


class WebrootClient:
    """Async httpx client wrapping the Webroot Unity API (GSM/Console.GSM
    and SkyStatus.GSM scopes).

    Auth is a standard OAuth2 "password" grant:

      POST {base_url}/auth/token
        grant_type=password&username=...&password=...&client_id=...&client_secret=...&scope=Console.GSM SkyStatus.GSM
      -> {"access_token": "...", "expires_in": 299, ...}

    The access token is valid for only ~5 minutes, so this client
    re-authenticates fresh on every single call rather than caching it
    across MCP requests — nothing derived from credentials is ever kept
    around between requests, keeping the service fully stateless.
    """

    def __init__(
        self,
        username: str,
        password: str,
        client_id: str,
        client_secret: str,
        parent_keycode: str,
        base_url: str,
    ):
        self._username = username
        self._password = password
        self._client_id = client_id
        self._client_secret = client_secret
        self._parent_keycode = parent_keycode
        self._base_url = base_url.rstrip("/")

    @property
    def parent_keycode(self) -> str:
        return self._parent_keycode

    def _clean(self, params: dict | None) -> dict:
        if not params:
            return {}
        return {k: v for k, v in params.items() if v is not None}

    async def _login(self) -> str:
        resp = await _request(
            "POST",
            f"{self._base_url}/auth/token",
            data={
                "grant_type": "password",
                "username": self._username,
                "password": self._password,
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "Console.GSM SkyStatus.GSM",
            },
        )
        if resp.status_code >= 400:
            raise WebrootError(resp.status_code, f"login failed: {_error_message(resp)}")
        access_token = resp.json().get("access_token")
        if not access_token:
            raise WebrootError(resp.status_code, "login did not return an access_token")
        return access_token

    async def call(self, path: str, params: dict | None = None) -> Any:
        token = await self._login()
        headers = {"Authorization": f"Bearer {token}"}
        resp = await _request(
            "GET", f"{self._base_url}{path}", headers=headers, params=self._clean(params)
        )
        if resp.status_code >= 400:
            raise WebrootError(resp.status_code, _error_message(resp))
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw_response": resp.text}
