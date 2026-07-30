import httpx


class WebrootError(Exception):
    def __init__(self, message: str):
        super().__init__(f"Webroot Unity API error: {message}")


class WebrootClient:
    """Async httpx client wrapping the Webroot Unity API (GSM/Console.GSM
    and SkyStatus.GSM scopes).

    Auth is a standard OAuth2 "password" grant:

      POST {base_url}/auth/token
        grant_type=password&username=...&password=...&client_id=...&client_secret=...&scope=Console.GSM SkyStatus.GSM
      -> {"access_token": "...", "expires_in": 299, ...}

    The access token is valid for only ~5 minutes, so this client
    re-authenticates fresh on every single call rather than caching it
    across MCP requests, to stay fully stateless.
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

    async def _login(self, client: httpx.AsyncClient) -> str:
        try:
            resp = await client.post(
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
        except httpx.RequestError as e:
            raise WebrootError(f"{e or type(e).__name__} (auth/token)") from e
        if resp.status_code >= 400:
            raise WebrootError(f"HTTP {resp.status_code} during login: {resp.text}")
        access_token = resp.json().get("access_token")
        if not access_token:
            raise WebrootError(f"login did not return an access_token: {resp.text}")
        return access_token

    def _clean(self, params: dict | None) -> dict:
        if not params:
            return {}
        return {k: v for k, v in params.items() if v is not None}

    @property
    def parent_keycode(self) -> str:
        return self._parent_keycode

    async def call(self, path: str, params: dict | None = None) -> object:
        async with httpx.AsyncClient(timeout=30.0) as client:
            token = await self._login(client)
            headers = {"Authorization": f"Bearer {token}"}
            try:
                resp = await client.get(
                    f"{self._base_url}{path}", headers=headers, params=self._clean(params)
                )
            except httpx.RequestError as e:
                raise WebrootError(f"{e or type(e).__name__} (path={path})") from e
            if resp.status_code >= 400:
                raise WebrootError(f"HTTP {resp.status_code} calling {path}: {resp.text}")
            return resp.json()
