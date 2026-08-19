import contextvars
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .api_client import WebrootClient
from .config import Settings

# Per-request credential isolation via contextvars.
# GatewayTokenMiddleware sets this before the MCP handler runs.
# Python asyncio copies context per task, so concurrent SSE connections are isolated.
_gateway_creds_var: contextvars.ContextVar[tuple[str, str, str, str, str] | None] = (
    contextvars.ContextVar("webroot_gateway_creds", default=None)
)

REQUIRED_HEADERS = [
    "X-Webroot-Username",
    "X-Webroot-Password",
    "X-Webroot-Client-Id",
    "X-Webroot-Client-Secret",
    "X-Webroot-Parent-Keycode",
]


def get_client_from_context(settings: Settings) -> WebrootClient | None:
    """Resolve the active WebrootClient for the current request context."""
    creds = _gateway_creds_var.get()
    if not creds:
        return None
    username, password, client_id, client_secret, parent_keycode = creds
    return WebrootClient(username, password, client_id, client_secret, parent_keycode, settings.webroot_base_url)


class GatewayTokenMiddleware:
    """ASGI middleware.

    Reads X-Webroot-Username, X-Webroot-Password, X-Webroot-Client-Id,
    X-Webroot-Client-Secret, and X-Webroot-Parent-Keycode (all required)
    from request headers and stores them in the contextvar. Returns 401
    if any is missing on /mcp requests.
    """

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        username = request.headers.get("x-webroot-username")
        password = request.headers.get("x-webroot-password")
        client_id = request.headers.get("x-webroot-client-id")
        client_secret = request.headers.get("x-webroot-client-secret")
        parent_keycode = request.headers.get("x-webroot-parent-keycode")
        if not all([username, password, client_id, client_secret, parent_keycode]):
            response = JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": f"This server requires the {', '.join(REQUIRED_HEADERS)} headers",
                    "required_headers": REQUIRED_HEADERS,
                    "optional_headers": [],
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        ctx_token = _gateway_creds_var.set((username, password, client_id, client_secret, parent_keycode))
        try:
            await self.app(scope, receive, send)
        finally:
            _gateway_creds_var.reset(ctx_token)


def create_mcp_server(settings: Settings) -> FastMCP:
    """Build the FastMCP server instance and register all Webroot tools."""
    # DNS-rebinding protection is a browser-oriented safeguard that rejects
    # non-localhost Host headers with 421. Disable it so the server works
    # correctly behind a reverse proxy or docker network.
    mcp = FastMCP(
        name="webroot-mcp",
        instructions=(
            "Webroot (OpenText) is a cloud-based endpoint protection and DNS "
            "security platform for MSPs, managed through the Global Site Manager "
            "(GSM) console. It organizes customers as sites, each with protected "
            "endpoints (devices), endpoint groups, and assigned security "
            "policies. Use this server for: site/customer inventory "
            "(webroot_get_sites), endpoint and group inventory within a site "
            "(webroot_get_endpoints, webroot_get_groups), policy lookups "
            "(webroot_get_policies), threat detection history "
            "(webroot_get_threat_history), and real-time agent/license status "
            "(webroot_get_agent_status). DNS Protection (DNSP) is a separate "
            "add-on product with its own tools (webroot_get_dnsp_categories, "
            "webroot_get_dnsp_block_reasons, webroot_get_dnsp_traffic_summary, "
            "webroot_get_dnsp_blocked_traffic) — these fail with a "
            "dnsp_not_enabled error if DNSP isn't enabled for the console. All "
            "tools are read-only queries. Typical flow: webroot_get_sites to "
            "find a site ID, then webroot_get_endpoints/webroot_get_groups with "
            "that ID."
        ),
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    client_factory: Callable[[], WebrootClient | None] = lambda: get_client_from_context(settings)

    from .tools import resources

    resources.register(mcp, client_factory)

    return mcp
