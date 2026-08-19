from collections.abc import Callable
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import WebrootClient, WebrootError
from ._common import NO_TOKEN

# The vendor's public API reference does not document a maximum pageSize/
# batchSize for any of these endpoints (confirmed by reading the docs), so
# per SOP guidance we fall back to the SOP's own ceiling rather than trust
# an unbounded value.
_MAX_PAGE_SIZE = 200
_DEFAULT_PAGE_SIZE = 50


def register(mcp: FastMCP, client_factory: Callable[[], WebrootClient | None]) -> None:

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def webroot_get_sites() -> str:
        """List all endpoint protection sites (customer accounts) in this GSM console."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(f"/service/api/console/gsm/{client.parent_keycode}/sites")
            return dump_json_capped(result)
        except WebrootError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def webroot_get_endpoints(
        site_id: Annotated[str, Field(description="The site ID (from webroot_get_sites).")],
        page_size: Annotated[
            int, Field(description="Max results per page (default 50, capped at 200).")
        ] = _DEFAULT_PAGE_SIZE,
    ) -> str:
        """List endpoints (protected devices) for a specific site."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        page_size = min(page_size, _MAX_PAGE_SIZE)
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/sites/{site_id}/endpoints",
                params={"pageSize": page_size},
            )
            return dump_json_capped(result)
        except WebrootError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def webroot_get_groups(
        site_id: Annotated[str, Field(description="The site ID (from webroot_get_sites).")],
    ) -> str:
        """List endpoint groups for a specific site."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/sites/{site_id}/groups"
            )
            return dump_json_capped(result)
        except WebrootError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def webroot_get_policies() -> str:
        """List endpoint security policies available in this GSM console."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/policies"
            )
            return dump_json_capped(result)
        except WebrootError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def webroot_get_threat_history(
        site_id: Annotated[str, Field(description="The site ID (from webroot_get_sites).")],
        start_date: Annotated[
            str,
            Field(
                description='Range start, ISO 8601 (e.g. "2026-01-01T00:00:00Z"). '
                "The vendor rejects ranges over 3 months."
            ),
        ],
        end_date: Annotated[str, Field(description="Range end, ISO 8601.")],
        page_size: Annotated[
            int | None, Field(description="Max results per page (capped at 200).")
        ] = None,
        page_nr: Annotated[int | None, Field(description="Page number.")] = None,
    ) -> str:
        """Get the threat-detection/blocked-program history for a site within a date range."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        if page_size is not None:
            page_size = min(page_size, _MAX_PAGE_SIZE)
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/sites/{site_id}/threathistory",
                params={
                    "startDate": start_date,
                    "endDate": end_date,
                    "pageSize": page_size,
                    "pageNr": page_nr,
                },
            )
            return dump_json_capped(result)
        except WebrootError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def webroot_get_dnsp_blocked_traffic(
        site_id: Annotated[str, Field(description="The site ID (from webroot_get_sites).")],
        start_date: Annotated[str, Field(description="Range start, ISO 8601.")],
        end_date: Annotated[str, Field(description="Range end, ISO 8601.")],
        page_size: Annotated[
            int | None, Field(description="Max results per page (capped at 200).")
        ] = None,
        page_nr: Annotated[int | None, Field(description="Page number.")] = None,
    ) -> str:
        """Get DNS Protection blocked-traffic records for a site within a date range.

        Requires DNS Protection (DNSP) enabled for the console; otherwise
        returns a dnsp_not_enabled error.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        if page_size is not None:
            page_size = min(page_size, _MAX_PAGE_SIZE)
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/sites/{site_id}/dnsp/blockedtraffic",
                params={
                    "startDate": start_date,
                    "endDate": end_date,
                    "pageSize": page_size,
                    "pageNr": page_nr,
                },
            )
            return dump_json_capped(result)
        except WebrootError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def webroot_get_dnsp_categories() -> str:
        """List DNS Protection content filtering categories.

        Requires DNS Protection (DNSP) enabled for the console; otherwise
        returns a dnsp_not_enabled error.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/dnsp/categories"
            )
            return dump_json_capped(result)
        except WebrootError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def webroot_get_dnsp_block_reasons() -> str:
        """List DNS Protection block reason codes/descriptions.

        Requires DNS Protection (DNSP) enabled for the console; otherwise
        returns a dnsp_not_enabled error.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/dnsp/blockreasons"
            )
            return dump_json_capped(result)
        except WebrootError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def webroot_get_dnsp_traffic_summary(
        start_date: Annotated[str, Field(description="Range start, ISO 8601.")],
        end_date: Annotated[str, Field(description="Range end, ISO 8601.")],
    ) -> str:
        """Get a DNS Protection traffic summary across the console for a date range.

        Requires DNS Protection (DNSP) enabled for the console; otherwise
        returns a dnsp_not_enabled error.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/dnsp/trafficsummary",
                params={"startDate": start_date, "endDate": end_date},
            )
            return dump_json_capped(result)
        except WebrootError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def webroot_get_agent_status(
        batch_size: Annotated[
            int, Field(description="Max results per batch (default 50, capped at 200).")
        ] = _DEFAULT_PAGE_SIZE,
    ) -> str:
        """Get real-time agent/license status for endpoints in this GSM console."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        batch_size = min(batch_size, _MAX_PAGE_SIZE)
        try:
            result = await client.call(
                f"/service/api/status/gsm/{client.parent_keycode}", params={"batchSize": batch_size}
            )
            return dump_json_capped(result)
        except WebrootError as e:
            return e.to_envelope()
