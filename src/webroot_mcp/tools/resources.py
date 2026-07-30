import json
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP

from ..api_client import WebrootClient, WebrootError
from ._common import NO_TOKEN


def register(mcp: FastMCP, client_factory: Callable[[], WebrootClient | None]) -> None:

    @mcp.tool()
    async def webroot_get_sites() -> str:
        """List all endpoint protection sites (customer accounts) managed
        under this GSM console.

        API: GET /service/api/console/gsm/{parentKeycode}/sites

        No required parameters.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(f"/service/api/console/gsm/{client.parent_keycode}/sites")
            return json.dumps(result, indent=2)
        except WebrootError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def webroot_get_endpoints(site_id: str, page_size: int = 1000) -> str:
        """List endpoints (protected devices) for a specific site.

        API: GET /service/api/console/gsm/{parentKeycode}/sites/{siteId}/endpoints

        Args:
            site_id: Required. The site ID (get one from webroot_get_sites).
            page_size: Optional. Max results per page. Default 1000.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/sites/{site_id}/endpoints",
                params={"pageSize": page_size},
            )
            return json.dumps(result, indent=2)
        except WebrootError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def webroot_get_groups(site_id: str) -> str:
        """List endpoint groups for a specific site.

        API: GET /service/api/console/gsm/{parentKeycode}/sites/{siteId}/groups

        Args:
            site_id: Required. The site ID (get one from webroot_get_sites).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/sites/{site_id}/groups"
            )
            return json.dumps(result, indent=2)
        except WebrootError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def webroot_get_policies() -> str:
        """List endpoint security policies available under this GSM console.

        API: GET /service/api/console/gsm/{parentKeycode}/policies

        No required parameters.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(f"/service/api/console/gsm/{client.parent_keycode}/policies")
            return json.dumps(result, indent=2)
        except WebrootError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def webroot_get_threat_history(
        site_id: str, start_date: str, end_date: str, page_size: int | None = None, page_nr: int | None = None
    ) -> str:
        """Get the threat detection/blocked-program history for a site
        within a date range.

        API: GET /service/api/console/gsm/{parentKeycode}/sites/{siteId}/threathistory

        Args:
            site_id: Required. The site ID (get one from webroot_get_sites).
            start_date: Required. Range start, ISO 8601 (e.g.
                "2026-01-01T00:00:00Z"). The vendor rejects ranges over 3
                months.
            end_date: Required. Range end, ISO 8601.
            page_size: Optional. Max results per page.
            page_nr: Optional. Page number.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
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
            return json.dumps(result, indent=2)
        except WebrootError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def webroot_get_dnsp_blocked_traffic(
        site_id: str, start_date: str, end_date: str, page_size: int | None = None, page_nr: int | None = None
    ) -> str:
        """Get DNS Protection blocked-traffic records for a site within a
        date range. Requires DNS Protection (DNSP) to be enabled for the
        GSM console — returns a "dnsp_not_enabled" error otherwise.

        API: GET /service/api/console/gsm/{parentKeycode}/sites/{siteId}/dnsp/blockedtraffic

        Args:
            site_id: Required. The site ID (get one from webroot_get_sites).
            start_date: Required. Range start, ISO 8601.
            end_date: Required. Range end, ISO 8601.
            page_size: Optional. Max results per page.
            page_nr: Optional. Page number.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
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
            return json.dumps(result, indent=2)
        except WebrootError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def webroot_get_dnsp_categories() -> str:
        """List DNS Protection content filtering categories. Requires DNS
        Protection (DNSP) to be enabled for the GSM console — returns a
        "dnsp_not_enabled" error otherwise.

        API: GET /service/api/console/gsm/{parentKeycode}/dnsp/categories

        No required parameters.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/dnsp/categories"
            )
            return json.dumps(result, indent=2)
        except WebrootError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def webroot_get_dnsp_block_reasons() -> str:
        """List DNS Protection block reason codes/descriptions. Requires
        DNS Protection (DNSP) to be enabled for the GSM console — returns
        a "dnsp_not_enabled" error otherwise.

        API: GET /service/api/console/gsm/{parentKeycode}/dnsp/blockreasons

        No required parameters.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/dnsp/blockreasons"
            )
            return json.dumps(result, indent=2)
        except WebrootError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def webroot_get_dnsp_traffic_summary(start_date: str, end_date: str) -> str:
        """Get a DNS Protection traffic summary across the GSM console
        within a date range. Requires DNS Protection (DNSP) to be enabled
        for the GSM console — returns a "dnsp_not_enabled" error otherwise.

        API: GET /service/api/console/gsm/{parentKeycode}/dnsp/trafficsummary

        Args:
            start_date: Required. Range start, ISO 8601.
            end_date: Required. Range end, ISO 8601.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                f"/service/api/console/gsm/{client.parent_keycode}/dnsp/trafficsummary",
                params={"startDate": start_date, "endDate": end_date},
            )
            return json.dumps(result, indent=2)
        except WebrootError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def webroot_get_agent_status(batch_size: int = 500) -> str:
        """Get real-time agent/license status information for endpoints
        under this GSM console.

        API: GET /service/api/status/gsm/{parentKeycode}

        No required parameters.

        Args:
            batch_size: Optional. Max results per batch. Default 500.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                f"/service/api/status/gsm/{client.parent_keycode}", params={"batchSize": batch_size}
            )
            return json.dumps(result, indent=2)
        except WebrootError as e:
            return f"Error: {e}"
