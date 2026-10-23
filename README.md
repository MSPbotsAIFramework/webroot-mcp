# webroot-mcp

MCP server for **Webroot** (OpenText endpoint security / SecureAnywhere,
managed via the Global Site Manager "GSM" console). Exposes the Webroot
**Unity API**'s GSM console sites, endpoints, groups, policies, threat
history, real-time agent status, and DNS Protection (DNSP) methods as MCP
tools.

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

## Overview

- Stateless HTTP service. No credentials are ever persisted — each request
  supplies its own credentials via headers, used only for the lifetime of
  that single request.
- Supports concurrent requests; per-request credential isolation is done via
  Python `contextvars`, not a global/shared client instance.
- Entry points: `POST /mcp` (MCP protocol) and `GET /health` (health check).
- Default port: `8080` (configurable via `MCP_HTTP_PORT`).

## Authentication

The Webroot Unity API implements standard OAuth2, using the **password
grant**:

```
POST https://unityapi.webrootcloudav.com/auth/token
  grant_type=password&username=...&password=...&client_id=...&client_secret=...
  &scope=Console.GSM SkyStatus.GSM
-> {"access_token": "...", "expires_in": 299, "refresh_token": "...", ...}
```

The access token is valid only ~5 minutes, so this server re-authenticates
fresh on every single tool call rather than caching it across MCP
requests — nothing is cached or persisted. Every real API call then sends
`Authorization: Bearer <access_token>`.

### HEADER authentication parameters

| Header | Type | Required | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-Webroot-Username` | string | Yes | None | None | GSM console account email | `admin@example.com` |
| `X-Webroot-Password` | string | Yes | None | None | Corresponding password | `••••••••` |
| `X-Webroot-Client-Id` | string | Yes | None | None | Unity API Client ID (apply through Webroot) | `client_abc123@example.com` |
| `X-Webroot-Client-Secret` | string | Yes | None | None | Unity API Client Secret | `a1B2c3D4%e5F6` |
| `X-Webroot-Parent-Keycode` | string | Yes | None | None | Parent Key Code of the GSM console | `AB12-GSMT-3456-CD78-9EF0` |

Missing any header returns `401`:
```json
{
  "error": "Missing credentials",
  "message": "This server requires the X-Webroot-Username, X-Webroot-Password, X-Webroot-Client-Id, X-Webroot-Client-Secret, X-Webroot-Parent-Keycode headers",
  "required_headers": ["X-Webroot-Username", "X-Webroot-Password", "X-Webroot-Client-Id", "X-Webroot-Client-Secret", "X-Webroot-Parent-Keycode"],
  "optional_headers": []
}
```

An invalid credential surfaces as a structured tool-level error (see
"Error Handling" below) during the internal login step, not an HTTP-level
error from this server.

## Environment Variables

| Variable | Type | Required | Default | Description |
|---|---|---|---|---|
| `MCP_HTTP_PORT` | int | No | `8080` | HTTP listen port |
| `MCP_HTTP_HOST` | string | No | `0.0.0.0` | HTTP listen address |
| `WEBROOT_BASE_URL` | string | No | `https://unityapi.webrootcloudav.com` | Webroot Unity API base URL |

## MCP Endpoint

- `POST /mcp` — MCP protocol (streamable HTTP transport)
- `GET /health` — health check, returns `{"status": "ok"}` (pure local probe, does not depend on the Webroot API)

## Tool List

All 10 tools are read-only (`readOnlyHint=True`); there are no write/delete tools in this service.

| Tool | Function | Parameters |
|---|---|---|
| `webroot_get_sites` | List all sites (customer accounts) under this GSM console | None |
| `webroot_get_endpoints` | List protected endpoint devices under the specified site | `site_id` (required), `page_size` (optional, default 50, hard limit 200) |
| `webroot_get_groups` | List endpoint groups under the specified site | `site_id` (required) |
| `webroot_get_policies` | List security policies under this GSM console | None |
| `webroot_get_threat_history` | Get the threat detection history of the specified site within a date range (the range cannot exceed 3 months) | `site_id`, `start_date`, `end_date` (all required), `page_size` (optional, hard limit 200), `page_nr` (optional) |
| `webroot_get_dnsp_blocked_traffic` | Get the DNS Protection blocked traffic records of the specified site (requires DNSP to be enabled on the console) | `site_id`, `start_date`, `end_date` (all required), `page_size` (optional, hard limit 200), `page_nr` (optional) |
| `webroot_get_dnsp_categories` | List DNS Protection content filtering categories (requires DNSP to be enabled on the console) | None |
| `webroot_get_dnsp_block_reasons` | List DNS Protection block reason codes (requires DNSP to be enabled on the console) | None |
| `webroot_get_dnsp_traffic_summary` | Get DNS Protection traffic summary statistics (requires DNSP to be enabled on the console) | `start_date`, `end_date` (both required) |
| `webroot_get_agent_status` | Get the real-time status/license information of endpoint Agents | `batch_size` (optional, default 50, hard limit 200) |

`page_size`/`batch_size` caps: the vendor's public API reference does not
document a maximum for these parameters on any endpoint above, so this
server applies its own default (50) and hard cap (200) rather than pass
through an unbounded value.

Responses are the vendor's JSON, serialized compactly (no pretty-printing,
`ensure_ascii=False`) and capped at 20,000 characters — an oversized list
field is truncated with `truncated`/`original_count` markers rather than
ever returning an unbounded blob.

## Error Handling

Errors are returned as an in-band JSON envelope (a normal tool result
string, not an MCP protocol error):

```json
{"error": {"code": "not_found", "message": "...", "retryable": false}}
```

`code` is one of a fixed vocabulary: `not_configured`, `unauthorized`,
`not_found`, `invalid_argument`, `rate_limited`, `upstream_error`.
`retryable` tells the caller whether retrying the same call could
succeed (true for `rate_limited`/`upstream_error`, false otherwise). An
empty result set (e.g. a site with no endpoints) is a normal successful
result, not a `not_found` error.

Outbound calls to the Webroot API use a 5s connect / 30s read timeout,
and retry `429`/`5xx` responses up to 3 times with backoff (respecting
`Retry-After`, capped at 20s), reusing a single pooled HTTP client for the
process lifetime.

## Test Example

```bash
# Health check
curl -s http://localhost:8080/health

# Call a tool via the MCP protocol (streamable HTTP) — requires an
# initialize handshake first per the MCP spec; abbreviated example below
# shows the tool-call request body only:
curl -s -X POST http://localhost:8080/mcp \
  -H "X-Webroot-Username: admin@example.com" \
  -H "X-Webroot-Password: <your-password>" \
  -H "X-Webroot-Client-Id: <your-client-id>" \
  -H "X-Webroot-Client-Secret: <your-client-secret>" \
  -H "X-Webroot-Parent-Keycode: <your-parent-keycode>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: <session-id-from-initialize>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "webroot_get_sites",
      "arguments": {}
    }
  }'
```

**Live-verified** (2026-07-30) against a real GSM console, all 10 tools
called end-to-end through this running server with real credentials:
`webroot_get_sites` returned 92 real sites (e.g. "Pinnacle Technologies",
"Hohimer Wealth Management"); `webroot_get_policies` returned 11 real
policies; `webroot_get_agent_status` returned real per-device status
data; `webroot_get_endpoints` and `webroot_get_groups` (using a real site
ID) both returned real data (6 endpoints, 1 group with 46 devices);
`webroot_get_threat_history` returned a valid (empty) result for a real
2-month range. The 4 DNS Protection tools
(`webroot_get_dnsp_categories`/`_block_reasons`/`_traffic_summary`/
`_blocked_traffic`) all correctly reached the API and returned the
vendor's own `dnsp_not_enabled` error — proving the request/auth pipeline
is correct; DNS Protection is simply not enabled for this particular test
account's GSM console (see Known Gaps).

## API Reference

- Public, no login required: https://unityapi.webrootcloudav.com/Docs/en/APIDoc
  (Guide covers OAuth2 authentication in full; API Reference covers every
  method's parameters and response shape)

## Known Gaps

- **Scope is exactly MSPbots' 10 configured endpoints, not the vendor's
  full API surface** — the Unity API also covers ECom (license
  order/management), Notifications, agent command issuance, site
  creation/editing, and the OpenText Secure Cloud platform API; those are
  out of scope here.
- **The 4 DNS Protection (DNSP) tools could not be verified with real
  data** — DNS Protection is an add-on product that is not enabled for
  the test account's GSM console (`dnsp_not_enabled` error, confirmed
  live). The other 6 tools succeeded with real data using the exact same
  access token, confirming this is an account feature gap, not an
  implementation bug.
- **`webroot_get_endpoints`/`webroot_get_groups`/`webroot_get_threat_history`
  require a `site_id` the authenticated GSM user actually has access
  to** — Webroot GSM access is per-site; attempting these calls against a
  site the user isn't granted access to returns a clean
  `"User does not have access to this console"` error (observed live for
  one of the 92 sites during testing), not a bug in this server.
- **`webroot_get_threat_history` rejects date ranges over 3 months**
  (`Invalid data entered - Date Range Over 3 Months`, confirmed live) —
  this server does not enforce or auto-split the range; it passes
  `start_date`/`end_date` through as-is.
