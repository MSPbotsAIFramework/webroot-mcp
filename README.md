# webroot-mcp

MCP server for **Webroot** (OpenText endpoint security / SecureAnywhere,
managed via the Global Site Manager "GSM" console). Exposes the Webroot
**Unity API**'s GSM console sites, endpoints, groups, policies, threat
history, real-time agent status, and DNS Protection (DNSP) methods as MCP
tools.

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

### HEADER 授权参数说明

| Header | 类型 | 是否必填 | 默认值 | 枚举值 | 字段描述 | Example |
|---|---|---|---|---|---|---|
| `X-Webroot-Username` | string | 是 | 无 | 无 | GSM 控制台账号邮箱 | `admin@example.com` |
| `X-Webroot-Password` | string | 是 | 无 | 无 | 对应密码 | `••••••••` |
| `X-Webroot-Client-Id` | string | 是 | 无 | 无 | Unity API Client ID（需联系 Webroot 申请） | `client_abc123@example.com` |
| `X-Webroot-Client-Secret` | string | 是 | 无 | 无 | Unity API Client Secret | `a1B2c3D4%e5F6` |
| `X-Webroot-Parent-Keycode` | string | 是 | 无 | 无 | GSM 控制台的 Parent Key Code | `AB12-GSMT-3456-CD78-9EF0` |

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

| Variable | 类型 | 是否必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `MCP_HTTP_PORT` | int | 否 | `8080` | HTTP 监听端口 |
| `MCP_HTTP_HOST` | string | 否 | `0.0.0.0` | HTTP 监听地址 |
| `WEBROOT_BASE_URL` | string | 否 | `https://unityapi.webrootcloudav.com` | Webroot Unity API 基础 URL |

## MCP Endpoint

- `POST /mcp` — MCP protocol (streamable HTTP transport)
- `GET /health` — health check, returns `{"status": "ok"}` (pure local probe, does not depend on the Webroot API)

## Tool List

All 10 tools are read-only (`readOnlyHint=True`); there are no write/delete tools in this service.

| Tool | 功能 | 参数 |
|---|---|---|
| `webroot_get_sites` | 列出该 GSM 控制台下所有站点（客户账号） | 无 |
| `webroot_get_endpoints` | 列出指定站点下的受保护终端设备 | `site_id`（必填），`page_size`（可选，默认 50，硬上限 200） |
| `webroot_get_groups` | 列出指定站点下的终端分组 | `site_id`（必填） |
| `webroot_get_policies` | 列出该 GSM 控制台下的安全策略 | 无 |
| `webroot_get_threat_history` | 获取指定站点在某日期范围内的威胁检测历史（范围不能超过 3 个月） | `site_id`、`start_date`、`end_date`（均必填），`page_size`（可选，硬上限 200）、`page_nr`（可选） |
| `webroot_get_dnsp_blocked_traffic` | 获取指定站点的 DNS Protection 拦截流量记录（需该控制台已启用 DNSP） | `site_id`、`start_date`、`end_date`（均必填），`page_size`（可选，硬上限 200）、`page_nr`（可选） |
| `webroot_get_dnsp_categories` | 列出 DNS Protection 内容过滤分类（需该控制台已启用 DNSP） | 无 |
| `webroot_get_dnsp_block_reasons` | 列出 DNS Protection 拦截原因代码（需该控制台已启用 DNSP） | 无 |
| `webroot_get_dnsp_traffic_summary` | 获取 DNS Protection 流量汇总统计（需该控制台已启用 DNSP） | `start_date`、`end_date`（均必填） |
| `webroot_get_agent_status` | 获取终端 Agent 的实时状态/授权信息 | `batch_size`（可选，默认 50，硬上限 200） |

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

## 测试示例

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
