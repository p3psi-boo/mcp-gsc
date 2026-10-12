# CLAUDE.md

Context for AI coding assistants (Claude, Cursor, Copilot, etc.) working in this repo.

## What this is

MCP server that connects Google Search Console to AI assistants.
Single file: `gsc_server.py` (~2,300 lines). Built with FastMCP — no custom framework.

## Running locally

```bash
uv sync
uv run python gsc_server.py
```

## Auth

Two modes, tried in order:

1. **OAuth (default):** Place `client_secrets.json` in the repo root. On first run, a browser window opens for Google login. Token saved to `token.json` (gitignored), auto-refreshes when expired.
2. **Service account:** Set `GSC_CREDENTIALS_PATH` to the path of your service account JSON key file.

Set `GSC_SKIP_OAUTH=true` to force service account mode and skip OAuth entirely.

## Key environment variables

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | Set to `sse` for remote/Docker/network use |
| `MCP_HOST` | `127.0.0.1` | Host to bind when `MCP_TRANSPORT=sse` |
| `MCP_PORT` | `3001` | Port to bind when `MCP_TRANSPORT=sse` |
| `GSC_DATA_STATE` | `all` | `all` = matches GSC dashboard; `final` = confirmed data only (2–3 day lag) |
| `GSC_ALLOW_DESTRUCTIVE` | `false` | Set `true` to enable `add_site`, `delete_site`, `delete_sitemap` |
| `GSC_CREDENTIALS_PATH` | — | Path to service account JSON key file |
| `GSC_OAUTH_CLIENT_SECRETS_FILE` | `client_secrets.json` | Path to OAuth client secrets file |
| `GSC_SKIP_OAUTH` | `false` | Set `true` to skip OAuth and use service account only |
| `GSC_MAX_RESPONSE_CHARS` | `80000` | Size cap for row-based tool responses (trimmed with a `truncation` hint); `0` disables |
| `GSC_EXPORT_DIR` | `<config dir>/exports` | Where `export_search_analytics` writes files |
| `GSC_PAGESPEED_API_KEY` | — | Optional API key for `get_core_web_vitals` (PageSpeed Insights) |

## Adding a new tool

1. Add an `@mcp.tool()` decorated async function anywhere in `gsc_server.py`
2. Use `get_gsc_service()` for auth — it handles OAuth and service account automatically
3. Return `json.dumps(result)` not formatted text strings (LLMs work better with structured data)
4. Handle `HttpError` and return a plain string error message on failure
5. For row-based Search Analytics tools, build the body with `_build_search_analytics_request()` and serialize rows with `_dumps_rows_within_budget()` so `response_format` and `GSC_MAX_RESPONSE_CHARS` apply

```python
@mcp.tool()
async def my_new_tool(site_url: str) -> str:
    """One-line description shown to the AI as the tool's purpose."""
    try:
        service = get_gsc_service()
        result = service.someApi().someMethod(siteUrl=site_url).execute()
        return json.dumps(result)
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error: {str(e)}"
```

## Running tests

```bash
pytest test_gsc_server.py -v
```

No credentials needed — all Google API calls are mocked with `unittest.mock`.

## Docker

```bash
docker build -t mcp-gsc .
docker run -e MCP_TRANSPORT=sse -e MCP_PORT=3001 \
  -v /path/to/client_secrets.json:/app/client_secrets.json \
  -p 3001:3001 mcp-gsc
```
