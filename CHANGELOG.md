# Changelog

## 2026-10-12

- Search Analytics: `hour` dimension (`hourly_all`), `searchAppearance` dimension/filter, regex filter operators, `aggregation_type`, `googleNews` search type, and `data_freshness` metadata; `search_type` on `get_search_analytics`, `get_performance_overview`, `compare_search_periods` and `get_search_by_page_query`
- URL Inspection: `language_code`, AMP result, and discovering sitemaps
- New `export_search_analytics` tool (auto-paginated CSV/JSONL export)
- New `get_core_web_vitals` tool (PageSpeed Insights / CrUX)
- `response_format` (`json` / `compact` / `csv`) and `GSC_MAX_RESPONSE_CHARS` response trimming
- `get_performance_overview` no longer drops the last day of the daily trend
- Fix `check_indexing_issues` robots.txt detection (`DISALLOWED`, not `BLOCKED`)

## 2026-04-13

- Bump all Python dependencies to their latest minor/patch versions via `uv lock --upgrade` (thanks @Herriaan, #24)
  - google-api-python-client 2.163.0 -> 2.194.0
  - google-auth 2.38.0 -> 2.49.2
  - google-auth-httplib2 0.2.0 -> 0.3.1
  - google-auth-oauthlib 1.2.1 -> 1.3.1
  - mcp 1.3.0 -> 1.27.2
  - pydantic 2.10.6 -> 2.13.4
  - plus various transitive dependencies
