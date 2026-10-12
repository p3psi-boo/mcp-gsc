from typing import Any, Dict, List, Optional, Tuple
import asyncio
import csv
import io
import logging
import os
import json
import re
import sys
import shutil
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

# Fail loudly on unsupported Python. The mcp/FastMCP dependency requires 3.11+.
# On Python 3.10 or older the server dies during import, and when it is launched
# by a GUI client (e.g. Claude Desktop) that failure is silent — no tools appear
# and no log file is written, which is impossible to diagnose. See issue #19.
if sys.version_info < (3, 11):
    sys.exit(
        "mcp-gsc requires Python 3.11 or newer, but you are running "
        f"{sys.version_info.major}.{sys.version_info.minor}. "
        "Install Python 3.11+ (https://www.python.org/downloads/) and recreate "
        "your virtual environment, or use the uvx install method which manages "
        "the Python version for you."
    )

from platformdirs import user_config_dir

import google.auth
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Suppress the noisy file_cache warning from google-api-python-client.
# Some MCP hosts (e.g. GitHub Copilot CLI) treat any stderr output as a
# fatal error, so this prevents false crashes.
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.ERROR)

# MCP
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("gsc-server")

def _expand_path(path: Optional[str]) -> Optional[str]:
    """Expand ``~`` and environment variables in a path, returning None for empty input.

    This lets users write ``GSC_CREDENTIALS_PATH=~/creds.json`` or
    ``GSC_CREDENTIALS_PATH=$HOME/creds.json`` without hitting silent lookup failures.
    """
    if not path:
        return None
    return os.path.expandvars(os.path.expanduser(path))


# Path to your service account JSON or user credentials JSON
# First check if GSC_CREDENTIALS_PATH environment variable is set
# Then try looking in the script directory and current working directory as fallbacks
GSC_CREDENTIALS_PATH = _expand_path(os.environ.get("GSC_CREDENTIALS_PATH"))
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POSSIBLE_CREDENTIAL_PATHS = [
    GSC_CREDENTIALS_PATH,  # First try the environment variable if set
    os.path.join(SCRIPT_DIR, "service_account_credentials.json"),
    os.path.join(os.getcwd(), "service_account_credentials.json"),
    # Add any other potential paths here
]

# OAuth client secrets file path
OAUTH_CLIENT_SECRETS_FILE = _expand_path(os.environ.get("GSC_OAUTH_CLIENT_SECRETS_FILE"))
# Track whether the user explicitly set the env var (vs. using the SCRIPT_DIR fallback).
# Needed so get_gsc_service() can fail-fast when the explicit path is wrong, while
# leaving the fallback behavior unchanged for clone-install users.
GSC_OAUTH_CLIENT_SECRETS_FILE_EXPLICIT = OAUTH_CLIENT_SECRETS_FILE is not None
if not OAUTH_CLIENT_SECRETS_FILE:
    OAUTH_CLIENT_SECRETS_FILE = os.path.join(SCRIPT_DIR, "client_secrets.json")

# Token file path for storing OAuth tokens.
# Stored in the user config directory so it survives uvx updates (which replace SCRIPT_DIR).
# Override with GSC_CONFIG_DIR env var for Docker/power users.
_CONFIG_DIR = os.environ.get("GSC_CONFIG_DIR") or user_config_dir("mcp-gsc")
os.makedirs(_CONFIG_DIR, exist_ok=True)
TOKEN_FILE = os.path.join(_CONFIG_DIR, "token.json")

# Silently migrate token from old location (SCRIPT_DIR) on first run after upgrade.
# Existing users never need to re-authenticate.
_OLD_TOKEN = os.path.join(SCRIPT_DIR, "token.json")
if os.path.exists(_OLD_TOKEN) and not os.path.exists(TOKEN_FILE):
    shutil.move(_OLD_TOKEN, TOKEN_FILE)

# Environment variable to skip OAuth authentication
SKIP_OAUTH = os.environ.get("GSC_SKIP_OAUTH", "").lower() in ("true", "1", "yes")

# Safety flag for destructive operations (add_site, delete_site, delete_sitemap).
# Default is false — set GSC_ALLOW_DESTRUCTIVE=true to enable these tools.
ALLOW_DESTRUCTIVE = os.environ.get("GSC_ALLOW_DESTRUCTIVE", "false").lower() in ("true", "1", "yes")

# Data state for search analytics queries.
# "all"   → includes fresh/unconfirmed data, matches the GSC dashboard (default)
# "final" → only confirmed data, which lags 2-3 days behind the dashboard
_raw_data_state = os.environ.get("GSC_DATA_STATE", "all").lower().strip()
if _raw_data_state not in ("all", "final"):
    raise ValueError(
        f"Invalid GSC_DATA_STATE value '{_raw_data_state}'. "
        "Accepted values are 'all' (default, matches GSC dashboard) or 'final' (2-3 day lag)."
    )
DATA_STATE = _raw_data_state

# Upper bound (in characters) on the JSON returned by row-based tools. Large result
# sets are trimmed to fit and flagged with a "truncation" block, so a single call
# can't flood the model's context window. Set to 0 to disable.
try:
    MAX_RESPONSE_CHARS = int(os.environ.get("GSC_MAX_RESPONSE_CHARS", "80000"))
except ValueError:
    raise ValueError("GSC_MAX_RESPONSE_CHARS must be an integer (0 disables the limit)")

# Where export_search_analytics writes full result sets.
EXPORT_DIR = _expand_path(os.environ.get("GSC_EXPORT_DIR")) or os.path.join(_CONFIG_DIR, "exports")

# Optional API key for the PageSpeed Insights API (get_core_web_vitals). The API
# works without a key but with a very small shared quota.
PAGESPEED_API_KEY = os.environ.get("GSC_PAGESPEED_API_KEY")

SCOPES = ["https://www.googleapis.com/auth/webmasters"]

def get_gsc_service():
    """
    Returns an authorized Search Console service object.
    First tries OAuth authentication, then falls back to service account.
    """
    # Fail-fast if credential env vars are set but point to files that don't exist.
    # Without this, a typo'd or uvx-incompatible path would silently fall through to
    # SCRIPT_DIR/cwd fallbacks (which don't work under uvx) and emit a misleading
    # "file not found" error with no mention of the env var the user actually set.
    # We rely on the module-level captured values (GSC_CREDENTIALS_PATH,
    # GSC_OAUTH_CLIENT_SECRETS_FILE_EXPLICIT) rather than re-reading os.environ at
    # call time, because the env var may have been cleared by the caller after module
    # import (e.g. by test frameworks or MCP hosts that scope env vars narrowly).
    if GSC_CREDENTIALS_PATH and not os.path.exists(GSC_CREDENTIALS_PATH):
        raise FileNotFoundError(
            f"GSC_CREDENTIALS_PATH is set to {GSC_CREDENTIALS_PATH!r} but the file "
            f"does not exist. "
            f"If running via uvx, this MUST be an absolute path to your service account "
            f"credentials JSON file — placing the file in your project folder is not "
            f"sufficient because uvx runs the code from an internal cache directory."
        )
    if GSC_OAUTH_CLIENT_SECRETS_FILE_EXPLICIT and not os.path.exists(OAUTH_CLIENT_SECRETS_FILE):
        raise FileNotFoundError(
            f"GSC_OAUTH_CLIENT_SECRETS_FILE is set to {OAUTH_CLIENT_SECRETS_FILE!r} "
            f"but the file does not exist. "
            f"If running via uvx, this MUST be an absolute path to your OAuth "
            f"client_secrets.json file."
        )

    # Try OAuth authentication first if not skipped
    if not SKIP_OAUTH:
        try:
            return get_gsc_service_oauth()
        except Exception as e:
            # If OAuth fails, try service account
            logging.warning("OAuth authentication failed: %s", e)
            pass
    
    # Try service account authentication
    for cred_path in POSSIBLE_CREDENTIAL_PATHS:
        if cred_path and os.path.exists(cred_path):
            try:
                creds = service_account.Credentials.from_service_account_file(
                    cred_path, scopes=SCOPES
                )
                return build("searchconsole", "v1", credentials=creds, cache_discovery=False)
            except Exception as e:
                continue  # Try the next path if this one fails
    
    # If we get here, none of the authentication methods worked.
    # Note: uvx users can't place files "in the script directory" because uvx runs
    # the code from ~/.cache/uv/archive-v0/<hash>/lib/python*/site-packages/ — an
    # internal cache they cannot reach. They must use env vars with absolute paths.
    raise FileNotFoundError(
        f"Authentication failed. Please either:\n"
        f"1. Set up OAuth by setting GSC_OAUTH_CLIENT_SECRETS_FILE to an absolute path, "
        f"or (for clone installs) placing a client_secrets.json file in the script "
        f"directory, then call the 'reauthenticate' tool to open a browser login window "
        f"and complete authentication, or\n"
        f"2. Set GSC_CREDENTIALS_PATH to an absolute path, or (for clone installs) "
        f"place a service account credentials file in one of these locations: "
        f"{', '.join([p for p in POSSIBLE_CREDENTIAL_PATHS[1:] if p])}\n"
        f"\n"
        f"If you installed via uvx, the 'script directory' is an internal uv cache "
        f"that you cannot access — you MUST use the environment variables with "
        f"absolute paths."
    )

def get_gsc_service_oauth():
    """
    Returns an authorized Search Console service object using OAuth.
    """
    creds = None
    
    # Check if token file exists
    if os.path.exists(TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        except Exception as e:
            # If token file is corrupted, delete it
            if os.path.exists(TOKEN_FILE):
                os.remove(TOKEN_FILE)
            creds = None
    
    # If credentials don't exist or are invalid, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                # Save the refreshed credentials
                with open(TOKEN_FILE, 'w') as token:
                    token.write(creds.to_json())
            except Exception as e:
                # If refresh fails, delete the bad token and trigger new OAuth flow
                if os.path.exists(TOKEN_FILE):
                    os.remove(TOKEN_FILE)
                # Fall through to the OAuth flow below
                creds = None
        
        # Start new OAuth flow if we don't have valid credentials
        if not creds or not creds.valid:
            # Check if client secrets file exists
            if not os.path.exists(OAUTH_CLIENT_SECRETS_FILE):
                raise FileNotFoundError(
                    f"OAuth client secrets file not found. Please place a client_secrets.json file in the script directory "
                    f"or set the GSC_OAUTH_CLIENT_SECRETS_FILE environment variable."
                )

            # Start OAuth flow — opens a browser window on macOS even from MCP subprocess.
            flow = InstalledAppFlow.from_client_secrets_file(OAUTH_CLIENT_SECRETS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
            
            # Save the credentials for future use
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())
    
    # Build and return the service
    return build("searchconsole", "v1", credentials=creds, cache_discovery=False)


def _site_not_found_error(site_url: str) -> str:
    """Return a helpful message when a GSC property returns 404."""
    lines = [f"Property '{site_url}' not found (404). Possible causes:\n"]
    lines.append(
        "1. The site_url doesn't exactly match what is in GSC. "
        "Run list_properties to get the exact string to use."
    )
    if site_url.startswith("sc-domain:"):
        lines.append(
            "2. Domain properties require the service account to be explicitly added "
            "under GSC Settings > Users and permissions for that specific domain property. "
            "OAuth users must also have verified access to it."
        )
    else:
        lines.append(
            "2. If your property is a domain property (covers all subdomains), "
            "the correct format is 'sc-domain:example.com', not a full URL."
        )
    lines.append(
        "3. The authenticated account may not have access to this property."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Search Analytics helpers
# ---------------------------------------------------------------------------

_SEARCH_TYPES = ("WEB", "IMAGE", "VIDEO", "NEWS", "DISCOVER", "GOOGLE_NEWS")
_DIMENSIONS = ("query", "page", "country", "device", "date", "searchAppearance", "hour")
_FILTER_DIMENSIONS = ("query", "page", "country", "device", "searchAppearance")
_FILTER_OPERATORS = ("equals", "notEquals", "contains", "notContains", "includingRegex", "excludingRegex")
_AGGREGATION_TYPES = ("auto", "byPage", "byProperty", "byNewsShowcasePanel")
_DATA_STATES = ("all", "final", "hourly_all")
_RESPONSE_FORMATS = ("json", "compact", "csv")
_API_MAX_ROWS = 25000


def _normalize_choice(value: str, choices: Tuple[str, ...], label: str) -> str:
    """Match ``value`` against ``choices`` ignoring case, underscores and dashes."""
    key = re.sub(r"[_\-\s]", "", str(value)).lower()
    for choice in choices:
        if re.sub(r"[_\-\s]", "", choice).lower() == key:
            return choice
    raise ValueError(f"Invalid {label} '{value}'. Valid values: {', '.join(choices)}")


def _parse_dimensions(dimensions: Optional[str]) -> List[str]:
    if not dimensions:
        return []
    return [_normalize_choice(d.strip(), _DIMENSIONS, "dimension") for d in dimensions.split(",") if d.strip()]


def _parse_filters(
    filters: Optional[str] = None,
    filter_dimension: Optional[str] = None,
    filter_operator: str = "contains",
    filter_expression: Optional[str] = None,
) -> List[Dict[str, str]]:
    """Parse the JSON ``filters`` array (or the single-filter args) into API filter objects."""
    if filters:
        try:
            filter_list = json.loads(filters)
        except json.JSONDecodeError:
            raise ValueError("Invalid filters JSON. Please provide a valid JSON array of filter objects.")
        if not isinstance(filter_list, list) or len(filter_list) == 0:
            raise ValueError("Invalid filters value. Expected a non-empty JSON array of filter objects.")
    elif filter_dimension and filter_expression:
        filter_list = [{"dimension": filter_dimension, "operator": filter_operator, "expression": filter_expression}]
    else:
        return []

    parsed = []
    for f in filter_list:
        if not isinstance(f, dict) or not all(k in f for k in ("dimension", "operator", "expression")):
            raise ValueError(
                "Each filter object must have 'dimension', 'operator', and 'expression' keys. "
                f"Invalid filter: {f}"
            )
        parsed.append({
            "dimension": _normalize_choice(f["dimension"], _FILTER_DIMENSIONS, "filter dimension"),
            "operator": _normalize_choice(f["operator"], _FILTER_OPERATORS, "filter operator"),
            "expression": str(f["expression"]),
        })
    return parsed


def _build_search_analytics_request(
    start_date: str,
    end_date: str,
    dimension_list: List[str],
    search_type: str = "web",
    data_state: Optional[str] = None,
    aggregation_type: Optional[str] = None,
    filter_list: Optional[List[Dict[str, str]]] = None,
    row_limit: Optional[int] = None,
    start_row: Optional[int] = None,
) -> Dict[str, Any]:
    """Build and validate a searchanalytics.query body. Raises ValueError with a user-facing message."""
    if data_state:
        resolved_data_state = _normalize_choice(data_state, _DATA_STATES, "data_state")
    elif "hour" in dimension_list:
        resolved_data_state = "hourly_all"
    else:
        resolved_data_state = DATA_STATE

    if "hour" in dimension_list and resolved_data_state != "hourly_all":
        raise ValueError("The 'hour' dimension requires data_state='hourly_all' (leave data_state empty to set it automatically).")
    if resolved_data_state == "hourly_all" and "hour" not in dimension_list:
        raise ValueError("data_state='hourly_all' is only valid when grouping by the 'hour' dimension.")

    request: Dict[str, Any] = {
        "startDate": start_date,
        "endDate": end_date,
        "dimensions": dimension_list,
        "type": _normalize_choice(search_type or "web", _SEARCH_TYPES, "search_type"),
        "dataState": resolved_data_state,
    }
    if aggregation_type:
        request["aggregationType"] = _normalize_choice(aggregation_type, _AGGREGATION_TYPES, "aggregation_type")
    if filter_list:
        request["dimensionFilterGroups"] = [{"groupType": "and", "filters": filter_list}]
    if row_limit is not None:
        request["rowLimit"] = max(1, min(row_limit, _API_MAX_ROWS))
    if start_row:
        request["startRow"] = start_row
    return request


def _shape_rows(api_rows: List[Dict[str, Any]], dimension_list: List[str]) -> List[Dict[str, Any]]:
    rows = []
    for row in api_rows:
        keys = row.get("keys", [])
        entry = {dim: keys[i] if i < len(keys) else None for i, dim in enumerate(dimension_list)}
        entry["clicks"] = row.get("clicks", 0)
        entry["impressions"] = row.get("impressions", 0)
        entry["ctr"] = round(row.get("ctr", 0), 4)
        entry["position"] = round(row.get("position", 0), 1)
        rows.append(entry)
    return rows


def _data_freshness(response: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Surface the API's incomplete-data markers so the model doesn't read a partial day as a drop."""
    metadata = response.get("metadata") or {}
    freshness = {}
    if metadata.get("firstIncompleteDate"):
        freshness["first_incomplete_date"] = metadata["firstIncompleteDate"]
    if metadata.get("firstIncompleteHour"):
        freshness["first_incomplete_hour"] = metadata["firstIncompleteHour"]
    if not freshness:
        return None
    freshness["note"] = "Data on/after this point is still being processed and may change (America/Los_Angeles time)."
    return freshness


def _summarize_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    clicks = sum(r.get("clicks", 0) for r in rows)
    impressions = sum(r.get("impressions", 0) for r in rows)
    weighted_position = sum(r.get("position", 0) * r.get("impressions", 0) for r in rows)
    return {
        "clicks": clicks,
        "impressions": impressions,
        "ctr": round(clicks / impressions, 4) if impressions else 0,
        "position": round(weighted_position / impressions, 1) if impressions else 0,
    }


def _csv_cell(value: Any) -> Any:
    return " | ".join(str(v) for v in value) if isinstance(value, (list, tuple)) else value


def _rows_payload(rows: List[Dict[str, Any]], response_format: str) -> Dict[str, Any]:
    """Render rows as a list of objects (json), a column header plus value arrays (compact), or CSV text."""
    if response_format == "json" or not rows:
        return {"rows": rows}
    columns = list(rows[0].keys())
    if response_format == "compact":
        return {"columns": columns, "rows": [[r.get(c) for c in columns] for r in rows]}
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(columns)
    for r in rows:
        writer.writerow([_csv_cell(r.get(c)) for c in columns])
    return {"rows_csv": buf.getvalue()}


def _dumps_rows_within_budget(base: Dict[str, Any], rows: List[Dict[str, Any]], response_format: str = "json") -> str:
    """Serialize ``base`` plus ``rows``, dropping trailing rows so the output fits MAX_RESPONSE_CHARS."""
    response_format = _normalize_choice(response_format or "json", _RESPONSE_FORMATS, "response_format")

    def _render(n: int, truncated: bool) -> str:
        payload = dict(base)
        if truncated:
            payload["truncation"] = {
                "returned_rows": n,
                "total_rows": len(rows),
                "omitted_rows": len(rows) - n,
                "hint": (
                    "Response trimmed to fit the context budget (GSC_MAX_RESPONSE_CHARS). "
                    "Use response_format='compact' or 'csv', a smaller row_limit, filters, "
                    "or export_search_analytics to write the full result set to a file."
                ),
            }
        payload.update(_rows_payload(rows[:n], response_format))
        return json.dumps(payload, ensure_ascii=False)

    full = _render(len(rows), False)
    if MAX_RESPONSE_CHARS <= 0 or len(full) <= MAX_RESPONSE_CHARS:
        return full

    lo, hi = 0, len(rows) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(_render(mid, True)) <= MAX_RESPONSE_CHARS:
            lo = mid
        else:
            hi = mid - 1
    return _render(lo, True)


@mcp.tool()
async def get_capabilities() -> str:
    """
    Get a full list of all available tools, current auth status, and how to get started.
    ALWAYS call this first when asked what tools are available, what this server can do,
    or how to get started. Returns all tool names grouped by category in a single call —
    faster than searching individually. Also shows if authentication is needed.
    """
    # Check auth status
    try:
        get_gsc_service()
        auth_status = "✅ Authenticated — ready to use all tools."
    except Exception as e:
        auth_status = f"❌ Not authenticated — call the 'reauthenticate' tool first to open a browser login window.\nDetails: {e}"

    return f"""Google Search Console MCP Server

AUTH STATUS:
{auth_status}

GETTING STARTED:
1. If not authenticated, call the 'reauthenticate' tool to complete OAuth login.
2. Call 'list_properties' to see all your GSC sites and get the exact site_url for other tools.
3. Use any tool below with the site_url from step 2.

AVAILABLE TOOLS:

Authentication:
  - reauthenticate: Open browser OAuth login window. Call this if you see auth errors.

Properties:
  - list_properties: List all GSC sites/properties you have access to (start here)
  - get_site_details: Get verification and ownership details for a site

Analytics & Reporting:
  - get_search_analytics: Top queries and pages with clicks, impressions, CTR, position
  - get_performance_overview: Summary of site performance for a time period
  - compare_search_periods: Compare performance between two time periods
  - get_search_by_page_query: Search terms driving traffic to a specific page
  - get_advanced_search_analytics: Filtering (incl. regex), pagination, hourly data, search
    appearance breakdowns, aggregation type, Discover / Google News
  - export_search_analytics: Write large result sets (100k+ rows) to a CSV/JSONL file and
    return only a summary — use this instead of pulling huge tables into the chat

URL Inspection & Indexing:
  - inspect_url_enhanced: Detailed crawl/index, rich result and AMP status for a specific URL
  - batch_url_inspection: Inspect up to 10 URLs at once
  - check_indexing_issues: Check multiple URLs for indexing problems

Page Experience:
  - get_core_web_vitals: Core Web Vitals (LCP, INP, CLS) field + lab data via PageSpeed Insights

Keeping responses small:
  - Row-based tools accept response_format="compact" or "csv" (30-50% smaller than "json")
  - Responses over GSC_MAX_RESPONSE_CHARS are trimmed and include a "truncation" hint

Sitemaps:
  - get_sitemaps: List all sitemaps for a site
  - list_sitemaps_enhanced: Detailed sitemap info including errors and warnings
  - manage_sitemaps: Submit or delete sitemaps (requires GSC_ALLOW_DESTRUCTIVE=true for delete)

Destructive (disabled by default, set GSC_ALLOW_DESTRUCTIVE=true to enable):
  - add_site: Add a new property to GSC
  - delete_site: Remove a property from GSC
"""


@mcp.tool()
async def list_properties() -> str:
    """
    List all Google Search Console (GSC) properties and sites the user has access to.
    Use this to see all verified sites, domain properties, and URL-prefix properties
    in the connected Google Search Console account. Always call this first to get the
    exact site_url needed for other tools.
    """
    try:
        service = get_gsc_service()
        site_list = service.sites().list().execute()

        # site_list is typically something like:
        # {
        #   "siteEntry": [
        #       {"siteUrl": "...", "permissionLevel": "..."},
        #       ...
        #   ]
        # }
        sites = site_list.get("siteEntry", [])

        if not sites:
            return "No Search Console properties found."

        return json.dumps({
            "count": len(sites),
            "properties": [
                {
                    "site_url": site.get("siteUrl", "Unknown"),
                    "permission_level": site.get("permissionLevel", "Unknown"),
                }
                for site in sites
            ],
        })
    except FileNotFoundError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error retrieving properties: {str(e)}"

@mcp.tool()
async def add_site(site_url: str) -> str:
    """
    Add a site to your Search Console properties.
    
    Args:
        site_url: The URL of the site to add (must be exact match e.g. https://example.com, or https://www.example.com, or https://subdomain.example.com/path/, for domain properties use format: sc-domain:example.com)
    """
    if not ALLOW_DESTRUCTIVE:
        return (
            "Safety: add_site is a destructive operation that modifies your GSC account. "
            "Set GSC_ALLOW_DESTRUCTIVE=true in your environment to enable add/delete tools."
        )
    try:
        service = get_gsc_service()
        
        # Add the site
        response = service.sites().add(siteUrl=site_url).execute()
        
        # Format the response
        result_lines = [f"Site {site_url} has been added to Search Console."]
        
        # Add permission level if available
        if "permissionLevel" in response:
            result_lines.append(f"Permission level: {response['permissionLevel']}")
        
        return "\n".join(result_lines)
    except HttpError as e:
        error_content = json.loads(e.content.decode('utf-8'))
        error_details = error_content.get('error', {})
        error_code = e.resp.status
        error_message = error_details.get('message', str(e))
        error_reason = error_details.get('errors', [{}])[0].get('reason', '')
        
        if error_code == 409:
            return f"Site {site_url} is already added to Search Console."
        elif error_code == 403:
            if error_reason == 'forbidden':
                return f"Error: You don't have permission to add this site. Please verify ownership first."
            elif error_reason == 'quotaExceeded':
                return f"Error: API quota exceeded. Please try again later."
            else:
                return f"Error: Permission denied. {error_message}"
        elif error_code == 400:
            if error_reason == 'invalidParameter':
                return f"Error: Invalid site URL format. Please check the URL format and try again."
            else:
                return f"Error: Bad request. {error_message}"
        elif error_code == 401:
            return f"Error: Unauthorized. Please check your credentials."
        elif error_code == 429:
            return f"Error: Too many requests. Please try again later."
        elif error_code == 500:
            return f"Error: Internal server error from Google Search Console API. Please try again later."
        elif error_code == 503:
            return f"Error: Service unavailable. Google Search Console API is currently down. Please try again later."
        else:
            return f"Error adding site (HTTP {error_code}): {error_message}"
    except Exception as e:
        return f"Error adding site: {str(e)}"

@mcp.tool()
async def delete_site(site_url: str) -> str:
    """
    Remove a site from your Search Console properties.
    
    Args:
        site_url: The URL of the site to remove (must be exact match e.g. https://example.com, or https://www.example.com, or https://subdomain.example.com/path/, for domain properties use format: sc-domain:example.com)
    """
    if not ALLOW_DESTRUCTIVE:
        return (
            "Safety: delete_site permanently removes a property from your GSC account. "
            "Set GSC_ALLOW_DESTRUCTIVE=true in your environment to enable add/delete tools."
        )
    try:
        service = get_gsc_service()
        
        # Delete the site
        service.sites().delete(siteUrl=site_url).execute()
        
        return f"Site {site_url} has been removed from Search Console."
    except HttpError as e:
        error_content = json.loads(e.content.decode('utf-8'))
        error_details = error_content.get('error', {})
        error_code = e.resp.status
        error_message = error_details.get('message', str(e))
        error_reason = error_details.get('errors', [{}])[0].get('reason', '')
        
        if error_code == 404:
            return f"Site {site_url} was not found in Search Console."
        elif error_code == 403:
            if error_reason == 'forbidden':
                return f"Error: You don't have permission to remove this site."
            elif error_reason == 'quotaExceeded':
                return f"Error: API quota exceeded. Please try again later."
            else:
                return f"Error: Permission denied. {error_message}"
        elif error_code == 400:
            if error_reason == 'invalidParameter':
                return f"Error: Invalid site URL format. Please check the URL format and try again."
            else:
                return f"Error: Bad request. {error_message}"
        elif error_code == 401:
            return f"Error: Unauthorized. Please check your credentials."
        elif error_code == 429:
            return f"Error: Too many requests. Please try again later."
        elif error_code == 500:
            return f"Error: Internal server error from Google Search Console API. Please try again later."
        elif error_code == 503:
            return f"Error: Service unavailable. Google Search Console API is currently down. Please try again later."
        else:
            return f"Error removing site (HTTP {error_code}): {error_message}"
    except Exception as e:
        return f"Error removing site: {str(e)}"

@mcp.tool()
async def get_search_analytics(
    site_url: str,
    days: int = 28,
    dimensions: str = "query",
    row_limit: int = 20,
    search_type: str = "web",
    response_format: str = "json",
) -> str:
    """
    Get search analytics data for a specific property.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        days: Number of days to look back (default: 28)
        dimensions: Dimensions to group by (default: query). Options: query, page, device, country,
                   date, searchAppearance. You can provide multiple dimensions separated by comma
                   (e.g., "query,page"). For hourly data use get_advanced_search_analytics with "hour".
        row_limit: Number of rows to return (default: 20, max: 500). Use 5-20 for quick overviews,
                   50-200 for deeper analysis, up to 500 for comprehensive reports. For bulk exports
                   beyond 500 rows, use get_advanced_search_analytics which supports pagination.
        search_type: web (default), image, video, news, discover, googleNews
        response_format: "json" (list of objects, default), "compact" (column header + value
                   arrays, 30-50% smaller) or "csv"
    """
    try:
        response_format = _normalize_choice(response_format or "json", _RESPONSE_FORMATS, "response_format")
        dimension_list = _parse_dimensions(dimensions)
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        request = _build_search_analytics_request(
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d"),
            dimension_list,
            search_type=search_type,
            row_limit=min(max(1, row_limit), 500),
        )
    except ValueError as e:
        return str(e)

    try:
        service = get_gsc_service()
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
        
        if not response.get("rows"):
            return f"No search analytics data found for {site_url} in the last {days} days."

        rows = _shape_rows(response["rows"], dimension_list)
        base = {
            "site_url": site_url,
            "date_range": {
                "start": start_date.strftime("%Y-%m-%d"),
                "end": end_date.strftime("%Y-%m-%d"),
                "days": days,
            },
            "search_type": request["type"],
            "dimensions": dimension_list,
            "row_count": len(rows),
        }
        freshness = _data_freshness(response)
        if freshness:
            base["data_freshness"] = freshness
        return _dumps_rows_within_budget(base, rows, response_format)
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error retrieving search analytics: {str(e)}"

@mcp.tool()
async def get_site_details(site_url: str) -> str:
    """
    Get detailed information about a specific Search Console property.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
    """
    try:
        service = get_gsc_service()
        
        # Get site details
        site_info = service.sites().get(siteUrl=site_url).execute()
        
        result = {
            "site_url": site_url,
            "permission_level": site_info.get("permissionLevel", "Unknown"),
        }

        if "siteVerificationInfo" in site_info:
            verify_info = site_info["siteVerificationInfo"]
            result["verification"] = {
                "state": verify_info.get("verificationState", "Unknown"),
                "verified_user": verify_info.get("verifiedUser"),
                "method": verify_info.get("verificationMethod"),
            }

        if "ownershipInfo" in site_info:
            owner_info = site_info["ownershipInfo"]
            result["ownership"] = {
                "owner": owner_info.get("owner", "Unknown"),
                "verification_method": owner_info.get("verificationMethod"),
            }

        return json.dumps(result)
    except Exception as e:
        return f"Error retrieving site details: {str(e)}"

@mcp.tool()
async def get_sitemaps(site_url: str) -> str:
    """
    List all sitemaps for a specific Search Console property.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
    """
    try:
        service = get_gsc_service()
        
        # Get sitemaps list
        sitemaps = service.sitemaps().list(siteUrl=site_url).execute()
        
        if not sitemaps.get("sitemap"):
            return f"No sitemaps found for {site_url}."

        sitemap_list = []
        for sitemap in sitemaps.get("sitemap", []):
            last_downloaded = sitemap.get("lastDownloaded")
            if last_downloaded:
                try:
                    dt = datetime.fromisoformat(last_downloaded.replace("Z", "+00:00"))
                    last_downloaded = dt.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    pass

            errors = int(sitemap.get("errors", 0))
            warnings = int(sitemap.get("warnings", 0))

            status = "Valid"
            if errors > 0:
                status = "Has errors"
            elif warnings > 0:
                status = "Has warnings"

            indexed_urls = None
            if "contents" in sitemap:
                for content in sitemap["contents"]:
                    if content.get("type") == "web":
                        indexed_urls = content.get("submitted")
                        break

            sitemap_list.append({
                "path": sitemap.get("path", "Unknown"),
                "last_downloaded": last_downloaded,
                "status": status,
                "indexed_urls": indexed_urls,
                "errors": errors,
                "warnings": warnings,
            })

        return json.dumps({
            "site_url": site_url,
            "count": len(sitemap_list),
            "sitemaps": sitemap_list,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error retrieving sitemaps: {str(e)}"

def _rich_results_summary(inspection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Shape the richResultsResult of a URL inspection into a reportable summary.

    Shared by inspect_url_enhanced and batch_url_inspection so both tools report the
    same thing for the same page.

    Issues are nested under detectedItems[].items[].issues[] and the message key is
    "issueMessage". Reading a top-level "richResultsIssues" key -- which the API never
    returns -- made this list always empty, hiding every rich-result problem.
    """
    if "richResultsResult" not in inspection:
        return None

    rich = inspection["richResultsResult"]
    return {
        "verdict": rich.get("verdict", "UNKNOWN"),
        "detected_types": [
            item.get("richResultType", "Unknown")
            for item in rich.get("detectedItems", [])
        ],
        "issues": [
            {
                "type": detected.get("richResultType", "Unknown"),
                "item": item.get("name"),
                "severity": issue.get("severity"),
                "message": issue.get("issueMessage"),
            }
            for detected in rich.get("detectedItems", [])
            for item in detected.get("items", [])
            for issue in item.get("issues", [])
        ],
    }


def _format_crawl_time(value: Optional[str], fmt: str = "%Y-%m-%d %H:%M") -> Optional[str]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime(fmt)
    except Exception:
        return value


def _amp_summary(inspection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Shape the ampResult of a URL inspection; None when the page has no AMP version."""
    if "ampResult" not in inspection:
        return None
    amp = inspection["ampResult"]
    return {
        "verdict": amp.get("verdict", "UNKNOWN"),
        "amp_url": amp.get("ampUrl"),
        "index_status_verdict": amp.get("ampIndexStatusVerdict"),
        "indexing_state": amp.get("indexingState"),
        "page_fetch_state": amp.get("pageFetchState"),
        "robots_txt_state": amp.get("robotsTxtState"),
        "last_crawled": _format_crawl_time(amp.get("lastCrawlTime")),
        "issues": [
            {"severity": issue.get("severity"), "message": issue.get("issueMessage")}
            for issue in amp.get("issues", [])
        ],
    }


def _inspection_request(site_url: str, page_url: str, language_code: Optional[str] = None) -> Dict[str, str]:
    request = {"inspectionUrl": page_url, "siteUrl": site_url}
    if language_code:
        request["languageCode"] = language_code
    return request


@mcp.tool()
async def inspect_url_enhanced(site_url: str, page_url: str, language_code: str = None) -> str:
    """
    Enhanced URL inspection to check indexing status, rich results and AMP status in Google.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        page_url: The specific URL to inspect
        language_code: Optional IETF BCP-47 language code (e.g. "zh-CN", "ja", "de") for the
                  human-readable messages such as coverage state and issue text. Default: en-US.
    """
    try:
        service = get_gsc_service()
        request = _inspection_request(site_url, page_url, language_code)
        response = service.urlInspection().index().inspect(body=request).execute()
        
        if not response or "inspectionResult" not in response:
            return f"No inspection data found for {page_url}."

        inspection = response["inspectionResult"]
        index_status = inspection.get("indexStatusResult", {})

        result = {
            "page_url": page_url,
            "site_url": site_url,
            "inspection_result_link": inspection.get("inspectionResultLink"),
            "verdict": index_status.get("verdict", "UNKNOWN"),
            "coverage_state": index_status.get("coverageState"),
            "last_crawled": _format_crawl_time(index_status.get("lastCrawlTime")),
            "page_fetch_state": index_status.get("pageFetchState"),
            "robots_txt_state": index_status.get("robotsTxtState"),
            "indexing_state": index_status.get("indexingState"),
            "google_canonical": index_status.get("googleCanonical"),
            "user_canonical": index_status.get("userCanonical"),
            "crawled_as": index_status.get("crawledAs"),
            "sitemaps": index_status.get("sitemap", []),
            "referring_urls": index_status.get("referringUrls", [])[:5],
            "rich_results": _rich_results_summary(inspection),
        }
        amp = _amp_summary(inspection)
        if amp:
            result["amp"] = amp
        return json.dumps(result, ensure_ascii=False)
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error inspecting URL: {str(e)}"

# Max URLs inspected concurrently in batch_url_inspection. The URL Inspection API
# allows 600 queries/minute per site, so 10 in-flight is comfortably within limits.
_BATCH_INSPECTION_CONCURRENCY = 10


def _inspect_single_url(site_url: str, page_url: str, language_code: Optional[str] = None) -> Dict[str, Any]:
    """Inspect one URL and shape the result into a row.

    Builds its own Search Console service so it is safe to run in a worker thread —
    google-api-python-client's underlying http transport is not thread-safe to share
    across threads. Never raises: failures are returned as an ``error`` row so one bad
    URL doesn't sink the whole batch.
    """
    try:
        service = get_gsc_service()
        request = _inspection_request(site_url, page_url, language_code)
        response = service.urlInspection().index().inspect(body=request).execute()

        if not response or "inspectionResult" not in response:
            return {"url": page_url, "error": "No inspection data found"}

        inspection = response["inspectionResult"]
        index_status = inspection.get("indexStatusResult", {})

        # Rich results, in the same shape inspect_url_enhanced reports.
        row = {
            "url": page_url,
            "index_verdict": index_status.get("verdict", "UNKNOWN"),
            "coverage_state": index_status.get("coverageState", "Unknown"),
            "last_crawled": _format_crawl_time(index_status.get("lastCrawlTime"), "%Y-%m-%d") or "Never",
            "rich_results": _rich_results_summary(inspection),
        }
        amp = _amp_summary(inspection)
        if amp:
            row["amp"] = amp
        return row
    except Exception as e:
        return {"url": page_url, "error": str(e)}


@mcp.tool()
async def batch_url_inspection(site_url: str, urls: str, language_code: str = None) -> str:
    """
    Inspect multiple URLs in batch (within API limits).

    URLs are inspected concurrently, so a full batch stays well under the MCP
    client's request timeout even on slower sc-domain:* properties.

    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        urls: List of URLs to inspect, one per line
        language_code: Optional IETF BCP-47 language code (e.g. "zh-CN") for human-readable messages
    """
    try:
        # Validate auth once up front. This also refreshes the OAuth token a single
        # time so the concurrent workers below reuse it without racing on token.json.
        get_gsc_service()

        # Parse URLs
        url_list = [url.strip() for url in urls.split('\n') if url.strip()]

        if not url_list:
            return "No URLs provided for inspection."

        if len(url_list) > 10:
            return f"Too many URLs provided ({len(url_list)}). Please limit to 10 URLs per batch to avoid API quota issues."

        # Inspect concurrently. The URL Inspection API is slow (especially on
        # sc-domain:* properties); running 10 URLs sequentially blew past the MCP
        # client's default 60s timeout (#31). google-api-python-client is blocking,
        # so each call runs in a worker thread with its own service instance.
        semaphore = asyncio.Semaphore(_BATCH_INSPECTION_CONCURRENCY)

        async def _run(page_url: str) -> Dict[str, Any]:
            async with semaphore:
                return await asyncio.to_thread(_inspect_single_url, site_url, page_url, language_code)

        # asyncio.gather preserves the order of url_list.
        results = await asyncio.gather(*[_run(u) for u in url_list])

        return json.dumps({
            "site_url": site_url,
            "count": len(results),
            "results": list(results),
        }, ensure_ascii=False)

    except Exception as e:
        return f"Error performing batch inspection: {str(e)}"

def _check_indexing_single_url(site_url: str, page_url: str) -> Dict[str, Optional[str]]:
    """Inspect one URL and classify it into indexing-issue buckets.

    Builds its own service so it is safe to run in a worker thread. Never raises:
    failures are recorded under ``not_indexed``. Returns one string (or None) per
    category so the caller can aggregate results in input order.
    """
    result: Dict[str, Optional[str]] = {
        "not_indexed": None,
        "canonical_issues": None,
        "robots_blocked": None,
        "fetch_issues": None,
        "indexed": None,
    }
    try:
        service = get_gsc_service()
        request = {"inspectionUrl": page_url, "siteUrl": site_url}
        response = service.urlInspection().index().inspect(body=request).execute()

        if not response or "inspectionResult" not in response:
            result["not_indexed"] = f"{page_url} - No inspection data found"
            return result

        inspection = response["inspectionResult"]
        index_status = inspection.get("indexStatusResult", {})

        verdict = index_status.get("verdict", "UNKNOWN")
        coverage = index_status.get("coverageState", "Unknown")

        if verdict != "PASS" or "not indexed" in coverage.lower() or "excluded" in coverage.lower():
            result["not_indexed"] = f"{page_url} - {coverage}"
        else:
            result["indexed"] = page_url

        google_canonical = index_status.get("googleCanonical", "")
        user_canonical = index_status.get("userCanonical", "")
        if google_canonical and user_canonical and google_canonical != user_canonical:
            result["canonical_issues"] = (
                f"{page_url} - Google chose: {google_canonical} instead of user-declared: {user_canonical}"
            )

        robots_state = index_status.get("robotsTxtState", "")
        if robots_state == "DISALLOWED":
            result["robots_blocked"] = page_url

        fetch_state = index_status.get("pageFetchState", "")
        if fetch_state != "SUCCESSFUL":
            result["fetch_issues"] = f"{page_url} - {fetch_state}"
    except Exception as e:
        result["not_indexed"] = f"{page_url} - Error: {str(e)}"
    return result


@mcp.tool()
async def check_indexing_issues(site_url: str, urls: str) -> str:
    """
    Check for specific indexing issues across multiple URLs.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        urls: List of URLs to check, one per line
    """
    try:
        # Validate auth once up front (also refreshes the token so the concurrent
        # workers below reuse it without racing on token.json).
        get_gsc_service()

        # Parse URLs
        url_list = [url.strip() for url in urls.split('\n') if url.strip()]

        if not url_list:
            return "No URLs provided for inspection."

        if len(url_list) > 10:
            return f"Too many URLs provided ({len(url_list)}). Please limit to 10 URLs per batch to avoid API quota issues."

        # Inspect concurrently — same reasoning as batch_url_inspection (#31): the
        # sequential loop timed out on sc-domain:* properties near the 10-URL cap.
        semaphore = asyncio.Semaphore(_BATCH_INSPECTION_CONCURRENCY)

        async def _run(page_url: str) -> Dict[str, Optional[str]]:
            async with semaphore:
                return await asyncio.to_thread(_check_indexing_single_url, site_url, page_url)

        # asyncio.gather preserves url_list order.
        per_url = await asyncio.gather(*[_run(u) for u in url_list])

        # Aggregate the per-URL classifications by category, in input order.
        issues_summary = {
            "not_indexed": [],
            "canonical_issues": [],
            "robots_blocked": [],
            "fetch_issues": [],
            "indexed": []
        }
        for entry in per_url:
            for category, value in entry.items():
                if value is not None:
                    issues_summary[category].append(value)

        return json.dumps({
            "site_url": site_url,
            "summary": {
                "total_checked": len(url_list),
                "indexed": len(issues_summary["indexed"]),
                "not_indexed": len(issues_summary["not_indexed"]),
                "canonical_issues": len(issues_summary["canonical_issues"]),
                "robots_blocked": len(issues_summary["robots_blocked"]),
                "fetch_issues": len(issues_summary["fetch_issues"]),
            },
            "issues": {
                "not_indexed": issues_summary["not_indexed"],
                "canonical_issues": issues_summary["canonical_issues"],
                "robots_blocked": issues_summary["robots_blocked"],
                "fetch_issues": issues_summary["fetch_issues"],
            },
            "indexed_urls": issues_summary["indexed"],
        })

    except Exception as e:
        return f"Error checking indexing issues: {str(e)}"

@mcp.tool()
async def get_performance_overview(site_url: str, days: int = 28, search_type: str = "web") -> str:
    """
    Get a performance overview for a specific property.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        days: Number of days to look back (default: 28)
        search_type: web (default), image, video, news, discover, googleNews
    """
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=days)
    try:
        total_request = _build_search_analytics_request(
            start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d"), [],
            search_type=search_type, row_limit=1,
        )
        date_request = _build_search_analytics_request(
            start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d"), ["date"],
            search_type=search_type, row_limit=days + 1,
        )
    except ValueError as e:
        return str(e)

    try:
        service = get_gsc_service()
        total_response = service.searchanalytics().query(siteUrl=site_url, body=total_request).execute()
        date_response = service.searchanalytics().query(siteUrl=site_url, body=date_request).execute()
        
        if not total_response.get("rows"):
            return f"No performance data available for {site_url} in the last {days} days."

        totals_row = total_response["rows"][0]
        totals = {
            "clicks": totals_row.get("clicks", 0),
            "impressions": totals_row.get("impressions", 0),
            "ctr": round(totals_row.get("ctr", 0), 4),
            "position": round(totals_row.get("position", 0), 1),
        }

        daily_trend = []
        if date_response.get("rows"):
            sorted_rows = sorted(date_response["rows"], key=lambda x: x["keys"][0])
            for row in sorted_rows:
                daily_trend.append({
                    "date": row["keys"][0],
                    "clicks": row.get("clicks", 0),
                    "impressions": row.get("impressions", 0),
                    "ctr": round(row.get("ctr", 0), 4),
                    "position": round(row.get("position", 0), 1),
                })

        result = {
            "site_url": site_url,
            "date_range": {
                "start": start_date.strftime("%Y-%m-%d"),
                "end": end_date.strftime("%Y-%m-%d"),
                "days": days,
            },
            "search_type": total_request["type"],
            "totals": totals,
            "daily_trend": daily_trend,
        }
        freshness = _data_freshness(date_response)
        if freshness:
            result["data_freshness"] = freshness
        return json.dumps(result)
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error retrieving performance overview: {str(e)}"

@mcp.tool()
async def get_advanced_search_analytics(
    site_url: str, 
    start_date: str = None, 
    end_date: str = None, 
    dimensions: str = "query", 
    search_type: str = "WEB",
    row_limit: int = 1000,
    start_row: int = 0,
    sort_by: str = "clicks",
    sort_direction: str = "descending",
    filter_dimension: str = None,
    filter_operator: str = "contains", 
    filter_expression: str = None,
    filters: str = None,
    data_state: str = None,
    aggregation_type: str = None,
    response_format: str = "json",
) -> str:
    """
    Get advanced search analytics data with sorting, filtering, pagination, hourly data and
    search appearance breakdowns.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        start_date: Start date in YYYY-MM-DD format (defaults to 28 days ago)
        end_date: End date in YYYY-MM-DD format (defaults to today)
        dimensions: Dimensions to group by, comma-separated (e.g., "query,page,device").
                 Options: query, page, country, device, date, searchAppearance, hour.
                 "hour" returns hourly data for roughly the last 10 days (data_state is set
                 to hourly_all automatically). "searchAppearance" breaks results down by rich
                 result / feature type; Google may reject it combined with some dimensions,
                 so query it alone first and then filter by a specific appearance.
        search_type: web (default), image, video, news, discover, googleNews
        row_limit: Maximum number of rows to return (max 25000)
        start_row: Starting row for pagination
        sort_by: Metric to sort by (clicks, impressions, ctr, position). Applied
                 client-side to the returned rows, since Google only sorts by clicks.
        sort_direction: Sort direction (ascending or descending). For position,
                 ascending puts the best (lowest) average position first.
        filter_dimension: Single filter dimension (query, page, country, device, searchAppearance).
                 Use 'filters' instead for multiple filters.
        filter_operator: Single filter operator (contains, equals, notContains, notEquals,
                 includingRegex, excludingRegex)
        filter_expression: Single filter expression value. Regex operators use RE2 syntax.
        filters: JSON array of filter objects for AND logic across multiple dimensions. Overrides
                 filter_dimension/filter_operator/filter_expression when provided. Each object must
                 have 'dimension', 'operator', and 'expression' keys. Valid dimensions: query, page,
                 country, device, searchAppearance. Valid operators: contains, equals, notContains,
                 notEquals, includingRegex, excludingRegex (RE2 syntax).
                 Example: [{"dimension":"country","operator":"equals","expression":"usa"},
                           {"dimension":"query","operator":"includingRegex","expression":"^(how|what) "}]
        data_state: "all" (default, matches GSC dashboard), "final" (confirmed data only, 2-3 day
                 lag) or "hourly_all" (only with the hour dimension)
        aggregation_type: auto (default), byPage, byProperty or byNewsShowcasePanel. Use auto when
                 grouping or filtering by page. byNewsShowcasePanel is only for news/googleNews.
        response_format: "json" (list of objects, default), "compact" (column header + value
                 arrays, 30-50% smaller) or "csv". Large results are trimmed to fit
                 GSC_MAX_RESPONSE_CHARS; use export_search_analytics for full exports.
    """
    if not end_date:
        end_date = datetime.now().date().strftime("%Y-%m-%d")
    if not start_date:
        start_date = (datetime.now().date() - timedelta(days=28)).strftime("%Y-%m-%d")

    try:
        response_format = _normalize_choice(response_format or "json", _RESPONSE_FORMATS, "response_format")
        dimension_list = _parse_dimensions(dimensions)
        active_filters = _parse_filters(filters, filter_dimension, filter_operator, filter_expression)
        # The Search Analytics query API has no orderBy field (it always returns rows
        # sorted by clicks descending), so sorting is applied client-side below (#54).
        request = _build_search_analytics_request(
            start_date, end_date, dimension_list,
            search_type=search_type,
            data_state=data_state,
            aggregation_type=aggregation_type,
            filter_list=active_filters,
            row_limit=row_limit,
            start_row=start_row,
        )
    except ValueError as e:
        return str(e)

    try:
        service = get_gsc_service()
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
        
        if not response.get("rows"):
            no_data_msg = (
                f"No search analytics data found for {site_url} with the specified parameters.\n\n"
                f"Parameters used:\n"
                f"- Date range: {start_date} to {end_date}\n"
                f"- Dimensions: {dimensions}\n"
                f"- Search type: {search_type}\n"
            )
            if active_filters:
                no_data_msg += "- Filters:\n"
                for f in active_filters:
                    no_data_msg += f"    {f['dimension']} {f['operator']} '{f['expression']}'\n"
            else:
                no_data_msg += "- No filter applied\n"
            return no_data_msg
        
        rows = _shape_rows(response["rows"], dimension_list)

        # Sort the returned rows client-side. Google only sorts by clicks descending
        # server-side, so without this the sort_by/sort_direction args were silently
        # ignored (#54). Sorting applies within the returned page of rows.
        valid_sort_metrics = ("clicks", "impressions", "ctr", "position")
        if sort_by in valid_sort_metrics:
            reverse = sort_direction.lower() != "ascending"
            rows.sort(key=lambda r: r.get(sort_by, 0), reverse=reverse)

        page_size = request["rowLimit"]
        has_more = len(response["rows"]) == page_size
        base = {
            "site_url": site_url,
            "date_range": {"start": start_date, "end": end_date},
            "search_type": request["type"],
            "data_state": request["dataState"],
            "dimensions": dimension_list,
            "filters_applied": active_filters,
            "pagination": {
                "start_row": start_row,
                "row_count": len(rows),
                "has_more": has_more,
                "next_start_row": start_row + page_size if has_more else None,
            },
        }
        if response.get("responseAggregationType"):
            base["aggregation_type"] = response["responseAggregationType"]
        freshness = _data_freshness(response)
        if freshness:
            base["data_freshness"] = freshness
        return _dumps_rows_within_budget(base, rows, response_format)
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error retrieving advanced search analytics: {str(e)}"

@mcp.tool()
async def compare_search_periods(
    site_url: str,
    period1_start: str,
    period1_end: str,
    period2_start: str,
    period2_end: str,
    dimensions: str = "query",
    limit: int = 10,
    search_type: str = "web",
    response_format: str = "json",
) -> str:
    """
    Compare search analytics data between two time periods.

    Direction: Period 1 is the period you are analyzing and Period 2 is the baseline
    you compare it against. All deltas are Period 1 relative to Period 2, and the
    percentage baseline is Period 2. A positive value means Period 1 outperformed
    Period 2 — more clicks/impressions, higher CTR, or a better (lower) average
    position. For a current-vs-previous comparison, pass the current period as
    Period 1 and the previous period as Period 2. Percentages are null when the
    Period 2 baseline is zero.

    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        period1_start: Start date for period 1 / the analyzed period (YYYY-MM-DD)
        period1_end: End date for period 1 / the analyzed period (YYYY-MM-DD)
        period2_start: Start date for period 2 / the baseline period (YYYY-MM-DD)
        period2_end: End date for period 2 / the baseline period (YYYY-MM-DD)
        dimensions: Dimensions to group by (default: query). Options: query, page, country,
                    device, date, searchAppearance
        limit: Number of top results to compare (default: 10)
        search_type: web (default), image, video, news, discover, googleNews
        response_format: "json" (default), "compact" (column header + value arrays) or "csv"
    """
    try:
        response_format = _normalize_choice(response_format or "json", _RESPONSE_FORMATS, "response_format")
        dimension_list = _parse_dimensions(dimensions)
        # Fetch more rows than `limit` so items can be matched between periods.
        period1_request = _build_search_analytics_request(
            period1_start, period1_end, dimension_list, search_type=search_type, row_limit=1000,
        )
        period2_request = _build_search_analytics_request(
            period2_start, period2_end, dimension_list, search_type=search_type, row_limit=1000,
        )
    except ValueError as e:
        return str(e)

    try:
        service = get_gsc_service()

        period1_response = service.searchanalytics().query(siteUrl=site_url, body=period1_request).execute()
        period2_response = service.searchanalytics().query(siteUrl=site_url, body=period2_request).execute()
        
        period1_rows = period1_response.get("rows", [])
        period2_rows = period2_response.get("rows", [])
        
        if not period1_rows and not period2_rows:
            return f"No data found for either period for {site_url}."
        
        # Create dictionaries for easy lookup
        period1_data = {tuple(row.get("keys", [])): row for row in period1_rows}
        period2_data = {tuple(row.get("keys", [])): row for row in period2_rows}
        
        # Find common keys and calculate differences
        all_keys = set(period1_data.keys()) | set(period2_data.keys())
        comparison_data = []
        
        for key in all_keys:
            p1_row = period1_data.get(key, {"clicks": 0, "impressions": 0, "ctr": 0, "position": 0})
            p2_row = period2_data.get(key, {"clicks": 0, "impressions": 0, "ctr": 0, "position": 0})
            
            # Differences are Period 1 relative to Period 2, with Period 2 as the
            # baseline. A positive value always means Period 1 outperformed Period 2
            # (more clicks/impressions, higher CTR, or a better — i.e. lower — position).
            click_diff = p1_row.get("clicks", 0) - p2_row.get("clicks", 0)
            click_pct = (click_diff / p2_row.get("clicks", 1)) * 100 if p2_row.get("clicks", 0) > 0 else float('inf')
            
            imp_diff = p1_row.get("impressions", 0) - p2_row.get("impressions", 0)
            imp_pct = (imp_diff / p2_row.get("impressions", 1)) * 100 if p2_row.get("impressions", 0) > 0 else float('inf')
            
            ctr_diff = p1_row.get("ctr", 0) - p2_row.get("ctr", 0)
            pos_diff = p2_row.get("position", 0) - p1_row.get("position", 0)  # lower position is better, so positive = Period 1 improved
            
            comparison_data.append({
                "key": key,
                "p1_clicks": p1_row.get("clicks", 0),
                "p2_clicks": p2_row.get("clicks", 0),
                "click_diff": click_diff,
                "click_pct": click_pct,
                "p1_impressions": p1_row.get("impressions", 0),
                "p2_impressions": p2_row.get("impressions", 0),
                "imp_diff": imp_diff,
                "imp_pct": imp_pct,
                "p1_ctr": p1_row.get("ctr", 0),
                "p2_ctr": p2_row.get("ctr", 0),
                "ctr_diff": ctr_diff,
                "p1_position": p1_row.get("position", 0),
                "p2_position": p2_row.get("position", 0),
                "pos_diff": pos_diff
            })
        
        # Sort by absolute click difference
        comparison_data.sort(key=lambda x: abs(x["click_diff"]), reverse=True)

        serialisable = []
        for item in comparison_data[:limit]:
            click_pct = item["click_pct"] if item["click_pct"] != float("inf") else None
            imp_pct = item["imp_pct"] if item["imp_pct"] != float("inf") else None
            serialisable.append({
                "key": list(item["key"]),
                "p1_clicks": item["p1_clicks"],
                "p2_clicks": item["p2_clicks"],
                "click_diff": item["click_diff"],
                "click_pct": round(click_pct, 1) if click_pct is not None else None,
                "p1_impressions": item["p1_impressions"],
                "p2_impressions": item["p2_impressions"],
                "imp_diff": item["imp_diff"],
                "imp_pct": round(imp_pct, 1) if imp_pct is not None else None,
                "p1_ctr": round(item["p1_ctr"], 4),
                "p2_ctr": round(item["p2_ctr"], 4),
                "ctr_diff": round(item["ctr_diff"], 4),
                "p1_position": round(item["p1_position"], 1),
                "p2_position": round(item["p2_position"], 1),
                "position_diff": round(item["pos_diff"], 1),
            })

        base = {
            "site_url": site_url,
            "period1": {"start": period1_start, "end": period1_end},
            "period2": {"start": period2_start, "end": period2_end},
            "search_type": period1_request["type"],
            "dimensions": dimension_list,
            "total_items": len(comparison_data),
            "showing": len(serialisable),
        }
        payload = json.loads(_dumps_rows_within_budget(base, serialisable, response_format))
        # Keep the established "comparison" key for the default JSON shape.
        if "rows" in payload and response_format == "json":
            payload["comparison"] = payload.pop("rows")
        return json.dumps(payload, ensure_ascii=False)
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error comparing search periods: {str(e)}"

@mcp.tool()
async def get_search_by_page_query(
    site_url: str,
    page_url: str,
    days: int = 28,
    row_limit: int = 20,
    search_type: str = "web",
    response_format: str = "json",
) -> str:
    """
    Get search analytics data for a specific page, broken down by query.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        page_url: The specific page URL to analyze
        days: Number of days to look back (default: 28)
        row_limit: Number of rows to return (default: 20, max: 500). Use 5-20 for quick overviews,
                   50-200 for deeper analysis, up to 500 for comprehensive reports. For bulk exports
                   beyond 500 rows, use get_advanced_search_analytics which supports pagination.
        search_type: web (default), image, video, news, discover, googleNews
        response_format: "json" (default), "compact" (column header + value arrays) or "csv"
    """
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=days)
    try:
        response_format = _normalize_choice(response_format or "json", _RESPONSE_FORMATS, "response_format")
        # The API always returns rows sorted by clicks descending, which is what we want here.
        request = _build_search_analytics_request(
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d"),
            ["query"],
            search_type=search_type,
            filter_list=[{"dimension": "page", "operator": "equals", "expression": page_url}],
            row_limit=min(max(1, row_limit), 500),
        )
    except ValueError as e:
        return str(e)

    try:
        service = get_gsc_service()
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
        
        if not response.get("rows"):
            return f"No search data found for page {page_url} in the last {days} days."
        
        rows = []
        for row in response.get("rows", []):
            rows.append({
                "query": row.get("keys", ["Unknown"])[0],
                "clicks": row.get("clicks", 0),
                "impressions": row.get("impressions", 0),
                "ctr": round(row.get("ctr", 0), 4),
                "position": round(row.get("position", 0), 1),
            })

        total_clicks = sum(r["clicks"] for r in rows)
        total_impressions = sum(r["impressions"] for r in rows)

        base = {
            "site_url": site_url,
            "page_url": page_url,
            "date_range": {
                "start": start_date.strftime("%Y-%m-%d"),
                "end": end_date.strftime("%Y-%m-%d"),
                "days": days,
            },
            "search_type": request["type"],
            "totals": {
                "clicks": total_clicks,
                "impressions": total_impressions,
                "avg_ctr": round(total_clicks / total_impressions, 4) if total_impressions > 0 else 0,
            },
            "row_count": len(rows),
        }
        return _dumps_rows_within_budget(base, rows, response_format)
    except Exception as e:
        return f"Error retrieving page query data: {str(e)}"


def _run_export(
    service: Any,
    site_url: str,
    base_request: Dict[str, Any],
    dimension_list: List[str],
    max_rows: int,
    file_format: str,
    path: str,
    preview_rows: int,
) -> Dict[str, Any]:
    """Page through searchanalytics.query (25k rows per call) and stream every row to ``path``."""
    fetched = 0
    pages = 0
    complete = False
    preview: List[Dict[str, Any]] = []
    clicks = impressions = weighted_position = 0.0
    freshness = None
    columns = dimension_list + ["clicks", "impressions", "ctr", "position"]

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh) if file_format == "csv" else None
        if writer:
            writer.writerow(columns)
        while fetched < max_rows:
            body = dict(base_request, rowLimit=min(_API_MAX_ROWS, max_rows - fetched), startRow=fetched)
            response = service.searchanalytics().query(siteUrl=site_url, body=body).execute()
            pages += 1
            api_rows = response.get("rows", [])
            freshness = freshness or _data_freshness(response)
            rows = _shape_rows(api_rows, dimension_list)
            for r in rows:
                if writer:
                    writer.writerow([r.get(c) for c in columns])
                else:
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")
                clicks += r["clicks"]
                impressions += r["impressions"]
                weighted_position += r["position"] * r["impressions"]
            if len(preview) < preview_rows:
                preview.extend(rows[: preview_rows - len(preview)])
            fetched += len(rows)
            if len(api_rows) < body["rowLimit"]:
                complete = True
                break

    return {
        "row_count": fetched,
        "api_calls": pages,
        "complete": complete,
        "totals": {
            "clicks": int(clicks),
            "impressions": int(impressions),
            "ctr": round(clicks / impressions, 4) if impressions else 0,
            "position": round(weighted_position / impressions, 1) if impressions else 0,
        },
        "preview": preview,
        "data_freshness": freshness,
    }


@mcp.tool()
async def export_search_analytics(
    site_url: str,
    start_date: str = None,
    end_date: str = None,
    dimensions: str = "query,page",
    search_type: str = "web",
    filters: str = None,
    data_state: str = None,
    aggregation_type: str = None,
    max_rows: int = 100000,
    file_format: str = "csv",
    preview_rows: int = 10,
) -> str:
    """
    Export a large search analytics result set to a local file instead of the chat context.

    Pages through the API automatically (25,000 rows per call) and writes every row to a
    CSV or JSONL file on the machine running this server. Only a short summary — file path,
    row count, totals and the top `preview_rows` rows by clicks — is returned, so tens of
    thousands of rows cost a few hundred tokens. Use this for bulk analysis, spreadsheets,
    or when other tools report a "truncation" block.

    Args:
        site_url: Exact GSC property URL from list_properties
        start_date: Start date YYYY-MM-DD (defaults to 28 days ago)
        end_date: End date YYYY-MM-DD (defaults to today)
        dimensions: Comma-separated dimensions (default "query,page"). Options: query, page,
                    country, device, date, searchAppearance, hour
        search_type: web (default), image, video, news, discover, googleNews
        filters: Optional JSON array of filter objects, same format as get_advanced_search_analytics
        data_state: "all", "final" or "hourly_all" (defaults to GSC_DATA_STATE)
        aggregation_type: auto, byPage, byProperty or byNewsShowcasePanel
        max_rows: Stop after this many rows (default 100000)
        file_format: "csv" (default) or "jsonl"
        preview_rows: Number of top rows to include in the response (default 10, 0 for none)
    """
    if not end_date:
        end_date = datetime.now().date().strftime("%Y-%m-%d")
    if not start_date:
        start_date = (datetime.now().date() - timedelta(days=28)).strftime("%Y-%m-%d")

    try:
        file_format = _normalize_choice(file_format or "csv", ("csv", "jsonl"), "file_format")
        dimension_list = _parse_dimensions(dimensions)
        filter_list = _parse_filters(filters)
        base_request = _build_search_analytics_request(
            start_date, end_date, dimension_list,
            search_type=search_type,
            data_state=data_state,
            aggregation_type=aggregation_type,
            filter_list=filter_list,
        )
    except ValueError as e:
        return str(e)
    if max_rows < 1:
        return "max_rows must be at least 1."

    os.makedirs(EXPORT_DIR, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9]+", "_", site_url).strip("_")[:60]
    filename = f"gsc_{slug}_{start_date}_{end_date}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{file_format}"
    path = os.path.join(EXPORT_DIR, filename)

    try:
        service = get_gsc_service()
        summary = await asyncio.to_thread(
            _run_export, service, site_url, base_request, dimension_list,
            max_rows, file_format, path, max(0, preview_rows),
        )
    except Exception as e:
        if os.path.exists(path):
            os.remove(path)
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error exporting search analytics: {str(e)}"

    if summary["row_count"] == 0:
        os.remove(path)
        return f"No search analytics data found for {site_url} between {start_date} and {end_date}."

    result = {
        "site_url": site_url,
        "file_path": path,
        "file_format": file_format,
        "date_range": {"start": start_date, "end": end_date},
        "search_type": base_request["type"],
        "data_state": base_request["dataState"],
        "dimensions": dimension_list,
        "filters_applied": filter_list,
        "row_count": summary["row_count"],
        "api_calls": summary["api_calls"],
        "complete": summary["complete"],
        "totals_of_exported_rows": summary["totals"],
        "preview": summary["preview"],
    }
    if not summary["complete"]:
        result["note"] = f"Stopped at max_rows={max_rows}; more rows are available."
    if "query" in dimension_list:
        result["totals_note"] = (
            "Totals are summed from exported rows; Google omits anonymized queries, so they "
            "are lower than get_performance_overview totals."
        )
    if summary["data_freshness"]:
        result["data_freshness"] = summary["data_freshness"]
    return json.dumps(result, ensure_ascii=False)


_PAGESPEED_ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"

# CrUX field metric key -> (output name, divisor). CLS is reported multiplied by 100.
_CWV_FIELD_METRICS = {
    "LARGEST_CONTENTFUL_PAINT_MS": ("lcp_ms", 1),
    "INTERACTION_TO_NEXT_PAINT": ("inp_ms", 1),
    "CUMULATIVE_LAYOUT_SHIFT_SCORE": ("cls", 100),
    "FIRST_CONTENTFUL_PAINT_MS": ("fcp_ms", 1),
    "EXPERIMENTAL_TIME_TO_FIRST_BYTE": ("ttfb_ms", 1),
}

_LAB_AUDITS = {
    "largest-contentful-paint": "lcp_ms",
    "cumulative-layout-shift": "cls",
    "total-blocking-time": "tbt_ms",
    "first-contentful-paint": "fcp_ms",
    "speed-index": "speed_index_ms",
}


def _fetch_pagespeed(page_url: str, strategy: str) -> Dict[str, Any]:
    params = {"url": page_url, "strategy": strategy, "category": "PERFORMANCE"}
    if PAGESPEED_API_KEY:
        params["key"] = PAGESPEED_API_KEY
    url = f"{_PAGESPEED_ENDPOINT}?{urllib.parse.urlencode(params)}"
    with urllib.request.urlopen(url, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _field_data(experience: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not experience or not experience.get("metrics"):
        return None
    metrics = {}
    for api_key, (name, divisor) in _CWV_FIELD_METRICS.items():
        metric = experience["metrics"].get(api_key)
        if metric and metric.get("percentile") is not None:
            p75 = metric["percentile"]
            metrics[name] = {
                "p75": round(p75 / divisor, 2) if divisor != 1 else p75,
                "category": metric.get("category"),
            }
    field = {"overall_category": experience.get("overall_category"), "metrics": metrics}
    if experience.get("origin_fallback"):
        field["origin_fallback"] = True
    return field


def _lab_opportunities(audits: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
    found = []
    for audit_id, audit in audits.items():
        score = audit.get("score")
        if score is None or score >= 0.9:
            continue
        savings_ms = (audit.get("details") or {}).get("overallSavingsMs") or 0
        if not savings_ms:
            metric_savings = audit.get("metricSavings") or {}
            savings_ms = max((v for k, v in metric_savings.items() if k != "CLS" and isinstance(v, (int, float))), default=0)
        if savings_ms > 0:
            found.append({"id": audit_id, "title": audit.get("title"), "estimated_savings_ms": round(savings_ms)})
    found.sort(key=lambda o: o["estimated_savings_ms"], reverse=True)
    return found[:limit]


@mcp.tool()
async def get_core_web_vitals(page_url: str, strategy: str = "mobile", max_opportunities: int = 5) -> str:
    """
    Get Core Web Vitals (LCP, INP, CLS) for a URL via the PageSpeed Insights API.

    The Search Console API does not expose the Core Web Vitals report, so this returns the
    same underlying Chrome UX Report (CrUX) field data — 28-day p75 values for the page and
    its whole origin, with GOOD / NEEDS_IMPROVEMENT / POOR ratings — plus a Lighthouse lab
    run and its biggest performance opportunities. Takes 10-60 seconds per URL.

    Args:
        page_url: Full public URL to test (e.g. "https://example.com/page/")
        strategy: "mobile" (default, what Google uses for ranking) or "desktop"
        max_opportunities: Number of top lab improvement opportunities to include (default 5, 0 for none)
    """
    try:
        strategy = _normalize_choice(strategy or "mobile", ("mobile", "desktop"), "strategy")
    except ValueError as e:
        return str(e)

    try:
        data = await asyncio.to_thread(_fetch_pagespeed, page_url, strategy.upper())
    except urllib.error.HTTPError as e:
        try:
            message = json.loads(e.read().decode("utf-8")).get("error", {}).get("message", str(e))
        except Exception:
            message = str(e)
        if e.code == 429:
            return (
                "Error: PageSpeed Insights quota exceeded. Set GSC_PAGESPEED_API_KEY to a Google "
                f"Cloud API key with the PageSpeed Insights API enabled. Details: {message}"
            )
        return f"Error running PageSpeed Insights (HTTP {e.code}): {message}"
    except Exception as e:
        return f"Error running PageSpeed Insights: {str(e)}"

    lighthouse = data.get("lighthouseResult") or {}
    audits = lighthouse.get("audits") or {}
    performance = (lighthouse.get("categories") or {}).get("performance") or {}

    lab_metrics = {}
    for audit_id, name in _LAB_AUDITS.items():
        value = (audits.get(audit_id) or {}).get("numericValue")
        if value is not None:
            lab_metrics[name] = round(value, 3) if name == "cls" else round(value)

    result = {
        "page_url": page_url,
        "strategy": strategy,
        "field_data_page": _field_data(data.get("loadingExperience")),
        "field_data_origin": _field_data(data.get("originLoadingExperience")),
        "lab_data": {
            "performance_score": round(performance["score"] * 100) if performance.get("score") is not None else None,
            "metrics": lab_metrics,
        },
    }
    if max_opportunities > 0:
        result["lab_data"]["top_opportunities"] = _lab_opportunities(audits, max_opportunities)
    if not result["field_data_page"] and not result["field_data_origin"]:
        result["field_data_note"] = "Not enough real-user Chrome traffic for CrUX field data; only lab data is available."
    return json.dumps(result, ensure_ascii=False)

@mcp.tool()
async def list_sitemaps_enhanced(site_url: str, sitemap_index: str = None) -> str:
    """
    List all sitemaps for a specific Search Console property with detailed information.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        sitemap_index: Optional sitemap index URL to list child sitemaps
    """
    try:
        service = get_gsc_service()
        
        # Get sitemaps list
        if sitemap_index:
            sitemaps = service.sitemaps().list(siteUrl=site_url, sitemapIndex=sitemap_index).execute()
            source = f"child sitemaps from index: {sitemap_index}"
        else:
            sitemaps = service.sitemaps().list(siteUrl=site_url).execute()
            source = "all submitted sitemaps"
        
        if not sitemaps.get("sitemap"):
            return f"No sitemaps found for {site_url}" + (f" in index {sitemap_index}" if sitemap_index else ".")

        def _fmt_date(raw):
            if not raw:
                return None
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
            except Exception:
                return raw

        sitemap_list = []
        for sitemap in sitemaps.get("sitemap", []):
            errors = int(sitemap.get("errors", 0))
            warnings = int(sitemap.get("warnings", 0))
            url_count = None
            if "contents" in sitemap:
                for content in sitemap["contents"]:
                    if content.get("type") == "web":
                        url_count = content.get("submitted")
                        break
            sitemap_list.append({
                "path": sitemap.get("path", "Unknown"),
                "last_submitted": _fmt_date(sitemap.get("lastSubmitted")),
                "last_downloaded": _fmt_date(sitemap.get("lastDownloaded")),
                "type": "Index" if sitemap.get("isSitemapsIndex", False) else "Sitemap",
                "is_pending": sitemap.get("isPending", False),
                "url_count": url_count,
                "errors": errors,
                "warnings": warnings,
            })

        pending_count = sum(1 for s in sitemap_list if s["is_pending"])

        return json.dumps({
            "site_url": site_url,
            "sitemap_index": sitemap_index,
            "count": len(sitemap_list),
            "pending_count": pending_count,
            "sitemaps": sitemap_list,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error retrieving sitemaps: {str(e)}"

@mcp.tool()
async def get_sitemap_details(site_url: str, sitemap_url: str) -> str:
    """
    Get detailed information about a specific sitemap.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        sitemap_url: The full URL of the sitemap to inspect
    """
    try:
        service = get_gsc_service()
        
        # Get sitemap details
        details = service.sitemaps().get(siteUrl=site_url, feedpath=sitemap_url).execute()
        
        if not details:
            return f"No details found for sitemap {sitemap_url}."

        def _fmt_date(raw):
            if not raw:
                return None
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
            except Exception:
                return raw

        is_index = details.get("isSitemapsIndex", False)
        content_breakdown = [
            {
                "type": content.get("type", "unknown").upper(),
                "submitted": content.get("submitted", 0),
                "indexed": content.get("indexed"),
            }
            for content in details.get("contents", [])
        ]

        return json.dumps({
            "sitemap_url": sitemap_url,
            "site_url": site_url,
            "type": "Index" if is_index else "Sitemap",
            "status": "pending" if details.get("isPending", False) else "processed",
            "last_submitted": _fmt_date(details.get("lastSubmitted")),
            "last_downloaded": _fmt_date(details.get("lastDownloaded")),
            "errors": int(details.get("errors", 0)),
            "warnings": int(details.get("warnings", 0)),
            "content_breakdown": content_breakdown,
            "is_index": is_index,
        })
    except Exception as e:
        return f"Error retrieving sitemap details: {str(e)}"

@mcp.tool()
async def submit_sitemap(site_url: str, sitemap_url: str) -> str:
    """
    Submit a new sitemap or resubmit an existing one to Google.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        sitemap_url: The full URL of the sitemap to submit
    """
    try:
        service = get_gsc_service()
        
        # Submit the sitemap
        service.sitemaps().submit(siteUrl=site_url, feedpath=sitemap_url).execute()
        
        # Verify submission by getting details
        try:
            details = service.sitemaps().get(siteUrl=site_url, feedpath=sitemap_url).execute()
            
            # Format response
            result_lines = [f"Successfully submitted sitemap: {sitemap_url}"]
            
            # Add submission time if available
            if "lastSubmitted" in details:
                try:
                    dt = datetime.fromisoformat(details["lastSubmitted"].replace('Z', '+00:00'))
                    result_lines.append(f"Submission time: {dt.strftime('%Y-%m-%d %H:%M')}")
                except Exception:
                    result_lines.append(f"Submission time: {details['lastSubmitted']}")
            
            # Add processing status
            is_pending = details.get("isPending", True)
            result_lines.append(f"Status: {'Pending processing' if is_pending else 'Processing started'}")
            
            # Add note about processing time
            result_lines.append("\nNote: Google may take some time to process the sitemap. Check back later for full details.")
            
            return "\n".join(result_lines)
        except Exception:
            # If we can't get details, just return basic success message
            return f"Successfully submitted sitemap: {sitemap_url}\n\nGoogle will queue it for processing."
    
    except Exception as e:
        return f"Error submitting sitemap: {str(e)}"

@mcp.tool()
async def delete_sitemap(site_url: str, sitemap_url: str) -> str:
    """
    Delete (unsubmit) a sitemap from Google Search Console.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        sitemap_url: The full URL of the sitemap to delete
    """
    if not ALLOW_DESTRUCTIVE:
        return (
            "Safety: delete_sitemap permanently removes a sitemap from GSC. "
            "Set GSC_ALLOW_DESTRUCTIVE=true in your environment to enable add/delete tools."
        )
    try:
        service = get_gsc_service()
        
        # First check if the sitemap exists
        try:
            service.sitemaps().get(siteUrl=site_url, feedpath=sitemap_url).execute()
        except Exception as e:
            if "404" in str(e):
                return f"Sitemap not found: {sitemap_url}. It may have already been deleted or was never submitted."
            else:
                raise e
        
        # Delete the sitemap
        service.sitemaps().delete(siteUrl=site_url, feedpath=sitemap_url).execute()
        
        return f"Successfully deleted sitemap: {sitemap_url}\n\nNote: This only removes the sitemap from Search Console. Any URLs already indexed will remain in Google's index."
    
    except Exception as e:
        return f"Error deleting sitemap: {str(e)}"

@mcp.tool()
async def manage_sitemaps(site_url: str, action: str, sitemap_url: str = None, sitemap_index: str = None) -> str:
    """
    All-in-one tool to manage sitemaps (list, get details, submit, delete).
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        action: The action to perform (list, details, submit, delete)
        sitemap_url: The full URL of the sitemap (required for details, submit, delete)
        sitemap_index: Optional sitemap index URL for listing child sitemaps (only used with 'list' action)
    """
    try:
        # Validate inputs
        action = action.lower().strip()
        valid_actions = ["list", "details", "submit", "delete"]
        
        if action not in valid_actions:
            return f"Invalid action: {action}. Please use one of: {', '.join(valid_actions)}"
        
        if action in ["details", "submit", "delete"] and not sitemap_url:
            return f"The {action} action requires a sitemap_url parameter."
        
        # Perform the requested action
        if action == "list":
            return await list_sitemaps_enhanced(site_url, sitemap_index)
        elif action == "details":
            return await get_sitemap_details(site_url, sitemap_url)
        elif action == "submit":
            return await submit_sitemap(site_url, sitemap_url)
        elif action == "delete":
            return await delete_sitemap(site_url, sitemap_url)
    
    except Exception as e:
        return f"Error managing sitemaps: {str(e)}"

@mcp.tool()
async def get_creator_info() -> str:
    """
    Provides information about Amin Foroutan, the creator of the MCP-GSC tool.
    """
    creator_info = """
# About the Creator: Amin Foroutan

Amin Foroutan is an SEO consultant with over a decade of experience, specializing in technical SEO, Python-driven tools, and data analysis for SEO performance.

## Connect with Amin:

- **LinkedIn**: [Amin Foroutan](https://www.linkedin.com/in/ma-foroutan/)
- **Personal Website**: [aminforoutan.com](https://aminforoutan.com/)
- **YouTube**: [Amin Forout](https://www.youtube.com/channel/UCW7tPXg-rWdH4YzLrcAdBIw)
- **X (Twitter)**: [@aminfseo](https://x.com/aminfseo)

## Notable Projects:

Amin has created several popular SEO tools including:
- Advanced GSC Visualizer (6.4K+ users)
- SEO Render Insight Tool (3.5K+ users)
- Google AI Overview Impact Analysis (1.2K+ users)
- Google AI Overview Citation Analysis (900+ users)
- SEMRush Enhancer (570+ users)
- SEO Page Inspector (115+ users)

## Expertise:

Amin combines technical SEO knowledge with programming skills to create innovative solutions for SEO challenges.
"""
    return creator_info

@mcp.tool()
async def reauthenticate() -> str:
    """
    Perform a logout and new login sequence.
    Deletes the current OAuth token file and triggers the browser authentication flow.
    Useful when you need to switch to a different Google account.
    """
    try:
        # Delete existing token to force re-authentication
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)
            token_deleted = True
        else:
            token_deleted = False

        # Check if OAuth client secrets file exists
        if not os.path.exists(OAUTH_CLIENT_SECRETS_FILE):
            return (
                "Error: OAuth client secrets file not found. "
                "Cannot start new authentication flow. "
                "Please ensure client_secrets.json is present or set the "
                "GSC_OAUTH_CLIENT_SECRETS_FILE environment variable."
            )

        # Trigger new OAuth flow — opens a browser window on the local machine.
        # run_local_server() works on macOS even from an MCP subprocess because
        # macOS can open browsers via webbrowser.open() regardless of TTY state.
        flow = InstalledAppFlow.from_client_secrets_file(OAUTH_CLIENT_SECRETS_FILE, SCOPES)
        creds = flow.run_local_server(port=0)

        # Save the new credentials for future use
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())

        msg = "Successfully authenticated with a new Google account."
        if token_deleted:
            msg = "Previous session deleted. " + msg
        return msg

    except Exception as e:
        return f"Error during reauthentication: {str(e)}"


def main():
    """Entry point for the MCP server. Supports stdio (default) and SSE transports."""
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
    host = os.environ.get("MCP_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("MCP_PORT", "3001"))
    except ValueError:
        raise ValueError("MCP_PORT must be an integer")

    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport in {"sse", "http"}:
        # mcp SDK >= 1.27 removed the host/port kwargs from run() (they must be
        # set on mcp.settings instead) and enabled DNS-rebinding protection with
        # a Host allowlist of localhost only — which 421s the remote/Docker
        # binding the operator explicitly opted into via MCP_HOST. Disable that
        # check for the documented remote path. See issues #30 and #33.
        mcp.settings.host = host
        mcp.settings.port = port
        try:
            mcp.settings.transport_security.enable_dns_rebinding_protection = False
        except Exception:
            pass
        mcp.run(transport="sse")
    else:
        raise ValueError(
            f"Unknown MCP_TRANSPORT '{transport}'. "
            "Use 'stdio' (default) or 'sse'."
        )


if __name__ == "__main__":
    main()
