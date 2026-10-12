"""
Tests for gsc_server.py.

All Google API calls are mocked — no real credentials are needed to run these tests.
Run with: pytest test_gsc_server.py -v
"""
import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, PropertyMock


# ---------------------------------------------------------------------------
# Helpers to reload the module with a clean environment each test
# ---------------------------------------------------------------------------

def _load_module(env_overrides: dict | None = None):
    """Import gsc_server with a fresh environment."""
    env = {
        "GSC_SKIP_OAUTH": "true",          # prevent live OAuth attempts by default
        "GSC_DATA_STATE": "all",
        "GSC_ALLOW_DESTRUCTIVE": "false",
        **(env_overrides or {}),
    }
    with patch.dict(os.environ, env, clear=False):
        if "gsc_server" in sys.modules:
            del sys.modules["gsc_server"]
        import gsc_server as mod
    return mod


# ---------------------------------------------------------------------------
# TestAuth
# ---------------------------------------------------------------------------

class TestAuth(unittest.TestCase):

    def test_token_loaded_from_config_dir(self):
        """TOKEN_FILE must resolve inside the user config dir, not SCRIPT_DIR."""
        mod = _load_module()
        # By default, TOKEN_FILE should NOT equal os.path.join(SCRIPT_DIR, "token.json").
        self.assertNotEqual(mod.TOKEN_FILE, os.path.join(mod.SCRIPT_DIR, "token.json"))

    def test_old_token_migrated_silently(self):
        """On first run after upgrade, a token at the old SCRIPT_DIR location is moved.

        SCRIPT_DIR is derived from __file__ at module load time, so this test places a
        real token.json in the actual SCRIPT_DIR and re-imports with a fresh GSC_CONFIG_DIR.
        The test cleans up after itself regardless of outcome.
        """
        # Discover the real SCRIPT_DIR by importing once
        if "gsc_server" in sys.modules:
            del sys.modules["gsc_server"]
        with patch.dict(os.environ, {"GSC_SKIP_OAUTH": "true", "GSC_DATA_STATE": "all",
                                     "GSC_ALLOW_DESTRUCTIVE": "false"}, clear=False):
            import gsc_server as _tmp
        actual_script_dir = _tmp.SCRIPT_DIR
        del sys.modules["gsc_server"]

        old_token_path = os.path.join(actual_script_dir, "token.json")
        old_token_content = '{"test": "migration_test"}'
        preexisting_backup = None

        with tempfile.TemporaryDirectory() as new_config_dir:
            try:
                # Back up any real existing token so we don't destroy it
                if os.path.exists(old_token_path):
                    preexisting_backup = old_token_path + ".test_bak"
                    import shutil as _shutil
                    _shutil.copy2(old_token_path, preexisting_backup)

                # Place test token in old location
                with open(old_token_path, "w") as f:
                    f.write(old_token_content)

                # Re-import with new config dir (no token there yet → migration should fire)
                env = {
                    "GSC_SKIP_OAUTH": "true",
                    "GSC_DATA_STATE": "all",
                    "GSC_ALLOW_DESTRUCTIVE": "false",
                    "GSC_CONFIG_DIR": new_config_dir,
                }
                with patch.dict(os.environ, env, clear=False):
                    import gsc_server as mod

                new_token_path = os.path.join(new_config_dir, "token.json")
                self.assertTrue(os.path.exists(new_token_path), "Token was not migrated to new location")
                self.assertFalse(os.path.exists(old_token_path), "Old token was not removed after migration")
                with open(new_token_path) as f:
                    self.assertEqual(f.read(), old_token_content)

            finally:
                del sys.modules["gsc_server"]
                # Clean up any leftover test token in SCRIPT_DIR
                if os.path.exists(old_token_path):
                    os.remove(old_token_path)
                # Restore original token if it existed
                if preexisting_backup and os.path.exists(preexisting_backup):
                    import shutil as _shutil
                    _shutil.move(preexisting_backup, old_token_path)

    def test_expired_token_refresh_succeeds(self):
        """If refresh succeeds, get_gsc_service_oauth returns without error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            mock_creds = MagicMock()
            mock_creds.valid = False
            mock_creds.expired = True
            mock_creds.refresh_token = "refresh_token"
            mock_creds.to_json.return_value = '{"token": "refreshed"}'

            def fake_refresh(request):
                mock_creds.valid = True

            mock_creds.refresh.side_effect = fake_refresh

            with patch("gsc_server.Credentials.from_authorized_user_file", return_value=mock_creds), \
                 patch("gsc_server.build", return_value=MagicMock()), \
                 patch.object(mod, "TOKEN_FILE", os.path.join(tmpdir, "token.json")):
                open(os.path.join(tmpdir, "token.json"), "w").write("{}")
                service = mod.get_gsc_service_oauth()
                self.assertIsNotNone(service)

    def test_expired_token_no_refresh_raises_runtime_error(self):
        """When refresh fails and no secrets file, get_gsc_service_oauth raises RuntimeError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            mock_creds = MagicMock()
            mock_creds.valid = False
            mock_creds.expired = True
            mock_creds.refresh_token = None  # no refresh token available

            with patch("gsc_server.Credentials.from_authorized_user_file", return_value=mock_creds), \
                 patch.object(mod, "TOKEN_FILE", os.path.join(tmpdir, "token.json")), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "no_secrets.json")):
                open(os.path.join(tmpdir, "token.json"), "w").write("{}")
                with self.assertRaises((RuntimeError, FileNotFoundError)):
                    mod.get_gsc_service_oauth()

    def test_no_token_no_secrets_raises_file_not_found(self):
        """With no token file and no secrets file, FileNotFoundError is raised."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            with patch.object(mod, "TOKEN_FILE", os.path.join(tmpdir, "nonexistent_token.json")), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "nonexistent_secrets.json")):
                with self.assertRaises(FileNotFoundError):
                    mod.get_gsc_service_oauth()

    def test_skip_oauth_env_var(self):
        """GSC_SKIP_OAUTH=true makes get_gsc_service skip OAuth."""
        mod = _load_module({"GSC_SKIP_OAUTH": "true"})
        self.assertTrue(mod.SKIP_OAUTH)

    def test_gsc_credentials_path_set_but_missing_fails_fast(self):
        """When GSC_CREDENTIALS_PATH is set but the file does not exist, get_gsc_service
        must raise FileNotFoundError immediately with a message that names the specific
        path AND mentions uvx — instead of silently falling through to SCRIPT_DIR/cwd
        fallbacks that uvx users cannot reach. Regression guard for issue #25.
        """
        missing_path = "/tmp/definitely-does-not-exist-issue-25.json"
        mod = _load_module({
            "GSC_CREDENTIALS_PATH": missing_path,
            "GSC_SKIP_OAUTH": "true",
        })
        with self.assertRaises(FileNotFoundError) as ctx:
            mod.get_gsc_service()
        msg = str(ctx.exception)
        self.assertIn("GSC_CREDENTIALS_PATH", msg)
        self.assertIn(missing_path, msg)
        self.assertIn("uvx", msg.lower())

    def test_gsc_oauth_client_secrets_file_set_but_missing_fails_fast(self):
        """Same symmetry for OAuth: if GSC_OAUTH_CLIENT_SECRETS_FILE is set to a
        nonexistent file, get_gsc_service must fail fast with a clear message
        instead of silently falling through.
        """
        missing_path = "/tmp/definitely-does-not-exist-oauth-issue-25.json"
        mod = _load_module({
            "GSC_OAUTH_CLIENT_SECRETS_FILE": missing_path,
            "GSC_SKIP_OAUTH": "false",
        })
        with self.assertRaises(FileNotFoundError) as ctx:
            mod.get_gsc_service()
        msg = str(ctx.exception)
        self.assertIn("GSC_OAUTH_CLIENT_SECRETS_FILE", msg)
        self.assertIn(missing_path, msg)
        self.assertIn("uvx", msg.lower())

    def test_gsc_credentials_path_expands_tilde(self):
        """GSC_CREDENTIALS_PATH must expand ~ so users can write ~/creds.json."""
        mod = _load_module({"GSC_CREDENTIALS_PATH": "~/this-should-be-expanded.json"})
        self.assertIsNotNone(mod.GSC_CREDENTIALS_PATH)
        self.assertNotIn("~", mod.GSC_CREDENTIALS_PATH)
        self.assertTrue(mod.GSC_CREDENTIALS_PATH.startswith(os.path.expanduser("~")))


# ---------------------------------------------------------------------------
# Shared fixture helper
# ---------------------------------------------------------------------------

def _make_service():
    """Return a MagicMock that mimics the Google Search Console service object."""
    return MagicMock()


# ---------------------------------------------------------------------------
# TestListProperties
# ---------------------------------------------------------------------------

class TestListProperties(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_properties_list(self):
        mod = _load_module()
        service = _make_service()
        service.sites().list().execute.return_value = {
            "siteEntry": [
                {"siteUrl": "https://example.com/", "permissionLevel": "siteOwner"},
                {"siteUrl": "sc-domain:example.com", "permissionLevel": "siteFullUser"},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_properties()
        data = json.loads(result)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["properties"][0]["site_url"], "https://example.com/")
        self.assertEqual(data["properties"][1]["permission_level"], "siteFullUser")

    async def test_returns_message_when_no_properties(self):
        mod = _load_module()
        service = _make_service()
        service.sites().list().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_properties()
        self.assertIsInstance(result, str)
        self.assertIn("No Search Console properties", result)

    async def test_handles_api_error(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", side_effect=Exception("API error")):
            result = await mod.list_properties()
        self.assertIn("Error", result)

    async def test_surfaces_real_auth_error_not_hardcoded_message(self):
        """When auth fails with a FileNotFoundError, list_properties must surface the
        actual exception text (e.g. the OAuth failure reason), NOT a hardcoded
        service-account-only message. Regression guard for issue #25 comment by
        platky: an OAuth user saw "Service account credentials file not found" even
        though they had never configured service accounts.
        """
        mod = _load_module()
        real_error = FileNotFoundError(
            "OAuth token is missing or expired and cannot be refreshed."
        )
        with patch("gsc_server.get_gsc_service", side_effect=real_error):
            result = await mod.list_properties()
        self.assertIn("OAuth token is missing", result)
        self.assertNotIn("1. Create a service account in Google Cloud Console", result)


# ---------------------------------------------------------------------------
# TestGetSearchAnalytics
# ---------------------------------------------------------------------------

class TestGetSearchAnalytics(unittest.IsolatedAsyncioTestCase):

    def _make_rows(self):
        return {
            "rows": [
                {"keys": ["seo tool"], "clicks": 100, "impressions": 1000, "ctr": 0.1, "position": 5.0},
                {"keys": ["mcp server"], "clicks": 50, "impressions": 500, "ctr": 0.1, "position": 8.2},
            ]
        }

    async def test_returns_json_with_rows(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = self._make_rows()
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_search_analytics("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["row_count"], 2)
        self.assertEqual(data["rows"][0]["query"], "seo tool")
        self.assertEqual(data["rows"][0]["clicks"], 100)
        self.assertIn("ctr", data["rows"][0])

    async def test_no_data_returns_string_message(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_search_analytics("https://example.com/")
        self.assertIsInstance(result, str)
        self.assertNotIn("{", result[:5])  # not JSON

    async def test_row_limit_capped_at_500(self):
        """Requesting more than 500 rows should be capped."""
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {"rows": []}
        with patch("gsc_server.get_gsc_service", return_value=service):
            await mod.get_search_analytics("https://example.com/", row_limit=9999)
        # Verify the request body capped at 500
        call_args = service.searchanalytics().query.call_args
        if call_args:
            body = call_args[1].get("body") or (call_args[0][0] if call_args[0] else None)
            if body and "rowLimit" in body:
                self.assertLessEqual(body["rowLimit"], 500)

    async def test_handles_404(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", side_effect=Exception("404")):
            result = await mod.get_search_analytics("https://example.com/")
        self.assertIn("not found", result.lower())


# ---------------------------------------------------------------------------
# TestGetSiteDetails
# ---------------------------------------------------------------------------

class TestGetSiteDetails(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_permission_and_verification(self):
        mod = _load_module()
        service = _make_service()
        service.sites().get().execute.return_value = {
            "permissionLevel": "siteOwner",
            "siteVerificationInfo": {"verificationState": "VERIFIED"},
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_site_details("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["permission_level"], "siteOwner")
        self.assertEqual(data["verification"]["state"], "VERIFIED")

    async def test_handles_404(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", side_effect=Exception("404")):
            result = await mod.get_site_details("https://example.com/")
        self.assertIn("Error", result)


# ---------------------------------------------------------------------------
# TestGetSitemaps
# ---------------------------------------------------------------------------

class TestGetSitemaps(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_sitemap_list(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {
            "sitemap": [
                {"path": "https://example.com/sitemap.xml", "errors": "0", "warnings": "1",
                 "contents": [{"type": "web", "submitted": "1000"}]},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_sitemaps("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["sitemaps"][0]["warnings"], 1)
        self.assertEqual(data["sitemaps"][0]["status"], "Has warnings")
        self.assertEqual(data["sitemaps"][0]["indexed_urls"], "1000")

    async def test_no_sitemaps_returns_message(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_sitemaps("https://example.com/")
        self.assertIsInstance(result, str)
        self.assertIn("No sitemaps", result)


# ---------------------------------------------------------------------------
# TestInspectUrl
# ---------------------------------------------------------------------------

class TestInspectUrl(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_verdict(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                    "pageFetchState": "SUCCESSFUL",
                    "robotsTxtState": "ALLOWED",
                    "lastCrawlTime": "2026-04-01T10:00:00Z",
                }
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.inspect_url_enhanced("https://example.com/", "https://example.com/page/")
        data = json.loads(result)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["page_url"], "https://example.com/page/")
        self.assertIn("last_crawled", data)

    async def test_reports_rich_result_issues(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {"verdict": "PASS"},
                "richResultsResult": {
                    "verdict": "PASS",
                    "detectedItems": [
                        {
                            "richResultType": "Merchant listings",
                            "items": [
                                {
                                    "name": "Example product",
                                    "issues": [
                                        {
                                            "issueMessage": "Missing field 'shippingDetails'",
                                            "severity": "WARNING",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.inspect_url_enhanced("https://example.com/", "https://example.com/page/")
        issues = json.loads(result)["rich_results"]["issues"]
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["severity"], "WARNING")
        self.assertEqual(issues[0]["message"], "Missing field 'shippingDetails'")
        self.assertEqual(issues[0]["type"], "Merchant listings")
        self.assertEqual(issues[0]["item"], "Example product")


# ---------------------------------------------------------------------------
# TestBatchUrlInspection
# ---------------------------------------------------------------------------

class TestBatchUrlInspection(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_results(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                    "lastCrawlTime": "2026-04-01T10:00:00Z",
                }
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.batch_url_inspection(
                "https://example.com/",
                "https://example.com/a/\nhttps://example.com/b/"
            )
        data = json.loads(result)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["results"][0]["index_verdict"], "PASS")

    async def test_reports_failing_rich_results(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                },
                "richResultsResult": {
                    "verdict": "FAIL",
                    "detectedItems": [
                        {
                            "richResultType": "Merchant listings",
                            "items": [
                                {
                                    "name": "Example product",
                                    "issues": [
                                        {
                                            "issueMessage": "Missing field 'image'",
                                            "severity": "ERROR",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.batch_url_inspection(
                "https://example.com/", "https://example.com/page/"
            )
        row = json.loads(result)["results"][0]
        self.assertEqual(row["index_verdict"], "PASS")
        self.assertEqual(row["rich_results"]["verdict"], "FAIL")
        self.assertEqual(row["rich_results"]["detected_types"], ["Merchant listings"])
        self.assertEqual(len(row["rich_results"]["issues"]), 1)
        self.assertEqual(row["rich_results"]["issues"][0]["severity"], "ERROR")
        self.assertEqual(
            row["rich_results"]["issues"][0]["message"], "Missing field 'image'"
        )

    async def test_batch_limit_enforced_at_10_urls(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", return_value=_make_service()):
            urls = "\n".join([f"https://example.com/{i}/" for i in range(11)])
            result = await mod.batch_url_inspection("https://example.com/", urls)
        self.assertIn("Too many URLs", result)

    async def test_processes_all_urls_in_input_order(self):
        # URLs are inspected concurrently (#31); results must still come back in the
        # same order the caller supplied them.
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {"indexStatusResult": {"verdict": "PASS"}}
        }
        input_urls = [f"https://example.com/{i}/" for i in range(5)]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.batch_url_inspection(
                "https://example.com/", "\n".join(input_urls)
            )
        data = json.loads(result)
        self.assertEqual(data["count"], 5)
        self.assertEqual([row["url"] for row in data["results"]], input_urls)


# ---------------------------------------------------------------------------
# TestCheckIndexingIssues
# ---------------------------------------------------------------------------

class TestCheckIndexingIssues(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_summary(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                }
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.check_indexing_issues(
                "https://example.com/", "https://example.com/page/"
            )
        data = json.loads(result)
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["total_checked"], 1)
        self.assertEqual(data["summary"]["indexed"], 1)

    async def test_processes_all_urls_concurrently_and_aggregates(self):
        # Concurrency mirror of #31 applied to check_indexing_issues (#55): all URLs
        # are processed and correctly classified regardless of run order.
        mod = _load_module()
        service = _make_service()

        def _inspect(body=None):
            page = body["inspectionUrl"]
            call = MagicMock()
            if page.endswith("/blocked/"):
                call.execute.return_value = {"inspectionResult": {"indexStatusResult": {
                    "verdict": "FAIL", "coverageState": "Blocked by robots.txt",
                    "robotsTxtState": "DISALLOWED"}}}
            else:
                call.execute.return_value = {"inspectionResult": {"indexStatusResult": {
                    "verdict": "PASS", "coverageState": "Submitted and indexed"}}}
            return call

        service.urlInspection().index().inspect.side_effect = _inspect
        input_urls = [
            "https://example.com/a/",
            "https://example.com/blocked/",
            "https://example.com/c/",
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.check_indexing_issues(
                "https://example.com/", "\n".join(input_urls)
            )
        data = json.loads(result)
        self.assertEqual(data["summary"]["total_checked"], 3)
        self.assertEqual(data["summary"]["indexed"], 2)
        self.assertEqual(data["summary"]["robots_blocked"], 1)
        self.assertEqual(data["issues"]["robots_blocked"], ["https://example.com/blocked/"])


# ---------------------------------------------------------------------------
# TestGetPerformanceOverview
# ---------------------------------------------------------------------------

class TestGetPerformanceOverview(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_totals_and_trend(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": [{"keys": [], "clicks": 500, "impressions": 5000, "ctr": 0.1, "position": 12.0}]},
            {"rows": [
                {"keys": ["2026-04-01"], "clicks": 250, "impressions": 2500, "ctr": 0.1, "position": 12.0},
                {"keys": ["2026-04-02"], "clicks": 250, "impressions": 2500, "ctr": 0.1, "position": 12.0},
            ]},
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_performance_overview("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["totals"]["clicks"], 500)
        self.assertEqual(len(data["daily_trend"]), 2)


# ---------------------------------------------------------------------------
# TestGetAdvancedSearchAnalytics
# ---------------------------------------------------------------------------

class TestGetAdvancedSearchAnalytics(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_rows(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            "rows": [
                {"keys": ["seo"], "clicks": 100, "impressions": 1000, "ctr": 0.1, "position": 5.0},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["rows"][0]["query"], "seo")
        self.assertIn("pagination", data)

    async def test_invalid_filters_json_returns_error_string(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", return_value=_make_service()):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", filters="not valid json"
            )
        self.assertIn("Invalid filters", result)

    async def test_pagination_info_included(self):
        mod = _load_module()
        service = _make_service()
        # Return exactly row_limit rows → has_more=True
        rows = [{"keys": [f"q{i}"], "clicks": 1, "impressions": 10, "ctr": 0.1, "position": 5.0}
                for i in range(10)]
        service.searchanalytics().query().execute.return_value = {"rows": rows}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", row_limit=10
            )
        data = json.loads(result)
        self.assertTrue(data["pagination"]["has_more"])
        self.assertEqual(data["pagination"]["next_start_row"], 10)

    async def test_sort_by_impressions_reorders_rows(self):
        # Google returns rows clicks-descending; sort_by should reorder client-side (#54).
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            "rows": [
                {"keys": ["a"], "clicks": 100, "impressions": 10, "ctr": 0.1, "position": 3.0},
                {"keys": ["b"], "clicks": 50, "impressions": 900, "ctr": 0.2, "position": 8.0},
                {"keys": ["c"], "clicks": 10, "impressions": 500, "ctr": 0.3, "position": 1.5},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", sort_by="impressions", sort_direction="descending"
            )
        rows = json.loads(result)["rows"]
        self.assertEqual([r["query"] for r in rows], ["b", "c", "a"])

    async def test_sort_by_position_ascending_puts_best_rank_first(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            "rows": [
                {"keys": ["a"], "clicks": 100, "impressions": 10, "ctr": 0.1, "position": 3.0},
                {"keys": ["b"], "clicks": 50, "impressions": 900, "ctr": 0.2, "position": 8.0},
                {"keys": ["c"], "clicks": 10, "impressions": 500, "ctr": 0.3, "position": 1.5},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", sort_by="position", sort_direction="ascending"
            )
        rows = json.loads(result)["rows"]
        self.assertEqual([r["query"] for r in rows], ["c", "a", "b"])


# ---------------------------------------------------------------------------
# TestCompareSearchPeriods
# ---------------------------------------------------------------------------

class TestCompareSearchPeriods(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_comparison(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": [{"keys": ["seo"], "clicks": 100, "impressions": 1000, "ctr": 0.1, "position": 5.0}]},
            {"rows": [{"keys": ["seo"], "clicks": 120, "impressions": 1100, "ctr": 0.11, "position": 4.5}]},
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.compare_search_periods(
                "https://example.com/",
                "2026-03-01", "2026-03-28",
                "2026-04-01", "2026-04-07",
            )
        data = json.loads(result)
        self.assertIn("comparison", data)
        self.assertEqual(len(data["comparison"]), 1)
        self.assertEqual(data["comparison"][0]["key"], ["seo"])

    async def _compare(self, mod, p1_row, p2_row):
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": [p1_row]},
            {"rows": [p2_row]},
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.compare_search_periods(
                "https://example.com/",
                "2026-04-01", "2026-04-28",  # period 1 / analyzed (current)
                "2026-03-01", "2026-03-28",  # period 2 / baseline (previous)
            )
        return json.loads(result)["comparison"][0]

    async def test_period1_growth_is_positive(self):
        # Period 1 (current) 78 clicks vs Period 2 (previous) 51 → +27 (+52.9%).
        mod = _load_module()
        item = await self._compare(
            mod,
            {"keys": ["seo"], "clicks": 78, "impressions": 800, "ctr": 0.1, "position": 10.6},
            {"keys": ["seo"], "clicks": 51, "impressions": 500, "ctr": 0.08, "position": 14.4},
        )
        self.assertEqual(item["click_diff"], 27)
        self.assertEqual(item["click_pct"], 52.9)
        # Position improved from 14.4 to 10.6 → positive delta.
        self.assertEqual(item["position_diff"], 3.8)

    async def test_period1_decline_is_negative(self):
        mod = _load_module()
        item = await self._compare(
            mod,
            {"keys": ["seo"], "clicks": 51, "impressions": 500, "ctr": 0.08, "position": 14.4},
            {"keys": ["seo"], "clicks": 78, "impressions": 800, "ctr": 0.1, "position": 10.6},
        )
        self.assertEqual(item["click_diff"], -27)
        self.assertEqual(item["click_pct"], -34.6)
        # Position worsened from 10.6 to 14.4 → negative delta.
        self.assertEqual(item["position_diff"], -3.8)

    async def test_zero_baseline_yields_null_percentage(self):
        # Key present only in Period 1 → Period 2 baseline is zero, so pct is null
        # rather than dividing by zero.
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": [{"keys": ["seo"], "clicks": 10, "impressions": 100, "ctr": 0.1, "position": 5.0}]},
            {"rows": []},
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.compare_search_periods(
                "https://example.com/",
                "2026-04-01", "2026-04-28",
                "2026-03-01", "2026-03-28",
            )
        item = json.loads(result)["comparison"][0]
        self.assertEqual(item["click_diff"], 10)
        self.assertIsNone(item["click_pct"])
        self.assertIsNone(item["imp_pct"])


# ---------------------------------------------------------------------------
# TestGetSearchByPageQuery
# ---------------------------------------------------------------------------

class TestGetSearchByPageQuery(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_totals(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            "rows": [
                {"keys": ["best seo tool"], "clicks": 50, "impressions": 500, "ctr": 0.1, "position": 7.5},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_search_by_page_query(
                "https://example.com/", "https://example.com/blog/seo/"
            )
        data = json.loads(result)
        self.assertEqual(data["page_url"], "https://example.com/blog/seo/")
        self.assertEqual(data["totals"]["clicks"], 50)
        self.assertEqual(data["rows"][0]["query"], "best seo tool")


# ---------------------------------------------------------------------------
# TestListSitemapsEnhanced
# ---------------------------------------------------------------------------

class TestListSitemapsEnhanced(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_sitemap_list(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {
            "sitemap": [
                {"path": "https://example.com/sitemap.xml", "errors": "0", "warnings": "0",
                 "isSitemapsIndex": False, "isPending": False},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_sitemaps_enhanced("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["pending_count"], 0)

    async def test_warning_status_correctly_set(self):
        """Regression: status should be 'Has warnings' when warnings > 0."""
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {
            "sitemap": [
                {"path": "https://example.com/sitemap.xml", "errors": "0", "warnings": "3"},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_sitemaps_enhanced("https://example.com/")
        # list_sitemaps_enhanced returns JSON without a status field (it's in get_sitemaps),
        # but warnings count must still be 3
        data = json.loads(result)
        self.assertEqual(data["sitemaps"][0]["warnings"], 3)


# ---------------------------------------------------------------------------
# TestGetSitemapDetails
# ---------------------------------------------------------------------------

class TestGetSitemapDetails(unittest.IsolatedAsyncioTestCase):

    async def test_get_details_returns_json(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().get().execute.return_value = {
            "isSitemapsIndex": False,
            "isPending": False,
            "errors": "0",
            "warnings": "0",
            "contents": [{"type": "web", "submitted": 500, "indexed": 480}],
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_sitemap_details("https://example.com/", "https://example.com/sitemap.xml")
        data = json.loads(result)
        self.assertEqual(data["type"], "Sitemap")
        self.assertEqual(data["status"], "processed")
        self.assertEqual(data["content_breakdown"][0]["submitted"], 500)


# ---------------------------------------------------------------------------
# TestSafetyGuards
# ---------------------------------------------------------------------------

class TestSafetyGuards(unittest.IsolatedAsyncioTestCase):

    async def test_add_site_blocked_by_default(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "false"})
        result = await mod.add_site("https://newsite.com/")
        self.assertIn("Safety", result)

    async def test_delete_site_blocked_by_default(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "false"})
        result = await mod.delete_site("https://newsite.com/")
        self.assertIn("Safety", result)

    async def test_delete_sitemap_blocked_by_default(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "false"})
        result = await mod.delete_sitemap("https://example.com/", "https://example.com/sitemap.xml")
        self.assertIn("Safety", result)

    async def test_add_site_allowed_when_flag_set(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true"})
        service = _make_service()
        service.sites().add().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.add_site("https://newsite.com/")
        self.assertNotIn("Safety", result)

    async def test_delete_site_allowed_when_flag_set(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true"})
        service = _make_service()
        service.sites().delete().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.delete_site("https://example.com/")
        self.assertNotIn("Safety", result)

    async def test_delete_sitemap_allowed_when_flag_set(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true"})
        service = _make_service()
        service.sitemaps().delete().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.delete_sitemap("https://example.com/", "https://example.com/sitemap.xml")
        self.assertNotIn("Safety", result)


# ---------------------------------------------------------------------------
# TestReauthenticate
# ---------------------------------------------------------------------------

class TestReauthenticate(unittest.IsolatedAsyncioTestCase):

    async def test_deletes_token_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            open(token_path, "w").write('{"old": "token"}')
            secrets_path = os.path.join(tmpdir, "secrets.json")
            open(secrets_path, "w").write("{}")

            mod = _load_module()

            mock_creds = MagicMock()
            mock_creds.to_json.return_value = '{"token": "new"}'

            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", secrets_path), \
                 patch("gsc_server.InstalledAppFlow") as mock_flow_cls:
                mock_flow = MagicMock()
                mock_flow.run_local_server.return_value = mock_creds
                mock_flow_cls.from_client_secrets_file.return_value = mock_flow
                result = await mod.reauthenticate()

            self.assertIn("Successfully authenticated", result)
            self.assertIn("Previous session deleted", result)
            self.assertTrue(os.path.exists(token_path))

    async def test_returns_error_when_no_secrets_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mod = _load_module()
            with patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "no_secrets.json")):
                result = await mod.reauthenticate()
        self.assertIn("Error", result)


# ---------------------------------------------------------------------------
# TestStdoutClean
# ---------------------------------------------------------------------------

class TestStdoutClean(unittest.TestCase):

    def test_auth_fallback_does_not_write_to_stdout(self):
        """get_gsc_service must not print() to stdout on OAuth failure (prevents MCP corruption)."""
        mod = _load_module({"GSC_SKIP_OAUTH": "false"})

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        try:
            with patch("gsc_server.get_gsc_service_oauth", side_effect=RuntimeError("no token")), \
                 patch("gsc_server.service_account.Credentials.from_service_account_file",
                        side_effect=Exception("no file")):
                try:
                    mod.get_gsc_service()
                except Exception:
                    pass
        finally:
            sys.stdout = old_stdout

        stdout_output = captured.getvalue()
        self.assertEqual(stdout_output, "", f"Unexpected stdout: {stdout_output!r}")


# ---------------------------------------------------------------------------
# Search Analytics: hourly data, search appearance, regex, aggregation, metadata
# ---------------------------------------------------------------------------

def _query_body(service):
    return service.searchanalytics().query.call_args.kwargs["body"]


_ONE_ROW = {"rows": [{"keys": ["seo"], "clicks": 1, "impressions": 10, "ctr": 0.1, "position": 2.0}]}


class TestSearchAnalyticsApiCoverage(unittest.IsolatedAsyncioTestCase):

    async def test_hour_dimension_sets_hourly_all_and_surfaces_freshness(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            "rows": [{"keys": ["2026-10-11T10:00:00-07:00"], "clicks": 3, "impressions": 30,
                      "ctr": 0.1, "position": 4.0}],
            "metadata": {"firstIncompleteHour": "2026-10-11T10:00:00-07:00"},
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics("https://example.com/", dimensions="hour")
        body = _query_body(service)
        self.assertEqual(body["dataState"], "hourly_all")
        self.assertEqual(body["dimensions"], ["hour"])
        data = json.loads(result)
        self.assertEqual(data["data_freshness"]["first_incomplete_hour"], "2026-10-11T10:00:00-07:00")

    async def test_hour_dimension_rejects_other_data_state(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", return_value=_make_service()):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", dimensions="hour", data_state="final"
            )
        self.assertIn("hourly_all", result)

    async def test_hourly_all_requires_hour_dimension(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", return_value=_make_service()):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", dimensions="query", data_state="hourly_all"
            )
        self.assertIn("hour", result)

    async def test_search_appearance_regex_filter_and_aggregation(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            **_ONE_ROW, "responseAggregationType": "byProperty",
        }
        filters = json.dumps([
            {"dimension": "search_appearance", "operator": "equals", "expression": "VIDEO"},
            {"dimension": "query", "operator": "INCLUDING_REGEX", "expression": "^(how|what) "},
        ])
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", dimensions="query,searchappearance",
                filters=filters, aggregation_type="by_property", search_type="googleNews",
            )
        body = _query_body(service)
        self.assertEqual(body["dimensions"], ["query", "searchAppearance"])
        self.assertEqual(body["type"], "GOOGLE_NEWS")
        self.assertEqual(body["aggregationType"], "byProperty")
        group = body["dimensionFilterGroups"][0]
        self.assertEqual(group["filters"][0]["dimension"], "searchAppearance")
        self.assertEqual(group["filters"][1]["operator"], "includingRegex")
        self.assertEqual(json.loads(result)["aggregation_type"], "byProperty")

    async def test_invalid_operator_lists_valid_values(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", return_value=_make_service()):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", filter_dimension="query",
                filter_operator="startsWith", filter_expression="x",
            )
        self.assertIn("includingRegex", result)

    async def test_invalid_search_type_rejected(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", return_value=_make_service()):
            result = await mod.get_search_analytics("https://example.com/", search_type="shopping")
        self.assertIn("Invalid search_type", result)

    async def test_performance_overview_passes_search_type_and_covers_every_day(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": [{"keys": [], "clicks": 5, "impressions": 50, "ctr": 0.1, "position": 3.0}]},
            {"rows": [], "metadata": {"firstIncompleteDate": "2026-10-11"}},
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_performance_overview("https://example.com/", days=7, search_type="discover")
        body = _query_body(service)
        self.assertEqual(body["type"], "DISCOVER")
        self.assertEqual(body["rowLimit"], 8)
        self.assertEqual(json.loads(result)["data_freshness"]["first_incomplete_date"], "2026-10-11")


# ---------------------------------------------------------------------------
# Context budget: response formats and truncation
# ---------------------------------------------------------------------------

class TestResponseBudget(unittest.IsolatedAsyncioTestCase):

    def _rows(self, n):
        return {"rows": [{"keys": [f"query number {i}"], "clicks": n - i, "impressions": 100,
                          "ctr": 0.05, "position": 3.0} for i in range(n)]}

    async def test_compact_format_uses_columns_and_arrays(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = self._rows(3)
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_search_analytics("https://example.com/", response_format="compact")
        data = json.loads(result)
        self.assertEqual(data["columns"], ["query", "clicks", "impressions", "ctr", "position"])
        self.assertEqual(data["rows"][0], ["query number 0", 3, 100, 0.05, 3.0])

    async def test_csv_format(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = self._rows(2)
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_search_by_page_query(
                "https://example.com/", "https://example.com/a/", response_format="csv"
            )
        lines = json.loads(result)["rows_csv"].strip().split("\n")
        self.assertEqual(lines[0], "query,clicks,impressions,ctr,position")
        self.assertEqual(len(lines), 3)

    async def test_compact_is_smaller_than_json(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = self._rows(200)
        with patch("gsc_server.get_gsc_service", return_value=service):
            as_json = await mod.get_advanced_search_analytics("https://example.com/")
            as_compact = await mod.get_advanced_search_analytics("https://example.com/", response_format="compact")
        self.assertLess(len(as_compact), len(as_json) * 0.7)

    async def test_large_response_is_trimmed_with_hint(self):
        mod = _load_module({"GSC_MAX_RESPONSE_CHARS": "3000"})
        service = _make_service()
        service.searchanalytics().query().execute.return_value = self._rows(500)
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics("https://example.com/", row_limit=500)
        self.assertLessEqual(len(result), 3000)
        data = json.loads(result)
        self.assertEqual(data["truncation"]["total_rows"], 500)
        self.assertEqual(len(data["rows"]), data["truncation"]["returned_rows"])
        self.assertGreater(data["truncation"]["returned_rows"], 0)
        self.assertIn("export_search_analytics", data["truncation"]["hint"])

    async def test_limit_can_be_disabled(self):
        mod = _load_module({"GSC_MAX_RESPONSE_CHARS": "0"})
        service = _make_service()
        service.searchanalytics().query().execute.return_value = self._rows(500)
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics("https://example.com/", row_limit=500)
        data = json.loads(result)
        self.assertNotIn("truncation", data)
        self.assertEqual(len(data["rows"]), 500)

    async def test_compare_periods_keeps_comparison_key(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [_ONE_ROW, _ONE_ROW]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.compare_search_periods(
                "https://example.com/", "2026-09-01", "2026-09-30", "2026-08-01", "2026-08-31",
            )
        self.assertIn("comparison", json.loads(result))


# ---------------------------------------------------------------------------
# export_search_analytics
# ---------------------------------------------------------------------------

class TestExportSearchAnalytics(unittest.IsolatedAsyncioTestCase):

    def _page(self, start, n):
        return {"rows": [{"keys": [f"q{i}", f"https://example.com/{i}"], "clicks": 10, "impressions": 100,
                          "ctr": 0.1, "position": 2.0} for i in range(start, start + n)]}

    async def test_pages_through_api_and_writes_csv(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            self._page(0, 2), self._page(2, 2), self._page(4, 1),
        ]
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(mod, "EXPORT_DIR", tmp), patch.object(mod, "_API_MAX_ROWS", 2), \
             patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.export_search_analytics("https://example.com/", preview_rows=2)
            data = json.loads(result)
            with open(data["file_path"], encoding="utf-8") as fh:
                lines = fh.read().strip().split("\n")

        self.assertEqual(data["row_count"], 5)
        self.assertEqual(data["api_calls"], 3)
        self.assertTrue(data["complete"])
        self.assertEqual(len(data["preview"]), 2)
        self.assertEqual(data["totals_of_exported_rows"]["clicks"], 50)
        self.assertEqual(lines[0], "query,page,clicks,impressions,ctr,position")
        self.assertEqual(len(lines), 6)
        start_rows = [c.kwargs["body"]["startRow"] for c in service.searchanalytics().query.call_args_list
                      if c.kwargs.get("body")]
        self.assertEqual(start_rows, [0, 2, 4])

    async def test_stops_at_max_rows_and_writes_jsonl(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = self._page(0, 3)
        with tempfile.TemporaryDirectory() as tmp, patch.object(mod, "EXPORT_DIR", tmp), \
             patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.export_search_analytics(
                "https://example.com/", max_rows=3, file_format="jsonl"
            )
            data = json.loads(result)
            with open(data["file_path"], encoding="utf-8") as fh:
                records = [json.loads(line) for line in fh]
        self.assertFalse(data["complete"])
        self.assertIn("max_rows", data["note"])
        self.assertEqual(records[0]["query"], "q0")

    async def test_no_data_leaves_no_file(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {}
        with tempfile.TemporaryDirectory() as tmp, patch.object(mod, "EXPORT_DIR", tmp), \
             patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.export_search_analytics("https://example.com/")
            self.assertEqual(os.listdir(tmp), [])
        self.assertIn("No search analytics data", result)


# ---------------------------------------------------------------------------
# URL inspection: languageCode, AMP, sitemaps
# ---------------------------------------------------------------------------

class TestUrlInspectionCoverage(unittest.IsolatedAsyncioTestCase):

    _RESPONSE = {
        "inspectionResult": {
            "indexStatusResult": {
                "verdict": "PASS",
                "sitemap": ["https://example.com/sitemap.xml"],
            },
            "ampResult": {
                "verdict": "FAIL",
                "ampUrl": "https://example.com/page/amp/",
                "issues": [{"severity": "ERROR", "issueMessage": "Referenced AMP URL is not an AMP"}],
            },
        }
    }

    async def test_inspect_passes_language_and_reports_amp_and_sitemaps(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = self._RESPONSE
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.inspect_url_enhanced(
                "https://example.com/", "https://example.com/page/", language_code="zh-CN"
            )
        body = service.urlInspection().index().inspect.call_args.kwargs["body"]
        self.assertEqual(body["languageCode"], "zh-CN")
        data = json.loads(result)
        self.assertEqual(data["sitemaps"], ["https://example.com/sitemap.xml"])
        self.assertEqual(data["amp"]["verdict"], "FAIL")
        self.assertEqual(data["amp"]["issues"][0]["severity"], "ERROR")

    async def test_inspect_omits_amp_when_absent(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {"indexStatusResult": {"verdict": "PASS"}}
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.inspect_url_enhanced("https://example.com/", "https://example.com/page/")
        body = service.urlInspection().index().inspect.call_args.kwargs["body"]
        self.assertNotIn("languageCode", body)
        self.assertNotIn("amp", json.loads(result))

    async def test_batch_passes_language_and_reports_amp(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = self._RESPONSE
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.batch_url_inspection(
                "https://example.com/", "https://example.com/page/", language_code="ja"
            )
        body = service.urlInspection().index().inspect.call_args.kwargs["body"]
        self.assertEqual(body["languageCode"], "ja")
        self.assertEqual(json.loads(result)["results"][0]["amp"]["verdict"], "FAIL")


# ---------------------------------------------------------------------------
# get_core_web_vitals
# ---------------------------------------------------------------------------

class TestCoreWebVitals(unittest.IsolatedAsyncioTestCase):

    _PSI = {
        "loadingExperience": {
            "overall_category": "AVERAGE",
            "metrics": {
                "LARGEST_CONTENTFUL_PAINT_MS": {"percentile": 2900, "category": "AVERAGE"},
                "INTERACTION_TO_NEXT_PAINT": {"percentile": 180, "category": "FAST"},
                "CUMULATIVE_LAYOUT_SHIFT_SCORE": {"percentile": 12, "category": "AVERAGE"},
            },
        },
        "lighthouseResult": {
            "categories": {"performance": {"score": 0.62}},
            "audits": {
                "largest-contentful-paint": {"numericValue": 4123.4},
                "cumulative-layout-shift": {"numericValue": 0.1234},
                "render-blocking-resources": {"score": 0.3, "title": "Eliminate render-blocking resources",
                                              "details": {"type": "opportunity", "overallSavingsMs": 900}},
                "unused-javascript": {"score": 0.5, "title": "Reduce unused JavaScript",
                                      "metricSavings": {"LCP": 1500, "FCP": 300}},
                "uses-http2": {"score": 1, "title": "Use HTTP/2",
                               "details": {"type": "opportunity", "overallSavingsMs": 0}},
            },
        },
    }

    async def test_shapes_field_and_lab_data(self):
        mod = _load_module()
        with patch("gsc_server._fetch_pagespeed", return_value=self._PSI) as fetch:
            result = await mod.get_core_web_vitals("https://example.com/", strategy="desktop")
        fetch.assert_called_once_with("https://example.com/", "DESKTOP")
        data = json.loads(result)
        field = data["field_data_page"]["metrics"]
        self.assertEqual(field["lcp_ms"], {"p75": 2900, "category": "AVERAGE"})
        self.assertEqual(field["cls"]["p75"], 0.12)
        self.assertIsNone(data["field_data_origin"])
        self.assertEqual(data["lab_data"]["performance_score"], 62)
        self.assertEqual(data["lab_data"]["metrics"]["cls"], 0.123)
        self.assertEqual(
            [o["id"] for o in data["lab_data"]["top_opportunities"]],
            ["unused-javascript", "render-blocking-resources"],
        )

    async def test_no_field_data_adds_note(self):
        mod = _load_module()
        with patch("gsc_server._fetch_pagespeed", return_value={"lighthouseResult": {}}):
            result = await mod.get_core_web_vitals("https://example.com/")
        self.assertIn("field_data_note", json.loads(result))

    async def test_quota_error_mentions_api_key(self):
        import urllib.error
        mod = _load_module()
        err = urllib.error.HTTPError(
            "https://x", 429, "Too Many Requests", {},
            io.BytesIO(b'{"error": {"message": "Quota exceeded"}}'),
        )
        with patch("gsc_server._fetch_pagespeed", side_effect=err):
            result = await mod.get_core_web_vitals("https://example.com/")
        self.assertIn("GSC_PAGESPEED_API_KEY", result)
        self.assertIn("Quota exceeded", result)

    async def test_invalid_strategy(self):
        mod = _load_module()
        result = await mod.get_core_web_vitals("https://example.com/", strategy="tablet")
        self.assertIn("Invalid strategy", result)


if __name__ == "__main__":
    unittest.main()
