"""Regression tests for SQL Server version and servicing-track handling."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from ingest.affected import cpe_norm
from ingest.affected.sources.microsoft import _product_cpes
from ingest.api import _bulk_match
from ingest.component_alias import temporary_cpe_alias
from ingest.match import (_cpe_verdict, _ms_major, _sql_server_2019_track,
                          _sql_server_engine_version, _sql_server_version_for_compare,
                          remediation)


class SqlServerVersionTests(unittest.TestCase):
    def test_file_and_engine_versions_normalize_to_same_build(self):
        self.assertEqual(_sql_server_engine_version("2019.150.2180.2"), "15.0.2180.2")
        self.assertEqual(_sql_server_engine_version("15.0.2180.2"), "15.0.2180.2")
        self.assertEqual(_ms_major("2019.150.2180.2"), "15")

    def test_track_classification_keeps_rtm_ambiguous(self):
        self.assertIsNone(_sql_server_2019_track("2019.150.2000.5"))
        self.assertEqual(_sql_server_2019_track("2019.150.2180.2"), "gdr")
        self.assertEqual(_sql_server_2019_track("15.0.4316.3"), "cu")

    def test_verdict_compares_file_version_to_engine_fix_without_rewriting_output(self):
        rows = [
            ("microsoft", "15.0", "15.0.2101.7", None, "generic", "fixed", "KB5021125"),
        ]
        hits = _cpe_verdict("2019.150.2000.5", rows, _sql_server_version_for_compare)
        self.assertEqual(hits[0][2], "15.0.2101.7")

    def test_sql_verdict_preserves_parallel_tracks_when_requested(self):
        rows = [
            ("microsoft", "15.0", "15.0.2101.7", None, "generic", "fixed", "KB-GDR"),
            ("microsoft", "15.0", "15.0.4316.3", None, "generic", "fixed", "KB-CU"),
        ]
        hits = _cpe_verdict(
            "2019.150.2000.5", rows, _sql_server_version_for_compare, preserve_fixes=True,
        )
        self.assertEqual([hit[2] for hit in hits], ["15.0.2101.7", "15.0.4316.3"])

    def test_cu_host_is_not_cleared_by_lower_gdr_fix(self):
        rows = [
            ("microsoft", "15.0", "15.0.2200.1", None, "generic", "fixed", "KB-GDR"),
            ("microsoft", "15.0", "15.0.4300.1", None, "generic", "fixed", "KB-CU"),
        ]
        hits = _cpe_verdict(
            "15.0.4200.1", rows, _sql_server_version_for_compare, preserve_fixes=True,
        )
        self.assertEqual([hit[2] for hit in hits], ["15.0.2200.1", "15.0.4300.1"])

    def test_known_sql_track_overrides_conflicting_request(self):
        rows = [
            ("microsoft", "15.0", "15.0.2200.1", None, "generic", "fixed", "KB-GDR"),
            ("microsoft", "15.0", "15.0.4300.1", None, "generic", "fixed", "KB-CU"),
        ]
        hits = _cpe_verdict(
            "15.0.2500.1", rows, _sql_server_version_for_compare,
            preserve_fixes=True, servicing_track="cu",
        )
        self.assertEqual(hits, [])

    def test_unclassified_sql_edition_keeps_legacy_parallel_fix_verdict(self):
        rows = [
            ("microsoft", "16.0", "16.0.2100.1", None, "generic", "fixed", "KB-GDR"),
            ("microsoft", "16.0", "16.0.4100.1", None, "generic", "fixed", "KB-CU"),
        ]
        hits = _cpe_verdict(
            "16.0.2200.1", rows, _sql_server_version_for_compare,
            preserve_fixes=True, servicing_track="cu",
        )
        self.assertEqual(hits, [])


class SqlServerRemediationTests(unittest.TestCase):
    _COMPONENT = "cpe:2.3:a:microsoft:sql_server:15.0.2000.5:*:*:*:*:*:*:*"

    @staticmethod
    def _findings():
        return {
            "CVE-GDR-1": [("microsoft", "fixed", "15.0.2101.7", "KB-GDR-1", "generic")],
            "CVE-GDR-2": [("microsoft", "fixed", "2019.150.2180.2", "KB-GDR-2", "generic")],
            "CVE-BOTH": [
                ("microsoft", "fixed", "15.0.2180.2", "KB-GDR-3", "generic"),
                ("microsoft", "fixed", "15.0.4316.3", "KB-CU-2", "generic"),
            ],
            "CVE-CU-ONLY": [("microsoft", "fixed", "15.0.4316.3", "KB-CU", "generic")],
        }

    def test_requested_gdr_never_selects_higher_cu_fix(self):
        result = remediation(self._findings(), component=self._COMPONENT,
                             version="2019.150.2000.5", preferred_track="gdr")
        self.assertEqual(result["track"], "gdr")
        self.assertEqual(result["fixed"], "2019.150.2180.2")
        self.assertEqual(result["closes"], 3)
        self.assertEqual(result["unfixed"], 1)
        self.assertEqual(result["by_track"]["cu"]["fixed"], "15.0.4316.3")
        self.assertEqual(result["by_track"]["cu"]["closes"], 2)

    def test_rtm_returns_track_alternatives_without_hidden_default(self):
        result = remediation(self._findings(), component=self._COMPONENT, version="15.0.2000.5")
        self.assertIsNone(result["fixed"])
        self.assertIsNone(result["track"])
        self.assertEqual(result["selection"], "ambiguous")
        self.assertEqual(result["by_track"]["gdr"]["closes"], 3)
        self.assertEqual(result["by_track"]["cu"]["closes"], 2)

    def test_cpe_version_selects_installed_track_without_separate_version(self):
        result = remediation(
            self._findings(),
            component="cpe:2.3:a:microsoft:sql_server:15.0.2180.2:*:*:*:*:*:*:*",
        )
        self.assertEqual(result["track"], "gdr")
        self.assertEqual(result["selection"], "installed")
        self.assertEqual(result["fixed"], "2019.150.2180.2")

    def test_unclassified_sql_edition_does_not_guess_a_track(self):
        findings = {
            "CVE-SQL-2022": [
                ("microsoft", "fixed", "16.0.2100.1", "KB-GDR", "generic"),
                ("microsoft", "fixed", "16.0.4100.1", "KB-CU", "generic"),
            ],
        }
        result = remediation(
            findings,
            component="cpe:2.3:a:microsoft:sql_server:16.0.3000.1:*:*:*:*:*:*:*",
            version="16.0.3000.1",
        )
        self.assertIsNone(result["fixed"])
        self.assertEqual(result["selection"], "ambiguous")

    def test_installed_track_labels_conflicting_request_as_installed(self):
        result = remediation(
            self._findings(),
            component="cpe:2.3:a:microsoft:sql_server:15.0.2500.1:*:*:*:*:*:*:*",
            preferred_track="cu",
        )
        self.assertEqual(result["track"], "gdr")
        self.assertEqual(result["selection"], "installed")

    def test_legacy_remediation_keeps_the_selected_fix_kb(self):
        findings = {
            "CVE-ONE": [
                ("example", "fixed", "1.2.0", "KB-OLD", "generic"),
                ("example", "fixed", "1.10.0", "KB-NEW", "generic"),
            ],
        }
        result = remediation(findings, component="cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*")
        self.assertEqual(result["fixed"], "1.10.0")
        self.assertEqual(result["fix_kb"], "KB-NEW")

    def test_non_sql_behavior_still_returns_single_highest_fix(self):
        findings = {
            "CVE-ONE": [("example", "fixed", "1.2.0", None, "generic")],
            "CVE-TWO": [("example", "fixed", "1.10.0", None, "generic")],
        }
        result = remediation(findings, component="cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*")
        self.assertEqual(result["fixed"], "1.10.0")
        self.assertNotIn("by_track", result)


class MicrosoftDriverIdentityTests(unittest.TestCase):
    def setUp(self):
        self._vp, self._vpu = cpe_norm._VP, cpe_norm._VPU
        cpe_norm._VP = {
            ("microsoft", "sql_server"),
            ("microsoft", "odbc_driver_for_sql_server"),
            ("microsoft", "ole_db_driver_for_sql_server"),
        }
        cpe_norm._VPU = set()

    def tearDown(self):
        cpe_norm._VP, cpe_norm._VPU = self._vp, self._vpu

    def test_odbc_name_resolves_to_driver_not_sql_server(self):
        key = cpe_norm.from_name("Microsoft ODBC Driver 17 for SQL Server")
        self.assertIn(":odbc_driver_for_sql_server:", key)

    def test_versioned_odbc_cpe_resolves_to_unversioned_driver_product(self):
        key, _version = cpe_norm.canonical(
            "cpe:2.3:a:microsoft:odbc_driver_17_for_sql_server:17.4.0.1:*:*:*:*:*:*:*"
        )
        self.assertIn(":odbc_driver_for_sql_server:", key)

    def test_invalid_raw_driver_cpe_falls_back_to_validated_driver_name(self):
        doc = {
            "ProductTree": {
                "FullProductName": [{
                    "ProductID": "odbc-17",
                    "CPE": "cpe:2.3:a:microsoft:non_nvd_odbc_driver:17.4.0.1:*:*:*:*:*:*:*",
                    "Value": "Microsoft ODBC Driver 17 for SQL Server",
                }],
            },
        }
        self.assertIn(":odbc_driver_for_sql_server:", _product_cpes(doc)["odbc-17"])


class ExplicitCpeFallbackTests(unittest.TestCase):
    def test_temporary_aliases_require_an_existing_precise_identity(self):
        self.assertEqual(
            temporary_cpe_alias(
                {"purl": "pkg:maven/log4j/log4j@1.2.17"}, "1.2.17",
            )[1],
            "legacy_maven_log4j",
        )
        self.assertEqual(
            temporary_cpe_alias({"name": "msodbcsql17.dll"}, "17.4.0.1")[1],
            "legacy_sql_odbc_driver",
        )
        self.assertEqual(
            temporary_cpe_alias({"purl": "pkg:generic/curl@7.83.1.0"}, "7.83.1.0")[1],
            "legacy_curl",
        )
        self.assertEqual(
            temporary_cpe_alias({"name": "msoledbsql.dll"}, "18.2.3.0")[1],
            "legacy_sql_ole_db_driver",
        )
        self.assertEqual(
            temporary_cpe_alias(
                {"path": r"C:\Program Files\Legacy\log4j-1.2.17.jar"}, "1.2.17",
            )[1],
            "legacy_log4j_filename",
        )
        self.assertIsNone(temporary_cpe_alias({"name": "log4j-1.2.17.jar"}, "1.2.16"))

    def test_ecosystem_purl_does_not_fall_back_to_declared_cpe(self):
        purl = "pkg:maven/org.apache.log4j/log4j@1.2.17"
        cpe = "cpe:2.3:a:apache:log4j:1.2.17:*:*:*:*:*:*:*"
        findings = {"CVE-2021-4104": [("nvd", "affected", None, None, "generic")]}

        class Connection:
            def close(self):
                pass

        with (
            patch("ingest.api.get_conn", return_value=Connection()),
            patch("ingest.api.load_curations", return_value={}),
            patch("ingest.api.match", side_effect=[{}, findings]) as match,
            patch("ingest.api.remediation", return_value=None),
        ):
            result = _bulk_match([{"purl": purl, "cpe": cpe, "version": "1.2.17"}])

        self.assertEqual([call.args[1] for call in match.call_args_list], [purl])
        self.assertEqual(result[0]["component"], purl)
        self.assertEqual(result[0]["status"], "compliant")
        self.assertNotIn("_matched_component", result[0])

    def test_cache_keeps_gdr_and_cu_requests_separate(self):
        component = "cpe:2.3:a:microsoft:sql_server:15.0.2000.5:*:*:*:*:*:*:*"
        findings = {"CVE-TEST": [("microsoft", "fixed", "15.0.2101.7", "KB-GDR", "generic")]}

        class Connection:
            def close(self):
                pass

        with (
            patch("ingest.api.get_conn", return_value=Connection()),
            patch("ingest.api.load_curations", return_value={}),
            patch("ingest.api.match", return_value=findings) as match,
            patch("ingest.api.remediation", return_value=None) as select_remediation,
        ):
            _bulk_match([
                {"cpe": component, "version": "15.0.2000.5", "servicing_track": "gdr"},
                {"cpe": component, "version": "15.0.2000.5", "servicing_track": "cu"},
            ])

        self.assertEqual(match.call_count, 2)
        self.assertEqual(
            [call.kwargs["servicing_track"] for call in match.call_args_list], ["gdr", "cu"],
        )
        self.assertEqual(
            [call.kwargs["preferred_track"] for call in select_remediation.call_args_list], ["gdr", "cu"],
        )

    def test_invalid_optional_cpe_does_not_make_compliant_purl_unknown(self):
        purl = "pkg:maven/example/component@1.0.0"

        class Connection:
            def close(self):
                pass

        with (
            patch("ingest.api.get_conn", return_value=Connection()),
            patch("ingest.api.load_curations", return_value={}),
            patch("ingest.api.match", side_effect=[{}, ValueError("invalid cpe")]),
            patch("ingest.api.remediation", return_value=None),
        ):
            result = _bulk_match([{"purl": purl, "cpe": "not-a-cpe", "version": "1.0.0"}])

        self.assertEqual(result[0]["component"], purl)
        self.assertEqual(result[0]["status"], "compliant")

    def test_legacy_log4j_purl_falls_back_to_temporary_alias(self):
        purl = "pkg:maven/log4j/log4j@1.2.17"
        alias = "cpe:2.3:a:apache:log4j:1.2.17:*:*:*:*:*:*:*"
        findings = {"CVE-2021-4104": [("nvd", "affected", None, None, "generic")]}

        class Connection:
            def close(self):
                pass

        with (
            patch("ingest.api.get_conn", return_value=Connection()),
            patch("ingest.api.load_curations", return_value={}),
            patch("ingest.api.match", side_effect=[{}, findings]) as match,
            patch("ingest.api.remediation", return_value=None),
        ):
            result = _bulk_match([{"purl": purl, "version": "1.2.17"}])

        self.assertEqual([call.args[1] for call in match.call_args_list], [purl, alias])
        self.assertEqual(result[0]["component"], alias)
        self.assertEqual(result[0]["identity_source"], "legacy_maven_log4j")

    def test_reviewed_alias_is_retried_when_same_cpe_is_already_supplied(self):
        purl = "pkg:maven/log4j/log4j@1.2.17"
        alias = "cpe:2.3:a:apache:log4j:1.2.17:*:*:*:*:*:*:*"
        findings = {"CVE-2021-4104": [("nvd", "affected", None, None, "generic")]}

        class Connection:
            def close(self):
                pass

        with (
            patch("ingest.api.get_conn", return_value=Connection()),
            patch("ingest.api.load_curations", return_value={}),
            patch("ingest.api.match", side_effect=[{}, findings]) as match,
            patch("ingest.api.remediation", return_value=None),
        ):
            result = _bulk_match([{"purl": purl, "cpe": alias, "version": "1.2.17"}])

        self.assertEqual([call.args[1] for call in match.call_args_list], [purl, alias])
        self.assertEqual(result[0]["status"], "vulnerable")
        self.assertEqual(result[0]["component"], alias)
        self.assertEqual(result[0]["identity_source"], "legacy_maven_log4j")
