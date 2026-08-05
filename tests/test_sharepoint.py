import unittest

from ingest import api
from ingest.affected import cpe_norm
from ingest.match import _sharepoint_edition, match_cpe


CPE_KEY = 'cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*'
CVE = 'CVE-2026-58644'
ROWS = [
    (CVE, 'microsoft', '16.0', '16.0.5556.1005', None, 'generic', 'fixed', 'KB5002880',
     'sharepoint_server'),
    (CVE, 'microsoft', '16.0', '16.0.10417.20153', None, 'generic', 'fixed', 'KB5002874',
     'sharepoint_server'),
    (CVE, 'microsoft', '16.0', '16.0.19725.20384', None, 'generic', 'fixed', 'KB5002873',
     'sharepoint_server'),
]


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, _sql, _params=None):
        pass

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, rows=()):
        self.rows = rows

    def cursor(self):
        return FakeCursor(self.rows)

    def close(self):
        pass


class SharePointCpeNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.old_vp, self.old_vpu = cpe_norm._VP, cpe_norm._VPU
        cpe_norm._VP = {
            ('microsoft', 'sharepoint_server'),
            ('microsoft', 'sql_server_2019'),
            ('microsoft', 'office_2019'),
            ('microsoft', 'unrelated'),
        }
        cpe_norm._VPU = set()

    def tearDown(self):
        cpe_norm._VP, cpe_norm._VPU = self.old_vp, self.old_vpu

    def test_sharepoint_year_products_fall_back_to_generic_product(self):
        expected = cpe_norm._key('a', 'microsoft', 'sharepoint_server', None)
        for product in ('sharepoint_server_2016', 'sharepoint_server_2019'):
            with self.subTest(product=product):
                self.assertEqual(expected, cpe_norm._resolve('a', 'microsoft', product, None))

    def test_exact_year_products_keep_their_identity(self):
        for product in ('sql_server_2019', 'office_2019'):
            with self.subTest(product=product):
                expected = cpe_norm._key('a', 'microsoft', product, None)
                self.assertEqual(expected, cpe_norm._resolve('a', 'microsoft', product, None))

    def test_unrelated_year_product_is_not_collapsed(self):
        self.assertIsNone(cpe_norm._resolve('a', 'microsoft', 'unrelated_2019', None))


class SharePointMatchingTests(unittest.TestCase):
    def assert_vulnerable_with(self, version, fixed, kb):
        findings = match_cpe(FakeConnection(ROWS), CPE_KEY, version, {})
        self.assertIn(CVE, findings)
        self.assertEqual(fixed, findings[CVE][0][2])
        self.assertEqual(kb, findings[CVE][0][3])

    def assert_compliant(self, version):
        self.assertNotIn(CVE, match_cpe(FakeConnection(ROWS), CPE_KEY, version, {}))

    def test_supported_build_bands(self):
        cases = {
            '16.0.4351.1000': '2016',
            '16.0.5552.1002': '2016',
            '16.0.8000.0': '2016',            # closed band gap: below the 2019 floor -> 2016
            '16.0.10337.12109': '2019',
            '16.0.10417.20114': '2019',
            '16.0.14000.0': 'subscription',   # closed band gap: 14000+ -> Subscription Edition
            '16.0.14326.20450': 'subscription',
            '16.0.19725.20384': 'subscription',
        }
        for build, edition in cases.items():
            with self.subTest(build=build):
                self.assertEqual(edition, _sharepoint_edition(build))
        for build in ('', '15.0.9999.0', 'not-a-build'):
            with self.subTest(build=build):
                self.assertIsNone(_sharepoint_edition(build))

    def test_2016_hosts_use_only_the_2016_fix(self):
        self.assert_vulnerable_with('16.0.5552.1002', '16.0.5556.1005', 'KB5002880')
        self.assert_compliant('16.0.5561.1001')

    def test_2019_hosts_use_only_the_2019_fix(self):
        self.assert_vulnerable_with('16.0.10337.12109', '16.0.10417.20153', 'KB5002874')
        self.assert_vulnerable_with('16.0.10417.20114', '16.0.10417.20153', 'KB5002874')
        self.assert_compliant('16.0.10417.20153')

    def test_subscription_hosts_use_only_the_subscription_fix(self):
        self.assert_vulnerable_with('16.0.19127.20442', '16.0.19725.20384', 'KB5002873')
        self.assert_compliant('16.0.19725.20384')

    def test_single_edition_cve_does_not_cross_match(self):
        subscription_only = [ROWS[2]]
        findings = match_cpe(FakeConnection(subscription_only), CPE_KEY, '16.0.5552.1002', {})
        self.assertNotIn(CVE, findings)


class SharePointBulkApiTests(unittest.TestCase):
    def test_generic_purl_prefers_cpe_and_repository_version_is_fixable(self):
        old_get_conn = api.get_conn
        old_load_curations = api.load_curations
        old_match = api.match
        calls = []
        connection = FakeConnection()

        def fake_match(_conn, ident, version, release, _curations):
            calls.append((ident, version, release))
            if version == '16.0.5552.1002':
                return {CVE: [('microsoft', 'fixed', '16.0.5556.1005', 'KB5002880', 'generic')]}
            return {}

        api.get_conn = lambda: connection
        api.load_curations = lambda _conn: {}
        api.match = fake_match
        try:
            cpe = 'cpe:2.3:a:microsoft:sharepoint_server:16.0.5552.1002:*:*:*:*:*:*:*'
            components = [
                {'purl': 'pkg:generic/microsoft-sharepoint@16.0.5552.1002', 'cpe': cpe,
                 'version': '16.0.5552.1002', 'repository_version': '16.0.5556.1005', 'path': 'C:\\A'},
                {'purl': 'pkg:generic/microsoft-sharepoint@16.0.5552.1002', 'cpe': cpe,
                 'version': '16.0.5552.1002', 'path': 'D:\\B'},
            ]
            results = api._bulk_match(components)
        finally:
            api.get_conn = old_get_conn
            api.load_curations = old_load_curations
            api.match = old_match

        self.assertEqual(2, len(results))
        self.assertTrue(results[0]['cves'][0]['repo_fixable'])
        self.assertEqual([CVE], results[0]['repo_fixed_cves'])
        self.assertTrue(all(result['component'] == cpe for result in results))
        self.assertEqual([(cpe, '16.0.5552.1002', None), (cpe, '16.0.5556.1005', None)], calls)


if __name__ == '__main__':
    unittest.main()
