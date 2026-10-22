import asyncio
import unittest

from secassess.adapters.base import AdapterRegistry
from secassess.adapters.mock_nmap import MAX_HOSTS, MockNmapAdapter, expand_hosts
from secassess.adapters.mock_placeholder import PlaceholderAdapter
from secassess.models import Category, ScanRequest, ScanType


def req(scan_type, targets, **options):
    return ScanRequest(targets=targets, scan_type=scan_type, scope_token="tok", options=options)


class MockAdaptersTest(unittest.IsolatedAsyncioTestCase):
    async def test_nmap_is_deterministic(self):
        adapter = MockNmapAdapter(delay=0)
        r = req("port_discovery", ["192.0.2.0/28"])
        first = await adapter.scan(r, lambda *_: None)
        second = await adapter.scan(r, lambda *_: None)
        self.assertTrue(first)
        self.assertEqual([f.fingerprint for f in first], [f.fingerprint for f in second])
        self.assertTrue(all(f.category is Category.ASSET and "port" in f.details for f in first))

    def test_cidr_expansion_is_capped(self):
        self.assertEqual(len(expand_hosts(["10.0.0.0/8"])), MAX_HOSTS)
        self.assertEqual(expand_hosts(["192.0.2.5", "example.com"]), ["192.0.2.5", "example.com"])
        self.assertEqual(len(expand_hosts(["192.0.2.0/30"])), 2)

    async def test_progress_is_monotonic_and_completes(self):
        seen = []
        await MockNmapAdapter(delay=0).scan(req("port_discovery", ["192.0.2.0/29"]),
                                            lambda frac, _msg: seen.append(frac))
        self.assertEqual(seen, sorted(seen))
        self.assertAlmostEqual(seen[-1], 1.0)

    async def test_scan_is_cancellable(self):
        task = asyncio.create_task(MockNmapAdapter(delay=0.05).scan(req("port_discovery", ["10.0.0.0/24"]),
                                                                     lambda *_: None))
        await asyncio.sleep(0.01)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_placeholder_findings_are_synthetic(self):
        adapter = PlaceholderAdapter(ScanType.VULN, delay=0)
        targets = [f"192.0.2.{i}:80" for i in range(1, 20)]
        findings = await adapter.scan(req("vuln", targets), lambda *_: None)
        self.assertTrue(findings)
        for f in findings:
            self.assertTrue(f.details["rule_id"].startswith("SIM-VULN-"))
            self.assertTrue(f.details["simulated"])
            self.assertEqual(f.cve, [])
            self.assertIs(f.category, Category.VULNERABILITY)
        self.assertTrue(PlaceholderAdapter(ScanType.CONFIG_BASELINE).capability().needs_credential)
        with self.assertRaises(ValueError):
            PlaceholderAdapter(ScanType.PHISHING)

    def test_registry(self):
        reg = AdapterRegistry()
        reg.register(MockNmapAdapter())
        reg.register(PlaceholderAdapter(ScanType.VULN))
        with self.assertRaises(ValueError):
            reg.register(MockNmapAdapter())
        self.assertEqual([a.name for a in reg.for_scan_type(ScanType.VULN)], ["mock-vuln"])
        with self.assertRaises(KeyError):
            reg.get("nope")
        self.assertEqual(len(reg.describe()), 2)


if __name__ == "__main__":
    unittest.main()
