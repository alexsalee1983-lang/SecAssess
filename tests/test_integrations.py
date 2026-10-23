import os
import tempfile
import unittest

from secassess.core.rbac import Principal, Role
from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.integrations.siem import (InMemoryExporter, JsonlFileExporter, collect_events, export_project,
                                         finding_event)
from secassess.integrations.sso import ApiKeyProvider, AuthError, MappingOIDCProvider
from secassess.models import Category, FindingSource, NormalizedFinding, Severity


class SsoTest(unittest.TestCase):
    def test_api_key_provider(self):
        alice = Principal("alice", Role.LEAD)
        provider = ApiKeyProvider({"k": alice})
        self.assertIs(provider.resolve("k"), alice)
        for bad in ("", None, "wrong"):
            with self.assertRaises(AuthError):
                provider.resolve(bad)

    def test_oidc_provider_fail_closed_without_verifier(self):
        provider = MappingOIDCProvider({"sub-1": {"user": "u", "role": "assessor", "tenant": "acme"}})
        with self.assertRaises(AuthError):
            provider.resolve("some-token")  # 无校验器 → 拒绝

    def test_oidc_provider_maps_verified_subject(self):
        provider = MappingOIDCProvider({"sub-1": {"user": "u", "role": "assessor", "projects": ["p1"],
                                                  "tenant": "acme"}},
                                       claims_verifier=lambda tok: {"sub": "sub-1"} if tok == "good" else {})
        p = provider.resolve("good")
        self.assertEqual((p.user, p.role.value, p.tenant), ("u", "assessor", "acme"))
        with self.assertRaises(AuthError):
            provider.resolve("bad")  # 校验返回空 sub → 未授权


class SiemTest(unittest.TestCase):
    def setUp(self):
        self.evidence = EvidenceStore()
        FactStore(self.evidence, AssetGraph()).add_findings([NormalizedFinding(
            scan_id="s", project_id="p1", source=FindingSource("nuclei", "nuclei"), target="192.0.2.7:443",
            category=Category.VULNERABILITY, title="RCE", severity=Severity.CRITICAL, cve=["CVE-2024-1"],
            details={"rule_id": "R"})])

    def test_finding_event_shape(self):
        ev = finding_event(self.evidence.query("p1")[0])
        self.assertEqual(ev["type"], "finding")
        self.assertEqual(ev["severity_num"], 10)
        self.assertEqual(ev["cve"], ["CVE-2024-1"])

    def test_inmemory_and_collect(self):
        exporter = InMemoryExporter()
        n = export_project(exporter, self.evidence, "p1",
                           audit_entries=[{"ts": "t", "actor": "a", "action": "x", "project_id": "p1", "seq": 1}])
        self.assertEqual(n, 2)
        types = {e["type"] for e in exporter.events}
        self.assertEqual(types, {"finding", "audit"})
        self.assertEqual(len(collect_events(self.evidence, "p1")), 1)  # 仅发现

    def test_jsonl_file_exporter(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            JsonlFileExporter(path).emit(collect_events(self.evidence, "p1"))
            lines = open(path, encoding="utf-8").read().strip().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertIn("finding", lines[0])


if __name__ == "__main__":
    unittest.main()
