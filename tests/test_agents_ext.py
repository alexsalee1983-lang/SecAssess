import unittest

from secassess.adapters.base import AdapterError, AdapterRegistry
from secassess.adapters.mock_placeholder import APPROVAL_OPTION, PlaceholderAdapter
from secassess.adapters.openapi_review import OpenAPIReviewAdapter
from secassess.agents.easm import EasmAgent
from secassess.agents.phishing import PhishingAgent
from secassess.agents.webapi import WebApiAgent
from secassess.data.asset_graph import AssetGraph
from secassess.models import Category, IntrusiveLevel, ScanRequest, ScanType, Severity


def request(scan_type, targets, **options):
    return ScanRequest(targets=targets, scan_type=scan_type, scope_token="tok", options=options)


class ExtAgentTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.registry = AdapterRegistry()
        for st in (ScanType.EXPOSURE, ScanType.WEB, ScanType.PHISHING):
            self.registry.register(PlaceholderAdapter(st, delay=0))
        self.registry.register(OpenAPIReviewAdapter())
        self.graph = AssetGraph()

    def test_easm_is_readonly(self):
        plan = EasmAgent(self.registry, self.graph).prepare("p1", ["example.com"])
        self.assertIs(plan.intrusive_level, IntrusiveLevel.READONLY)

    def test_phishing_is_always_external(self):
        plan = PhishingAgent(self.registry, self.graph).prepare("p1", ["user@example.com"], adapter="mock-phishing")
        self.assertIs(plan.intrusive_level, IntrusiveLevel.EXTERNAL)

    async def test_phishing_adapter_refuses_without_approval(self):
        adapter = PlaceholderAdapter(ScanType.PHISHING, delay=0)
        with self.assertRaises(AdapterError):
            await adapter.scan(request("phishing", ["user@example.com"]), lambda *_: None)
        findings = await adapter.scan(request("phishing", ["user@example.com"], **{APPROVAL_OPTION: True}),
                                      lambda *_: None)
        self.assertTrue(all(f.category is Category.EXPOSURE for f in findings))

    def test_webapi_targets_from_services(self):
        self.graph.upsert_node("p1", "service", "192.0.2.5:443")
        plan = WebApiAgent(self.registry, self.graph).prepare("p1", adapter="mock-web")
        self.assertEqual(plan.targets, ["192.0.2.5:443"])


SPEC = {
    "openapi": "3.0.0",
    "servers": [{"url": "http://api.example.com"}, {"url": "https://api.example.com"}],
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "security": [{"bearer": []}],
    "paths": {
        "/public": {"get": {"security": []}},          # 显式无安全要求
        "/private": {"get": {}},                        # 继承全局安全要求
        "/admin": {"post": {"security": [{"bearer": []}]}},
    },
}
SPEC_NO_SCHEME = {"openapi": "3.0.0", "servers": [{"url": "https://x.example.com"}],
                  "paths": {"/a": {"get": {}}}}


class OpenAPIReviewTest(unittest.IsolatedAsyncioTestCase):
    async def findings(self, spec):
        adapter = OpenAPIReviewAdapter()
        return await adapter.scan(request("web", ["https://api.example.com"], spec=spec), lambda *_: None)

    async def test_detects_design_flaws_without_network(self):
        rules = {f.details["rule_id"] for f in await self.findings(SPEC)}
        self.assertIn("OPENAPI-CLEARTEXT-SERVER", rules)       # http:// 服务器
        self.assertIn("OPENAPI-OP-NO-SECURITY", rules)         # /public security: []
        self.assertNotIn("OPENAPI-NO-AUTH-SCHEME", rules)      # 声明了 securitySchemes
        no_sec = [f for f in await self.findings(SPEC) if f.details["rule_id"] == "OPENAPI-OP-NO-SECURITY"]
        self.assertEqual({f.details["path"] for f in no_sec}, {"/public"})  # /private 继承全局，不算

    async def test_missing_scheme_flagged(self):
        rules = {f.details["rule_id"] for f in await self.findings(SPEC_NO_SCHEME)}
        self.assertIn("OPENAPI-NO-AUTH-SCHEME", rules)
        self.assertTrue(all(f.severity in set(Severity) for f in await self.findings(SPEC_NO_SCHEME)))

    async def test_requires_spec(self):
        with self.assertRaises(AdapterError):
            await OpenAPIReviewAdapter().scan(request("web", ["https://x"]), lambda *_: None)


if __name__ == "__main__":
    unittest.main()
