import unittest

from secassess.content.registry import (ContentPack, ContentRegistry, ContentRegistryError, PackKind,
                                        PackStatus, ReviewGate, ReviewResult)


def pack(name="nuclei-templates", version="v10.1.0", sha=None, source="github.com/example/pin", kind=None):
    return ContentPack(name=name, version=version, kind=kind or PackKind.TEMPLATES,
                       sha256=sha if sha is not None else "a" * 64, source=source)


class ContentRegistryTest(unittest.TestCase):
    def setUp(self):
        self.reg = ContentRegistry()

    def test_benchmark_gate_approves_well_formed_pack(self):
        self.reg.register(pack())
        p = self.reg.submit_review("nuclei-templates@v10.1.0")
        self.assertIs(p.status, PackStatus.APPROVED)
        self.assertTrue(p.review["passed"])

    def test_gate_rejects_latest_or_missing_sha_or_source(self):
        for bad in (pack(version="latest"), pack(sha="short"), pack(source="")):
            self.reg.register(bad)
            reviewed = self.reg.submit_review(bad.key)
            self.assertIs(reviewed.status, PackStatus.REJECTED)
            self.assertFalse(reviewed.review["passed"])

    def test_approved_pack_cannot_be_reregistered(self):
        self.reg.register(pack())
        self.reg.submit_review("nuclei-templates@v10.1.0")
        with self.assertRaises(ContentRegistryError):
            self.reg.register(pack())  # 同版本已上线
        # 新版本可以登记
        self.reg.register(pack(version="v10.2.0"))

    def test_active_returns_highest_approved(self):
        for v in ("v1.0.0", "v1.1.0"):
            self.reg.register(pack(version=v))
            self.reg.submit_review(f"nuclei-templates@{v}")
        self.reg.register(pack(version="v2.0.0", sha="short"))  # 会被拒
        self.reg.submit_review("nuclei-templates@v2.0.0")
        active = self.reg.active("nuclei-templates")
        self.assertEqual(active.version, "v1.1.0")  # 最高的已通过版本

    def test_list_filters_and_unknown(self):
        self.reg.register(pack(kind=PackKind.MCP_ADAPTER, name="nmap-mcp"))
        self.assertEqual(len(self.reg.list(kind="mcp_adapter")), 1)
        self.assertEqual(self.reg.list(status="approved"), [])
        with self.assertRaises(ContentRegistryError):
            self.reg.submit_review("missing@v1")

    def test_custom_gate(self):
        class AllowAll(ReviewGate):
            def review(self, p):
                return ReviewResult(passed=True, checks=[])
        reg = ContentRegistry(gate=AllowAll())
        reg.register(pack(version="latest"))
        self.assertIs(reg.submit_review("nuclei-templates@latest").status, PackStatus.APPROVED)


if __name__ == "__main__":
    unittest.main()
