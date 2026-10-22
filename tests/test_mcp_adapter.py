import asyncio
import os
import sys
import unittest

from secassess.adapters.mcp import MCPError, MCPToolAdapter, within_targets
from secassess.data.evidence import EvidenceStore
from secassess.data.vault import Vault
from secassess.models import ScanRequest, Severity

SERVER = os.path.join(os.path.dirname(__file__), "fake_mcp_server.py")


def adapter(mode="ok", **kw):
    return MCPToolAdapter("fake-mcp", [sys.executable, SERVER, mode], "scan", scan_types={"vuln"}, **kw)


def request(targets=("192.0.2.10",), **kw):
    return ScanRequest(targets=list(targets), scan_type="vuln", scope_token="tok", project_id="p1", **kw)


class MCPAdapterTest(unittest.IsolatedAsyncioTestCase):
    async def test_handshake_call_progress_and_normalization(self):
        ad = adapter()
        progress = []
        findings = await ad.scan(request(["192.0.2.10", "192.0.2.11"]), lambda f, m: progress.append((f, m)))
        self.assertEqual(sorted(f.target for f in findings), ["192.0.2.10:443", "192.0.2.11:443"])
        self.assertTrue(all(f.severity is Severity.MEDIUM and f.source.adapter == "fake-mcp" for f in findings))
        self.assertEqual(progress, [(0.5, "step 1"), (1.0, "step 2")])

    async def test_out_of_scope_results_are_dropped(self):
        ad = adapter()
        findings = await ad.scan(request(), lambda *_: None)
        self.assertNotIn("203.0.113.99", [f.target for f in findings])
        self.assertEqual(ad.dropped, 1)

    async def test_tool_error_and_crash(self):
        with self.assertRaises(MCPError):
            await adapter("tool_error").scan(request(), lambda *_: None)
        with self.assertRaises(MCPError):
            await adapter("crash").scan(request(), lambda *_: None)

    async def test_cancel_kills_subprocess(self):
        ad = adapter("slow")
        task = asyncio.create_task(ad.scan(request(), lambda *_: None))
        await asyncio.sleep(0.5)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertIsNotNone(ad.last_process.returncode)

    async def test_credentials_resolved_from_vault_and_not_leaked(self):
        vault = Vault()
        ref = vault.put("scan-token", "TOPSECRET-123")
        findings = await adapter(vault=vault).scan(request(credential_ref=ref), lambda *_: None)
        self.assertTrue(findings[0].details["credential_received"])
        for f in findings:
            self.assertNotIn("TOPSECRET-123", f.to_json())
        with self.assertRaises(MCPError):
            await adapter().scan(request(credential_ref=ref), lambda *_: None)  # 无 Vault

    async def test_raw_output_stored_as_evidence(self):
        store = EvidenceStore()
        findings = await adapter(evidence_sink=store.put_raw).scan(request(), lambda *_: None)
        content, _ = store.get_raw(findings[0].raw_ref)
        self.assertIn(b"SIM-MCP-001", content)
        self.assertEqual(findings[0].evidence_ref, findings[0].raw_ref)

    def test_availability_and_target_matching(self):
        self.assertTrue(adapter().available())
        self.assertFalse(MCPToolAdapter("x", ["no-such-binary-xyz"], "t", scan_types={"vuln"}).available())
        self.assertTrue(within_targets("192.0.2.5:22", ["192.0.2.0/24"]))
        self.assertTrue(within_targets("https://a.example.com/x", ["example.com"]))
        self.assertFalse(within_targets("192.0.3.5", ["192.0.2.0/24"]))
        self.assertFalse(within_targets("badexample.com", ["example.com"]))


if __name__ == "__main__":
    unittest.main()
