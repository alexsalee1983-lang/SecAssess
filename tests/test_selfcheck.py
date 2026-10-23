import os
import unittest
from unittest import mock

from secassess.core.selfcheck import run_self_check
from secassess.platform import Platform


class SelfCheckTest(unittest.TestCase):
    def test_default_platform_passes_hard_controls(self):
        report = run_self_check(Platform.create({"scopes": [
            {"project_id": "p1", "authorization_ref": "A", "allowed_cidrs": ["192.0.2.0/24"]}]}))
        self.assertTrue(report["passed"], report["hard_failures"])
        ids = {c["id"]: c for c in report["checks"]}
        for hard in ("gate_fail_closed", "audit_integrity", "rbac_separation_of_duties",
                     "credentials_are_references", "targets_sanitized", "tenant_isolation"):
            self.assertTrue(ids[hard]["passed"], hard)

    def test_mock_adapters_and_secret_are_warnings_not_failures(self):
        report = run_self_check(Platform.create())
        # 默认注册了 mock 适配器 → engines_vetted 为 warn 且不通过，但不影响整体达标
        self.assertIn("engines_vetted", report["warnings"])
        self.assertTrue(report["passed"])

    def test_secret_env_satisfies_token_check(self):
        with mock.patch.dict(os.environ, {"SECASSESS_SECRET": "x" * 32}):
            report = run_self_check(Platform.create())
            ids = {c["id"]: c for c in report["checks"]}
            self.assertTrue(ids["token_secret_persistent"]["passed"])

    def test_tampered_audit_fails(self):
        platform = Platform.create()
        platform.audit.record(actor="a", action="x", project_id="p1")
        platform.audit._db.execute("UPDATE audit SET actor='evil' WHERE seq=1")
        platform.audit._db.commit()
        report = run_self_check(platform)
        self.assertFalse(report["passed"])
        self.assertIn("audit_integrity", report["hard_failures"])


if __name__ == "__main__":
    unittest.main()
