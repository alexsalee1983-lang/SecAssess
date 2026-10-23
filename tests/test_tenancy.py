import unittest

from secassess.core.rbac import PermissionDenied, Principal, Role
from secassess.core.tenancy import DEFAULT_TENANT, TenantRegistry

try:
    from fastapi.testclient import TestClient

    from secassess.api.app import create_app
except ImportError:
    TestClient = None

from secassess.platform import Platform


class TenantRegistryTest(unittest.TestCase):
    def test_isolation_even_with_wildcard_projects(self):
        reg = TenantRegistry()
        reg.set_project_tenant("p-acme", "acme")
        reg.set_project_tenant("p-globex", "globex")
        acme_admin = Principal("a", Role.LEAD, frozenset({"*"}), tenant="acme")
        self.assertTrue(reg.can_access(acme_admin, "p-acme"))
        self.assertFalse(reg.can_access(acme_admin, "p-globex"))  # 通配也不能越租户
        with self.assertRaises(PermissionDenied):
            reg.require_access(acme_admin, "p-globex")
        self.assertEqual(reg.visible_projects("acme"), ["p-acme"])

    def test_unregistered_defaults(self):
        reg = TenantRegistry()
        self.assertFalse(reg.is_registered("x"))
        self.assertEqual(reg.tenant_of("x"), DEFAULT_TENANT)


@unittest.skipIf(TestClient is None, "未安装 fastapi/httpx")
class TenantApiTest(unittest.TestCase):
    def setUp(self):
        platform = Platform.create({
            "mock_delay": 0,
            "project_tenants": {"acme-proj": "acme", "globex-proj": "globex"},
            "scopes": [{"project_id": "acme-proj", "authorization_ref": "A", "allowed_cidrs": ["192.0.2.0/24"]},
                       {"project_id": "globex-proj", "authorization_ref": "G", "allowed_cidrs": ["192.0.2.0/24"]}],
            "api_keys": {"acme-k": {"user": "alice", "role": "lead", "tenant": "acme"},
                         "globex-k": {"user": "gaby", "role": "lead", "tenant": "globex"}}})
        self.cm = TestClient(create_app(platform))
        self.client = self.cm.__enter__()

    def tearDown(self):
        self.cm.__exit__(None, None, None)

    def test_cross_tenant_access_denied(self):
        acme = {"X-API-Key": "acme-k"}
        globex = {"X-API-Key": "globex-k"}
        # acme 管理员读自己的项目 OK
        self.assertEqual(self.client.get("/projects/acme-proj/scope", headers=acme).status_code, 200)
        # acme 管理员读 globex 的项目 → 403（即便角色是 lead/通配）
        self.assertEqual(self.client.get("/projects/globex-proj/scope", headers=acme).status_code, 403)
        self.assertEqual(self.client.get("/findings", params={"project_id": "globex-proj"},
                                         headers=acme).status_code, 403)
        # globex 管理员访问自己的 OK
        self.assertEqual(self.client.get("/projects/globex-proj/scope", headers=globex).status_code, 200)

    def test_new_project_claims_setter_tenant(self):
        acme = {"X-API-Key": "acme-k"}
        globex = {"X-API-Key": "globex-k"}
        r = self.client.put("/projects/newproj/scope",
                            json={"authorization_ref": "N", "allowed_cidrs": ["192.0.2.0/24"]}, headers=acme)
        self.assertEqual(r.status_code, 200)
        # 新项目归属 acme，globex 不能访问
        self.assertEqual(self.client.get("/projects/newproj/scope", headers=globex).status_code, 403)


if __name__ == "__main__":
    unittest.main()
