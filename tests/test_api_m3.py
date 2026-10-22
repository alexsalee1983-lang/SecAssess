import unittest

try:
    from fastapi.testclient import TestClient

    from secassess.api.app import create_app
except ImportError:
    TestClient = None

from secassess.platform import Platform

LEAD = {"X-API-Key": "lead-k"}
ALICE = {"X-API-Key": "alice-k"}
CLIENT = {"X-API-Key": "client-k"}
SCOPE = {"authorization_ref": "AUTH-M3", "allowed_cidrs": ["192.0.2.0/24"]}

NESSUS = """<?xml version="1.0"?>
<NessusClientData_v2><Report name="r"><ReportHost name="192.0.2.7">
  <ReportItem port="443" severity="4" pluginID="1" pluginName="严重漏洞"><cve>CVE-2024-0001</cve></ReportItem>
</ReportHost></Report></NessusClientData_v2>"""


def platform():
    return Platform.create({"mock_delay": 0,
                            "api_keys": {"lead-k": {"user": "lead", "role": "lead"},
                                         "alice-k": {"user": "alice", "role": "assessor", "projects": ["p1"]},
                                         "client-k": {"user": "carol", "role": "client", "projects": ["p1"]}}})


@unittest.skipIf(TestClient is None, "未安装 fastapi/httpx")
class ApiM3Test(unittest.TestCase):
    def setUp(self):
        self.cm = TestClient(create_app(platform()))
        self.client = self.cm.__enter__()
        self.client.put("/projects/p1/scope", json=SCOPE, headers=LEAD)

    def tearDown(self):
        self.cm.__exit__(None, None, None)

    def test_import_permission_gate(self):
        # 评估员无 integrate 权限
        r = self.client.post("/projects/p1/imports/cmdb", json={"rows": [{"host": "192.0.2.5", "criticality": "5"}]},
                             headers=ALICE)
        self.assertEqual(r.status_code, 403)
        r = self.client.post("/projects/p1/imports/cmdb", json={"rows": [{"host": "192.0.2.5", "criticality": "5"}]},
                             headers=LEAD)
        self.assertEqual(r.status_code, 202)
        self.assertEqual(r.json()["imported"], 1)
        assets = self.client.get("/assets", params={"project_id": "p1", "kind": "asset"}, headers=ALICE).json()
        self.assertEqual(assets[0]["attrs"]["criticality"], 5)

    def test_nessus_import_and_evidence_chain(self):
        r = self.client.post("/projects/p1/imports/nessus", json={"xml": NESSUS}, headers=LEAD)
        self.assertEqual(r.status_code, 202)
        findings = self.client.get("/findings", params={"project_id": "p1"}, headers=ALICE).json()
        self.assertTrue(findings)
        fid = findings[0]["finding_id"]
        chain = self.client.get(f"/findings/{fid}/evidence", headers=CLIENT).json()
        self.assertTrue(any("import" in c for c in chain["chain"]))
        self.assertEqual(self.client.get("/findings/fnd_missing/evidence", headers=ALICE).status_code, 404)

    def test_import_out_of_scope_marked(self):
        r = self.client.post("/projects/p1/imports/cmdb",
                             json={"rows": [{"host": "192.0.2.5"}, {"host": "203.0.113.1"}]}, headers=LEAD).json()
        self.assertEqual(r["imported"], 1)
        self.assertEqual(r["skipped"], [{"value": "203.0.113.1", "reason": "out_of_scope"}])

    def test_lifecycle_endpoints(self):
        aid = self.client.post("/assessments", params={"project_id": "p1"}, headers=ALICE).json()["assessment_id"]
        self.assertEqual(self.client.post(f"/assessments/{aid}/transition", json={"target": "scoped"},
                                          headers=ALICE).json()["state"], "scoped")
        # active 需要就绪（已设置 scope，无需凭证）
        self.assertEqual(self.client.post(f"/assessments/{aid}/transition", json={"target": "active"},
                                          headers=ALICE).json()["state"], "active")
        # 非法跳转 409
        self.assertEqual(self.client.post(f"/assessments/{aid}/transition", json={"target": "closed"},
                                          headers=ALICE).status_code, 409)
        self.assertEqual(self.client.get(f"/assessments/{aid}", headers=CLIENT).json()["state"], "active")

    def test_exposure_and_validate_endpoints(self):
        # 导入资产并建立一条可达边，验证攻击路径端点
        self.client.post("/projects/p1/imports/cmdb", json={"rows": [{"host": "192.0.2.1"},
                         {"host": "192.0.2.2"}]}, headers=LEAD)
        assets = self.client.get("/assets", params={"project_id": "p1", "kind": "asset"}, headers=ALICE).json()
        ids = {a["key"]: a["id"] for a in assets}
        body = {"entries": [ids["192.0.2.1"]], "crown_jewels": [ids["192.0.2.2"]]}
        resp = self.client.post("/exposure/p1", json=body, headers=ALICE)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("paths", resp.json())
        self.assertIn("choke_points", resp.json())

    def test_validate_version_range(self):
        self.client.post("/projects/p1/imports/nessus", json={"xml": NESSUS}, headers=LEAD)
        fid = self.client.get("/findings", params={"project_id": "p1"}, headers=ALICE).json()[0]["finding_id"]
        r = self.client.post(f"/findings/{fid}/validate",
                             json={"kind": "version_range", "params": {"fixed_version": "9.9"},
                                   "intrusive": True}, headers=ALICE).json()
        self.assertEqual(r["verdict"], "needs_hitl")  # 侵入式需审批

    def test_nessus_rejects_xxe_via_api(self):
        xxe = ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
               '<NessusClientData_v2><Report><ReportHost name="192.0.2.7"/></Report></NessusClientData_v2>')
        self.assertEqual(self.client.post("/projects/p1/imports/nessus", json={"xml": xxe},
                                          headers=LEAD).status_code, 400)


if __name__ == "__main__":
    unittest.main()
