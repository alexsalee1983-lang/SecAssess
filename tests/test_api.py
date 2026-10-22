import json
import os
import subprocess
import sys
import unittest

try:
    from fastapi.testclient import TestClient

    from secassess.api.app import create_app
except ImportError:  # 未安装可选依赖 secassess[api]
    TestClient = None

from secassess.platform import Platform

ROOT = os.path.join(os.path.dirname(__file__), "..")
LEAD, ALICE, BOB, CLIENT = ({"X-API-Key": k} for k in ("lead-k", "alice-k", "bob-k", "client-k"))
SCOPE = {"authorization_ref": "AUTH-API-1", "allowed_cidrs": ["192.0.2.0/24"], "excluded": ["192.0.2.254"]}


def platform():
    return Platform.create({
        "mock_delay": 0,
        "api_keys": {"lead-k": {"user": "lead", "role": "lead"},
                     "alice-k": {"user": "alice", "role": "assessor", "projects": ["p1"]},
                     "bob-k": {"user": "bob", "role": "approver", "projects": ["p1"]},
                     "client-k": {"user": "carol", "role": "client", "projects": ["p1"]}}})


@unittest.skipIf(TestClient is None, "未安装 fastapi/httpx")
class ApiTest(unittest.TestCase):
    def setUp(self):
        self.client_cm = TestClient(create_app(platform()))
        self.client = self.client_cm.__enter__()
        self.assertEqual(self.client.put("/projects/p1/scope", json=SCOPE, headers=LEAD).status_code, 200)

    def tearDown(self):
        self.client_cm.__exit__(None, None, None)

    def wait_done(self, job_id, headers=ALICE):
        """消费 SSE 流直到终态（不用 sleep 轮询）。"""
        events = []
        with self.client.stream("GET", f"/scans/{job_id}/stream", headers=headers) as resp:
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.headers["content-type"].startswith("text/event-stream"))
            for line in resp.iter_lines():
                if line.startswith("data: "):
                    events.append(json.loads(line[6:]))
        return events

    def test_authentication_and_authorization(self):
        self.assertEqual(self.client.get("/adapters").status_code, 401)
        self.assertEqual(self.client.get("/adapters", headers={"X-API-Key": "wrong"}).status_code, 401)
        body = {"project_id": "p1", "agent": "asset", "targets": ["192.0.2.1"]}
        self.assertEqual(self.client.post("/scans", json=body, headers=CLIENT).status_code, 403)
        self.assertEqual(self.client.put("/projects/p1/scope", json=SCOPE, headers=ALICE).status_code, 403)
        self.assertEqual(self.client.get("/findings", params={"project_id": "p2"}, headers=ALICE).status_code, 403)
        self.assertEqual(self.client.put("/projects/p1/scope", json={"authorization_ref": ""},
                                         headers=LEAD).status_code, 400)

    def test_scan_lifecycle_with_polling_and_sse(self):
        resp = self.client.post("/scans", json={"project_id": "p1", "agent": "asset", "targets": ["192.0.2.0/29"]},
                                headers=ALICE)
        self.assertEqual(resp.status_code, 202)
        job_id = resp.json()["job_id"]
        events = self.wait_done(job_id)
        self.assertEqual(events[-1]["state"], "done")
        status = self.client.get(f"/scans/{job_id}", headers=CLIENT).json()
        self.assertEqual(status["state"], "done")
        results = self.client.get(f"/scans/{job_id}/results", headers=ALICE).json()
        self.assertEqual(len(results), status["finding_count"])
        self.assertTrue(self.client.get("/assets", params={"project_id": "p1"}, headers=ALICE).json())
        self.assertFalse(self.client.post(f"/scans/{job_id}/cancel", headers=ALICE).json()["cancelled"])
        self.assertEqual(self.client.get("/scans/job_missing", headers=ALICE).status_code, 404)

    def test_out_of_scope_is_denied(self):
        resp = self.client.post("/scans", json={"project_id": "p1", "agent": "asset",
                                                "targets": ["192.0.2.1", "203.0.113.1"]}, headers=ALICE)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["state"], "denied")

    def test_deep_scan_approval_flow(self):
        resp = self.client.post("/scans", json={"project_id": "p1", "agent": "asset", "targets": ["192.0.2.3"],
                                                "options": {"profile": "deep"}}, headers=ALICE)
        self.assertEqual(resp.status_code, 202)
        approval_id = resp.json()["approval_id"]
        pending = self.client.get("/approvals", params={"project_id": "p1", "state": "pending"}, headers=BOB).json()
        self.assertEqual([a["approval_id"] for a in pending], [approval_id])
        self.assertEqual(self.client.post(f"/approvals/{approval_id}/approve", json={}, headers=ALICE).status_code, 403)
        self.assertEqual(self.client.post(f"/approvals/{approval_id}/approve", json={"comment": "ok"},
                                          headers=BOB).status_code, 200)
        resumed = self.client.post(f"/approvals/{approval_id}/resume", headers=ALICE)
        self.assertEqual(resumed.status_code, 202)
        self.assertEqual(self.wait_done(resumed.json()["job_id"])[-1]["state"], "done")
        self.assertEqual(self.client.post(f"/approvals/{approval_id}/resume", headers=ALICE).status_code, 409)

    def test_pipeline_review_report_and_audit(self):
        cred = self.client.post("/projects/p1/credentials", json={"name": "ssh", "value": "secret-key"},
                                headers=LEAD).json()["credential_ref"]
        resp = self.client.post("/pipelines", json={"project_id": "p1", "seeds": ["192.0.2.0/28"],
                                                    "credential_ref": cred}, headers=ALICE)
        self.assertEqual(resp.status_code, 202)
        pipeline_id = resp.json()["pipeline_id"]
        run = self.client.get(f"/pipelines/{pipeline_id}", params={"wait": 30}, headers=ALICE).json()
        self.assertEqual(run["state"], "done", run)
        self.assertEqual([s["agent"] for s in run["steps"]], ["asset", "vuln", "baseline"])
        findings = self.client.get("/findings", params={"project_id": "p1"}, headers=ALICE).json()
        self.assertEqual({f["category"] for f in findings}, {"asset", "vulnerability", "misconfig"})
        self.assertNotIn("secret-key", json.dumps(findings))

        high = [f for f in findings if f["severity"] in ("high", "critical")][0]
        self.assertEqual(self.client.patch(f"/findings/{high['finding_id']}", json={"status": "accepted"},
                                           headers=ALICE).status_code, 403)
        self.assertEqual(self.client.patch(f"/findings/{high['finding_id']}", json={"status": "accepted"},
                                           headers=LEAD).json()["status"], "accepted")
        self.assertEqual(self.client.patch(f"/findings/{high['finding_id']}", json={"status": "open"},
                                           headers=CLIENT).status_code, 403)

        md = self.client.get("/reports/p1", params={"format": "md"}, headers=ALICE)
        self.assertEqual(md.status_code, 200)
        self.assertIn("AUTH-API-1", md.text)
        self.assertEqual(self.client.get("/reports/p1", params={"format": "html"}, headers=ALICE).status_code, 200)
        self.assertEqual(self.client.get("/reports/p1", headers=CLIENT).status_code, 403)
        audit = self.client.get("/audit", params={"project_id": "p1"}, headers=LEAD).json()
        self.assertTrue(audit["chain_valid"])
        self.assertIn("finding.review", {e["action"] for e in audit["entries"]})

    def test_copilot_run_and_ask(self):
        resp = self.client.post("/copilot/runs", json={"project_id": "p1",
                                "instruction": "对 192.0.2.0/28 做资产测绘和漏洞扫描"}, headers=ALICE)
        self.assertEqual(resp.status_code, 202)
        run = resp.json()
        self.assertEqual(run["state"], "done", run)
        self.assertEqual(self.client.get(f"/copilot/runs/{run['run_id']}", headers=CLIENT).json()["state"], "done")
        self.assertEqual(self.client.get("/copilot/runs/cop_missing", headers=ALICE).status_code, 404)
        ask = self.client.post("/copilot/ask", json={"project_id": "p1", "question": "有哪些漏洞？"},
                               headers=CLIENT).json()
        self.assertGreater(ask["count"], 0)
        self.assertEqual(ask["filters"]["category"], "vulnerability")

    def test_copilot_deep_scan_waits_for_approval(self):
        resp = self.client.post("/copilot/runs", json={"project_id": "p1",
                                "instruction": "对 192.0.2.3 做深度扫描"}, headers=ALICE)
        run = resp.json()
        self.assertEqual(run["state"], "waiting_approval", run)
        approval_id = run["pending_approvals"][0]["approval_id"]
        self.assertEqual(self.client.post(f"/approvals/{approval_id}/approve", json={}, headers=BOB).status_code, 200)
        cont = self.client.post(f"/copilot/runs/{run['run_id']}/continue", headers=ALICE).json()
        self.assertEqual(cont["state"], "done", cont)


class CliTest(unittest.TestCase):
    def test_help(self):
        result = subprocess.run([sys.executable, "-m", "secassess", "--help"], cwd=ROOT, capture_output=True)
        self.assertEqual(result.returncode, 0)

    def test_example_platform_config_loads(self):
        p = Platform.from_file(os.path.join(ROOT, "examples", "platform.json"), base_dir=ROOT)
        self.assertIsNotNone(p.gate.policy("demo"))
        self.assertEqual(p.api_keys["demo-approver-key"].user, "bob")


if __name__ == "__main__":
    unittest.main()
