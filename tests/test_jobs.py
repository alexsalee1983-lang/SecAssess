import asyncio
import time
import unittest

from secassess.adapters.base import ScannerAdapter
from secassess.core.jobs import JobManager, JobState
from secassess.core.scope_gate import ScopeGate, ScopePolicy, ScopeViolation, build_action
from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.models import Capability, Category, IntrusiveLevel, ScanRequest, ScanType, Severity


class FakeAdapter(ScannerAdapter):
    """可控的测试适配器：分步 sleep、记录并发度、可抛错。"""

    def __init__(self, name="fake", duration=0.05, steps=5, fail=False, scan_types=(ScanType.PORT_DISCOVERY,)):
        self.name, self.duration, self.steps, self.fail = name, duration, steps, fail
        self._types = frozenset(scan_types)
        self.running = 0
        self.max_running = 0

    def capability(self):
        return Capability(engine="fake", scan_types=self._types, intrusive_level=IntrusiveLevel.SAFE)

    async def scan(self, request, on_progress):
        self.running += 1
        self.max_running = max(self.max_running, self.running)
        try:
            for i in range(1, self.steps + 1):
                await asyncio.sleep(self.duration / self.steps)
                on_progress(i / self.steps, f"step {i}")
            if self.fail:
                raise RuntimeError("engine crashed")
            return [self.finding(request, target=t, category=Category.ASSET, title=f"seen {t}",
                                 severity=Severity.INFO, details={"rule_id": f"R-{t}"}) for t in request.targets]
        finally:
            self.running -= 1


class JobManagerTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.gate = ScopeGate(b"k" * 32)
        self.gate.set_policy(ScopePolicy(project_id="p1", authorization_ref="AUTH-1", allowed_cidrs=["192.0.2.0/24"]))
        self.facts = FactStore(EvidenceStore(), AssetGraph())

    def manager(self, **kw):
        return JobManager(sink=self.facts, verifier=self.gate, **kw)

    def request(self, targets=("192.0.2.1",), scan_type="port_discovery", token=None):
        targets = list(targets)
        if token is None:
            token = self.gate.issue_token(build_action(project_id="p1", targets=targets, scan_type=scan_type,
                                                       adapter="fake", intrusive_level="safe"))
        return ScanRequest(targets=targets, scan_type=scan_type, scope_token=token, project_id="p1")

    async def test_submit_returns_immediately(self):
        jobs = self.manager()
        start = time.perf_counter()
        job_id = jobs.submit(FakeAdapter(duration=2.0), self.request())
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 0.05)
        self.assertIn(jobs.status(job_id)["state"], (JobState.QUEUED, JobState.RUNNING))
        await jobs.shutdown()

    async def test_concurrency_limit(self):
        jobs = self.manager(max_concurrent=2)
        adapter = FakeAdapter(duration=0.05)
        ids = [jobs.submit(adapter, self.request([f"192.0.2.{i}"])) for i in range(5)]
        await asyncio.sleep(0.01)
        self.assertEqual(sum(jobs.status(i)["state"] == JobState.QUEUED for i in ids), 3)
        for job_id in ids:
            await jobs.wait(job_id, timeout=2)
        self.assertEqual(adapter.max_running, 2)
        self.assertTrue(all(jobs.status(i)["state"] == JobState.DONE for i in ids))

    async def test_cancel_running_and_queued(self):
        jobs = self.manager(max_concurrent=1)
        running = jobs.submit(FakeAdapter(duration=5), self.request())
        queued = jobs.submit(FakeAdapter(duration=5), self.request())
        await asyncio.sleep(0.01)
        self.assertEqual(jobs.status(running)["state"], JobState.RUNNING)
        self.assertEqual(jobs.status(queued)["state"], JobState.QUEUED)
        self.assertTrue(jobs.cancel(queued))
        self.assertTrue(jobs.cancel(running))
        self.assertEqual((await jobs.wait(running, timeout=1))["state"], JobState.CANCELLED)
        self.assertEqual((await jobs.wait(queued, timeout=1))["state"], JobState.CANCELLED)
        self.assertFalse(jobs.cancel(running))

    async def test_cancel_after_done_returns_false(self):
        jobs = self.manager()
        job_id = jobs.submit(FakeAdapter(duration=0.01), self.request())
        await jobs.wait(job_id, timeout=1)
        self.assertFalse(jobs.cancel(job_id))

    async def test_timeout_marks_failed(self):
        jobs = self.manager()
        job_id = jobs.submit(FakeAdapter(duration=5), self.request(), timeout=0.05)
        view = await jobs.wait(job_id, timeout=2)
        self.assertEqual(view["state"], JobState.FAILED)
        self.assertIn("timeout", view["error"])

    async def test_failure_is_isolated(self):
        jobs = self.manager()
        bad = jobs.submit(FakeAdapter(fail=True, duration=0.01), self.request())
        good = jobs.submit(FakeAdapter(duration=0.02), self.request(["192.0.2.2"]))
        self.assertEqual((await jobs.wait(bad, timeout=1))["state"], JobState.FAILED)
        self.assertIn("engine crashed", jobs.status(bad)["error"])
        self.assertEqual((await jobs.wait(good, timeout=1))["state"], JobState.DONE)

    async def test_stream_ends_in_terminal_state_with_monotonic_progress(self):
        jobs = self.manager()
        job_id = jobs.submit(FakeAdapter(duration=0.05, steps=5), self.request())
        snapshots = [s async for s in jobs.stream(job_id)]
        self.assertEqual(snapshots[-1]["state"], JobState.DONE)
        progress = [s["progress"] for s in snapshots]
        self.assertEqual(progress, sorted(progress))
        self.assertGreaterEqual(len(snapshots), 3)

    async def test_results_come_from_sink(self):
        jobs = self.manager()
        req = self.request(["192.0.2.1", "192.0.2.2"])
        job_id = jobs.submit(FakeAdapter(duration=0.01), req)
        await jobs.wait(job_id, timeout=1)
        results = jobs.results(job_id)
        self.assertEqual(sorted(f.target for f in results), ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(results, self.facts.findings_for_scan(req.scan_id))
        self.assertEqual(jobs.status(job_id)["finding_count"], 2)

    async def test_fail_closed_submission(self):
        good_request = self.request()
        with self.assertRaises(RuntimeError):
            JobManager(sink=self.facts, verifier=None).submit(FakeAdapter(), good_request)
        jobs = self.manager()
        with self.assertRaises(ScopeViolation):
            jobs.submit(FakeAdapter(), self.request(token="forged.token"))
        with self.assertRaises(ValueError):
            jobs.submit(FakeAdapter(scan_types=(ScanType.VULN,)), good_request)
        self.assertEqual(jobs.list(), [])

    async def test_unknown_job(self):
        with self.assertRaises(KeyError):
            self.manager().status("job_missing")


if __name__ == "__main__":
    unittest.main()
