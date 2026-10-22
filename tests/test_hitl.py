import unittest
from datetime import datetime, timedelta, timezone

from secassess.core.hitl import ApprovalError, ApprovalQueue, ApprovalState


class FakeClock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)


ACTION = {"project_id": "p1", "targets": ["192.0.2.1"], "scan_type": "port_discovery", "options": {"profile": "deep"}}


class ApprovalQueueTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.queue = ApprovalQueue(ttl=timedelta(hours=1), clock=self.clock)
        self.item = self.queue.request(project_id="p1", action=dict(ACTION), reasons=["deep 扫描"],
                                       requested_by="alice")

    def test_happy_path(self):
        self.assertEqual(self.item.state, ApprovalState.PENDING)
        self.queue.approve(self.item.approval_id, "bob", "ok")
        self.assertEqual(self.queue.get(self.item.approval_id).decided_by, "bob")
        self.queue.consume(self.item.approval_id, dict(ACTION))
        self.assertEqual(self.queue.get(self.item.approval_id).state, ApprovalState.CONSUMED)

    def test_separation_of_duties(self):
        with self.assertRaises(ApprovalError):
            self.queue.approve(self.item.approval_id, "alice")
        with self.assertRaises(ApprovalError):
            self.queue.reject(self.item.approval_id, "alice")
        self.assertEqual(self.item.state, ApprovalState.PENDING)

    def test_modified_action_cannot_be_consumed(self):
        self.queue.approve(self.item.approval_id, "bob")
        tampered = dict(ACTION, targets=["192.0.2.1", "192.0.2.2"])
        with self.assertRaises(ApprovalError):
            self.queue.consume(self.item.approval_id, tampered)
        self.assertEqual(self.item.state, ApprovalState.APPROVED)

    def test_consume_only_once(self):
        self.queue.approve(self.item.approval_id, "bob")
        self.queue.consume(self.item.approval_id, dict(ACTION))
        with self.assertRaises(ApprovalError):
            self.queue.consume(self.item.approval_id, dict(ACTION))

    def test_pending_must_not_be_consumed(self):
        with self.assertRaises(ApprovalError):
            self.queue.consume(self.item.approval_id, dict(ACTION))

    def test_expiry_blocks_approve_and_consume(self):
        self.clock.advance(hours=1)
        self.assertEqual(self.queue.get(self.item.approval_id).state, ApprovalState.EXPIRED)
        with self.assertRaises(ApprovalError):
            self.queue.approve(self.item.approval_id, "bob")
        other = self.queue.request(project_id="p1", action=dict(ACTION), reasons=[], requested_by="alice")
        self.queue.approve(other.approval_id, "bob")
        self.clock.advance(hours=2)
        with self.assertRaises(ApprovalError):
            self.queue.consume(other.approval_id, dict(ACTION))

    def test_rejected_cannot_be_approved(self):
        self.queue.reject(self.item.approval_id, "bob", "no")
        with self.assertRaises(ApprovalError):
            self.queue.approve(self.item.approval_id, "carol")
        with self.assertRaises(ApprovalError):
            self.queue.consume(self.item.approval_id, dict(ACTION))

    def test_list_filters_and_unknown_id(self):
        self.queue.request(project_id="p2", action={}, reasons=[], requested_by="x")
        self.assertEqual(len(self.queue.list(project_id="p1")), 1)
        self.assertEqual(len(self.queue.list(state=ApprovalState.PENDING)), 2)
        with self.assertRaises(ApprovalError):
            self.queue.get("apr_missing")


if __name__ == "__main__":
    unittest.main()
