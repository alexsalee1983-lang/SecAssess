import unittest

from secassess.models import Category, FindingSource, NormalizedFinding, Severity
from secassess.remediation.tickets import TicketConnector, TicketError, TicketStatus, TicketStore


def finding(fid="fnd_1", title="漏洞 A"):
    return NormalizedFinding(finding_id=fid, scan_id="s", project_id="p1", source=FindingSource("a", "e"),
                             target="192.0.2.7:443", category=Category.VULNERABILITY, title=title,
                             severity=Severity.HIGH, details={"rule_id": "R"})


class RecordingConnector(TicketConnector):
    def __init__(self):
        self.created, self.updated = [], []

    def create(self, ticket):
        self.created.append(ticket.ticket_id)
        return f"JIRA-{len(self.created)}"

    def update_status(self, ticket):
        self.updated.append((ticket.ticket_id, ticket.status.value))


class TicketStoreTest(unittest.TestCase):
    def setUp(self):
        self.conn = RecordingConnector()
        self.store = TicketStore(connector=self.conn)

    def test_open_from_finding_dedups(self):
        t1 = self.store.open_from_finding(finding(), assignee="ops")
        t2 = self.store.open_from_finding(finding())
        self.assertEqual(t1.ticket_id, t2.ticket_id)  # 同发现不重复开单
        self.assertEqual(t1.external_ref, "JIRA-1")
        self.assertEqual(t1.assignee, "ops")
        self.assertEqual(self.conn.created, [t1.ticket_id])

    def test_status_flow_and_connector_sync(self):
        t = self.store.open_from_finding(finding())
        self.store.transition(t.ticket_id, TicketStatus.IN_PROGRESS, actor="ops", note="开始修复")
        self.store.transition(t.ticket_id, TicketStatus.RESOLVED, actor="ops")
        closed = self.store.transition(t.ticket_id, TicketStatus.CLOSED, actor="lead", note="复测通过")
        self.assertEqual(closed.status, TicketStatus.CLOSED)
        self.assertTrue(closed.status.is_terminal)
        self.assertEqual(len(closed.notes), 3)  # 每次带 actor 的流转都记一条
        self.assertIn((t.ticket_id, "closed"), self.conn.updated)

    def test_illegal_transition(self):
        t = self.store.open_from_finding(finding())
        with self.assertRaises(TicketError):
            self.store.transition(t.ticket_id, TicketStatus.CLOSED)  # open 不能直接 closed
        with self.assertRaises(TicketError):
            self.store.transition("tkt_missing", TicketStatus.OPEN)

    def test_reopen_after_closed_creates_new(self):
        t = self.store.open_from_finding(finding())
        self.store.transition(t.ticket_id, TicketStatus.WONT_FIX)
        # 已关闭后，同一发现可再次开单（去重只针对未关闭）
        t2 = self.store.open_from_finding(finding())
        self.assertNotEqual(t.ticket_id, t2.ticket_id)

    def test_list_scoped_by_project_and_status(self):
        self.store.open_from_finding(finding("fnd_a", "A"))
        other = finding("fnd_b", "B")
        other.project_id = "p2"
        self.store.open_from_finding(other)
        self.assertEqual(len(self.store.list("p1")), 1)
        self.assertEqual(len(self.store.list("p1", status="open")), 1)
        self.assertEqual(len(self.store.list("p2")), 1)


if __name__ == "__main__":
    unittest.main()
