import unittest

from secassess.core.audit import AuditLog
from secassess.core.rbac import MATRIX, Permission, PermissionDenied, Principal, Role

# ARCHITECTURE.md §8.1 表格：查看 / 启动扫描 / 审批 / 接入凭证 / 报告
DOC_TABLE = {
    Role.LEAD: {"view": True, "scan": True, "approve": True, "integrate": True, "report": True},
    Role.ASSESSOR: {"view": True, "scan": True, "approve": False, "integrate": False, "report": True},
    Role.APPROVER: {"view": True, "scan": False, "approve": True, "integrate": False, "report": False},
    Role.CLIENT: {"view": True, "scan": False, "approve": False, "integrate": False, "report": False},
}


class RbacTest(unittest.TestCase):
    def test_matrix_matches_architecture_table(self):
        for role, row in DOC_TABLE.items():
            for perm, expected in row.items():
                with self.subTest(role=role.value, perm=perm):
                    self.assertEqual(Permission(perm) in MATRIX[role], expected)
                    self.assertEqual(Principal("u", role).can(Permission(perm)), expected)

    def test_require_raises(self):
        with self.assertRaises(PermissionDenied):
            Principal("c", Role.CLIENT).require(Permission.SCAN)
        Principal("a", Role.ASSESSOR).require(Permission.SCAN)

    def test_project_isolation(self):
        p = Principal("a", "assessor", frozenset({"p1"}))
        p.require(Permission.SCAN, "p1")
        self.assertFalse(p.can(Permission.VIEW, "p2"))
        with self.assertRaises(PermissionDenied):
            p.require(Permission.VIEW, "p2")
        self.assertTrue(Principal("lead", Role.LEAD).can(Permission.VIEW, "any"))


class AuditLogTest(unittest.TestCase):
    def test_chain_and_tamper_detection(self):
        log = AuditLog()
        for i in range(5):
            log.record(actor="alice", action="scan.submit", project_id="p1", target=f"192.0.2.{i}",
                       detail={"i": i}, basis="AUTH-1")
        log.record(actor="bob", action="approval.approve", project_id="p2")
        self.assertTrue(log.verify_chain())
        self.assertEqual(len(log.entries("p1")), 5)
        self.assertEqual(log.entries()[0]["action"], "approval.approve")  # 最新在前
        self.assertEqual(log.entries("p1")[-1]["detail"], {"i": 0})
        log._db.execute("UPDATE audit SET target = '203.0.113.1' WHERE seq = 3")
        log._db.commit()
        self.assertFalse(log.verify_chain())

    def test_deleting_an_entry_breaks_chain(self):
        log = AuditLog()
        for i in range(3):
            log.record(actor="a", action="x", detail={"i": i})
        log._db.execute("DELETE FROM audit WHERE seq = 2")
        log._db.commit()
        self.assertFalse(log.verify_chain())

    def test_empty_chain_is_valid(self):
        self.assertTrue(AuditLog().verify_chain())


if __name__ == "__main__":
    unittest.main()
