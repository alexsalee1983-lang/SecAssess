import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from secassess.data.evidence import EvidenceIntegrityError, EvidenceStore
from secassess.models import Category, Confidence, FindingSource, FindingStatus, NormalizedFinding, Severity

T0 = datetime(2026, 3, 1, tzinfo=timezone.utc)


def finding(engine="eng-a", scan="scan_1", **kw):
    data = dict(scan_id=scan, project_id="p1", source=FindingSource(f"ad-{engine}", engine), target="192.0.2.10:443",
                category=Category.VULNERABILITY, title=f"Issue reported by {engine}", severity=Severity.MEDIUM,
                confidence=Confidence.TENTATIVE, details={"rule_id": "SIM-VULN-100", "port": 443}, collected_at=T0)
    data.update(kw)
    return NormalizedFinding(**data)


class EvidenceStoreTest(unittest.TestCase):
    def setUp(self):
        self.store = EvidenceStore()

    def test_multi_source_merge(self):
        first = self.store.add_findings([finding()])[0]
        merged = self.store.add_findings([finding(engine="eng-b", scan="scan_2", severity=Severity.HIGH,
                                                  confidence=Confidence.FIRM,
                                                  collected_at=T0 + timedelta(hours=1))])[0]
        self.assertEqual(merged.finding_id, first.finding_id)
        self.assertEqual(len(self.store.query("p1")), 1)
        self.assertEqual({s.engine for s in merged.sources}, {"eng-a", "eng-b"})
        self.assertIs(merged.severity, Severity.HIGH)
        self.assertIs(merged.confidence, Confidence.FIRM)
        self.assertEqual(merged.first_seen, T0)
        self.assertEqual(merged.last_seen, T0 + timedelta(hours=1))
        # 两次扫描都能查到这条发现
        self.assertEqual(len(self.store.findings_for_scan("scan_1")), 1)
        self.assertEqual(len(self.store.findings_for_scan("scan_2")), 1)

    def test_same_source_twice_does_not_duplicate_sources(self):
        self.store.add_findings([finding()])
        merged = self.store.add_findings([finding(scan="scan_2")])[0]
        self.assertEqual(len(merged.sources), 1)

    def test_manual_review_status_survives_rescan(self):
        f = self.store.add_findings([finding()])[0]
        f.status = FindingStatus.FALSE_POSITIVE
        self.store.update(f)
        again = self.store.add_findings([finding(engine="eng-b", scan="scan_2")])[0]
        self.assertIs(again.status, FindingStatus.FALSE_POSITIVE)
        self.assertEqual(len(self.store.query("p1", status="false_positive")), 1)

    def test_query_filters_and_isolation(self):
        self.store.add_findings([
            finding(),
            finding(details={"rule_id": "SIM-VULN-200"}, severity=Severity.CRITICAL),
            finding(details={"rule_id": "SIM-CFG-001"}, category=Category.MISCONFIG, severity=Severity.LOW),
            finding(project_id="p2"),
        ])
        self.assertEqual(len(self.store.query("p1")), 3)
        self.assertEqual(len(self.store.query("p2")), 1)
        self.assertEqual([f.severity for f in self.store.query("p1", min_severity="medium")],
                         [Severity.CRITICAL, Severity.MEDIUM])
        self.assertEqual(len(self.store.query("p1", category="misconfig")), 1)

    def test_raw_evidence_integrity(self):
        ref = self.store.put_raw("p1", '{"raw": "output"}', "application/json")
        self.assertTrue(ref.startswith("evidence://p1/"))
        self.assertEqual(self.store.get_raw(ref), (b'{"raw": "output"}', "application/json"))
        self.assertEqual(self.store.put_raw("p1", '{"raw": "output"}'), ref)  # 内容寻址，幂等
        self.assertIsNone(self.store.get_raw("evidence://p1/missing"))
        self.store._db.execute("UPDATE evidence SET content = ? WHERE ref = ?", (b"tampered", ref))
        with self.assertRaises(EvidenceIntegrityError):
            self.store.get_raw(ref)

    def test_file_backed_store_persists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "evidence.db")
            fid = EvidenceStore(path).add_findings([finding()])[0].finding_id
            self.assertEqual(EvidenceStore(path).get(fid).title, "Issue reported by eng-a")


if __name__ == "__main__":
    unittest.main()
