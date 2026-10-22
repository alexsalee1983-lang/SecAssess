import unittest

from secassess.models import (Category, Confidence, FindingSource, NormalizedFinding, RateLimit,
                              ScanRequest, ScanType, Severity)


def make_request(**overrides):
    kwargs = dict(targets=["192.0.2.10"], scan_type="port_discovery", scope_token="tok")
    kwargs.update(overrides)
    return ScanRequest(**kwargs)


def make_finding(engine="eng-a", **overrides):
    kwargs = dict(scan_id="scan_1", source=FindingSource("ad", engine), target="192.0.2.10:22",
                  category=Category.VULNERABILITY, title="Example", severity=Severity.HIGH,
                  details={"rule_id": "SIM-VULN-001", "port": 22})
    kwargs.update(overrides)
    return NormalizedFinding(**kwargs)


class ScanRequestContractTest(unittest.TestCase):
    def test_valid_request_normalizes_fields(self):
        req = make_request(rate_limit={"pps": 10, "concurrency": 2})
        self.assertIs(req.scan_type, ScanType.PORT_DISCOVERY)
        self.assertEqual(req.rate_limit, RateLimit(10, 2))
        self.assertTrue(req.scan_id.startswith("scan_"))

    def test_rejects_empty_targets(self):
        with self.assertRaises(ValueError):
            make_request(targets=[])
        with self.assertRaises(ValueError):
            make_request(targets=["  "])

    def test_rejects_missing_scope_token(self):
        with self.assertRaises(ValueError):
            make_request(scope_token="")

    def test_rejects_plaintext_credentials(self):
        with self.assertRaises(ValueError):
            make_request(credential_ref="password123")
        self.assertEqual(make_request(credential_ref="vault://mem/ssh").credential_ref, "vault://mem/ssh")

    def test_rejects_argument_or_shell_injection_targets(self):
        for bad in ["-oX/tmp/x", "192.0.2.1;id", "a b", "host|cat", "$(id)", "`id`"]:
            with self.subTest(target=bad), self.assertRaises(ValueError):
                make_request(targets=[bad])

    def test_rejects_unknown_scan_type(self):
        with self.assertRaises(ValueError):
            make_request(scan_type="exploit")


class NormalizedFindingContractTest(unittest.TestCase):
    def test_fingerprint_is_stable_and_engine_independent(self):
        a, b = make_finding(engine="eng-a"), make_finding(engine="eng-b", title="Other wording")
        self.assertEqual(a.fingerprint, make_finding(engine="eng-a").fingerprint)
        self.assertEqual(a.fingerprint, b.fingerprint)  # 同一 rule_id/端口/目标
        self.assertNotEqual(a.fingerprint, make_finding(details={"rule_id": "SIM-VULN-002", "port": 22}).fingerprint)
        self.assertNotEqual(a.fingerprint, make_finding(project_id="other").fingerprint)

    def test_roundtrip_dict(self):
        f = make_finding(cve=["cve-2000-0001"], cvss={"version": "3.1", "score": 7.5, "vector": "x"},
                         confidence="firm")
        g = NormalizedFinding.from_dict(f.to_dict())
        self.assertEqual(g.to_dict(), f.to_dict())
        self.assertEqual(g.cve, ["CVE-2000-0001"])
        self.assertIs(g.confidence, Confidence.FIRM)

    def test_ranks(self):
        self.assertGreater(Severity.CRITICAL.rank, Severity.HIGH.rank)
        self.assertGreater(Confidence.CONFIRMED.rank, Confidence.TENTATIVE.rank)


if __name__ == "__main__":
    unittest.main()
