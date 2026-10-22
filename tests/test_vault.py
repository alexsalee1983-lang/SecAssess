import os
import unittest
from unittest import mock

from secassess.data.vault import Vault, VaultError


class VaultTest(unittest.TestCase):
    def test_mem_secret_is_masked(self):
        vault = Vault()
        ref = vault.put("ssh-key", "s3cr3t-value")
        secret = vault.resolve(ref)
        self.assertEqual(secret.reveal(), "s3cr3t-value")
        for rendered in (repr(secret), str(secret), f"{secret}", f"{[secret]}"):
            self.assertNotIn("s3cr3t-value", rendered)

    def test_env_backend(self):
        with mock.patch.dict(os.environ, {"SECASSESS_TEST_TOKEN": "abc"}):
            self.assertEqual(Vault().resolve("vault://env/SECASSESS_TEST_TOKEN").reveal(), "abc")

    def test_invalid_and_missing_refs(self):
        vault = Vault()
        refs = ("plaintext", "vault://mem/missing", "vault://env/SECASSESS_DOES_NOT_EXIST", "vault://other/x", None)
        for ref in refs:
            with self.subTest(ref=ref), self.assertRaises(VaultError):
                vault.resolve(ref)
        self.assertFalse(vault.exists("vault://mem/missing"))
        with self.assertRaises(VaultError):
            vault.put("a/b", "x")

    def test_kv_requires_configuration(self):
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(VaultError):
            Vault().resolve("vault://kv/secret/app#password")


if __name__ == "__main__":
    unittest.main()
