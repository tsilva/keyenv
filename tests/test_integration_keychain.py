from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import keyring
from keyring.errors import KeyringError

import keyenv.core as core
from keyenv.core import Manifest, SecretSpec


@unittest.skipUnless(
    os.environ.get("KEYENV_INTEGRATION") == "1",
    "set KEYENV_INTEGRATION=1 to exercise the native macOS Keychain",
)
class NativeKeychainIntegrationTests(unittest.TestCase):
    def test_migration_roundtrip_and_cleanup(self) -> None:
        core.require_native_keychain()
        suffix = uuid.uuid4().hex
        current_service = f"io.github.tsilva.keyenv.test.current.{suffix}"
        legacy_service = f"io.github.tsilva.keyenv.test.legacy.{suffix}"
        account = f"integration/{suffix}"
        value = "non-secret-integration-value"

        with tempfile.TemporaryDirectory() as temporary:
            manifest = Manifest(
                path=Path(temporary) / ".keyenv.toml",
                secrets={"TEST_VALUE": SecretSpec(account=account, required=True)},
            )
            try:
                keyring.set_password(legacy_service, account, value)
                with patch.object(core, "KEYCHAIN_SERVICE", current_service):
                    with patch.object(core, "LEGACY_KEYCHAIN_SERVICE", legacy_service):
                        statuses, healthy = core.migrate_manifest(manifest)
                        self.assertTrue(healthy)
                        self.assertEqual(statuses, {"TEST_VALUE": "copied"})
                        self.assertEqual(
                            keyring.get_password(current_service, account), value
                        )
                        self.assertEqual(
                            keyring.get_password(legacy_service, account), value
                        )

                        statuses, healthy = core.migrate_manifest(
                            manifest, delete_legacy=True
                        )
                        self.assertTrue(healthy)
                        self.assertEqual(statuses, {"TEST_VALUE": "deleted-legacy"})
                        self.assertIsNone(keyring.get_password(legacy_service, account))
            finally:
                for service in (current_service, legacy_service):
                    try:
                        keyring.delete_password(service, account)
                    except KeyringError:
                        pass


if __name__ == "__main__":
    unittest.main()
