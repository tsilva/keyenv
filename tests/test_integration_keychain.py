from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
import uuid
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import keyring
from keyring.errors import KeyringError

import keyenv.cli as cli
import keyenv.core as core
from keyenv.core import LaunchProfile, Manifest, SecretSpec


@unittest.skipUnless(
    os.environ.get("KEYENV_INTEGRATION") == "1",
    "set KEYENV_INTEGRATION=1 to exercise the native macOS Keychain",
)
class NativeKeychainIntegrationTests(unittest.TestCase):
    def test_background_launch_reads_native_keychain_without_terminal(self) -> None:
        core.require_native_keychain()
        account = f"integration/background/{uuid.uuid4().hex}"
        value = "non-secret-integration-value"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / ".keyenv.toml"
            path.write_text("synthetic manifest fixture")
            manifest = Manifest(
                path,
                {"TEST_VALUE": SecretSpec(account)},
                profiles={"demo": LaunchProfile(sys.executable, ("TEST_VALUE",))},
            )
            command = [sys.executable, "-c", "pass"]

            class Terminal(io.StringIO):
                def isatty(self) -> bool:
                    return True

            try:
                keyring.set_password(core.KEYCHAIN_SERVICE, account, value)
                keyring.set_password(
                    core.BINDING_KEYCHAIN_SERVICE,
                    account,
                    core.manifest_binding_record(manifest),
                )
                with ExitStack() as stack:
                    stack.enter_context(patch.object(Path, "home", return_value=root))
                    stack.enter_context(patch.object(Path, "cwd", return_value=root))
                    stack.enter_context(
                        patch.object(cli, "_load", return_value=manifest)
                    )
                    stack.enter_context(patch.dict(os.environ, {}, clear=True))
                    stack.enter_context(redirect_stdout(io.StringIO()))
                    stack.enter_context(redirect_stderr(Terminal()))
                    with patch.object(sys.stdin, "isatty", return_value=True):
                        with patch("builtins.input", return_value="demo"):
                            self.assertEqual(
                                cli.main(
                                    [
                                        "background",
                                        "authorize",
                                        "--profile",
                                        "demo",
                                        "--",
                                        *command,
                                    ]
                                ),
                                0,
                            )
                    with patch.object(sys.stdin, "isatty", return_value=False):
                        with patch(
                            "builtins.input", side_effect=AssertionError("prompted")
                        ):
                            with patch(
                                "os.execve", side_effect=RuntimeError("replaced")
                            ) as execute:
                                with self.assertRaisesRegex(RuntimeError, "replaced"):
                                    cli.main(
                                        [
                                            "run",
                                            "--background",
                                            "--profile",
                                            "demo",
                                            "--",
                                            *command,
                                        ]
                                    )
                            self.assertEqual(
                                execute.call_args.args[2]["TEST_VALUE"], value
                            )
            finally:
                for service in (core.KEYCHAIN_SERVICE, core.BINDING_KEYCHAIN_SERVICE):
                    try:
                        keyring.delete_password(service, account)
                    except KeyringError:
                        pass

    def test_migration_roundtrip_and_cleanup(self) -> None:
        core.require_native_keychain()
        suffix = uuid.uuid4().hex
        current_service = f"io.github.tsilva.keyenv.test.current.{suffix}"
        legacy_service = f"io.github.tsilva.keyenv.test.legacy.{suffix}"
        binding_service = f"io.github.tsilva.keyenv.test.binding.{suffix}"
        account = f"integration/{suffix}"
        value = "non-secret-integration-value"

        with tempfile.TemporaryDirectory() as temporary:
            manifest = Manifest(
                path=Path(temporary) / ".keyenv.toml",
                secrets={"TEST_VALUE": SecretSpec(account=account, required=True)},
            )
            try:
                keyring.set_password(legacy_service, account, value)
                keyring.set_password(
                    binding_service, account, core.manifest_binding_record(manifest)
                )
                with patch.object(core, "KEYCHAIN_SERVICE", current_service):
                    with patch.object(core, "LEGACY_KEYCHAIN_SERVICE", legacy_service):
                        with patch.object(
                            core, "BINDING_KEYCHAIN_SERVICE", binding_service
                        ):
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
                            self.assertIsNone(
                                keyring.get_password(legacy_service, account)
                            )
                            self.assertEqual(
                                keyring.get_password(binding_service, account),
                                core.manifest_binding_record(manifest),
                            )
            finally:
                for service in (current_service, legacy_service, binding_service):
                    try:
                        keyring.delete_password(service, account)
                    except KeyringError:
                        pass


if __name__ == "__main__":
    unittest.main()
