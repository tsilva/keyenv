from __future__ import annotations

import ctypes
import io
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack, nullcontext, redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from keyring.errors import KeyringError

import keyenv.background as background
import keyenv.cli as cli
import keyenv.core as core
from keyenv.core import KeyenvError, LaunchProfile, Manifest, SecretSpec


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


class Replaced(Exception):
    pass


class BackgroundTests(unittest.TestCase):
    def setUp(self) -> None:
        stack = ExitStack()
        self.addCleanup(stack.close)
        temporary = stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(temporary).resolve()
        self.path = self.root / ".keyenv.toml"
        self.path.write_text("value-free manifest fixture")
        self.manifest = Manifest(
            self.path,
            {"TEST_SECRET": SecretSpec("synthetic/background")},
            profiles={"listener": LaunchProfile(sys.executable, ("TEST_SECRET",))},
        )
        self.command = [sys.executable, "-c", "synthetic-private-argument"]
        self.error = Terminal()
        self.output = Terminal()
        stack.enter_context(redirect_stderr(self.error))
        stack.enter_context(redirect_stdout(self.output))
        stack.enter_context(patch.dict(os.environ, {}, clear=True))
        stack.enter_context(patch.object(Path, "home", return_value=self.root))
        stack.enter_context(patch.object(Path, "cwd", return_value=self.root))
        stack.enter_context(patch.object(cli, "require_native_keychain"))
        stack.enter_context(patch.object(cli, "_plaintext_failure", return_value=False))
        stack.enter_context(
            patch.object(cli, "_load", side_effect=lambda _: self.manifest)
        )
        stack.enter_context(patch.object(sys.stdin, "isatty", return_value=True))
        self.approve = stack.enter_context(
            patch("builtins.input", return_value="listener")
        )
        self.read = stack.enter_context(
            patch("keyenv.core.keyring.get_password", side_effect=self.lookup)
        )
        self.ui = stack.enter_context(
            patch.object(cli, "without_keychain_ui", side_effect=nullcontext)
        )
        self.execute = stack.enter_context(
            patch.object(os, "execve", side_effect=Replaced)
        )

    def lookup(self, service: str, account: str) -> str:
        if service == core.BINDING_KEYCHAIN_SERVICE:
            return core.manifest_binding_record(self.manifest)
        return "synthetic-private-value"

    def authorize(self) -> None:
        self.assertEqual(
            cli.main(
                [
                    "background",
                    "authorize",
                    "--profile",
                    "listener",
                    "--",
                    *self.command,
                ]
            ),
            0,
        )
        self.read.reset_mock()
        self.approve.reset_mock()

    def launch(self, command: list[str] | None = None) -> int:
        with patch.object(sys.stdin, "isatty", return_value=False):
            with redirect_stderr(io.StringIO()):
                return cli.main(
                    [
                        "run",
                        "--background",
                        "--profile",
                        "listener",
                        "--",
                        *(command or self.command),
                    ]
                )

    def test_authorized_background_launch_reads_without_terminal_and_injects(
        self,
    ) -> None:
        self.authorize()
        with self.assertRaises(Replaced):
            self.launch()
        self.approve.assert_not_called()
        self.ui.assert_called_once()
        self.assertGreater(self.read.call_count, 0)
        self.assertEqual(
            self.execute.call_args.args[2]["TEST_SECRET"], "synthetic-private-value"
        )
        self.assertNotIn("synthetic-private-value", self.error.getvalue())
        self.assertNotIn("synthetic-private-argument", self.error.getvalue())
        grant = background.grant_path(self.manifest, "listener")
        self.assertEqual(grant.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("synthetic", grant.read_text())

    def test_missing_or_revoked_grant_prevents_every_keychain_read(self) -> None:
        self.assertEqual(self.launch(), 1)
        self.read.assert_not_called()
        self.authorize()
        self.assertEqual(cli.main(["background", "revoke", "--profile", "listener"]), 0)
        self.assertEqual(self.launch(), 1)
        self.read.assert_not_called()
        self.execute.assert_not_called()

    def test_command_or_manifest_change_requires_new_authorization(self) -> None:
        self.authorize()
        self.assertEqual(self.launch([sys.executable, "different-script"]), 1)
        self.path.write_text("changed manifest")
        self.assertEqual(self.launch(), 1)
        self.read.assert_not_called()
        self.execute.assert_not_called()

    def test_profile_account_or_executable_change_invalidates_grant(self) -> None:
        self.authorize()
        original = self.manifest
        for change in (
            replace(original, secrets={"TEST_SECRET": SecretSpec("different/account")}),
            replace(
                original,
                profiles={"listener": LaunchProfile("/bin/sh", ("TEST_SECRET",))},
            ),
        ):
            self.manifest = change
            self.assertEqual(self.launch(), 1)
            self.read.assert_not_called()
        self.execute.assert_not_called()

    def test_unsafe_permissions_corrupt_grants_and_symlinks_fail_closed(self) -> None:
        self.authorize()
        path = background.grant_path(self.manifest, "listener")
        path.chmod(0o644)
        self.assertEqual(self.launch(), 1)
        path.chmod(0o600)
        path.write_text("not json")
        self.assertEqual(self.launch(), 1)
        path.unlink()
        path.symlink_to(self.path)
        self.assertEqual(self.launch(), 1)
        self.read.assert_not_called()
        self.execute.assert_not_called()

    def test_denied_authorization_creates_no_grant_or_keychain_reads(self) -> None:
        self.approve.return_value = "deny"
        self.assertEqual(
            cli.main(
                [
                    "background",
                    "authorize",
                    "--profile",
                    "listener",
                    "--",
                    *self.command,
                ]
            ),
            1,
        )
        self.read.assert_not_called()
        self.assertFalse(background.grant_path(self.manifest, "listener").exists())

    def test_normal_launch_still_requires_interactive_approval(self) -> None:
        self.authorize()
        with patch.object(sys.stdin, "isatty", return_value=False):
            self.assertEqual(
                cli.main(["run", "--profile", "listener", "--", *self.command]), 1
            )
        self.read.assert_not_called()
        self.execute.assert_not_called()

    def test_reader_changes_require_new_authorization(self) -> None:
        self.authorize()
        with patch.object(sys, "executable", "/bin/sh"):
            with self.assertRaises(KeyenvError):
                background.require_grant(
                    self.manifest, "listener", self.command[0], self.command
                )

    def test_working_directory_change_invalidates_grant(self) -> None:
        self.authorize()
        subdirectory = self.root / "another-directory"
        subdirectory.mkdir()
        with patch.object(Path, "cwd", return_value=subdirectory):
            self.assertEqual(self.launch(), 1)
        self.read.assert_not_called()
        self.execute.assert_not_called()

    def test_keychain_failure_never_launches_or_prompts(self) -> None:
        self.authorize()
        self.read.side_effect = KeyringError("synthetic permission failure")
        self.assertEqual(self.launch(), 1)
        self.execute.assert_not_called()
        self.approve.assert_not_called()

    def test_without_keychain_ui_restores_previous_state(self) -> None:
        with patch.object(ctypes, "CDLL") as library:
            security = library.return_value
            security.SecKeychainGetUserInteractionAllowed.return_value = 0
            security.SecKeychainSetUserInteractionAllowed.return_value = 0

            def read_state(pointer: object) -> int:
                pointer._obj.value = 1  # type: ignore[attr-defined]
                return 0

            security.SecKeychainGetUserInteractionAllowed.side_effect = read_state
            with self.assertRaisesRegex(RuntimeError, "worker failed"):
                with background.without_keychain_ui():
                    raise RuntimeError("worker failed")
            calls = security.SecKeychainSetUserInteractionAllowed.call_args_list
            self.assertEqual([call.args[0] for call in calls], [0, 1])
