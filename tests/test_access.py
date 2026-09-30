from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from keyring.errors import KeyringError

import keyenv.cli as cli
import keyenv.core as core
from keyenv.access import access_request
from keyenv.core import LaunchProfile, Manifest, SecretSpec


class TerminalOutput(io.StringIO):
    def __init__(self, *, terminal: bool = True) -> None:
        super().__init__()
        self.terminal = terminal

    def isatty(self) -> bool:
        return self.terminal


class ProcessReplaced(Exception):
    pass


class AccessHarness(unittest.TestCase):
    def setUp(self) -> None:
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.output = TerminalOutput()
        self.error = TerminalOutput()
        stack.enter_context(redirect_stdout(self.output))
        stack.enter_context(redirect_stderr(self.error))
        stack.enter_context(patch.dict(os.environ, {}, clear=True))
        stack.enter_context(patch.object(sys.stdin, "isatty", return_value=True))
        self.approval = stack.enter_context(
            patch("builtins.input", return_value="allow")
        )
        self.native = stack.enter_context(patch.object(cli, "require_native_keychain"))
        self.manifest = Manifest(
            path=Path.cwd().resolve() / ".keyenv.toml",
            secrets={
                "FIRST_SECRET": SecretSpec("test/first"),
                "SECOND_SECRET": SecretSpec("test/second"),
            },
        )
        stack.enter_context(
            patch.object(cli, "_load", side_effect=lambda _: self.manifest)
        )
        stack.enter_context(patch.object(cli, "_plaintext_failure", return_value=False))
        self.which = stack.enter_context(
            patch("keyenv.cli.shutil.which", return_value="/tools/runner")
        )
        self.read = stack.enter_context(
            patch("keyenv.core.keyring.get_password", side_effect=self.read_password)
        )
        self.write = stack.enter_context(patch("keyenv.core.keyring.set_password"))
        self.delete = stack.enter_context(patch("keyenv.core.keyring.delete_password"))
        self.execute = stack.enter_context(
            patch("keyenv.cli.os.execve", side_effect=ProcessReplaced)
        )

    def read_password(self, service: str, account: str) -> str | None:
        self.assertEqual(self.approval.call_count, 1)
        # Context and progress must already be visible when native access happens.
        self.assertIn(str(self.manifest.root), self.error.getvalue())
        self.assertIn(account, self.error.getvalue())
        if service == core.BINDING_KEYCHAIN_SERVICE:
            self.assertIn("read project authorization", self.error.getvalue())
            return core.manifest_binding_record(self.manifest)
        self.assertIn("read credential", self.error.getvalue())
        return "synthetic-private-value"

    def launch(self, *options: str) -> dict[str, str]:
        with self.assertRaises(ProcessReplaced):
            cli.main(["run", *options, "--", "runner", "synthetic-private-argument"])
        environment: dict[str, str] = self.execute.call_args.args[2]
        return environment

    def assert_no_keychain_access(self) -> None:
        self.read.assert_not_called()
        self.write.assert_not_called()
        self.delete.assert_not_called()


class AccessTests(AccessHarness):
    def test_summary_and_approval_precede_all_reads_without_values_or_arguments(
        self,
    ) -> None:
        def approve() -> str:
            self.assert_no_keychain_access()
            for text in (
                "FIRST_SECRET",
                "SECOND_SECRET",
                "/tools/runner",
                "descendants",
            ):
                self.assertIn(text, self.error.getvalue())
            return "allow"

        self.approval.side_effect = approve
        environment = self.launch()
        self.assertEqual(environment["FIRST_SECRET"], "synthetic-private-value")
        self.approval.assert_called_once_with()
        self.assertEqual(self.output.getvalue(), "")
        self.assertNotIn("synthetic-private-value", self.error.getvalue())
        self.assertNotIn("synthetic-private-argument", self.error.getvalue())
        self.assertIsNone(core.keychain_observer.get())

    def test_denied_launch_never_reads_bindings_credentials_or_executes(self) -> None:
        self.approval.return_value = "deny"
        self.assertEqual(cli.main(["run", "--", "runner"]), 1)
        self.assert_no_keychain_access()
        self.execute.assert_not_called()
        self.assertIsNone(core.keychain_observer.get())

    def test_closed_input_and_interrupt_cancel_without_native_access(self) -> None:
        for failure in (EOFError(), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                self.approval.side_effect = failure
                self.assertEqual(cli.main(["run", "--", "runner"]), 1)
                self.assert_no_keychain_access()
                self.execute.assert_not_called()
        self.assertIn("approval cancelled", self.error.getvalue())

    def test_noninteractive_launch_refuses_before_native_access(self) -> None:
        with patch.object(sys.stdin, "isatty", return_value=False):
            self.assertEqual(cli.main(["run", "--", "runner"]), 1)
        self.assert_no_keychain_access()
        self.execute.assert_not_called()
        self.approval.assert_not_called()
        self.assertIn("process environment", self.error.getvalue())

    def test_hidden_summary_cannot_be_approved(self) -> None:
        self.error.terminal = False
        self.assertEqual(cli.main(["run", "--", "runner"]), 1)
        self.assert_no_keychain_access()
        self.approval.assert_not_called()

    def test_process_only_launch_works_without_a_terminal_or_keychain(self) -> None:
        with patch.dict(
            os.environ,
            {"FIRST_SECRET": "synthetic-first", "SECOND_SECRET": "synthetic-second"},
        ):
            with patch.object(sys.stdin, "isatty", return_value=False):
                self.error.terminal = False
                environment = self.launch()
        self.assertEqual(environment["FIRST_SECRET"], "synthetic-first")
        self.assert_no_keychain_access()
        self.approval.assert_not_called()
        self.assertNotIn("synthetic-first", self.error.getvalue())

    def test_partial_process_environment_skips_its_binding_and_credential(self) -> None:
        with patch.dict(os.environ, {"FIRST_SECRET": "synthetic-process"}):
            environment = self.launch()
        self.assertEqual(environment["FIRST_SECRET"], "synthetic-process")
        self.assertEqual(
            {call.args[1] for call in self.read.call_args_list}, {"test/second"}
        )

    def test_injected_path_cannot_change_the_approved_executable(self) -> None:
        self.manifest = replace(
            self.manifest, secrets={"PATH": SecretSpec("test/first")}
        )
        environment = self.launch()
        self.assertEqual(environment["PATH"], "synthetic-private-value")
        self.assertEqual(self.execute.call_args.args[0], "/tools/runner")
        self.which.assert_called_once_with("runner")

    def test_process_supplied_names_are_outside_the_keychain_request(self) -> None:
        with access_request(
            self.manifest,
            "launch",
            environment={"FIRST_SECRET": "synthetic-process"},
        ):
            with self.assertRaisesRegex(core.KeyenvError, "outside"):
                core.keychain_lookup(self.manifest, "test/first")
        self.assert_no_keychain_access()

    def test_approval_is_required_again_for_each_operation(self) -> None:
        self.launch()
        self.read.side_effect = None
        self.read.return_value = None
        self.approval.return_value = "deny"
        self.read.reset_mock()
        self.execute.reset_mock()
        self.assertEqual(cli.main(["run", "--", "runner"]), 1)
        self.assert_no_keychain_access()
        self.assertEqual(self.approval.call_count, 2)
        self.execute.assert_not_called()

    def test_keychain_denial_stops_without_retry_or_backend_detail_output(self) -> None:
        self.read.side_effect = KeyringError("synthetic-private-backend-detail")
        self.assertEqual(cli.main(["run", "--", "runner"]), 1)
        self.assertEqual(self.read.call_count, 1)
        self.execute.assert_not_called()
        self.assertNotIn("synthetic-private-backend-detail", self.error.getvalue())

    def test_default_doctor_never_initializes_or_reads_keychain(self) -> None:
        self.assertEqual(cli.main(["doctor"]), 0)
        self.assert_no_keychain_access()
        self.native.assert_not_called()
        self.approval.assert_not_called()
        self.assertIn("keychain-unchecked\tFIRST_SECRET", self.output.getvalue())
        self.assertEqual(self.error.getvalue(), "")

    def test_doctor_verify_requires_approval_and_reads_credentials(self) -> None:
        self.assertEqual(cli.main(["doctor", "--verify"]), 0)
        self.approval.assert_called_once_with()
        self.assertIn("verify credentials request", self.error.getvalue())
        self.assertIn("keychain\tFIRST_SECRET", self.output.getvalue())

    def test_doctor_verify_refuses_noninteractive_access(self) -> None:
        with patch.object(sys.stdin, "isatty", return_value=False):
            self.assertEqual(cli.main(["doctor", "--verify"]), 1)
        self.assert_no_keychain_access()

    def test_authorize_confirmation_happens_before_binding_lookup(self) -> None:
        self.approval.return_value = "FIRST_SECRET"
        self.assertEqual(cli.main(["authorize", "FIRST_SECRET"]), 0)
        self.read.assert_called_once_with(core.BINDING_KEYCHAIN_SERVICE, "test/first")
        self.assertIn("authorize project request", self.error.getvalue())
        self.assertNotIn("SECOND_SECRET", self.error.getvalue())

    def test_set_denial_prevents_binding_access_and_hidden_credential_prompt(
        self,
    ) -> None:
        self.approval.return_value = "deny"
        with patch("keyenv.core.getpass.getpass") as hidden_prompt:
            self.assertEqual(cli.main(["set", "FIRST_SECRET"]), 1)
        self.assert_no_keychain_access()
        hidden_prompt.assert_not_called()

    def test_set_approves_one_name_before_prompting_and_verifying(self) -> None:
        with patch(
            "keyenv.core.getpass.getpass", return_value="synthetic-private-value"
        ) as hidden_prompt:
            self.assertEqual(cli.main(["set", "FIRST_SECRET"]), 0)
        self.assertEqual(hidden_prompt.call_count, 2)
        self.write.assert_called_once_with(
            core.KEYCHAIN_SERVICE, "test/first", "synthetic-private-value"
        )
        self.assertNotIn("SECOND_SECRET", self.error.getvalue())
        self.assertNotIn("synthetic-private-value", self.error.getvalue())
        self.assertIn("stored\tFIRST_SECRET", self.output.getvalue())

    def test_migration_denial_prevents_every_read_write_and_delete(self) -> None:
        self.approval.return_value = "deny"
        self.assertEqual(cli.main(["migrate", "--delete-legacy"]), 1)
        self.assert_no_keychain_access()
        self.assertIn("delete verified legacy credentials", self.error.getvalue())

    def test_scope_rejects_unapproved_accounts_and_mutations(self) -> None:
        with access_request(self.manifest, "verify"):
            for service, account, action in (
                (core.KEYCHAIN_SERVICE, "outside/account", "read"),
                ("outside.service", "test/first", "read"),
                (core.KEYCHAIN_SERVICE, "test/first", "delete"),
                (core.KEYCHAIN_SERVICE, "test/first", "write"),
            ):
                observer = core.keychain_observer.get()
                assert observer is not None
                with self.assertRaisesRegex(core.KeyenvError, "outside"):
                    observer(action, service, account)
        self.assert_no_keychain_access()
        self.assertIsNone(core.keychain_observer.get())

    def test_context_escapes_terminal_controls_in_paths(self) -> None:
        manifest = Manifest(
            Path("/project-\x1b[31m/.keyenv.toml"), self.manifest.secrets
        )
        with access_request(manifest, "launch", executable="/tools/runner-\rmarker"):
            pass
        self.assertNotIn("\x1b", self.error.getvalue())
        self.assertNotIn("\r", self.error.getvalue())
        self.assertIn("\\x1b", self.error.getvalue())
        self.assertIn("\\r", self.error.getvalue())


class ProfileLaunchTests(AccessHarness):
    def setUp(self) -> None:
        super().setUp()
        self.manifest = replace(
            self.manifest, profiles={"dev": LaunchProfile("runner", ("FIRST_SECRET",))}
        )

    def test_profile_limits_reads_and_removes_other_inherited_declared_secrets(
        self,
    ) -> None:
        with patch.dict(os.environ, {"SECOND_SECRET": "synthetic-excluded"}):
            environment = self.launch("--profile", "dev")
        self.assertNotIn("SECOND_SECRET", environment)
        self.assertEqual(
            {call.args[1] for call in self.read.call_args_list}, {"test/first"}
        )
        self.assertNotIn("SECOND_SECRET", self.error.getvalue())
        self.assertIn("profile: 'dev'", self.error.getvalue())

    def test_profiles_cannot_be_bypassed_by_omitting_selection(self) -> None:
        self.assertEqual(cli.main(["run", "--", "runner"]), 1)
        self.assert_no_keychain_access()
        self.approval.assert_not_called()
        self.execute.assert_not_called()

    def test_unknown_profile_is_rejected_before_access(self) -> None:
        self.assertEqual(cli.main(["run", "--profile", "missing", "--", "runner"]), 1)
        self.assert_no_keychain_access()
        self.approval.assert_not_called()

    def test_profile_executable_mismatch_is_rejected_before_access(self) -> None:
        self.which.side_effect = ["/tools/other", "/tools/runner"]
        self.assertEqual(cli.main(["run", "--profile", "dev", "--", "other"]), 1)
        self.assert_no_keychain_access()
        self.approval.assert_not_called()
        self.execute.assert_not_called()

    def test_empty_profile_removes_all_declared_secrets_without_keychain_access(
        self,
    ) -> None:
        self.manifest = replace(
            self.manifest,
            profiles={**self.manifest.profiles, "empty": LaunchProfile("runner", ())},
        )
        with patch.dict(os.environ, {"FIRST_SECRET": "synthetic-excluded"}):
            environment = self.launch("--profile", "empty")
        self.assertNotIn("FIRST_SECRET", environment)
        self.assertNotIn("SECOND_SECRET", environment)
        self.assert_no_keychain_access()
        self.approval.assert_not_called()


class ExecutableTests(unittest.TestCase):
    def test_resolution_preserves_virtualenv_symlink_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "base-python"
            target.touch(mode=0o755)
            link = root / "venv-python"
            link.symlink_to(target)
            self.assertEqual(cli._resolve_executable(str(link)), str(link))

    def test_missing_and_nonexecutable_programs_fail_at_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unavailable = root / "unavailable"
            with self.assertRaisesRegex(core.KeyenvError, "not found"):
                cli._resolve_executable(str(unavailable))
            unavailable.touch(mode=0o644)
            with self.assertRaisesRegex(core.KeyenvError, "not executable"):
                cli._resolve_executable(str(unavailable))


if __name__ == "__main__":
    unittest.main()
