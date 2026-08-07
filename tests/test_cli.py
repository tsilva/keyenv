from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import keyenv.cli as cli
from keyenv.core import Manifest, SecretSpec


def sample_manifest(root: Path) -> Manifest:
    return Manifest(
        path=Path.cwd().resolve() / ".keyenv.toml",
        secrets={"MY_SECRET": SecretSpec(account="sample/MY_SECRET", required=True)},
    )


class CliTests(unittest.TestCase):
    def test_version_is_available_without_an_operational_command(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                cli.main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue(), "keyenv 0.1.0\n")

    def test_doctor_prints_names_and_sources_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = sample_manifest(Path(temporary))
            output = io.StringIO()
            with patch.object(cli, "require_native_keychain"):
                with patch.object(cli, "_load", return_value=manifest):
                    with patch.object(cli, "_plaintext_failure", return_value=False):
                        with patch.object(
                            cli,
                            "inspect_sources",
                            return_value=({"MY_SECRET": "legacy-keychain"}, True),
                        ):
                            with redirect_stdout(output):
                                code = cli.main(["doctor"])
            self.assertEqual(code, 0)
            self.assertEqual(output.getvalue(), "legacy-keychain\tMY_SECRET\n")

    def test_migrate_reports_status_and_propagates_health(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = sample_manifest(Path(temporary))
            output = io.StringIO()
            with patch.object(cli, "require_native_keychain"):
                with patch.object(cli, "_load", return_value=manifest):
                    with patch.object(
                        cli,
                        "migrate_manifest",
                        return_value=({"MY_SECRET": "conflict"}, False),
                    ) as migrate:
                        with redirect_stdout(output):
                            code = cli.main(["migrate", "--delete-legacy"])
            self.assertEqual(code, 1)
            self.assertEqual(output.getvalue(), "conflict\tMY_SECRET\n")
            migrate.assert_called_once_with(manifest, delete_legacy=True)

    def test_set_requires_a_tty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = sample_manifest(Path(temporary))
            error = io.StringIO()
            with patch.object(cli, "require_native_keychain"):
                with patch.object(cli, "_load", return_value=manifest):
                    with patch("keyenv.cli.sys.stdin.isatty", return_value=False):
                        with redirect_stderr(error):
                            code = cli.main(["set", "MY_SECRET"])
            self.assertEqual(code, 1)
            self.assertIn("requires an interactive terminal", error.getvalue())

    def test_undeclared_name_error_escapes_terminal_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = sample_manifest(Path(temporary))
            error = io.StringIO()
            with patch.object(cli, "require_native_keychain"):
                with patch.object(cli, "_load", return_value=manifest):
                    with redirect_stderr(error):
                        code = cli.main(["set", "MISSING-\x1b[31m"])

            self.assertEqual(code, 1)
            self.assertNotIn("\x1b", error.getvalue())
            self.assertIn("\\x1b", error.getvalue())

    def test_authorize_requires_exact_interactive_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = sample_manifest(Path(temporary))
            output = io.StringIO()
            with patch.object(cli, "require_native_keychain"):
                with patch.object(cli, "_load", return_value=manifest):
                    with patch.object(cli, "binding_state", return_value="missing"):
                        with patch.object(
                            cli,
                            "authorize_manifest_account",
                            return_value="authorized",
                        ) as authorize:
                            with patch(
                                "keyenv.cli.sys.stdin.isatty", return_value=True
                            ):
                                with patch("builtins.input", return_value="MY_SECRET"):
                                    with redirect_stdout(output):
                                        code = cli.main(["authorize", "MY_SECRET"])
            self.assertEqual(code, 0)
            self.assertIn("authorized\tMY_SECRET", output.getvalue())
            self.assertNotIn("credential:", output.getvalue())
            authorize.assert_called_once_with(
                manifest, "sample/MY_SECRET", rebind=False
            )

    def test_authorize_rejects_wrong_confirmation_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = sample_manifest(Path(temporary))
            error = io.StringIO()
            with patch.object(cli, "require_native_keychain"):
                with patch.object(cli, "_load", return_value=manifest):
                    with patch.object(cli, "binding_state", return_value="missing"):
                        with patch.object(
                            cli, "authorize_manifest_account"
                        ) as authorize:
                            with patch(
                                "keyenv.cli.sys.stdin.isatty", return_value=True
                            ):
                                with patch("builtins.input", return_value="WRONG"):
                                    with redirect_stdout(io.StringIO()):
                                        with redirect_stderr(error):
                                            code = cli.main(["authorize", "MY_SECRET"])
            self.assertEqual(code, 1)
            self.assertIn("did not match", error.getvalue())
            authorize.assert_not_called()

    def test_run_injects_environment_without_printing_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = sample_manifest(Path(temporary))
            environment = {"PATH": "/usr/bin", "MY_SECRET": "not-for-output"}
            output = io.StringIO()
            error = io.StringIO()
            with patch.object(cli, "require_native_keychain"):
                with patch.object(cli, "_load", return_value=manifest):
                    with patch.object(cli, "_plaintext_failure", return_value=False):
                        with patch.object(
                            cli,
                            "resolve_environment",
                            return_value=(environment, {"MY_SECRET": "keychain"}),
                        ):
                            with patch(
                                "os.execvpe",
                                side_effect=RuntimeError("process replaced"),
                            ) as execvpe:
                                with redirect_stdout(output), redirect_stderr(error):
                                    with self.assertRaisesRegex(
                                        RuntimeError, "process replaced"
                                    ):
                                        cli.main(["run", "--", "tool", "arg"])
            execvpe.assert_called_once_with("tool", ["tool", "arg"], environment)
            self.assertNotIn("not-for-output", output.getvalue())
            self.assertNotIn("not-for-output", error.getvalue())

    def test_run_refuses_plaintext_before_resolving_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = sample_manifest(Path(temporary))
            error = io.StringIO()
            with patch.object(cli, "require_native_keychain"):
                with patch.object(cli, "_load", return_value=manifest):
                    with patch.object(cli, "_plaintext_failure", return_value=True):
                        with patch.object(cli, "resolve_environment") as resolve:
                            with redirect_stderr(error):
                                code = cli.main(["run", "--", "tool"])
            self.assertEqual(code, 1)
            self.assertIn("refusing to launch", error.getvalue())
            resolve.assert_not_called()

    def test_run_reports_missing_and_non_executable_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = sample_manifest(Path(temporary))
            for failure, message in (
                (FileNotFoundError(), "command not found"),
                (PermissionError(), "not executable"),
            ):
                with self.subTest(message=message):
                    error = io.StringIO()
                    with patch.object(cli, "require_native_keychain"):
                        with patch.object(cli, "_load", return_value=manifest):
                            with patch.object(
                                cli, "_plaintext_failure", return_value=False
                            ):
                                with patch.object(
                                    cli,
                                    "resolve_environment",
                                    return_value=({}, {}),
                                ):
                                    with patch("os.execvpe", side_effect=failure):
                                        with redirect_stderr(error):
                                            code = cli.main(
                                                ["run", "--", "missing-tool"]
                                            )
                    self.assertEqual(code, 1)
                    self.assertIn(message, error.getvalue())

    def test_run_escapes_terminal_controls_in_command_errors(self) -> None:
        for control, escaped in (
            ("\x1b", "\\x1b"),
            ("\n", "\\n"),
            ("\r", "\\r"),
            ("\t", "\\t"),
        ):
            with self.subTest(control=repr(control)):
                with tempfile.TemporaryDirectory() as temporary:
                    manifest = sample_manifest(Path(temporary))
                    command = f"missing-{control}marker-tool"
                    error = io.StringIO()
                    with patch.object(cli, "require_native_keychain"):
                        with patch.object(cli, "_load", return_value=manifest):
                            with patch.object(
                                cli, "_plaintext_failure", return_value=False
                            ):
                                with patch.object(
                                    cli, "resolve_environment", return_value=({}, {})
                                ):
                                    with patch(
                                        "os.execvpe", side_effect=FileNotFoundError()
                                    ):
                                        with redirect_stderr(error):
                                            code = cli.main(["run", "--", command])

                    message = error.getvalue().removesuffix("\n")
                    self.assertEqual(code, 1)
                    self.assertNotIn(control, message)
                    self.assertIn(escaped, message)

    def test_run_requires_child_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = sample_manifest(Path(temporary))
            error = io.StringIO()
            with patch.object(cli, "require_native_keychain"):
                with patch.object(cli, "_load", return_value=manifest):
                    with patch.object(cli, "_plaintext_failure", return_value=False):
                        with redirect_stderr(error):
                            code = cli.main(["run"])
            self.assertEqual(code, 1)
            self.assertIn("requires a command", error.getvalue())

    def test_run_rejects_manifest_outside_working_tree_before_resolution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Manifest(
                path=Path(temporary).resolve() / ".keyenv.toml",
                secrets={
                    "MY_SECRET": SecretSpec(account="sample/MY_SECRET", required=True)
                },
            )
            error = io.StringIO()
            with patch.object(cli, "require_native_keychain"):
                with patch.object(cli, "_load", return_value=manifest):
                    with patch.object(cli, "resolve_environment") as resolve:
                        with redirect_stderr(error):
                            code = cli.main(["run", "--", "tool"])
            self.assertEqual(code, 1)
            self.assertIn("inside the manifest project root", error.getvalue())
            resolve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
