from __future__ import annotations

import os
import tempfile
import textwrap
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import keyenv.core as core
from keyenv.core import KeyenvError, Manifest, SecretSpec


def write_manifest(root: Path, body: str | None = None) -> Path:
    path = root / ".keyenv.toml"
    path.write_text(
        body
        or textwrap.dedent(
            """
            [keyenv]
            version = 1

            [secrets.MY_SECRET]
            account = "sample/MY_SECRET"
            required = true
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def manifest_at(root: Path, account: str = "sample/MY_SECRET") -> Manifest:
    return Manifest(
        path=(root / ".keyenv.toml").resolve(),
        secrets={"MY_SECRET": SecretSpec(account=account, required=True)},
    )


class BindingRegressionTests(unittest.TestCase):
    def test_foreign_project_is_rejected_before_credential_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owner = manifest_at(base / "owner")
            attacker = manifest_at(base / "attacker")
            credential_reads: list[str] = []

            def read(service: str, account: str) -> str | None:
                if service == core.BINDING_KEYCHAIN_SERVICE:
                    return core.manifest_binding_record(owner)
                credential_reads.append(service)
                return "must-not-be-read"

            with patch.object(core, "_read_password", side_effect=read):
                with self.assertRaisesRegex(KeyenvError, "another project"):
                    core.keychain_lookup(attacker, "sample/MY_SECRET")

            self.assertEqual(credential_reads, [])

    def test_malformed_binding_is_rejected_before_credential_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = manifest_at(Path(temporary))
            credential_reads: list[str] = []

            def read(service: str, _account: str) -> str | None:
                if service == core.BINDING_KEYCHAIN_SERVICE:
                    return "not-a-binding-record"
                credential_reads.append(service)
                return "must-not-be-read"

            with patch.object(core, "_read_password", side_effect=read):
                with self.assertRaisesRegex(KeyenvError, "authorization is invalid"):
                    core.keychain_lookup(manifest, "sample/MY_SECRET")
            self.assertEqual(credential_reads, [])

    def test_process_environment_needs_no_binding_or_keychain_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = manifest_at(Path(temporary))
            with patch.object(
                core, "_read_password", side_effect=AssertionError("unexpected read")
            ):
                environment, sources = core.resolve_environment(
                    manifest, {"MY_SECRET": "from-process"}
                )
            self.assertEqual(environment["MY_SECRET"], "from-process")
            self.assertEqual(sources, {"MY_SECRET": "process"})

    def test_migration_preflights_every_binding_before_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = Manifest(
                path=(root / ".keyenv.toml").resolve(),
                secrets={
                    "FIRST_SECRET": SecretSpec("sample/FIRST_SECRET"),
                    "SECOND_SECRET": SecretSpec("sample/SECOND_SECRET"),
                },
            )
            credential_reads: list[tuple[str, str]] = []

            def read(service: str, account: str) -> str | None:
                if service == core.BINDING_KEYCHAIN_SERVICE:
                    if account == "sample/FIRST_SECRET":
                        return core.manifest_binding_record(manifest)
                    return None
                credential_reads.append((service, account))
                return "must-not-be-read"

            with patch.object(core, "_read_password", side_effect=read):
                with self.assertRaisesRegex(KeyenvError, "not authorized"):
                    core.migrate_manifest(manifest)

            self.assertEqual(credential_reads, [])

    def test_authorize_rebinds_only_with_explicit_flag_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = manifest_at(Path(temporary))
            store = {
                (core.BINDING_KEYCHAIN_SERVICE, "sample/MY_SECRET"): "v1:" + "0" * 64
            }

            def read(service: str, account: str) -> str | None:
                return store.get((service, account))

            def write(service: str, account: str, value: str) -> None:
                store[(service, account)] = value

            with patch.object(core, "_read_password", side_effect=read):
                with patch.object(core, "_write_password", side_effect=write) as writer:
                    with self.assertRaisesRegex(KeyenvError, "--rebind"):
                        core.authorize_manifest_account(
                            manifest, "sample/MY_SECRET", rebind=False
                        )
                    self.assertEqual(
                        core.authorize_manifest_account(
                            manifest, "sample/MY_SECRET", rebind=True
                        ),
                        "rebound",
                    )

            writer.assert_called_once_with(
                core.BINDING_KEYCHAIN_SERVICE,
                "sample/MY_SECRET",
                core.manifest_binding_record(manifest),
            )

    def test_binding_identity_canonicalizes_directory_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            real_root = base / "real"
            real_root.mkdir()
            alias = base / "alias"
            alias.symlink_to(real_root, target_is_directory=True)
            real_manifest = manifest_at(real_root)
            alias_manifest = Manifest(
                path=alias / ".keyenv.toml",
                secrets=real_manifest.secrets,
            )
            self.assertEqual(
                core.manifest_binding_record(alias_manifest),
                core.manifest_binding_record(real_manifest),
            )


class ManifestBoundaryTests(unittest.TestCase):
    def test_rejects_symlinked_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.toml"
            target.write_text(
                "[keyenv]\nversion = 1\n[secrets.MY_SECRET]\n"
                'account = "sample/MY_SECRET"\n',
                encoding="utf-8",
            )
            link = root / ".keyenv.toml"
            link.symlink_to(target)
            with self.assertRaisesRegex(KeyenvError, "symbolic link"):
                core.load_manifest(link)

    def test_rejects_new_default_public_prefixes(self) -> None:
        for prefix in ("REACT_APP_", "GATSBY_", "VUE_APP_", "NUXT_PUBLIC_"):
            with self.subTest(prefix=prefix):
                with tempfile.TemporaryDirectory() as temporary:
                    path = write_manifest(
                        Path(temporary),
                        "[keyenv]\nversion = 1\n"
                        f"[secrets.{prefix}TOKEN]\n"
                        'account = "sample/public"\n',
                    )
                    with self.assertRaisesRegex(KeyenvError, "public environment"):
                        core.load_manifest(path)

    def test_custom_public_prefix_is_additive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = write_manifest(
                Path(temporary),
                "[keyenv]\nversion = 1\n"
                'public_prefixes = ["CLIENT_VISIBLE_"]\n'
                "[secrets.CLIENT_VISIBLE_TOKEN]\n"
                'account = "sample/public"\n',
            )
            with self.assertRaisesRegex(KeyenvError, "public environment"):
                core.load_manifest(path)

    def test_custom_prefixes_cannot_remove_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = write_manifest(
                Path(temporary),
                "[keyenv]\nversion = 1\n"
                'public_prefixes = ["CLIENT_VISIBLE_"]\n'
                "[secrets.NEXT_PUBLIC_TOKEN]\n"
                'account = "sample/public"\n',
            )
            with self.assertRaisesRegex(KeyenvError, "public environment"):
                core.load_manifest(path)

    def test_rejects_invalid_or_duplicate_custom_prefixes(self) -> None:
        for declaration in (
            'public_prefixes = ["client_visible_"]',
            'public_prefixes = ["NEXT_PUBLIC_"]',
            'public_prefixes = ["CLIENT_VISIBLE_", "CLIENT_VISIBLE_"]',
        ):
            with self.subTest(declaration=declaration):
                with tempfile.TemporaryDirectory() as temporary:
                    path = write_manifest(
                        Path(temporary),
                        "[keyenv]\nversion = 1\n"
                        f"{declaration}\n"
                        "[secrets.MY_SECRET]\n"
                        'account = "sample/secret"\n',
                    )
                    with self.assertRaises(KeyenvError):
                        core.load_manifest(path)

    def test_rejects_unprintable_or_padded_account(self) -> None:
        for account in (" padded", "padded ", "bad\taccount", "bad\raccount"):
            with self.subTest(account=repr(account)):
                with tempfile.TemporaryDirectory() as temporary:
                    path = write_manifest(
                        Path(temporary),
                        "[keyenv]\nversion = 1\n[secrets.MY_SECRET]\n"
                        f"account = {account!r}\n".replace("'", '"'),
                    )
                    with self.assertRaises(KeyenvError):
                        core.load_manifest(path)


class DotenvRegressionTests(unittest.TestCase):
    def test_scans_project_output_directories(self) -> None:
        for directory_name in (
            ".next",
            "build",
            "dist",
            "galleries",
            "runs",
            "vendor",
        ):
            with self.subTest(directory=directory_name):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    manifest = core.load_manifest(write_manifest(root))
                    output_directory = root / directory_name
                    output_directory.mkdir()
                    (output_directory / ".env").write_text(
                        "MY_SECRET=synthetic-value\n", encoding="utf-8"
                    )

                    issues = core.find_plaintext_assignments(manifest)

                    self.assertEqual(
                        [(issue.name, issue.path.parent.name) for issue in issues],
                        [("MY_SECRET", directory_name)],
                    )

    def test_ignores_documented_metadata_and_dependency_trees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = core.load_manifest(write_manifest(root))
            for directory_name in (
                ".git",
                ".venv",
                "__pycache__",
                "node_modules",
                "venv",
            ):
                directory = root / directory_name
                directory.mkdir()
                (directory / ".env").write_text(
                    "MY_SECRET=synthetic-value\n", encoding="utf-8"
                )

            self.assertEqual(core.find_plaintext_assignments(manifest), [])

    def test_rejects_directory_symlinks_in_scanned_project_trees(self) -> None:
        for target_location in ("inside", "outside"):
            with self.subTest(target=target_location):
                with tempfile.TemporaryDirectory() as temporary:
                    base = Path(temporary)
                    root = base / "project"
                    root.mkdir()
                    manifest = core.load_manifest(write_manifest(root))
                    target = (
                        root / "linked-config"
                        if target_location == "inside"
                        else base / "linked-config"
                    )
                    target.mkdir()
                    (target / ".env").write_text(
                        "MY_SECRET=synthetic-value\n", encoding="utf-8"
                    )
                    (root / "config").symlink_to(target, target_is_directory=True)

                    with self.assertRaisesRegex(KeyenvError, "symbolic link") as raised:
                        core.find_plaintext_assignments(manifest)

                    self.assertNotIn("synthetic-value", str(raised.exception))

    def test_rejects_cyclic_directory_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = core.load_manifest(write_manifest(root))
            (root / "cycle").symlink_to(root, target_is_directory=True)

            with self.assertRaisesRegex(KeyenvError, "symbolic link"):
                core.find_plaintext_assignments(manifest)

    def test_scans_dotenv_file_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "project"
            root.mkdir()
            manifest = core.load_manifest(write_manifest(root))
            target = base / "shared.env"
            target.write_text("MY_SECRET=synthetic-value\n", encoding="utf-8")
            (root / ".env").symlink_to(target)

            issues = core.find_plaintext_assignments(manifest)

            self.assertEqual([issue.name for issue in issues], ["MY_SECRET"])

    def test_broken_symlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = core.load_manifest(write_manifest(root))
            (root / "config").symlink_to(root / "missing", target_is_directory=True)

            with self.assertRaisesRegex(KeyenvError, "cannot safely inspect"):
                core.find_plaintext_assignments(manifest)

    def test_case_variant_dotenv_names_are_scanned(self) -> None:
        for filename in (".ENV", ".Env.Local", "service.ENV"):
            with self.subTest(filename=filename):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    manifest = core.load_manifest(write_manifest(root))
                    (root / filename).write_text(
                        "MY_SECRET=synthetic-value\n", encoding="utf-8"
                    )

                    issues = core.find_plaintext_assignments(manifest)

                    self.assertEqual([issue.name for issue in issues], ["MY_SECRET"])

    def test_manifest_parse_error_escapes_terminal_controls(self) -> None:
        for control, escaped in (
            ("\x1b", "\\x1b"),
            ("\n", "\\n"),
            ("\r", "\\r"),
            ("\t", "\\t"),
        ):
            with self.subTest(control=repr(control)):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary) / f"project-{control}marker"
                    root.mkdir()
                    path = root / ".keyenv.toml"
                    path.write_text("not valid TOML = [\n", encoding="utf-8")

                    with self.assertRaises(KeyenvError) as raised:
                        core.load_manifest(path)

                    message = str(raised.exception)
                    self.assertNotIn(control, message)
                    self.assertIn(escaped, message)

    def test_invalid_manifest_name_escapes_terminal_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = write_manifest(
                root,
                '[keyenv]\nversion = 1\n[secrets."BAD\\u001bNAME"]\n'
                'account = "sample/secret"\n',
            )

            with self.assertRaises(KeyenvError) as raised:
                core.load_manifest(path)

            message = str(raised.exception)
            self.assertNotIn("\x1b", message)
            self.assertIn("\\x1b", message)

    def test_bom_and_export_tab_assignments_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = core.load_manifest(write_manifest(root))
            (root / ".env").write_text(
                "\ufeffexport\tMY_SECRET=private\n", encoding="utf-8"
            )
            issues = core.find_plaintext_assignments(manifest)
            self.assertEqual([issue.name for issue in issues], ["MY_SECRET"])

    def test_invalid_utf8_fails_closed_without_file_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = core.load_manifest(write_manifest(root))
            (root / ".env").write_bytes(b"MY_SECRET=private\xff\n")
            with self.assertRaisesRegex(KeyenvError, "cannot safely inspect") as raised:
                core.find_plaintext_assignments(manifest)
            self.assertNotIn("private", str(raised.exception))

    def test_read_failure_fails_closed_without_backend_details(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = core.load_manifest(write_manifest(root))
            (root / ".env").write_text("MY_SECRET=private\n", encoding="utf-8")
            original_read_text = Path.read_text

            def read_text(
                path: Path,
                encoding: str | None = None,
                errors: str | None = None,
            ) -> str:
                if path.name == ".env":
                    raise PermissionError("backend-private-detail")
                return original_read_text(path, encoding=encoding, errors=errors)

            with patch.object(Path, "read_text", autospec=True, side_effect=read_text):
                with self.assertRaisesRegex(
                    KeyenvError, "cannot safely inspect"
                ) as raised:
                    core.find_plaintext_assignments(manifest)
            self.assertNotIn("backend-private-detail", str(raised.exception))
            self.assertNotIn("private", str(raised.exception))

    def test_directory_walk_failure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = core.load_manifest(write_manifest(root))

            def walk(
                _root: Path, *, onerror: Callable[[OSError], None]
            ) -> list[tuple[str, list[str], list[str]]]:
                error = PermissionError("backend-private-detail")
                error.filename = os.fspath(root / "blocked")
                onerror(error)
                return []

            with patch("keyenv.core.os.walk", side_effect=walk):
                with self.assertRaisesRegex(
                    KeyenvError, "cannot safely inspect"
                ) as raised:
                    core.find_plaintext_assignments(manifest)
            self.assertNotIn("backend-private-detail", str(raised.exception))

    def test_only_structural_placeholders_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = core.load_manifest(write_manifest(root))
            for value, populated in (
                ("<set-with-keyenv>", False),
                ("${MY_SECRET}", False),
                ("changeme-real-value", True),
                ("<actual-secret>", True),
                ("${not-valid-shell-name}", True),
            ):
                with self.subTest(value=value):
                    (root / ".env").write_text(f"MY_SECRET={value}\n", encoding="utf-8")
                    self.assertEqual(
                        bool(core.find_plaintext_assignments(manifest)), populated
                    )


if __name__ == "__main__":
    unittest.main()
