from __future__ import annotations

import tempfile
import textwrap
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock, patch

import keyring
from keyring.errors import KeyringError

import keyenv.core as core
from keyenv.core import (
    KEYCHAIN_SERVICE,
    LEGACY_KEYCHAIN_SERVICE,
    KeyenvError,
    Manifest,
    StoredCredential,
    find_manifest,
    find_plaintext_assignments,
    inspect_sources,
    keychain_lookup,
    keychain_set_interactive,
    load_manifest,
    migrate_manifest,
    require_native_keychain,
    resolve_environment,
)


def write_manifest(root: Path, body: str | None = None) -> Path:
    path = root / ".keyenv.toml"
    path.write_text(
        body
        or textwrap.dedent(
            """
            [keyenv]
            version = 1

            [secrets.OPENROUTER_API_KEY]
            account = "sample/OPENROUTER_API_KEY"
            required = true
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def stored_lookup(source: str) -> Callable[[str], StoredCredential]:
    def lookup(_account: str) -> StoredCredential:
        return StoredCredential("stored-value", source)

    return lookup


class PlatformTests(unittest.TestCase):
    def test_rejects_non_macos_platform(self) -> None:
        with patch("sys.platform", "linux"):
            with self.assertRaisesRegex(KeyenvError, "requires macOS"):
                require_native_keychain()

    def test_rejects_non_native_backend(self) -> None:
        class OtherBackend:
            pass

        with patch("sys.platform", "darwin"):
            with patch.object(keyring, "get_keyring", return_value=OtherBackend()):
                with self.assertRaisesRegex(KeyenvError, "native macOS"):
                    require_native_keychain()


class ManifestTests(unittest.TestCase):
    def test_finds_nearest_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = write_manifest(root)
            nested = root / "one" / "two"
            nested.mkdir(parents=True)
            self.assertEqual(find_manifest(nested), manifest_path.resolve())

    def test_rejects_public_secret_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = write_manifest(
                Path(temporary),
                """
                [keyenv]
                version = 1
                [secrets.NEXT_PUBLIC_SECRET]
                account = "sample/public"
                """,
            )
            with self.assertRaisesRegex(KeyenvError, "cannot be declared secret"):
                load_manifest(path)

    def test_rejects_duplicate_accounts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = write_manifest(
                Path(temporary),
                """
                [keyenv]
                version = 1
                [secrets.FIRST_SECRET]
                account = "sample/shared"
                [secrets.SECOND_SECRET]
                account = "sample/shared"
                """,
            )
            with self.assertRaisesRegex(KeyenvError, "duplicate Keychain account"):
                load_manifest(path)

    def test_rejects_unknown_manifest_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = write_manifest(
                Path(temporary),
                """
                [keyenv]
                version = 1
                label = "unexpected"
                [secrets.MY_SECRET]
                account = "sample/secret"
                """,
            )
            with self.assertRaisesRegex(KeyenvError, "only version"):
                load_manifest(path)


class PlaintextTests(unittest.TestCase):
    def test_detects_declared_secret_and_oidc_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = load_manifest(write_manifest(root))
            (root / ".env.local").write_text(
                "OPENROUTER_API_KEY=private\nVERCEL_OIDC_TOKEN=temporary\n",
                encoding="utf-8",
            )
            issues = find_plaintext_assignments(manifest)
            self.assertEqual(
                [(issue.name, issue.path.name) for issue in issues],
                [
                    ("OPENROUTER_API_KEY", ".env.local"),
                    ("VERCEL_OIDC_TOKEN", ".env.local"),
                ],
            )

    def test_ignores_examples_public_config_and_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = load_manifest(write_manifest(root))
            (root / ".env").write_text(
                "OPENROUTER_API_KEY=<set-with-keyenv>\n"
                "NEXT_PUBLIC_URL=https://example.test\n",
                encoding="utf-8",
            )
            (root / ".env.example").write_text(
                "OPENROUTER_API_KEY=example-value\n", encoding="utf-8"
            )
            self.assertEqual(find_plaintext_assignments(manifest), [])


class ResolutionTests(unittest.TestCase):
    def test_process_environment_wins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = load_manifest(write_manifest(Path(temporary)))
            environment, sources = resolve_environment(
                manifest,
                {"OPENROUTER_API_KEY": "from-process"},
                lookup=lambda _: StoredCredential("from-keychain", "keychain"),
            )
            self.assertEqual(environment["OPENROUTER_API_KEY"], "from-process")
            self.assertEqual(sources["OPENROUTER_API_KEY"], "process")

    def test_new_and_legacy_sources_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = load_manifest(write_manifest(Path(temporary)))
            for source in ("keychain", "legacy-keychain"):
                with self.subTest(source=source):
                    environment, sources = resolve_environment(
                        manifest,
                        {},
                        lookup=stored_lookup(source),
                    )
                    self.assertEqual(environment["OPENROUTER_API_KEY"], "stored-value")
                    self.assertEqual(sources["OPENROUTER_API_KEY"], source)

    def test_required_missing_value_fails_without_value_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = load_manifest(write_manifest(Path(temporary)))
            with self.assertRaisesRegex(KeyenvError, "OPENROUTER_API_KEY") as raised:
                resolve_environment(manifest, {}, lookup=lambda _: None)
            self.assertNotIn("stored-value", str(raised.exception))

    def test_doctor_reports_match_mismatch_and_legacy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = load_manifest(write_manifest(Path(temporary)))
            matching, healthy = inspect_sources(
                manifest,
                {"OPENROUTER_API_KEY": "same"},
                lookup=lambda _: StoredCredential("same", "legacy-keychain"),
            )
            self.assertTrue(healthy)
            self.assertEqual(matching["OPENROUTER_API_KEY"], "matching")

            mismatch, healthy = inspect_sources(
                manifest,
                {"OPENROUTER_API_KEY": "one"},
                lookup=lambda _: StoredCredential("two", "keychain"),
            )
            self.assertFalse(healthy)
            self.assertEqual(mismatch["OPENROUTER_API_KEY"], "mismatch")

            legacy, healthy = inspect_sources(
                manifest,
                {},
                lookup=lambda _: StoredCredential("same", "legacy-keychain"),
            )
            self.assertTrue(healthy)
            self.assertEqual(legacy["OPENROUTER_API_KEY"], "legacy-keychain")


class KeychainTests(unittest.TestCase):
    def test_lookup_prefers_current_then_falls_back_to_legacy(self) -> None:
        values = {
            (KEYCHAIN_SERVICE, "current"): "new-value",
            (LEGACY_KEYCHAIN_SERVICE, "current"): "old-value",
            (LEGACY_KEYCHAIN_SERVICE, "legacy"): "old-value",
        }
        with patch.object(
            core,
            "_read_password",
            side_effect=lambda service, account: values.get((service, account)),
        ):
            self.assertEqual(
                keychain_lookup("current"), StoredCredential("new-value", "keychain")
            )
            self.assertEqual(
                keychain_lookup("legacy"),
                StoredCredential("old-value", "legacy-keychain"),
            )

    def test_read_failure_is_not_reported_as_missing(self) -> None:
        with patch.object(
            keyring, "get_password", side_effect=KeyringError("backend detail")
        ):
            with self.assertRaisesRegex(KeyenvError, "Keychain read failed") as raised:
                core._read_password(KEYCHAIN_SERVICE, "sample/account")
            self.assertNotIn("backend detail", str(raised.exception))

    @patch("keyenv.core._read_password", return_value="long-value")
    @patch("keyenv.core._write_password")
    @patch("keyenv.core.getpass.getpass", side_effect=["long-value", "long-value"])
    def test_interactive_set_writes_and_verifies_current_service(
        self,
        getpass: MagicMock,
        write_password: MagicMock,
        read_password: MagicMock,
    ) -> None:
        keychain_set_interactive("sample/OPENROUTER_API_KEY")
        self.assertEqual(getpass.call_count, 2)
        write_password.assert_called_once_with(
            KEYCHAIN_SERVICE, "sample/OPENROUTER_API_KEY", "long-value"
        )
        read_password.assert_called_once_with(
            KEYCHAIN_SERVICE, "sample/OPENROUTER_API_KEY"
        )

    @patch("keyenv.core._write_password")
    @patch("keyenv.core.getpass.getpass", side_effect=["one", "two"])
    def test_interactive_set_rejects_mismatch(
        self, _getpass: MagicMock, write_password: MagicMock
    ) -> None:
        with self.assertRaisesRegex(KeyenvError, "did not match"):
            keychain_set_interactive("sample/OPENROUTER_API_KEY")
        write_password.assert_not_called()


class MigrationTests(unittest.TestCase):
    def _manifest(self, root: Path, *, required: bool = True) -> Manifest:
        return load_manifest(
            write_manifest(
                root,
                textwrap.dedent(
                    f"""
                    [keyenv]
                    version = 1
                    [secrets.MY_SECRET]
                    account = "sample/MY_SECRET"
                    required = {str(required).lower()}
                    """
                ),
            )
        )

    def test_copies_and_verifies_without_deleting_legacy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self._manifest(Path(temporary))
            store = {(LEGACY_KEYCHAIN_SERVICE, "sample/MY_SECRET"): "secret-value"}

            def read(service: str, account: str) -> str | None:
                return store.get((service, account))

            def write(service: str, account: str, value: str) -> None:
                store[(service, account)] = value

            with patch.object(core, "_read_password", side_effect=read):
                with patch.object(core, "_write_password", side_effect=write):
                    with patch.object(core, "_delete_password") as delete:
                        statuses, healthy = migrate_manifest(manifest)

            self.assertTrue(healthy)
            self.assertEqual(statuses, {"MY_SECRET": "copied"})
            self.assertEqual(
                store[(KEYCHAIN_SERVICE, "sample/MY_SECRET")], "secret-value"
            )
            delete.assert_not_called()

    def test_conflict_leaves_both_entries_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self._manifest(Path(temporary))
            store = {
                (KEYCHAIN_SERVICE, "sample/MY_SECRET"): "new-value",
                (LEGACY_KEYCHAIN_SERVICE, "sample/MY_SECRET"): "old-value",
            }
            with patch.object(
                core,
                "_read_password",
                side_effect=lambda service, account: store.get((service, account)),
            ):
                with patch.object(core, "_write_password") as write:
                    with patch.object(core, "_delete_password") as delete:
                        statuses, healthy = migrate_manifest(
                            manifest, delete_legacy=True
                        )

            self.assertFalse(healthy)
            self.assertEqual(statuses, {"MY_SECRET": "conflict"})
            write.assert_not_called()
            delete.assert_not_called()

    def test_explicit_cleanup_deletes_only_verified_legacy_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self._manifest(Path(temporary))
            store = {
                (KEYCHAIN_SERVICE, "sample/MY_SECRET"): "same-value",
                (LEGACY_KEYCHAIN_SERVICE, "sample/MY_SECRET"): "same-value",
            }
            with patch.object(
                core,
                "_read_password",
                side_effect=lambda service, account: store.get((service, account)),
            ):
                with patch.object(core, "_delete_password") as delete:
                    statuses, healthy = migrate_manifest(manifest, delete_legacy=True)

            self.assertTrue(healthy)
            self.assertEqual(statuses, {"MY_SECRET": "deleted-legacy"})
            delete.assert_called_once_with(LEGACY_KEYCHAIN_SERVICE, "sample/MY_SECRET")

    def test_required_missing_blocks_cleanup_but_optional_missing_is_healthy(
        self,
    ) -> None:
        for required, expected_healthy in ((True, False), (False, True)):
            with self.subTest(required=required):
                with tempfile.TemporaryDirectory() as temporary:
                    manifest = self._manifest(Path(temporary), required=required)
                    with patch.object(core, "_read_password", return_value=None):
                        statuses, healthy = migrate_manifest(manifest)
                    self.assertEqual(statuses, {"MY_SECRET": "missing"})
                    self.assertEqual(healthy, expected_healthy)


if __name__ == "__main__":
    unittest.main()
