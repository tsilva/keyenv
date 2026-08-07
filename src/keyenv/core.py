from __future__ import annotations

import getpass
import hashlib
import hmac
import os
import re
import stat
import sys
import tomllib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

import keyring
from keyring.errors import KeyringError

KEYCHAIN_SERVICE = "io.github.tsilva.keyenv.v1"
LEGACY_KEYCHAIN_SERVICE = "dev.tsilva.keyenv.v1"
BINDING_KEYCHAIN_SERVICE = "io.github.tsilva.keyenv.bindings.v1"
MACOS_KEYRING_MODULE = "keyring.backends.macOS"
ENV_NAME_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")
PUBLIC_PREFIXES = (
    "EXPO_PUBLIC_",
    "GATSBY_",
    "NEXT_PUBLIC_",
    "NUXT_PUBLIC_",
    "PUBLIC_",
    "REACT_APP_",
    "VITE_",
    "VUE_APP_",
)
RESERVED_PLAINTEXT_NAMES = frozenset({"VERCEL_OIDC_TOKEN"})
EXCLUDED_SCAN_DIRECTORIES = frozenset(
    {
        ".git",
        ".venv",
        "__pycache__",
        "node_modules",
        "venv",
    }
)
PLACEHOLDER_PATTERN = re.compile(r"(?:<set-with-keyenv>|\$\{[A-Za-z_][A-Za-z0-9_]*\})")
BINDING_RECORD_PATTERN = re.compile(r"v1:[0-9a-f]{64}")
BINDING_HASH_DOMAIN = b"keyenv-project-root-binding-v1\0"


class KeyenvError(RuntimeError):
    """A safe, user-facing keyenv failure."""


@dataclass(frozen=True)
class SecretSpec:
    account: str
    required: bool = True


@dataclass(frozen=True)
class Manifest:
    path: Path
    secrets: Mapping[str, SecretSpec]
    public_prefixes: tuple[str, ...] = PUBLIC_PREFIXES

    @property
    def root(self) -> Path:
        return self.path.parent


@dataclass(frozen=True)
class PlaintextAssignment:
    path: Path
    name: str


@dataclass(frozen=True)
class StoredCredential:
    value: str
    source: str


CredentialLookup = Callable[[str], StoredCredential | None]


def _safe_text(value: str | os.PathLike[str]) -> str:
    return ascii(os.fspath(value))


def _resolve_manifest_path(path: Path) -> Path:
    candidate = path.expanduser()
    try:
        if candidate.is_symlink():
            raise KeyenvError(
                f"manifest must not be a symbolic link: {_safe_text(candidate)}"
            )
        resolved = candidate.resolve()
        if not resolved.is_file():
            raise KeyenvError(f"manifest does not exist: {_safe_text(resolved)}")
    except OSError as exc:
        raise KeyenvError(
            f"cannot safely inspect manifest: {_safe_text(candidate)}"
        ) from exc
    return resolved


def require_native_keychain() -> None:
    """Refuse operational use outside the native macOS Keychain backend."""
    if sys.platform != "darwin":
        raise KeyenvError("keyenv requires macOS")
    try:
        backend = keyring.get_keyring()
    except KeyringError as exc:
        raise KeyenvError("cannot initialize the macOS Keychain backend") from exc
    if type(backend).__module__ != MACOS_KEYRING_MODULE:
        raise KeyenvError("keyenv requires the native macOS Keychain backend")


def find_manifest(start: Path, explicit: Path | None = None) -> Path:
    if explicit is not None:
        return _resolve_manifest_path(explicit)

    current = start.expanduser().resolve()
    if current.is_file():
        current = current.parent
    while True:
        candidate = current / ".keyenv.toml"
        if candidate.is_file():
            return _resolve_manifest_path(candidate)
        if (current / ".git").exists() or current.parent == current:
            break
        current = current.parent
    raise KeyenvError("no .keyenv.toml found from the current directory")


def load_manifest(path: Path) -> Manifest:
    resolved = _resolve_manifest_path(path)
    try:
        document = tomllib.loads(resolved.read_text(encoding="utf-8"))
    except OSError as exc:
        raise KeyenvError(f"cannot read manifest {_safe_text(resolved)}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise KeyenvError(f"invalid TOML in {_safe_text(resolved)}") from exc

    if set(document) != {"keyenv", "secrets"}:
        raise KeyenvError("manifest must contain only [keyenv] and [secrets.*] tables")

    metadata = document.get("keyenv")
    if not isinstance(metadata, dict) or not set(metadata).issubset(
        {"version", "public_prefixes"}
    ):
        raise KeyenvError("[keyenv] accepts only version and public_prefixes fields")
    if metadata.get("version") != 1:
        raise KeyenvError("unsupported manifest version; expected version = 1")

    raw_public_prefixes = metadata.get("public_prefixes", [])
    if not isinstance(raw_public_prefixes, list):
        raise KeyenvError("[keyenv].public_prefixes must be an array of strings")
    public_prefixes = list(PUBLIC_PREFIXES)
    seen_prefixes = set(public_prefixes)
    for prefix in raw_public_prefixes:
        if (
            not isinstance(prefix, str)
            or ENV_NAME_PATTERN.fullmatch(prefix) is None
            or not prefix.endswith("_")
        ):
            raise KeyenvError(
                "[keyenv].public_prefixes entries must be uppercase prefixes "
                "ending in _"
            )
        if prefix in seen_prefixes:
            raise KeyenvError(f"duplicate public environment prefix: {prefix}")
        seen_prefixes.add(prefix)
        public_prefixes.append(prefix)
    effective_public_prefixes = tuple(public_prefixes)

    raw_secrets = document.get("secrets")
    if not isinstance(raw_secrets, dict) or not raw_secrets:
        raise KeyenvError("manifest must declare at least one [secrets.ENV_NAME] table")

    secrets: dict[str, SecretSpec] = {}
    accounts: set[str] = set()
    for raw_name, raw_spec in raw_secrets.items():
        name = str(raw_name)
        if ENV_NAME_PATTERN.fullmatch(name) is None:
            raise KeyenvError(
                f"invalid environment name in manifest: {_safe_text(name)}"
            )
        if name.startswith(effective_public_prefixes):
            raise KeyenvError(
                f"public environment name cannot be declared secret: {name}"
            )
        if not isinstance(raw_spec, dict) or not set(raw_spec).issubset(
            {"account", "required"}
        ):
            raise KeyenvError(
                f"[secrets.{name}] accepts only account and required fields"
            )
        account = raw_spec.get("account")
        required = raw_spec.get("required", True)
        if (
            not isinstance(account, str)
            or not account
            or account != account.strip()
            or not account.isprintable()
        ):
            raise KeyenvError(
                f"[secrets.{name}].account must be a trimmed printable string"
            )
        if not isinstance(required, bool):
            raise KeyenvError(f"[secrets.{name}].required must be true or false")
        if account in accounts:
            raise KeyenvError(f"duplicate Keychain account in manifest: {account}")
        accounts.add(account)
        secrets[name] = SecretSpec(account=account, required=required)

    return Manifest(
        path=resolved,
        secrets=secrets,
        public_prefixes=effective_public_prefixes,
    )


def _read_password(service: str, account: str) -> str | None:
    try:
        value = keyring.get_password(service, account)
    except KeyringError as exc:
        raise KeyenvError(f"Keychain read failed for account {account}") from exc
    if not value:
        return None
    if service != BINDING_KEYCHAIN_SERVICE and ("\x00" in value or "\n" in value):
        raise KeyenvError(f"invalid credential stored for account {account}")
    return value


def _write_password(service: str, account: str, value: str) -> None:
    try:
        keyring.set_password(service, account, value)
    except KeyringError as exc:
        raise KeyenvError(f"Keychain write failed for account {account}") from exc


def _delete_password(service: str, account: str) -> None:
    try:
        keyring.delete_password(service, account)
    except KeyringError as exc:
        raise KeyenvError(f"Keychain delete failed for account {account}") from exc


def manifest_binding_record(manifest: Manifest) -> str:
    root = manifest.root.expanduser().resolve()
    digest = hashlib.sha256(BINDING_HASH_DOMAIN + os.fsencode(root)).hexdigest()
    return f"v1:{digest}"


def binding_state(manifest: Manifest, account: str) -> str:
    record = _read_password(BINDING_KEYCHAIN_SERVICE, account)
    if record is None:
        return "missing"
    if BINDING_RECORD_PATTERN.fullmatch(record) is None:
        return "malformed"
    if hmac.compare_digest(record, manifest_binding_record(manifest)):
        return "authorized"
    return "foreign"


def authorize_manifest_account(
    manifest: Manifest, account: str, *, rebind: bool = False
) -> str:
    state = binding_state(manifest, account)
    if state == "authorized":
        return "authorized"
    if state in {"foreign", "malformed"} and not rebind:
        raise KeyenvError(
            f"Keychain account {_safe_text(account)} is authorized to another "
            "project or has an invalid authorization; use --rebind to transfer it"
        )

    expected = manifest_binding_record(manifest)
    _write_password(BINDING_KEYCHAIN_SERVICE, account, expected)
    verified = _read_password(BINDING_KEYCHAIN_SERVICE, account)
    if verified is None or not hmac.compare_digest(expected, verified):
        raise KeyenvError(
            f"Keychain authorization verification failed for account "
            f"{_safe_text(account)}"
        )
    return "rebound" if state in {"foreign", "malformed"} else "authorized"


@dataclass(frozen=True)
class _AuthorizedKeychain:
    accounts: frozenset[str]

    def _require_account(self, account: str) -> None:
        if account not in self.accounts:
            raise KeyenvError(
                f"Keychain account is outside the authorized operation: "
                f"{_safe_text(account)}"
            )

    @staticmethod
    def _require_credential_service(service: str) -> None:
        if service not in {KEYCHAIN_SERVICE, LEGACY_KEYCHAIN_SERVICE}:
            raise KeyenvError("Keychain service is outside the credential boundary")

    def read(self, service: str, account: str) -> str | None:
        self._require_account(account)
        self._require_credential_service(service)
        return _read_password(service, account)

    def write(self, service: str, account: str, value: str) -> None:
        self._require_account(account)
        self._require_credential_service(service)
        _write_password(service, account, value)

    def delete(self, service: str, account: str) -> None:
        self._require_account(account)
        self._require_credential_service(service)
        _delete_password(service, account)

    def lookup(self, account: str) -> StoredCredential | None:
        current = self.read(KEYCHAIN_SERVICE, account)
        if current is not None:
            return StoredCredential(current, "keychain")
        legacy = self.read(LEGACY_KEYCHAIN_SERVICE, account)
        if legacy is not None:
            return StoredCredential(legacy, "legacy-keychain")
        return None

    def set_interactive(self, account: str) -> None:
        self._require_account(account)
        first = getpass.getpass("credential: ")
        second = getpass.getpass("retype credential: ")
        if first != second:
            raise KeyenvError("credential entries did not match")
        if not first or "\x00" in first or "\n" in first:
            raise KeyenvError("credential must be a non-empty single line")
        self.write(KEYCHAIN_SERVICE, account, first)
        stored = self.read(KEYCHAIN_SERVICE, account)
        if stored is None or not hmac.compare_digest(first, stored):
            raise KeyenvError(f"Keychain verification failed for account {account}")


def _authorized_keychain(
    manifest: Manifest, accounts: Iterable[str]
) -> _AuthorizedKeychain:
    authorized_accounts = frozenset(accounts)
    for account in authorized_accounts:
        state = binding_state(manifest, account)
        if state == "missing":
            raise KeyenvError(
                f"Keychain account {_safe_text(account)} is not authorized for this "
                "project; run keyenv authorize NAME"
            )
        if state == "malformed":
            raise KeyenvError(
                f"Keychain authorization is invalid for account "
                f"{_safe_text(account)}; run keyenv authorize --rebind NAME"
            )
        if state == "foreign":
            raise KeyenvError(
                f"Keychain account {_safe_text(account)} is authorized to another "
                "project; run keyenv authorize --rebind NAME to transfer it"
            )
    return _AuthorizedKeychain(authorized_accounts)


def keychain_lookup(manifest: Manifest, account: str) -> StoredCredential | None:
    return _authorized_keychain(manifest, [account]).lookup(account)


def keychain_set_interactive(manifest: Manifest, account: str) -> None:
    _authorized_keychain(manifest, [account]).set_interactive(account)


def migrate_manifest(
    manifest: Manifest, *, delete_legacy: bool = False
) -> tuple[dict[str, str], bool]:
    """Copy declared credentials to the current service and optionally clean up."""
    keychain = _authorized_keychain(
        manifest, (spec.account for spec in manifest.secrets.values())
    )
    statuses: dict[str, str] = {}
    deletable: list[tuple[str, str]] = []
    healthy = True

    for name, spec in manifest.secrets.items():
        current = keychain.read(KEYCHAIN_SERVICE, spec.account)
        legacy = keychain.read(LEGACY_KEYCHAIN_SERVICE, spec.account)

        if current is not None and legacy is not None:
            if hmac.compare_digest(current, legacy):
                statuses[name] = "current"
                deletable.append((name, spec.account))
            else:
                statuses[name] = "conflict"
                healthy = False
            continue

        if current is not None:
            statuses[name] = "current"
            continue

        if legacy is None:
            statuses[name] = "missing"
            healthy = healthy and not spec.required
            continue

        keychain.write(KEYCHAIN_SERVICE, spec.account, legacy)
        verified = keychain.read(KEYCHAIN_SERVICE, spec.account)
        if verified is None or not hmac.compare_digest(verified, legacy):
            raise KeyenvError(
                f"Keychain verification failed for account {spec.account}"
            )
        statuses[name] = "copied"
        deletable.append((name, spec.account))

    if delete_legacy and healthy:
        for name, account in deletable:
            keychain.delete(LEGACY_KEYCHAIN_SERVICE, account)
            statuses[name] = "deleted-legacy"

    return statuses, healthy


def _is_env_file(name: str) -> bool:
    normalized = name.casefold()
    if ".example" in normalized:
        return False
    return (
        normalized == ".env"
        or normalized.startswith(".env.")
        or normalized.endswith(".env")
    )


def _assignment(line: str) -> tuple[str, str] | None:
    candidate = line.strip()
    if not candidate or candidate.startswith("#"):
        return None
    export_match = re.match(r"export[ \t]+", candidate)
    if export_match is not None:
        candidate = candidate[export_match.end() :]
    match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", candidate)
    if match is None:
        return None
    value = match.group(2).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return match.group(1), value


def _is_populated(value: str) -> bool:
    return bool(value) and PLACEHOLDER_PATTERN.fullmatch(value) is None


def find_plaintext_assignments(manifest: Manifest) -> list[PlaintextAssignment]:
    forbidden = set(manifest.secrets) | set(RESERVED_PLAINTEXT_NAMES)
    assignments: list[PlaintextAssignment] = []
    root = manifest.root

    def display_path(path: Path) -> Path:
        try:
            return path.relative_to(root)
        except ValueError:
            return Path(path.name)

    def walk_error(exc: OSError) -> None:
        location = Path(exc.filename) if exc.filename else root
        raise KeyenvError(
            f"cannot safely inspect project directory: "
            f"{_safe_text(display_path(location))}"
        ) from exc

    def reject_unsafe_link(path: Path) -> None:
        try:
            link_status = path.lstat()
        except OSError as exc:
            raise KeyenvError(
                f"cannot safely inspect project path: {_safe_text(display_path(path))}"
            ) from exc
        if not stat.S_ISLNK(link_status.st_mode):
            return
        try:
            target_status = path.stat()
        except OSError as exc:
            raise KeyenvError(
                f"cannot safely inspect project symbolic link: "
                f"{_safe_text(display_path(path))}"
            ) from exc
        if stat.S_ISDIR(target_status.st_mode):
            raise KeyenvError(
                f"project directory must not be a symbolic link: "
                f"{_safe_text(display_path(path))}"
            )

    for directory, child_directories, filenames in os.walk(root, onerror=walk_error):
        child_directories[:] = sorted(
            name for name in child_directories if name not in EXCLUDED_SCAN_DIRECTORIES
        )
        ordered_filenames = sorted(filenames)
        current_directory = Path(directory)
        for entry_name in (*child_directories, *ordered_filenames):
            reject_unsafe_link(current_directory / entry_name)
        for filename in ordered_filenames:
            if not _is_env_file(filename):
                continue
            path = current_directory / filename
            try:
                lines = path.read_text(encoding="utf-8-sig").splitlines()
            except (OSError, UnicodeDecodeError) as exc:
                relative = path.relative_to(root)
                raise KeyenvError(
                    f"cannot safely inspect dotenv file: {_safe_text(relative)}"
                ) from exc
            for line in lines:
                parsed = _assignment(line)
                if parsed is None:
                    continue
                name, value = parsed
                if name in forbidden and _is_populated(value):
                    assignments.append(PlaintextAssignment(path=path, name=name))
    return assignments


def resolve_environment(
    manifest: Manifest,
    environment: Mapping[str, str] | None = None,
    lookup: CredentialLookup | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    result = dict(os.environ if environment is None else environment)
    credential_lookup: CredentialLookup
    if lookup is None:
        unresolved_accounts = [
            spec.account
            for name, spec in manifest.secrets.items()
            if not result.get(name)
        ]
        credential_lookup = _authorized_keychain(manifest, unresolved_accounts).lookup
    else:
        credential_lookup = lookup
    sources: dict[str, str] = {}
    missing: list[str] = []
    for name, spec in manifest.secrets.items():
        existing = result.get(name)
        if existing:
            sources[name] = "process"
            continue
        credential = credential_lookup(spec.account)
        if credential is not None:
            result[name] = credential.value
            sources[name] = credential.source
        elif spec.required:
            missing.append(name)
            sources[name] = "missing"
        else:
            sources[name] = "missing"
    if missing:
        raise KeyenvError("missing required credentials: " + ", ".join(sorted(missing)))
    return result, sources


def inspect_sources(
    manifest: Manifest,
    environment: Mapping[str, str] | None = None,
    lookup: CredentialLookup | None = None,
) -> tuple[dict[str, str], bool]:
    values = os.environ if environment is None else environment
    credential_lookup: CredentialLookup
    if lookup is None:
        credential_lookup = _authorized_keychain(
            manifest, (spec.account for spec in manifest.secrets.values())
        ).lookup
    else:
        credential_lookup = lookup
    statuses: dict[str, str] = {}
    healthy = True
    for name, spec in manifest.secrets.items():
        process_value = values.get(name) or None
        credential = credential_lookup(spec.account)
        if process_value is not None and credential is not None:
            matches = hmac.compare_digest(process_value, credential.value)
            statuses[name] = "matching" if matches else "mismatch"
            healthy = healthy and matches
        elif process_value is not None:
            statuses[name] = "process"
        elif credential is not None:
            statuses[name] = credential.source
        else:
            statuses[name] = "missing"
            healthy = healthy and not spec.required
    return statuses, healthy
