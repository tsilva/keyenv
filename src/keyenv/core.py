from __future__ import annotations

import getpass
import hmac
import os
import re
import sys
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

import keyring
from keyring.errors import KeyringError

KEYCHAIN_SERVICE = "io.github.tsilva.keyenv.v1"
LEGACY_KEYCHAIN_SERVICE = "dev.tsilva.keyenv.v1"
MACOS_KEYRING_MODULE = "keyring.backends.macOS"
ENV_NAME_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")
PUBLIC_PREFIXES = ("EXPO_PUBLIC_", "NEXT_PUBLIC_", "PUBLIC_", "VITE_")
RESERVED_PLAINTEXT_NAMES = frozenset({"VERCEL_OIDC_TOKEN"})
PRUNED_DIRECTORIES = frozenset(
    {
        ".git",
        ".next",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "galleries",
        "node_modules",
        "runs",
        "vendor",
        "venv",
    }
)
PLACEHOLDER_PATTERN = re.compile(
    r"^(?:changeme|example|replace[-_]|todo|xxx+|your[-_]|<.*>|\$\{.*\})",
    re.IGNORECASE,
)


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
        candidate = explicit.expanduser().resolve()
        if not candidate.is_file():
            raise KeyenvError(f"manifest does not exist: {candidate}")
        return candidate

    current = start.expanduser().resolve()
    if current.is_file():
        current = current.parent
    while True:
        candidate = current / ".keyenv.toml"
        if candidate.is_file():
            return candidate
        if (current / ".git").exists() or current.parent == current:
            break
        current = current.parent
    raise KeyenvError("no .keyenv.toml found from the current directory")


def load_manifest(path: Path) -> Manifest:
    resolved = path.expanduser().resolve()
    try:
        document = tomllib.loads(resolved.read_text(encoding="utf-8"))
    except OSError as exc:
        raise KeyenvError(f"cannot read manifest {resolved}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise KeyenvError(f"invalid TOML in {resolved}: {exc}") from exc

    if set(document) != {"keyenv", "secrets"}:
        raise KeyenvError("manifest must contain only [keyenv] and [secrets.*] tables")

    metadata = document.get("keyenv")
    if not isinstance(metadata, dict) or set(metadata) != {"version"}:
        raise KeyenvError("[keyenv] must contain only version = 1")
    if metadata.get("version") != 1:
        raise KeyenvError("unsupported manifest version; expected version = 1")

    raw_secrets = document.get("secrets")
    if not isinstance(raw_secrets, dict) or not raw_secrets:
        raise KeyenvError("manifest must declare at least one [secrets.ENV_NAME] table")

    secrets: dict[str, SecretSpec] = {}
    accounts: set[str] = set()
    for raw_name, raw_spec in raw_secrets.items():
        name = str(raw_name)
        if ENV_NAME_PATTERN.fullmatch(name) is None:
            raise KeyenvError(f"invalid environment name in manifest: {name}")
        if name.startswith(PUBLIC_PREFIXES):
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
            or not account.strip()
            or "\n" in account
            or "\x00" in account
        ):
            raise KeyenvError(f"[secrets.{name}].account must be a non-empty line")
        if not isinstance(required, bool):
            raise KeyenvError(f"[secrets.{name}].required must be true or false")
        if account in accounts:
            raise KeyenvError(f"duplicate Keychain account in manifest: {account}")
        accounts.add(account)
        secrets[name] = SecretSpec(account=account, required=required)

    return Manifest(path=resolved, secrets=secrets)


def _read_password(service: str, account: str) -> str | None:
    try:
        value = keyring.get_password(service, account)
    except KeyringError as exc:
        raise KeyenvError(f"Keychain read failed for account {account}") from exc
    if not value:
        return None
    if "\x00" in value or "\n" in value:
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


def keychain_lookup(account: str) -> StoredCredential | None:
    current = _read_password(KEYCHAIN_SERVICE, account)
    if current is not None:
        return StoredCredential(current, "keychain")
    legacy = _read_password(LEGACY_KEYCHAIN_SERVICE, account)
    if legacy is not None:
        return StoredCredential(legacy, "legacy-keychain")
    return None


def keychain_set_interactive(account: str) -> None:
    first = getpass.getpass("credential: ")
    second = getpass.getpass("retype credential: ")
    if first != second:
        raise KeyenvError("credential entries did not match")
    if not first or "\x00" in first or "\n" in first:
        raise KeyenvError("credential must be a non-empty single line")
    _write_password(KEYCHAIN_SERVICE, account, first)
    stored = _read_password(KEYCHAIN_SERVICE, account)
    if stored is None or not hmac.compare_digest(first, stored):
        raise KeyenvError(f"Keychain verification failed for account {account}")


def migrate_manifest(
    manifest: Manifest, *, delete_legacy: bool = False
) -> tuple[dict[str, str], bool]:
    """Copy declared credentials to the current service and optionally clean up."""
    statuses: dict[str, str] = {}
    deletable: list[tuple[str, str]] = []
    healthy = True

    for name, spec in manifest.secrets.items():
        current = _read_password(KEYCHAIN_SERVICE, spec.account)
        legacy = _read_password(LEGACY_KEYCHAIN_SERVICE, spec.account)

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

        _write_password(KEYCHAIN_SERVICE, spec.account, legacy)
        verified = _read_password(KEYCHAIN_SERVICE, spec.account)
        if verified is None or not hmac.compare_digest(verified, legacy):
            raise KeyenvError(
                f"Keychain verification failed for account {spec.account}"
            )
        statuses[name] = "copied"
        deletable.append((name, spec.account))

    if delete_legacy and healthy:
        for name, account in deletable:
            _delete_password(LEGACY_KEYCHAIN_SERVICE, account)
            statuses[name] = "deleted-legacy"

    return statuses, healthy


def _is_env_file(name: str) -> bool:
    if ".example" in name:
        return False
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def _assignment(line: str) -> tuple[str, str] | None:
    candidate = line.strip()
    if not candidate or candidate.startswith("#"):
        return None
    if candidate.startswith("export "):
        candidate = candidate[7:].lstrip()
    match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", candidate)
    if match is None:
        return None
    value = match.group(2).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return match.group(1), value


def _is_populated(value: str) -> bool:
    return bool(value) and PLACEHOLDER_PATTERN.match(value) is None


def find_plaintext_assignments(manifest: Manifest) -> list[PlaintextAssignment]:
    forbidden = set(manifest.secrets) | set(RESERVED_PLAINTEXT_NAMES)
    assignments: list[PlaintextAssignment] = []
    for directory, child_directories, filenames in os.walk(manifest.root):
        child_directories[:] = [
            name for name in child_directories if name not in PRUNED_DIRECTORIES
        ]
        for filename in filenames:
            if not _is_env_file(filename):
                continue
            path = Path(directory) / filename
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
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
    lookup: CredentialLookup = keychain_lookup,
) -> tuple[dict[str, str], dict[str, str]]:
    result = dict(os.environ if environment is None else environment)
    sources: dict[str, str] = {}
    missing: list[str] = []
    for name, spec in manifest.secrets.items():
        existing = result.get(name)
        if existing:
            sources[name] = "process"
            continue
        credential = lookup(spec.account)
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
    lookup: CredentialLookup = keychain_lookup,
) -> tuple[dict[str, str], bool]:
    values = os.environ if environment is None else environment
    statuses: dict[str, str] = {}
    healthy = True
    for name, spec in manifest.secrets.items():
        process_value = values.get(name) or None
        credential = lookup(spec.account)
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
