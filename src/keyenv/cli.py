from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import NoReturn

from . import __version__
from .core import (
    KeyenvError,
    Manifest,
    find_manifest,
    find_plaintext_assignments,
    inspect_sources,
    keychain_set_interactive,
    load_manifest,
    migrate_manifest,
    require_native_keychain,
    resolve_environment,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keyenv",
        description="Inject macOS Keychain credentials into a child process.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    doctor = subparsers.add_parser("doctor", help="check manifest credential sources")
    doctor.add_argument("--manifest", type=Path)

    set_command = subparsers.add_parser("set", help="set one manifest credential")
    set_command.add_argument("--manifest", type=Path)
    set_command.add_argument("name")

    migrate = subparsers.add_parser(
        "migrate", help="copy legacy credentials to the current Keychain service"
    )
    migrate.add_argument("--manifest", type=Path)
    migrate.add_argument(
        "--delete-legacy",
        action="store_true",
        help="delete verified legacy entries after every declared credential is safe",
    )

    run = subparsers.add_parser(
        "run", help="launch a command with resolved credentials"
    )
    run.add_argument("--manifest", type=Path)
    run.add_argument("child_command", nargs=argparse.REMAINDER)
    return parser


def _load(explicit: Path | None) -> Manifest:
    return load_manifest(find_manifest(Path.cwd(), explicit))


def _plaintext_failure(manifest: Manifest) -> bool:
    assignments = find_plaintext_assignments(manifest)
    for assignment in assignments:
        relative = assignment.path.relative_to(manifest.root)
        print(f"plaintext\t{assignment.name}\t{relative}")
    return bool(assignments)


def _doctor(args: argparse.Namespace) -> int:
    require_native_keychain()
    manifest = _load(args.manifest)
    plaintext = _plaintext_failure(manifest)
    statuses, healthy = inspect_sources(manifest)
    for name in sorted(statuses):
        print(f"{statuses[name]}\t{name}")
    return 0 if healthy and not plaintext else 1


def _set(args: argparse.Namespace) -> int:
    require_native_keychain()
    manifest = _load(args.manifest)
    try:
        spec = manifest.secrets[args.name]
    except KeyError as exc:
        raise KeyenvError(
            f"credential is not declared in the manifest: {args.name}"
        ) from exc
    if not sys.stdin.isatty():
        raise KeyenvError("keyenv set requires an interactive terminal")
    keychain_set_interactive(spec.account)
    print(f"stored\t{args.name}")
    return 0


def _migrate(args: argparse.Namespace) -> int:
    require_native_keychain()
    manifest = _load(args.manifest)
    statuses, healthy = migrate_manifest(
        manifest, delete_legacy=bool(args.delete_legacy)
    )
    for name in sorted(statuses):
        print(f"{statuses[name]}\t{name}")
    return 0 if healthy else 1


def _run(args: argparse.Namespace) -> NoReturn:
    require_native_keychain()
    manifest = _load(args.manifest)
    if _plaintext_failure(manifest):
        raise KeyenvError("refusing to launch with plaintext credential assignments")
    child_command = list(args.child_command)
    if child_command and child_command[0] == "--":
        child_command.pop(0)
    if not child_command:
        raise KeyenvError("keyenv run requires a command after --")
    environment, _ = resolve_environment(manifest)
    try:
        os.execvpe(child_command[0], child_command, environment)
    except FileNotFoundError as exc:
        raise KeyenvError(f"command not found: {child_command[0]}") from exc
    except PermissionError as exc:
        raise KeyenvError(f"command is not executable: {child_command[0]}") from exc
    except OSError as exc:
        raise KeyenvError(f"cannot launch command: {child_command[0]}") from exc


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command_name == "doctor":
            return _doctor(args)
        if args.command_name == "set":
            return _set(args)
        if args.command_name == "migrate":
            return _migrate(args)
        if args.command_name == "run":
            _run(args)
        raise KeyenvError(f"unknown command: {args.command_name}")
    except KeyenvError as exc:
        print(f"keyenv: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
