from __future__ import annotations

import os
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass

from .core import (
    BINDING_KEYCHAIN_SERVICE,
    KEYCHAIN_SERVICE,
    LEGACY_KEYCHAIN_SERVICE,
    KeyenvError,
    Manifest,
    _safe_text,
    keychain_observer,
)


@dataclass
class _AccessRequest:
    manifest: Manifest
    operation: str
    confirmation: str
    actions: frozenset[str]
    accounts: frozenset[str]
    approved: bool = False

    def approve(self) -> None:
        if not self.approved:
            if not sys.stdin.isatty() or not sys.stderr.isatty():
                raise KeyenvError(
                    "Keychain access requires approval in an interactive terminal; "
                    "rerun there, or supply the selected secrets through the process "
                    "environment for CI/background runs"
                )
            print(
                f"Type {self.confirmation} to approve this {self.operation} once: ",
                end="",
                file=sys.stderr,
                flush=True,
            )
            try:
                answer = input()
            except (EOFError, KeyboardInterrupt) as exc:
                raise KeyenvError("Keychain approval cancelled") from exc
            if answer != self.confirmation:
                raise KeyenvError("Keychain approval confirmation did not match")
            self.approved = True

    def before_access(self, action: str, service: str, account: str) -> None:
        names = [
            name
            for name, spec in self.manifest.secrets.items()
            if spec.account == account
        ]
        services = {
            BINDING_KEYCHAIN_SERVICE: "project authorization",
            KEYCHAIN_SERVICE: "credential",
            LEGACY_KEYCHAIN_SERVICE: "legacy credential",
        }
        if (
            account not in self.accounts
            or not names
            or service not in services
            or action not in self.actions
        ):
            raise KeyenvError("Keychain access is outside the approved request")
        self.approve()
        print(
            f"keyenv [{os.getpid()}]: {action} {services[service]} "
            f"for {', '.join(names)} (account {_safe_text(account)})",
            file=sys.stderr,
            flush=True,
        )


@contextmanager
def access_request(
    manifest: Manifest,
    operation: str,
    *,
    executable: str | None = None,
    profile: str | None = None,
    environment: Mapping[str, str] | None = None,
    confirmation: str = "allow",
    actions: frozenset[str] = frozenset({"read"}),
    needs_keychain: bool = True,
) -> Iterator[None]:
    """Show context and gate the first Keychain call, including binding reads."""
    print(f"keyenv [{os.getpid()}]: {operation} request", file=sys.stderr)
    print(f"  project: {_safe_text(manifest.root)}", file=sys.stderr)
    print(f"  manifest: {_safe_text(manifest.path)}", file=sys.stderr)
    print(f"  Keychain caller: Python {_safe_text(sys.executable)}", file=sys.stderr)
    if executable is not None:
        print(f"  executable: {_safe_text(executable)}", file=sys.stderr)
        print(
            "  The program and its descendants can read the injected secrets.",
            file=sys.stderr,
        )
    if profile is not None:
        print(f"  profile: {_safe_text(profile)}", file=sys.stderr)
    for name, spec in manifest.secrets.items():
        source = (
            "process environment; no Keychain read"
            if environment is not None and environment.get(name)
            else "Keychain access"
        )
        print(
            f"  {name}: {source} (account {_safe_text(spec.account)})",
            file=sys.stderr,
        )
    if not manifest.secrets:
        print("  No declared secrets selected.", file=sys.stderr)
    sys.stderr.flush()
    accounts = frozenset(
        spec.account
        for name, spec in manifest.secrets.items()
        if environment is None or not environment.get(name)
    )
    request = _AccessRequest(manifest, operation, confirmation, actions, accounts)
    if needs_keychain:
        request.approve()
    token = keychain_observer.set(request.before_access)
    try:
        yield
    finally:
        keychain_observer.reset(token)
