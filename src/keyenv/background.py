"""Owner-only, revocable grants for exact unattended launch commands."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .core import KeyenvError, Manifest, select_launch_manifest


def grant_path(manifest: Manifest, profile: str) -> Path:
    select_launch_manifest(manifest, profile)
    identity = hashlib.sha256(os.fsencode(manifest.root.resolve())).hexdigest()
    return (
        Path.home() / ".config" / "keyenv" / "background" / f"{identity}-{profile}.json"
    )


def launch_fingerprint(
    manifest: Manifest, profile: str, executable: str, command: list[str]
) -> str:
    """Hash arguments rather than persist them; bind reader and executable bytes."""
    selected = select_launch_manifest(manifest, profile)
    try:
        package = Path(__file__).parent
        record = {
            "root": str(manifest.root.resolve()),
            "cwd": str(Path.cwd().resolve()),
            "manifest": hashlib.sha256(manifest.path.read_bytes()).hexdigest(),
            "profile": profile,
            "secrets": {
                name: {"account": spec.account, "required": spec.required}
                for name, spec in selected.secrets.items()
            },
            "executable": executable,
            "executable_hash": hashlib.sha256(
                Path(executable).read_bytes()
            ).hexdigest(),
            "command": [executable, *command[1:]],
            "reader": os.path.abspath(sys.executable),
            "reader_hash": hashlib.sha256(
                Path(sys.executable).read_bytes()
            ).hexdigest(),
            "implementation": {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(package.glob("*.py"))
            },
        }
    except OSError as exc:
        raise KeyenvError("cannot fingerprint the background launch") from exc
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()


def _private_directory(directory: Path, *, create: bool = False) -> None:
    if create:
        directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.mkdir(exist_ok=True, mode=0o700)
    for path in (directory.parent, directory):
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise KeyenvError("background grant directories must be owner-only (0700)")


def save_grant(
    manifest: Manifest, profile: str, executable: str, command: list[str]
) -> Path:
    path = grant_path(manifest, profile)
    fingerprint = launch_fingerprint(manifest, profile, executable, command)
    try:
        _private_directory(path.parent, create=True)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".grant-")
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump({"version": 1, "fingerprint": fingerprint}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    except OSError as exc:
        raise KeyenvError("cannot save background authorization") from exc
    return path


def require_grant(
    manifest: Manifest, profile: str, executable: str, command: list[str]
) -> None:
    path = grant_path(manifest, profile)
    try:
        _private_directory(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 1024
            ):
                raise KeyenvError(
                    "background grant must be an owner-only regular file (0600)"
                )
            record = json.load(stream)
    except (OSError, ValueError) as exc:
        raise KeyenvError(
            "background authorization is unavailable; run keyenv background authorize"
        ) from exc
    expected = {
        "version": 1,
        "fingerprint": launch_fingerprint(manifest, profile, executable, command),
    }
    if record != expected:
        raise KeyenvError(
            "background authorization changed; run keyenv background authorize again"
        )


def revoke_grant(manifest: Manifest, profile: str) -> None:
    path = grant_path(manifest, profile)
    if path.parent.exists():
        _private_directory(path.parent)
    path.unlink(missing_ok=True)


@contextmanager
def without_keychain_ui() -> Iterator[None]:
    """Fail promptly instead of displaying a Keychain dialog in a background job."""
    try:
        security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        get_state = security.SecKeychainGetUserInteractionAllowed
        get_state.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
        get_state.restype = ctypes.c_int32
        set_state = security.SecKeychainSetUserInteractionAllowed
        set_state.argtypes = [ctypes.c_ubyte]
        set_state.restype = ctypes.c_int32
        previous = ctypes.c_ubyte()
        if get_state(ctypes.byref(previous)) != 0 or set_state(0) != 0:
            raise KeyenvError("cannot disable background Keychain interaction")
    except (OSError, AttributeError) as exc:
        raise KeyenvError("cannot disable background Keychain interaction") from exc
    try:
        yield
    finally:
        if set_state(previous.value) != 0:
            raise KeyenvError("cannot restore Keychain interaction")
