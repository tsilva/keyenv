from __future__ import annotations

import re
import sys
import tarfile
import zipfile
from collections.abc import Iterable
from pathlib import Path

TOKEN_PATTERN = re.compile(
    rb"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
    rb"sk-[A-Za-z0-9_-]{20,}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----)"
)
PERSONAL_PATH_PATTERN = re.compile(rb"/Users/[A-Za-z0-9._-]+/")
WHEEL_NAME_PATTERN = re.compile(r"keyenv_macos-.*\.whl")
SDIST_NAME_PATTERN = re.compile(r"keyenv_macos-.*\.tar\.gz")
BANNED_CONTENT = (
    b'"excludedProjects"',
    b'"pending-revocation"',
    b'"sourceRoot"',
)
BANNED_NAMES = (
    "/.env",
    "build_migration_inventory.py",
    "migration/ledger.json",
)


def inspect_members(members: Iterable[tuple[str, bytes]]) -> None:
    for name, content in members:
        if any(banned in name for banned in BANNED_NAMES):
            raise SystemExit(f"private artifact member found: {name}")
        if any(marker in content for marker in BANNED_CONTENT):
            raise SystemExit(f"private content found in artifact member: {name}")
        if PERSONAL_PATH_PATTERN.search(content):
            raise SystemExit(f"personal absolute path found in artifact member: {name}")
        if TOKEN_PATTERN.search(content):
            raise SystemExit(
                f"credential-like content found in artifact member: {name}"
            )


def wheel_members(path: Path) -> list[tuple[str, bytes]]:
    with zipfile.ZipFile(path) as archive:
        return [(name, archive.read(name)) for name in archive.namelist()]


def sdist_members(path: Path) -> list[tuple[str, bytes]]:
    members: list[tuple[str, bytes]] = []
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is not None:
                members.append((member.name, extracted.read()))
    return members


def distribution_paths(dist: Path) -> tuple[Path, Path]:
    try:
        entries = sorted(dist.iterdir())
    except OSError as exc:
        raise SystemExit("cannot inspect distribution directory") from exc

    wheels = [path for path in entries if WHEEL_NAME_PATTERN.fullmatch(path.name)]
    sdists = [path for path in entries if SDIST_NAME_PATTERN.fullmatch(path.name)]
    expected = set(wheels + sdists)
    if (
        len(entries) != 2
        or len(wheels) != 1
        or len(sdists) != 1
        or set(entries) != expected
        or any(path.is_symlink() or not path.is_file() for path in entries)
    ):
        raise SystemExit("unexpected distribution artifact set")
    return wheels[0], sdists[0]


def main(dist: Path = Path("dist")) -> int:
    wheel_path, sdist_path = distribution_paths(dist)

    wheel = wheel_members(wheel_path)
    sdist = sdist_members(sdist_path)
    inspect_members(wheel)
    inspect_members(sdist)

    wheel_content = dict(wheel)
    metadata_name = next(
        (name for name in wheel_content if name.endswith(".dist-info/METADATA")), None
    )
    entry_points_name = next(
        (
            name
            for name in wheel_content
            if name.endswith(".dist-info/entry_points.txt")
        ),
        None,
    )
    if (
        metadata_name is None
        or b"Name: keyenv-macos\n" not in wheel_content[metadata_name]
    ):
        raise SystemExit("wheel metadata does not identify keyenv-macos")
    if (
        entry_points_name is None
        or b"keyenv = keyenv.cli:main\n" not in wheel_content[entry_points_name]
    ):
        raise SystemExit("wheel does not expose the keyenv console command")

    print("artifact privacy and metadata checks passed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 2:
        raise SystemExit("usage: check_artifacts.py [DIST_DIRECTORY]")
    distribution_directory = Path(sys.argv[1]) if len(sys.argv) == 2 else Path("dist")
    raise SystemExit(main(distribution_directory))
