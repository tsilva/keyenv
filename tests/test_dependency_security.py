from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class DependencySecurityTests(unittest.TestCase):
    def test_cryptography_is_at_the_patched_floor(self) -> None:
        lock = tomllib.loads((REPOSITORY_ROOT / "uv.lock").read_text("utf-8"))
        cryptography = next(
            package for package in lock["package"] if package["name"] == "cryptography"
        )
        version = tuple(int(part) for part in cryptography["version"].split(".")[:3])
        self.assertGreaterEqual(version, (50, 0, 0))

    def test_lock_uses_only_the_public_python_registry(self) -> None:
        lock = tomllib.loads((REPOSITORY_ROOT / "uv.lock").read_text("utf-8"))
        for package in lock["package"]:
            source = package.get("source", {})
            self.assertNotIn("git", source, package["name"])
            self.assertNotIn("url", source, package["name"])
            self.assertNotIn("path", source, package["name"])
            if registry := source.get("registry"):
                self.assertEqual(registry, "https://pypi.org/simple")
