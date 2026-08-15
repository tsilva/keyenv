from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
ACTION_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
USES_PATTERN = re.compile(r"^\s*-\s+uses:\s*[\"']?([^\"'#\s]+)")
UV_VERSION = "0.11.13"
ARTIFACT_CHECKER = ROOT / "scripts" / "check_artifacts.py"


def workflow_paths() -> list[Path]:
    return sorted((*WORKFLOW_ROOT.glob("*.yml"), *WORKFLOW_ROOT.glob("*.yaml")))


class WorkflowSecurityTests(unittest.TestCase):
    def test_artifact_checker_rejects_every_extra_dist_entry(self) -> None:
        for extra_kind in ("regular", "case-variant", "directory", "symlink"):
            with self.subTest(extra_kind=extra_kind):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    dist = root / "dist"
                    dist.mkdir()
                    if extra_kind == "case-variant":
                        (dist / "KeyEnv_Macos-0.1.0-py3-none-any.whl").write_bytes(b"")
                    else:
                        (dist / "keyenv_macos-0.1.0-py3-none-any.whl").write_bytes(b"")
                    (dist / "keyenv_macos-0.1.0.tar.gz").write_bytes(b"")
                    if extra_kind == "regular":
                        (dist / "extra.txt").write_bytes(b"")
                    elif extra_kind == "directory":
                        (dist / "extra").mkdir()
                    elif extra_kind == "symlink":
                        (dist / "extra").symlink_to(dist / "missing")

                    result = subprocess.run(
                        [sys.executable, str(ARTIFACT_CHECKER)],
                        cwd=root,
                        capture_output=True,
                        text=True,
                        check=False,
                    )

                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(
                        result.stderr.strip(), "unexpected distribution artifact set"
                    )

    def test_release_transports_and_rechecks_only_expected_artifacts(self) -> None:
        release = (WORKFLOW_ROOT / "release.yml").read_text(encoding="utf-8")
        self.assertNotRegex(release, r"(?m)^\s+path:\s+dist/\s*$")
        self.assertIn("keyenv_macos-*.whl", release)
        self.assertIn("keyenv_macos-*.tar.gz", release)
        self.assertIn("Verify downloaded distributions", release)
        self.assertGreaterEqual(release.count("scripts/check_artifacts.py"), 2)

    def test_repository_content_scans_do_not_print_matches(self) -> None:
        seen = 0
        quiet_option = re.compile(r"(?:^|\s)(?:--quiet|-[A-Za-z]*q[A-Za-z]*)(?=\s)")
        for path in workflow_paths():
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "git grep" not in line:
                    continue
                seen += 1
                arguments = line.split("git grep", maxsplit=1)[1]
                self.assertRegex(
                    arguments,
                    quiet_option,
                    f"printing git grep at {path}:{line_number}",
                )
        self.assertGreater(seen, 0)

    def test_external_actions_are_immutable(self) -> None:
        seen = 0
        for path in workflow_paths():
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                match = USES_PATTERN.match(line)
                if match is None:
                    continue
                seen += 1
                action = match.group(1)
                if action.startswith("./"):
                    continue
                if action.startswith("docker://"):
                    self.assertRegex(
                        action,
                        r"@sha256:[0-9a-f]{64}$",
                        f"mutable Docker action at {path}:{line_number}",
                    )
                    continue
                _target, separator, revision = action.rpartition("@")
                self.assertEqual(
                    separator,
                    "@",
                    f"action without revision at {path}:{line_number}",
                )
                self.assertIsNotNone(
                    ACTION_SHA_PATTERN.fullmatch(revision),
                    f"mutable action revision at {path}:{line_number}",
                )
        self.assertGreater(seen, 0)

    def test_setup_uv_steps_pin_the_uv_binary(self) -> None:
        seen = 0
        for path in workflow_paths():
            lines = path.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                match = USES_PATTERN.match(line)
                if match is None or not match.group(1).startswith(
                    "astral-sh/setup-uv@"
                ):
                    continue
                seen += 1
                indentation = len(line) - len(line.lstrip())
                block: list[str] = []
                for following in lines[index + 1 :]:
                    following_indent = len(following) - len(following.lstrip())
                    if following.lstrip().startswith("-") and (
                        following_indent == indentation
                    ):
                        break
                    block.append(following)
                self.assertRegex(
                    "\n".join(block),
                    rf"(?m)^\s+version:\s*[\"']{re.escape(UV_VERSION)}[\"']\s*$",
                    f"setup-uv does not pin uv {UV_VERSION} in {path}",
                )
        self.assertGreater(seen, 0)

    def test_builds_are_offline_and_use_the_locked_environment(self) -> None:
        expected = re.compile(
            r"- run: uv build --config-file uv\.toml --no-build-isolation --no-sources "
            r'--out-dir "\$\{KEYENV_DIST_DIR\}"\n'
            r"\s+env:\n"
            r'\s+UV_OFFLINE: "1"'
        )
        for path in workflow_paths():
            text = path.read_text(encoding="utf-8")
            if "uv build" in text:
                self.assertRegex(text, expected, f"unlocked build in {path}")
                self.assertIn("--config-file uv.toml", text)
                self.assertIn("Create isolated distribution directory", text)
                self.assertIn('rm -- "${KEYENV_DIST_DIR}/.gitignore"', text)
                self.assertIn('scripts/check_artifacts.py "${KEYENV_DIST_DIR}"', text)


if __name__ == "__main__":
    unittest.main()
