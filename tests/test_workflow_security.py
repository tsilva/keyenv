from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
ACTION_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
USES_PATTERN = re.compile(r"^\s*-\s+uses:\s*[\"']?([^\"'#\s]+)")
UV_VERSION = "0.11.13"


def workflow_paths() -> list[Path]:
    return sorted((*WORKFLOW_ROOT.glob("*.yml"), *WORKFLOW_ROOT.glob("*.yaml")))


class WorkflowSecurityTests(unittest.TestCase):
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
            r"- run: uv build --no-build-isolation --no-sources\n"
            r"\s+env:\n"
            r'\s+UV_OFFLINE: "1"'
        )
        for path in workflow_paths():
            text = path.read_text(encoding="utf-8")
            if "uv build" in text:
                self.assertRegex(text, expected, f"unlocked build in {path}")


if __name__ == "__main__":
    unittest.main()
