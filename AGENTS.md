# Repository Instructions

`keyenv` moves local development credentials from plaintext dotenv files into
the macOS login Keychain and injects them only into explicitly launched child
processes.

## Security invariants

- Never print, log, snapshot, persist, or place credential values in command arguments.
- Use the native macOS Keychain backend and hidden Python prompt; never pass values to subprocesses.
- Process-environment values take precedence so CI and provider-native injection keep working.
- Reject secret manifests that use browser/mobile-public environment prefixes.
- Refuse to launch while a declared secret still has a populated plaintext dotenv assignment.
- Prefer `io.github.tsilva.keyenv.v1`, fall back to the legacy service during migration, and never delete legacy entries without an explicit flag.

## Commands

```bash
uv run --locked python -m unittest discover -s tests -v
KEYENV_INTEGRATION=1 uv run --locked python -m unittest tests.test_integration_keychain -v
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
UV_OFFLINE=1 uv build --no-build-isolation --no-sources
uv run --locked python scripts/check_artifacts.py
uv run --locked keyenv --help
```
