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
uv sync --locked --all-groups --config-file uv.toml
uv run --locked --config-file uv.toml python -m unittest discover -s tests -v
KEYENV_INTEGRATION=1 uv run --locked --config-file uv.toml python -m unittest discover -s tests -p 'test_integration_keychain.py' -v
uv run --locked --config-file uv.toml ruff check .
uv run --locked --config-file uv.toml ruff format --check .
uv run --locked --config-file uv.toml mypy
uv run --locked --config-file uv.toml pip-audit
uv run --locked --config-file uv.toml keyenv --help
```

For isolated offline builds and artifact audits, follow `docs/development.md`.

## Release skill

Use `$build-release` at `.codex/skills/build-release/SKILL.md` for release
artifacts, local installation, publishing a new `keyenv-macos` version, or
verifying an existing release. It builds in GitHub Actions and covers macOS validation, privacy checks,
version consistency, tag-triggered GitHub Actions publication, and verification
of the exact PyPI and GitHub artifacts. A build or local installation request
does not authorize publication. Every authorized push must also use `$push`.
