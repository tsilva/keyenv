# Development

Run these commands from the repository root. The explicit `uv.toml` configuration
keeps the lockfile and dependency protections independent of global uv settings.

```bash
uv sync --locked --all-groups --config-file uv.toml
uv run --locked --config-file uv.toml ruff check .
uv run --locked --config-file uv.toml ruff format --check .
uv run --locked --config-file uv.toml mypy
uv run --locked --config-file uv.toml pip-audit
uv run --locked --config-file uv.toml python -m unittest discover -s tests -v
KEYENV_INTEGRATION=1 uv run --locked --config-file uv.toml python -m unittest discover -s tests -p 'test_integration_keychain.py' -v
KEYENV_DIST_DIR="$(mktemp -d)"
UV_OFFLINE=1 uv build --config-file uv.toml --no-build-isolation --no-sources --out-dir "$KEYENV_DIST_DIR"
rm -- "$KEYENV_DIST_DIR/.gitignore"
uv run --locked --config-file uv.toml python scripts/check_artifacts.py "$KEYENV_DIST_DIR"
```

The integration test uses disposable synthetic entries in the login Keychain
and removes them afterward.
