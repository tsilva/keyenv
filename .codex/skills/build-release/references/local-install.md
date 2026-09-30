# Local installation

Use only for an explicitly requested local deployment. Complete the main skill's
validation and artifact audit first. Install the audited wheel with runtime
versions constrained by the repository lock, using the same Python interpreter
as the validated project environment. Do not substitute a PyPI package merely
because its version string matches the local build.

The requested deployment of keyenv's own audited wheel is the local package
installation; it does not authorize adding local-path dependencies to the
project. Keep the constraints file separate from the two-file artifact directory.

From the repository root, in one shell session, after setting `KEYENV_DIST_DIR`
to the absolute path of the audited artifact directory:

```bash
KEYENV_INSTALL_DIR="$(mktemp -d)"
uv export --locked --config-file uv.toml --no-default-groups --no-emit-project \
  --no-hashes --no-header --no-annotate \
  --output-file "$KEYENV_INSTALL_DIR/constraints.txt"
KEYENV_INSTALL_PYTHON="$(pwd)/.venv/bin/python"
uv --no-config tool install --offline --force --no-build \
  --exclude-newer '7 days' --keyring-provider disabled \
  --python "$KEYENV_INSTALL_PYTHON" \
  --constraints "$KEYENV_INSTALL_DIR/constraints.txt" \
  "$KEYENV_DIST_DIR/keyenv_macos-<version>-py3-none-any.whl"
```

Replace `<version>` with the validated package version before running. The tool
installer uses `--no-config` because project dependency constraints can include
packages unrelated to the installed runtime. Exact exported runtime pins and the
explicit seven-day cutoff preserve the lock's protections; offline mode avoids
fetching replacement dependencies or authenticating with package indexes.
If the wheel or its pinned dependencies are unavailable, report that prerequisite
instead of relaxing the lock or silently selecting different versions.

Locate the uv tool binary directory with `uv tool dir --bin` and verify its
`keyenv --version` and `keyenv --help`. Confirm the command found through the
user's PATH resolves to that installed launcher; report a shadowed command.
Also compare the installed `keyenv` source files with the audited wheel's files
so a reused version number cannot hide installation of old code.

These checks require no Keychain access. If a visible approval demonstration is
requested, use a value-free temporary manifest and a clearly identified demo
account. The terminal approval can be exercised and denied without native
access. A real native macOS popup requires separate user-requested access and
may not appear for an existing grant; never reset permissions or touch production
credentials just to force it. Clean up any disposable demo Keychain entries.

Finish with the installed command path, version, source-match result, and
validation results. Retain useful build artifacts and do not uninstall other
tools unless the user requests cleanup.
