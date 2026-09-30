---
name: build-release
description: Build, install locally, publish, monitor, or verify keyenv-macos releases. Use when the user invokes $build-release or /build-release, requests release artifacts or local deployment, asks to cut or tag a release, or asks whether a version reached PyPI.
---

# Build Release

Prepare keyenv's Python distributions and use the repository-owned
`.github/workflows/release.yml` for publication. A pushed `v<MAJOR.MINOR.PATCH>`
tag runs macOS checks, builds one universal Python wheel and one source
distribution, publishes `keyenv-macos` through PyPI Trusted Publishing, and
creates a GitHub Release with both artifacts. The CLI is `keyenv`.

This repository has no `make release` target or `scripts/release.py` launcher.
Follow the preparation below; do not invoke commands copied from another
repository. Read the current workflow, `pyproject.toml`, `uv.toml`, and
`docs/development.md` before execution so their current configuration remains
authoritative.

## Choose the requested outcome

- **Build artifacts:** validate and build the current version without changing
  versions, committing, tagging, installing, or pushing. A dirty tree is allowed
  when the requested artifacts should include those changes; report that origin.
- **Install locally:** build and validate, then follow
  [references/local-install.md](references/local-install.md). Local installation
  does not authorize publication.
- **Cut/publish a release:** prepare a version, commit the release metadata,
  push the branch and tag using `$push`, then monitor and verify publication.
- **Monitor/verify an existing release:** inspect the exact tag, workflow run,
  PyPI version, and GitHub Release without creating a new version or tag.

Creating or editing this skill does not itself authorize a release. An explicit
request to cut or publish a release authorizes the required release commit and
tag push; do not request the same authorization again. A bare skill invocation
with no stated outcome prepares artifacts; clarify before publishing.

## Prepare a published release

1. Inspect the current branch, worktree, upstream, actual push destination, and
   remote release tags. Stay on the current branch. Fetch its upstream and tags,
   then require a clean, synchronized tree before changing release metadata.
   Report unrelated changes or divergence and stop release preparation; do not
   discard changes, commit unrelated work, switch branches, or force-push.

2. Select the version explicitly requested by the user. Otherwise reuse the
   project version only if it is untagged and absent from PyPI; if already
   released, select the next unused patch version. Use stable `MAJOR.MINOR.PATCH`
   versions supported by the workflow's tag trigger.

   Verify the proposed `v<version>` is absent both locally and remotely, and
   inspect `https://pypi.org/pypi/keyenv-macos/<version>/json`. Only an HTTP 404
   proves the PyPI version is unused. A timeout, authentication failure, or other
   HTTP error is an unresolved check, not permission to publish. Never move or
   overwrite a released tag or reuse a published PyPI version.

3. Update `[project].version` in `pyproject.toml` and `__version__` in
   `src/keyenv/__init__.py` together, then regenerate the lock mechanically:

   ```bash
   uv lock --config-file uv.toml
   ```

   Confirm both source versions and the `keyenv-macos` entry in `uv.lock` agree.
   Review the lock diff: this operation should change the root package version,
   preserving pinned dependency versions and the protections in `uv.toml`.
   Resolve unexpected dependency changes before continuing. Do not use
   `--upgrade`, weaken the seven-day cutoff, or remove security constraints.

## Validate and build

Run on macOS using the pinned uv version from `uv.toml`. Execute the commands in
`docs/development.md`: locked synchronization of all groups, Ruff lint and format
checks, mypy, pip-audit, unit tests, and the separate native Keychain integration
test. Require the native test to execute and pass rather than accepting a skip.
It uses disposable synthetic entries and cleans them up. Never use real project
credentials for build or installation smoke tests.

Build into a fresh directory outside the repository, keeping it in the same
shell session when using the variable below:

```bash
KEYENV_DIST_DIR="$(mktemp -d)"
UV_OFFLINE=1 uv build --config-file uv.toml --no-build-isolation --no-sources \
  --out-dir "$KEYENV_DIST_DIR"
rm -- "$KEYENV_DIST_DIR/.gitignore"
uv run --locked --config-file uv.toml python scripts/check_artifacts.py "$KEYENV_DIST_DIR"
```

Require exactly `keyenv_macos-<version>-py3-none-any.whl` and
`keyenv_macos-<version>.tar.gz`, with matching package versions in wheel METADATA
and sdist PKG-INFO. The existing audit checks privacy, package identity, and the
CLI entry point. Keep constraints, logs, and other files outside the distribution
directory so its exact two-file audit remains meaningful. Run Twine's README
check if README or packaging metadata changed, using existing tooling or an
ephemeral uv tool that retains the repository's dependency protections.

Before a release commit, run the workflow's repository scans in quiet mode;
report only the failed check, never matching credential text. Check formatting
with `git diff --check`. Stop at a failed gate and report its relevant error.
Do not publish partially validated artifacts or change CI to bypass a gate.

For a build-only request, finish here with the artifact paths and validation
results. For local installation, continue only in the linked installation guide.

## Commit and trigger publication

Review and stage only the intended release files, normally `pyproject.toml`,
`src/keyenv/__init__.py`, and `uv.lock`, then commit as `Release v<version>`.
If an unused pending version already exists in a clean commit, use that commit
without creating an empty release commit. Reconfirm version consistency and
that the version and tag remain unused. Fetch again and require the remote
branch still to point to the starting upstream commit; only the intended local
release commit may be ahead. Resolve any new remote commits before tagging.

Create an annotated `v<version>` tag on the validated release commit. Every push
must use the available `$push` skill, normally at
`${CODEX_HOME:-$HOME/.codex}/skills/push/SKILL.md`. Read it before pushing and
resolve the actual destination from Git configuration. Atomically push the
current branch to its intended branch ref and the exact tag to the same remote;
do not push every local tag. Use explicit refspecs and `git push --atomic`.

After a successful push, reconcile the destination repository description using
the push skill's helper and the published default-branch README. Report push and
description outcomes separately. If the push fails, retain and report local
release state for recovery; do not force-push, retag, or broaden authorization.

The pushed tag publishes automatically. Do not perform manual Twine uploads,
provision credentials, change Actions, or attempt recovery publication unless
the user explicitly requests that recovery path.

## Monitor and verify

Resolve the full release commit SHA and inspect the actual destination with
`gh --repo` arguments where applicable:

```bash
gh run list --repo OWNER/REPO --workflow release.yml --commit <full-release-sha> \
  --limit 5 --json databaseId,status,conclusion,event,headBranch,headSha,url
gh run view <run-id> --repo OWNER/REPO \
  --json url,status,conclusion,event,headBranch,headSha,jobs
```

Select the `push` run for both the exact tag and SHA. If the filtered result is
empty, inspect recent release runs and allow briefly for scheduling; do not
select an unrelated run. Poll with bounded waits and keep the user informed at
least every minute. On failure, inspect the matching failed job, report its URL
and step without exposing credentials, and stop automatic recovery.

After workflow success, query the exact-version PyPI JSON endpoint. Require both
expected, non-yanked filenames, each reporting the corresponding distribution
type (`bdist_wheel` or `sdist`). Retry missing files for up to five minutes with
20-second intervals; report verification as incomplete if visibility remains
unresolved. Do not infer publication solely from a successful push or build.

```bash
gh release view v<version> --repo OWNER/REPO --json url,tagName,isDraft,assets
```

Require a published GitHub Release for the same tag with both expected assets.
Compare its assets' SHA-256 digests with PyPI's distribution digests; if GitHub
does not expose digests, download only the two release distributions into a fresh
external directory and hash them. Report mismatched or missing files as failed
verification. Do not compare against local preflight hashes: CI rebuilds the
distributions, and source archive timestamps can differ.

## Completion

For publication, lead with `https://pypi.org/project/keyenv-macos/<version>/`.
Include the tag and commit, workflow URL and conclusion, GitHub Release URL,
both distribution filenames, and repository-description sync outcome.
For local work, report built paths or the installed executable and version.
On failure, identify the failed gate, whether any push or publication occurred,
and the next recovery action. Keep local installation, Git publication, PyPI
publication, and verified release status distinct.
