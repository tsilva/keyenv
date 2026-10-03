---
name: build-release
description: Build, install locally, publish, monitor, or verify keyenv-macos releases. Use when the user invokes $build-release or /build-release, requests release artifacts or local deployment, asks to cut or tag a release, or asks whether a version reached PyPI.
---

# Build Release

Read and apply the shared `$release-workflow` skill at
`${CODEX_HOME:-$HOME/.codex}/skills/release-workflow/SKILL.md` before execution.
It owns common preflight, publication safeguards, `$push` integration,
workflow monitoring, verification, and reporting. The rules below are this
project's adapter; they retain its invocation default and required gates.
If the shared skill is unavailable, stop and report the missing dependency.

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

- **Build artifacts:** dispatch Actions for the exact pushed main commit and
  download its audited artifacts. No version bump or publication occurs. Local
  changes must be committed/pushed explicitly before they can enter that build.
- **Install locally:** build and validate in Actions, download the wheel, then follow
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

## Validate and build in Actions

Normal builds and releases run only in GitHub Actions. Local preparation is
limited to metadata checks (`uv lock --check --config-file uv.toml`, source
version consistency, `git diff --check`) and Git operations. Do not run local
source gates, dependency synchronization, native Keychain tests, or `uv build`
as a normal release prerequisite.

For build-only validation, fetch the configured upstream on main and resolve
its exact full SHA. Dispatch the workflow on main:

```bash
gh workflow run release.yml --ref main -f ref=<full-pushed-main-sha>
```

This runs all macOS lint, formatting, type, vulnerability, unit, native Keychain,
privacy, offline build, and artifact gates. Native integration must execute and
pass with synthetic disposable entries; a skip is not validation. Publication
jobs run only for tag-push events. Monitor the exact SHA, download the
`distributions` artifact into a fresh external directory, run
`python3 scripts/check_artifacts.py <directory>`, and compare both file hashes
with the runner log. Require exactly one matching wheel and sdist.

For installation, continue in [references/local-install.md](references/local-install.md)
using that downloaded, audited wheel. An explicitly requested local source
build can follow `docs/development.md`; it is never implicit in `$build-release`.

## Commit and trigger publication

Review and stage only the intended release files, normally `pyproject.toml`,
`src/keyenv/__init__.py`, and `uv.lock`, then commit as `Release v<version>`.
If an unused pending version already exists in a clean commit, use that commit
without creating an empty release commit. Reconfirm version consistency and
that the version and tag remain unused. Fetch again and require the remote
branch still to point to the starting upstream commit; only the intended local
release commit may be ahead. Resolve any new remote commits before tagging.

Create an annotated `v<version>` tag on the metadata-checked release commit.
The tag workflow validates and builds it before publication. Follow
the shared `$push` procedure, using explicit branch and exact-tag refspecs to
the same actual destination with `git push --atomic`. The tag publishes
automatically through the checked-in workflow. Do not provision credentials,
change Actions, or attempt recovery publication without an explicit request.

## Monitor and verify

Follow shared monitoring for the `release.yml` `push` run matching both the
exact `v<version>` tag and full SHA in the actual GitHub destination.

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
