# Usage details

## Approving access

Before accessing Keychain, operational commands display the project root,
manifest, operation, and selected secret names and accounts on stderr. Launches
also show the executable path that will be invoked. Values and command arguments
are never displayed. Type `allow` to approve that operation once; `authorize`
requires the exact secret name instead. Any other answer, end of input, or
interruption cancels before Keychain access. There is no persistent approval
or automatic bypass option.

Each subsequent Keychain call announces its action, secret name, account, and
whether it accesses a project binding, credential, or legacy credential. These
messages are flushed before the call and share a process ID with the request
summary, so they provide context for the following macOS prompt. Reads of project
bindings are gated too. Approving in Keyenv does not approve the separate macOS
dialog; denying that dialog aborts the operation.

The macOS requester is still the Python interpreter used to run Keyenv. Its path
is included in the summary. These terminal messages do not authenticate an
unrelated system dialog or identify another application's prompts. A dedicated
signed native requester is not included in the Python distribution. Keyenv does
not change existing Keychain access-control lists or grant Python permanent
access.

Keychain operations require both stdin and stderr to be attached to a terminal,
so approval context cannot be silently redirected. Background/CI launches can
provide all selected values through the process environment and run without
Keychain access or approval. Partial injection still requires an interactive
approval for the remaining names.

`doctor` checks the manifest and plaintext dotenv assignments without initializing
Keychain. It reports `process` or `keychain-unchecked`; a successful check does
not establish that stored credentials exist or that project bindings are valid.
Use `doctor --verify` for the previous source/mismatch checks, with approval.

## Launch profiles

Optional profiles restrict the executable and the declared secrets available to
a launch:

```toml
[profiles.dev]
executable = "pnpm"
secrets = ["OPENROUTER_API_KEY"]

[profiles.tests]
executable = "python"
secrets = []
```

```bash
keyenv run --profile dev -- pnpm dev
keyenv run --profile tests -- python -m unittest
```

When a manifest defines profiles, `run` requires an explicit `--profile`.
The command must resolve to the same executable path as the profile before any
Keychain access. Names outside the profile are not read from Keychain and are
removed from the inherited environment, even if the parent already supplies
them. Other environment variables remain available. Without profiles, existing
manifests continue to select all declared secrets. The plaintext scan always
covers every declared secret, including those outside the selected profile.

Profiles constrain the immediate executable and selected names. They do not
verify scripts, arguments, package scripts, or descendants, and do not sandbox
the program. Review the actual command you launch. The program and its
descendants can read the selected secrets. Executable paths are fixed before
injection, but files at those paths can still be replaced by the same user.

## Notes

- Credentials resolve from a non-empty process environment value, the current
  Keychain service, the legacy Keychain service, and finally missing state, in
  that order. Existing environment values therefore keep CI and provider-native
  injection working.
- Keychain accounts have one authorized project-root owner. Projects that need
  the same underlying value should use distinct account names. Authorization
  stores only a path digest in Keychain and never reads the credential value.
  If a project moves, transfer its accounts with `keyenv authorize --rebind NAME`.
  A `run` command
  whose declared values all come from the process environment performs no
  Keychain authorization or credential reads for those values.
- `keyenv run` must start inside the manifest project root, and manifest files
  may not be symbolic links.
- The native macOS Keychain backend is required. Configuring another `keyring`
  backend causes operational commands to fail safely.
- `keyenv run` refuses to launch while a declared credential or
  `VERCEL_OIDC_TOKEN` has a populated assignment in a project dotenv file.
- Dotenv filenames are matched case-insensitively. Scanning covers project output
  trees such as `.next`, `build`, and `dist`, while excluding only `.git`, Python
  virtual environments, `node_modules`, and `__pycache__`. Directory symlinks or
  broken links in the scanned tree cause a safe refusal. Dotenv candidates must
  resolve to regular files and may not exceed 1 MiB.
- Secret names must be uppercase shell identifiers. Built-in browser and mobile
  public prefixes include `NEXT_PUBLIC_`, `NUXT_PUBLIC_`, `VITE_`, `VUE_APP_`,
  `REACT_APP_`, `GATSBY_`, `EXPO_PUBLIC_`, and `PUBLIC_`. Manifest additions are
  additive and cannot remove these defaults.
- Migration copies and verifies legacy entries under
  `io.github.tsilva.keyenv.v1`. It retains the originals unless
  `--delete-legacy` is supplied and every required entry is safe.
- For linked Vercel projects, use
  `vercel env run -e development -- keyenv run -- COMMAND` instead of
  `vercel env pull`, which writes plaintext files.
- A launched application and its descendants can read injected values. Code
  already running as the same macOS user is outside this protection boundary.
  Report suspected vulnerabilities through [SECURITY.md](../SECURITY.md) without
  including credential values.

## Custom public prefixes

Add application-specific public prefixes to the manifest's existing `[keyenv]`
table. These extend the built-in denylist; they cannot remove its defaults:

```toml
[keyenv]
version = 1
public_prefixes = ["MY_CLIENT_PUBLIC_"]
```

## Process behavior

`keyenv run` replaces itself with the requested command, which owns its signals
and exit status. Security and operational failures exit with status `1`; invalid
command-line usage exits with status `2`.

## Other launch examples

```bash
keyenv run -- uv run python app.py
keyenv run -- uv run jupyter lab
```

These examples assume a manifest without profiles. When profiles are defined,
select a matching executable and secret set with `--profile NAME`.
