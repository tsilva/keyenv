<p align="center">
  <img src="https://raw.githubusercontent.com/tsilva/keyenv/main/logo.png" alt="keyenv" width="320" />
  <br />
  <!-- repo-tagline:start -->
  <strong>🔐 Keep secrets in Keychain, inject on demand 🔐</strong>
  <!-- repo-tagline:end -->
</p>

<p align="center">
  <a href="https://github.com/tsilva/keyenv/actions/workflows/ci.yml"><img src="https://github.com/tsilva/keyenv/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status" /></a>
  <a href="https://pypi.org/project/keyenv-macos/"><img src="https://badge.fury.io/py/keyenv-macos.svg" alt="PyPI version" /></a>
  <a href="https://github.com/tsilva/keyenv/blob/main/pyproject.toml"><img src="https://badgen.net/badge/python/3.11%2B/blue" alt="Python 3.11 or newer" /></a>
  <a href="https://github.com/tsilva/keyenv/blob/main/LICENSE"><img src="https://badgen.net/badge/license/MIT/blue" alt="MIT license" /></a>
</p>

`keyenv` is a macOS command-line tool for developers who want to keep development
credentials out of plaintext dotenv files. Store secrets in the login Keychain,
then use `keyenv run` to inject them into a command's environment. Before Keychain
access, it shows the project, operation, and secret names and asks for approval.

## Install

Requires macOS, Python 3.11 or newer, and `uv`. Install the current repository
version, including the approval and profile commands below:

```bash
git clone https://github.com/tsilva/keyenv.git
cd keyenv
uv tool install --force --config-file uv.toml .
keyenv --help
```

Published releases are also available with `uv tool install keyenv-macos`.
The distribution is named `keyenv-macos`; the command is `keyenv`.

## Configure

Create a value-free `.keyenv.toml` in your project's root:

```toml
[keyenv]
version = 1

[secrets.OPENROUTER_API_KEY]
account = "my-project/OPENROUTER_API_KEY"
required = true
```

From that project, authorize the account, enter its value through the hidden
prompt, and launch your application:

```bash
keyenv authorize OPENROUTER_API_KEY
keyenv set OPENROUTER_API_KEY
keyenv doctor
keyenv run -- pnpm dev
```

Commit the manifest, but keep credential values out of it and dotenv files.
Your application reads the injected values through its normal environment API.

## Approvals

Before a launch reads Keychain, you see the project, executable path, and selected
secret names. Type `allow` to approve that operation once; `authorize` requires
the exact secret name. Any other answer cancels before access. Values and command
arguments are never displayed.

Each Keychain call announces which item it is accessing before a macOS dialog
can appear. macOS may still identify the requester as Python. Terminal approval
and the macOS dialog are separate; the summary cannot authenticate another
application's popup.

`doctor` checks configuration without opening Keychain. Use `doctor --verify` to
approve reads that check stored credentials and compare their sources.

## Commands

Run these from a configured project:

```bash
keyenv run -- COMMAND [ARGS...]              # launch with declared secrets
keyenv run --profile dev -- COMMAND [ARGS...] # use a configured launch profile
keyenv doctor                               # check config; no Keychain reads
keyenv doctor --verify                      # approve credential verification
keyenv authorize NAME                       # bind an account to this project
keyenv authorize --rebind NAME              # transfer a binding after a move
keyenv set NAME                             # enter and verify a credential
keyenv migrate                              # copy legacy entries; keep originals
keyenv migrate --delete-legacy              # delete verified legacy entries
keyenv --version                            # show the installed version
```

## Notes

- Non-empty process-environment values take precedence over Keychain. CI and
  background launches work without approval when all selected values are supplied
  that way. Keychain access requires visible stdin and stderr terminals.
- Optional launch profiles restrict the executable and selected secrets. Other
  declared secrets are removed from the inherited environment. See
  [profiles and access details](https://github.com/tsilva/keyenv/blob/main/docs/usage.md).
- A Keychain account belongs to one canonical project root. Run inside that root;
  moving it requires `authorize --rebind`. Use separate accounts across projects.
- Launches refuse populated dotenv assignments for any declared secret or
  `VERCEL_OIDC_TOKEN`. Browser/mobile public environment prefixes cannot be secrets.
- The launched program and its descendants can read injected secrets. Profiles
  do not sandbox code, and arbitrary code running as the same user is outside the
  protection boundary. See the [security policy](https://github.com/tsilva/keyenv/blob/main/SECURITY.md).

For scan rules, provider injection, migration, and exit codes, see the
[usage guide](https://github.com/tsilva/keyenv/blob/main/docs/usage.md).
For tests, dependency auditing, and package checks, see
[development](https://github.com/tsilva/keyenv/blob/main/docs/development.md).

## Architecture

![keyenv storage and launch flow](https://raw.githubusercontent.com/tsilva/keyenv/main/architecture.png)

## License

[MIT](https://github.com/tsilva/keyenv/blob/main/LICENSE)

Dependency patch auto-merge requires Dependabot as both the PR author and event sender. Maintainer-prepared updates are validated and merged manually.
