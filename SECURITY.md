# Security policy

Report vulnerabilities through GitHub's private vulnerability reporting for
this repository. Do not open a public issue for a suspected vulnerability.

Never include credential values, dotenv contents, Keychain exports, access
tokens, or other live secrets in a report. Use synthetic values and describe
the affected command, manifest shape, expected behavior, and observed behavior.

## Supported versions

Security fixes are provided for the latest released version. `keyenv` supports
macOS with Python 3.11 or newer and requires the native macOS Keychain backend.

## Security boundary

`keyenv` protects local credential storage at rest and limits injection to an
explicitly launched process tree. The launched application and its descendants
can read injected values. Arbitrary code already running as the same macOS user
is outside this protection boundary.

Each Keychain account is authorized to one canonical project-root path. Moving
a project requires an explicit `keyenv authorize --rebind NAME`; replacing a
project's contents at the same canonical path retains that path's authorization.
Manifest files may not be symbolic links, and `keyenv run` must start within the
authorized project root.

CLI operations require a visible terminal summary and one explicit approval
before any Keychain call, including project-binding reads. Approval applies only
to the selected accounts and operation's read/write/delete actions and ends with
that operation. Denial, EOF, interruption, or a noninteractive terminal prevents
access. Supplying all selected values through the process environment permits
background launches without Keychain access. The Python APIs themselves are not
a separate security boundary against arbitrary same-user code.

The summary and per-call messages contain metadata only, are written to stderr,
and are flushed before native access. They cannot authenticate other macOS
dialogs. The Keychain caller remains Python; the package does not contain a
signed native helper and does not broaden Keychain ACLs. Do not treat an unrelated
prompt as authorized merely because a Keyenv operation is in progress.

Optional launch profiles select declared secret names and the immediate
executable. Unselected declared names are removed even from inherited environment
values. Profiles do not restrict undeclared environment variables, scripts,
arguments, or descendant behavior. The displayed executable path is executed
directly, avoiding a second PATH lookup after injection. Symlinks are retained
to preserve virtual-environment behavior; same-user modification of executables
or their targets is outside the boundary. All declared secrets remain subject
to the plaintext scan regardless of profile selection.

Default `doctor` does not initialize or access Keychain and cannot establish
credential availability or authorization. `doctor --verify` explicitly approves
the reads needed to compare sources and values.

Before launch, dotenv filenames are classified case-insensitively and scanned
throughout the project except in explicit metadata or dependency trees:
`.git`, `.venv`, `venv`, `node_modules`, and `__pycache__`. Generic output trees
such as `build`, `dist`, and `.next` are scanned. Directory symlinks and broken
links in the scanned tree fail closed; dotenv file symlinks are inspected through
their targets. Dotenv candidates must resolve to regular files and may not exceed
1 MiB.

Release distributions are built in an isolated directory. The artifact checker
requires exactly one regular `keyenv-macos` wheel and one regular source archive,
rejects every other directory entry, and rechecks both files after workflow
transport before publishing.
