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

Before launch, dotenv filenames are classified case-insensitively and scanned
throughout the project except in explicit metadata or dependency trees:
`.git`, `.venv`, `venv`, `node_modules`, and `__pycache__`. Generic output trees
such as `build`, `dist`, and `.next` are scanned. Directory symlinks and broken
links in the scanned tree fail closed; dotenv file symlinks are inspected through
their targets.
