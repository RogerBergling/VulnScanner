# Dependency and supply-chain policy

VulnScanner uses a universal [uv](https://docs.astral.sh/uv/) lock so the same
dependency set is installed on Linux, Windows, developer machines and CI.

## Source of truth

| File | Purpose |
| --- | --- |
| `pyproject.toml` | Human-edited direct dependencies and Python requirement. |
| `uv.lock` | Universal lock for Linux/Windows and Python 3.11+. |
| `requirements.txt` | Generated runtime lock for `pip`, with SHA-256 hashes. |
| `requirements-dev.txt` | Generated runtime + test lock for `pip`, with hashes. |

`requirements.txt` and `requirements-dev.txt` are generated. Do not edit them by
hand.

## Installing

Runtime, as used by `run.sh`, `run.bat` and `scripts/update.sh`:

```bash
python -m pip install --require-hashes -r requirements.txt
```

Developer environment:

```bash
uv sync --frozen --no-install-project --group dev
.venv/bin/python -m pytest -q
.venv/bin/ruff check app tests agent
.venv/bin/bandit -q -lll -r app agent/vulnscanner_agent.py
```

`uv` 0.13 or newer is required. The lock is universal: platform-specific
packages such as `uvloop` are included with environment markers and are skipped
on Windows automatically.

## Changing dependencies

1. Edit the `dependencies` or `[dependency-groups]` section in
   `pyproject.toml`.
2. Regenerate the lock and pip exports:

   ```bash
   ./scripts/lock-dependencies.sh
   ```

3. Run the tests on the supported Python/platform matrix.
4. Run a vulnerability audit against the resulting lock.
5. Commit `pyproject.toml`, `uv.lock`, `requirements.txt` and
   `requirements-dev.txt` together.

For a targeted update:

```bash
uv lock --upgrade-package cryptography
./scripts/lock-dependencies.sh
```

For a full refresh, use `uv lock --upgrade` and review every changed package.

## CI and release gate

```bash
./scripts/check-dependencies.sh
uv sync --frozen --no-install-project --group dev
.venv/bin/python -m pytest -q
.venv/bin/ruff check app tests agent
.venv/bin/bandit -q -lll -r app agent/vulnscanner_agent.py
```

`check-dependencies.sh` verifies that `uv.lock` is current and that both
generated pip lock files match the lock. A stale generated file fails the check.

Recommended additional gates:

- `pip-audit -r requirements.txt` or an OSV scan on every pull request.
- The test suite on Ubuntu and Windows, with Python 3.11 and the newest
  supported Python.
- A scheduled dependency refresh at least monthly, and immediately when a
  security advisory affects a pinned package.

## Hash pinning and internal mirrors

The generated files use `--require-hashes`, so pip rejects a downloaded artifact
whose SHA-256 hash does not match the lock. This protects against a compromised
or accidentally changed package index.

If the enterprise uses an internal PyPI mirror, configure it through pip or
`UV_DEFAULT_INDEX` and confirm that it serves the same artifacts. For `uv sync`
behind a mirror, regenerate the lock with `uv lock --default-index <mirror>`;
mirrors that rebuild or recompress packages will not match the public hashes.

`uv.lock` records the package index used during resolution. For an air-gapped
environment, pre-populate a wheelhouse from `requirements.txt` and install with
`pip install --no-index --find-links <wheelhouse> --require-hashes -r requirements.txt`.

## Scope

This policy covers Python packages. Optional CLI tools such as Nmap, Nuclei,
testssl.sh, Trivy, Subfinder, OSV-Scanner, Gitleaks and Semgrep are installed
separately and must be tracked in the organisation's own patch-management
process. The SQLite database, certificates and the credential key are data, not
Python dependencies.
