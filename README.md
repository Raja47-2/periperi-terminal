# PARI PARI Terminal

Enterprise cryptographic discovery from the terminal or from VS Code.

`periperi` scans a folder, a single file or the current working directory for
cryptographic indicators, builds a **CBOM** (Cryptographic Bill of Materials),
and produces JSON, SARIF or HTML reports. It is local-first: nothing leaves
your machine unless you explicitly run `periperi sync`.

The same scanner powers the **PARI PARI Terminal** VS Code extension, so a scan
run in your editor and a scan run in CI use identical rules.

> Detected indicators are not proof of confirmed cryptographic usage. Every
> report is preliminary static analysis.

## Install

```bash
npm install -g pari-pari-terminal
```

Requires Node.js 20 or newer. Verify:

```bash
periperi --version
```

## Quick start

```bash
# Scan the current directory.
periperi scan

# Scan one file.
periperi scan --file src/auth.ts

# Scan a folder.
periperi scan ./packages/api

# Machine-readable output for CI.
periperi scan --json > scan.json
periperi scan --sarif > scan.sarif

# Fail the build when something risky is found.
periperi scan --fail-on high
```

## Commands

| Command | Purpose |
| --- | --- |
| `periperi scan [path]` | Scan a folder, or the working directory. `--file <file>` scans a single file. |
| `periperi cbom [path]` | Scan and write a CBOM to `.pari-pari/cbom/`. `--format json\|csv\|both`, `--out <dir>`. |
| `periperi export` | Re-export the most recent scan. `--format json\|csv\|both`, `--to <dir>`. |
| `periperi report` | Report on the most recent scan. `--html`, `--json`, `--sarif`, `--out <file>`. |
| `periperi risk` | Print the preliminary risk overview. Accepts `--fail-on`. |
| `periperi status` | Show version, working directory, configuration and backend status. `--check-server`. |
| `periperi sync` | Upload the most recent CBOM to a configured ECDAT server. `--yes`, `--dry-run`. |
| `periperi clear` | Delete stored results, CBOMs and reports for this directory. |
| `periperi help` | Show usage. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, and the `--fail-on` gate did not trip. |
| `1` | Runtime error (no stored scan, no server configured, unreadable path). |
| `2` | Usage error (unknown command, bad flag value, missing file). |
| `3` | Findings reached the `--fail-on` severity. |

This is what makes `periperi scan --fail-on high` usable as a CI gate.

## Global options

| Option | Effect |
| --- | --- |
| `--exclude <list>` | Comma-separated directory and file names to skip. |
| `--max-files <n>` | Maximum number of files to read in one scan. |
| `--max-file-size <n>` | Maximum file size in bytes; larger files are skipped. |
| `--no-write` | Do not write anything into `.pari-pari/`. |
| `--fail-on <severity>` | Exit `3` at `critical`, `high`, `medium`, `low` or `info`. |
| `--json` / `--sarif` | Machine-readable output on stdout, and nothing else. |
| `--quiet`, `-q` | Print only the findings the gate would trip on. |
| `--server-url <url>` | ECDAT server URL. Omit to stay fully local. |
| `--api-key <key>` | ECDAT API key. Prefer `PERIPERI_API_KEY`. |
| `--project-id <id>` | Project identifier sent with a sync. |

`--json` and `--sarif` own stdout completely, so the output is safe to pipe:

```bash
periperi scan --json | jq '.summary'
periperi scan --sarif > results.sarif
```

## Configuration

Settings are merged in this order, later sources winning:

1. Command-line flags
2. Environment variables
3. An rc file in the working directory
4. Built-in defaults

### Environment variables

| Variable | Sets |
| --- | --- |
| `PERIPERI_SERVER_URL` | ECDAT server URL. |
| `PERIPERI_API_KEY` | ECDAT API key. |
| `PERIPERI_PROJECT_ID` | Project identifier. |
| `PERIPERI_EXCLUDE` | Comma-separated exclude list. |
| `PERIPERI_MAX_FILES` | Maximum files per scan. |
| `PERIPERI_MAX_FILE_SIZE` | Maximum file size in bytes. |
| `PERIPERI_TELEMETRY` | Opt-in counters, off by default. |
| `PERIPERI_ROOT` | Directory to scan when no path is given. |

### rc files

`.periperirc` and `.pari-parirc` are read from the working directory, then
`~/.config/periperi/config.json`. Both plain `key = value` text and JSON work,
and `#` or `;` starts a comment:

```ini
# .periperirc
max-files = 20000
exclude = node_modules, .pari-pari, vendor
server-url = https://ecdat.example.com
```

```json
{ "maxFiles": 20000, "exclude": ["node_modules", ".pari-pari"] }
```

A malformed rc file is ignored rather than fatal: bad configuration never stops
a scan from running.

## Output on disk

Results live in `.pari-pari/` inside the project, and the directory is excluded
from scanning so a scan never re-reads its own CBOM:

```
.pari-pari/
  scans/      scan-<id>.json      full scan result
  cbom/       cbom-<id>.json|csv  Cryptographic Bill of Materials
  reports/    report-<id>.html    self-contained HTML report
```

Use `--no-write` to keep the working directory untouched, or `--out` / `--to` to
send a single artefact somewhere specific. `--out` is available on `cbom` and
`report`; for `scan` machine output, redirect stdout.

## Use in CI

```yaml
- run: npm install -g pari-pari-terminal
- run: periperi scan --sarif --fail-on high > security-results.sarif
```

Upload `security-results.sarif` as a SARIF artifact and GitHub code scanning
will render the findings. `--fail-on high` fails the job only when a finding is
at least that severe.

## Security posture

- Source code, file contents and private key bodies are never uploaded.
- Matching contexts are redacted before they are written to a report.
- Nothing is sent anywhere unless you configure a server and run `sync`.
- The API key is read from the environment or VS Code secret storage, and is
  never written to logs or into the workspace.

## VS Code extension

The extension adds a PARI PARI activity bar with scan results, a security
dashboard, CBOM export and a dedicated terminal that has `periperi` on its
PATH, so everything in this README is also available inside the editor.

## Development

```bash
npm install
npm run compile     # build both bundles, then typecheck
npm test            # unit and end-to-end CLI tests
npm run lint
npm run watch       # rebuild on change
npm run gen:icon    # regenerate media/icon.png from media/icon.svg
npm run package     # build a .vsix
```

## License

MIT. See [LICENSE](LICENSE).
