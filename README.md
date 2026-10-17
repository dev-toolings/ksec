# ksec

**Self-contained security scanner for your codebase.** One binary, zero dependencies, five scanners running in parallel.

ksec detects leaked secrets, vulnerable dependencies, supply chain attacks, OWASP Top 10 vulnerabilities, and obfuscated code — all without installing external tools.

```
$ ksec scan .

═══ ksec scan report ═══

  ✓ secrets — 0 findings (12ms)
  ✓ supply-chain — 0 findings (8ms)
  ✓ sast — 0 findings (6ms)
  ✓ obfuscation — 0 findings (1ms)
  ⚠ deps — 2 findings (680ms)
       HIGH  CVE-2024-1234 — lodash@4.17.20
       MEDIUM  GHSA-abcd — express@4.18.0

─── summary ───
  scanners: 5 run
  findings: 2 total, 1 high/critical
```

## Why ksec?

| Tool | Installs needed | What it covers |
|---|---|---|
| gitleaks + trivy + osv-scanner + semgrep + socket | 5 separate binaries | secrets, deps, SAST, supply chain |
| **ksec** | **1 binary (4.6 MB)** | **all of the above + obfuscation** |

- **No external tools required** — everything is built-in
- **Fast** — parallel execution, regex-based scanning, ~3s for a full project scan
- **Low false positives** — smart allowlists for form labels, test files, comments, config patterns
- **Offline-first** — only the deps scanner needs network (OSV API)

## Install

### One-liner (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/dev-toolings/ksec/master/install.sh | sh
```

### From source (Rust)

```bash
git clone https://github.com/dev-toolings/ksec.git
cd ksec
cargo build --release
cp target/release/ksec ~/.local/bin/
```

### Pre-built binaries

Binaries for Linux (x86_64, aarch64) and macOS (x86_64, aarch64) are available on the [Releases](https://github.com/dev-toolings/ksec/releases) page.

## Usage

```bash
# Full scan (all 5 scanners in parallel)
ksec scan .

# Scan specific category
ksec secrets .
ksec deps .
ksec sast .
ksec supply-chain .
ksec obfuscation .

# JSON output (pipeable to jq, CI, etc.)
ksec scan --json .

# Filter by severity
ksec scan --min-severity high .

# Dev machine: let through what a dev box holds by design (see Policy)
ksec scan --profile dev ~/lab

# Freeze the remaining findings, then only see new ones
ksec baseline ~/lab

# Validate one protected finding (obfuscation) by its exact content
ksec hash node_modules/some-pkg/dist/index.js

# Show everything, ignoring .ksec.toml, profile and baseline
ksec scan --no-policy .

# Generate pre-commit hooks (lefthook)
ksec init
```

## Scanners

### Secrets (60+ rules)

Detects leaked API keys, tokens, private keys, and database URIs using embedded regex patterns.

**Covered providers:** AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, Discord, Twilio, SendGrid, Firebase, Supabase, NPM, PyPI, Docker Hub, Telegram, Heroku, Shopify, Mailchimp, HashiCorp Vault, Datadog, Sentry, Vercel, Cloudflare, and more.

Also detects: private keys (RSA, DSA, EC, OpenSSH, PGP), database URIs with passwords, basic auth in URLs, hardcoded bearer tokens, JWTs, and password assignments.

**Smart filtering:** Skips comments, regex definitions, form labels, validation schemas, test files, placeholder values, and environment variable references.

### Dependencies

Parses lockfiles and queries the [OSV API](https://osv.dev/) (Google's open vulnerability database) for known CVEs.

**Supported lockfiles:**
- `package-lock.json`, `bun.lock`, `yarn.lock` (npm)
- `Cargo.lock` (Rust)
- `composer.lock` (PHP)
- `requirements.txt`, `poetry.lock` (Python)
- `go.sum` (Go)

### Supply Chain

Detects suspicious patterns in JavaScript packages that indicate malicious behavior:

- **Dynamic code execution** — `eval()`, `Function()`, `vm.runInNewContext()`
- **Network exfiltration** — HTTP requests, DNS lookups, WebSocket connections
- **Filesystem access** — reading `.ssh/`, `.env`, `/etc/passwd`
- **Obfuscation** — hex-encoded strings, `String.fromCharCode()`, `global[]` accessors
- **Malicious install scripts** — `curl`/`wget` in postinstall, downloading binaries
- **Environment harvesting** — dumping `process.env` over network

### SAST (OWASP Top 10)

Static analysis for common security vulnerabilities:

- **SQL Injection** — string concatenation/interpolation with user input in queries
- **XSS** — `innerHTML`, `dangerouslySetInnerHTML`, `document.write()`
- **Command Injection** — `exec()`/`os.system()` with user-controlled input
- **Path Traversal** — user input in file paths
- **SSRF** — `fetch()`/`requests.get()` with user-controlled URLs
- **Insecure Crypto** — DES, ECB mode, `Math.random()` for security
- **Deserialization** — `pickle.loads()`, `yaml.load()`, PHP `unserialize()`
- **Prototype Pollution** — `__proto__` assignment
- **NoSQL Injection** — `$where`/`$gt`/`$ne` from user input
- **Open Redirect** — unvalidated redirects
- **CORS Misconfiguration** — wildcard `Access-Control-Allow-Origin`

**Supported languages:** JavaScript, TypeScript, Python, PHP, Go, Rust, Ruby.

### Obfuscation

Runs first and is the priority scanner. It reads every JS/TS/Python file,
**including installed dependencies** (`node_modules`, `site-packages`, and
VS Code / Cursor `extensions`), because that is where droppers land. Rules
follow the 2025-2026 campaigns:

| Rule | Catches | Severity |
|---|---|---|
| `invisible-unicode-payload` | runs of Unicode variation selectors / tags hiding bytes, decoded via `codePointAt` + `eval` (GlassWorm) | High, Critical with a decoder |
| `obfuscator-io` | `_0x1a2b` identifiers, string array rotation `while(!![])` (npm stagers, Microsoft May 2026) | High, Critical with rotation |
| `decode-exec-chain` | `eval(atob(...))`, `exec(zlib.decompress(b64decode(...[::-1])))` (PyPI one-line loaders 2026) | Critical |
| `encoded-blob-exec` | a large base64 blob fed to `eval` / `exec` / `Function` on the same line | High |
| `pth-startup-exec` | `.pth` files that decode or fetch code at every Python start | Critical |
| `bidi-control` | Trojan Source bidirectional controls in project code | High |
| `config-*` | long lines, `global[]`, hex payloads in `*.config.*` files | Medium / High |

Any suspicious file that also exits under CI and runs detached
(`process.env.CI` + `.unref()`) is escalated to Critical. WebAssembly
modules (`AGFzbQ...`), `data:` URIs and source maps are not payloads.

The supply-chain scanner also knows the Shai-Hulud 2.0 files
(`setup_bun.js`, `bun_environment.js`).

## Policy: `.ksec.toml`, dev profile, baseline

`ksec` looks for `.ksec.toml` in the scanned directory, then in its parents:
one file in `~/lab` covers every project below it.

```toml
profile = "dev"          # or "strict" (default); --profile overrides it

[[allow]]
rule = "db-uri-password"            # rule id, title substring, or "*"
path = "tools/ploydok/apps/api/src/databases/templates/**"   # glob, relative to this file
reason = "connection string templates, rendered at deploy time"   # required

[[allow]]
rule = "decode-exec-chain"
path = "scraping/**/ublock-badware.js"
sha256 = "<output of ksec hash>"    # required for protected findings
reason = "uBlock Origin badware scriptlets: signatures, not code"
```

Filters apply in this order:

1. **Profile `dev`** lets through `.env.example` and other templates, database
   URIs that point at localhost / `infra-*` / a compose service, CI
   credentials, tests, fixtures and seeds, i18n labels, mock values and
   `DEV_*` / `DEMO_*` / `SEED_*` constants, and `fetch` / WebSocket in
   first-party code.
2. **`[[allow]]`** entries, each with a mandatory `reason`.
3. **Baseline** (`.ksec-baseline.json`, written by `ksec baseline` next to
   `.ksec.toml`): findings keyed by rule, file and line content, so they
   survive a line move but come back when the line changes.

**Protected findings are never hidden by the profile or the baseline:**
everything from the obfuscation scanner and every critical supply-chain
finding. An `[[allow]]` validates one only with the file's exact `sha256`;
if the file changes by one byte, the finding comes back.

The report prints how many findings each filter suppressed; `--no-policy`
shows them all.

## `.ksecignore`

Create a `.ksecignore` file at the root of your project to exclude paths from scanning. Uses gitignore syntax:

```gitignore
# Ignore test fixtures with fake secrets
tests/fixtures/

# Ignore generated files
generated/

# Ignore specific file
scripts/seed-data.sh

# Re-include a specific path
!tests/fixtures/real-secrets.env
```

## Pre-commit hooks

`ksec init` generates a `lefthook.yml` that runs ksec on pre-commit (fast checks) and pre-push (full scan):

```bash
ksec init
# Install lefthook: go install github.com/evilmartians/lefthook@latest
lefthook install
```

## CI Integration

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  ksec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install ksec
        run: |
          curl -fsSL https://github.com/dev-toolings/ksec/releases/latest/download/ksec-linux-x86_64 -o /usr/local/bin/ksec
          chmod +x /usr/local/bin/ksec
      - name: Run scan
        run: ksec scan --min-severity high .
```

## JSON Output

All findings are available as structured JSON for integration with other tools:

```bash
ksec scan --json . | jq '.[] | select(.findings | length > 0)'
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No high/critical findings |
| `1` | High or critical findings detected (after policy) |

## Architecture

```
ksec (single binary, ~4.6 MB)
├── secrets     60+ regex rules, .gitignore-aware file walker
├── deps        lockfile parsers + OSV API batch queries
├── supply-chain    pattern detection in JS packages
├── sast        OWASP Top 10 rules for JS/TS/Python/PHP/Go/Rust
├── obfuscation     long-line + global[] detection in config files
└── .ksecignore     gitignore-style exclusion file
```

## License

MIT
