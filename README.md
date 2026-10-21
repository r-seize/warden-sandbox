# warden-sandbox

[![npm version](https://img.shields.io/npm/v/warden-sandbox)](https://www.npmjs.com/package/warden-sandbox)
[![npm downloads](https://img.shields.io/npm/dt/warden-sandbox)](https://www.npmjs.com/package/warden-sandbox)
[![CI](https://github.com/r-seize/warden-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/r-seize/warden-sandbox/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/warden-sandbox)](LICENSE)
[![node](https://img.shields.io/node/v/warden-sandbox)](https://nodejs.org)

Runtime capability sandboxing for Node.js dependencies.

Warden addresses a class of supply-chain attacks where malicious code executes **at load time** (`require`/`import`), not at installation — bypassing npm's `postinstall` block. It scans your `node_modules` with static AST analysis, generates a lockfile of declared capabilities per package, and in enforcement mode creates isolated Compartments per dependency using [ses](https://github.com/endojs/endo/tree/master/packages/ses) so that a compromised package cannot access the network, filesystem, or environment variables it never declared needing.

## Table of Contents

- [Installation](#installation)
- [Workflow](#workflow)
- [Commands](#commands)
  - [warden scan](#warden-scan)
  - [warden diff](#warden-diff)
  - [warden verify](#warden-verify)
  - [warden approve](#warden-approve)
  - [warden unapprove](#warden-unapprove)
  - [warden run](#warden-run)
  - [warden status](#warden-status)
  - [warden audit](#warden-audit)
  - [warden report](#warden-report)
  - [warden explain](#warden-explain)
  - [warden inspect-script](#warden-inspect-script)
  - [warden graph](#warden-graph)
  - [warden install](#warden-install)
  - [warden update](#warden-update)
  - [warden watch](#warden-watch)
  - [warden integrity](#warden-integrity)
  - [warden ci](#warden-ci)
  - [warden config init](#warden-config-init)
  - [warden config recommend](#warden-config-recommend)
- [Configuration file](#configuration-file-wardenrcjson)
- [Lockfile format](#wardenlockjson-format)
- [Capabilities](#capabilities)
- [Package statuses](#package-statuses)
- [Profiles](#profiles)
- [Performance](#performance)
- [Security limitations](#security-limitations)
- [License](#license)
- [Contributing](#contributing)

## Installation

```bash
npm install -g warden-sandbox
# or per-project
npm install --save-dev warden-sandbox
```

Requires Node.js >= 18.19 for ESM enforcement (`module.register`). CommonJS enforcement works on all Node.js >= 16.

## Workflow

```bash
npm install
warden scan          # analyse node_modules, write warden.lock.json
warden approve --all # mark all packages as reviewed (first time only)
git add warden.lock.json
```

After that, on every dependency update:

```bash
warden update        # wraps npm update + auto-scan
warden diff          # see what new capabilities appeared
warden approve <pkg> # approve each changed package individually
warden verify        # CI gate — exits non-zero on any deviation
```

In CI, `warden ci` bundles `integrity` + `verify` + `audit` into a single gate:

```bash
warden ci   # one exit code instead of chaining three commands
```

To investigate a specific package:

```bash
warden explain axios              # show which files/lines triggered each capability
warden inspect-script axios postinstall   # sandbox-run (or review) its install-time script
warden graph                      # visualise the full dependency tree with capabilities
warden audit                      # risk breakdown across all packages
```

To run a script under observation or enforcement:

```bash
warden run script.js             # logs violations, never blocks
warden run --enforce script.js   # blocks violations at runtime
```

## Commands

### `warden scan`

Scans `node_modules` using static AST analysis and generates or updates `warden.lock.json`. Each package's JS files are parsed to detect which Node.js built-in modules are imported, and the results are grouped into capability categories.

Packages already present in the lockfile with a matching SHA-256 content hash are skipped — the scan is incremental and fast on subsequent runs.

Packages linked via symlink (pnpm's `node_modules`, and npm/yarn workspaces) are resolved and scanned like any other package. In a monorepo, `warden scan` also scans the `node_modules` of every workspace package declared in `package.json` (`workspaces`) or `pnpm-workspace.yaml` (`packages:`), merging the results with the root scan — no extra flag needed. Only simple glob patterns (e.g. `"packages/*"`) are supported.

Packages that declare an npm life-cycle script (`preinstall`, `install`, or `postinstall`) are flagged separately in the scan summary and in `warden audit`/`warden report`. These scripts run at install time, before Warden's hooks exist, so they are **not** sandboxed — the flag is informational, so you know to review them manually, or run `warden inspect-script` against them.

Package names are also checked against a small, offline list of popular packages for likely typosquats (e.g. `lodahs` vs `lodash`) — a one-character match downgrades an otherwise-clean package back to `pending-review` and flags it in the scan summary, `warden audit`, and `warden report`. This is a static, curated list (not a live registry lookup), so it only catches typos of the packages it knows about.

```
warden scan [--dir <path>] [--no-progress] [--verbose] [--json]
```

| Flag | Description |
|---|---|
| `--dir <path>` | Project directory to scan (default: cwd) |
| `--no-progress` | Suppress the progress bar — useful in CI |
| `--verbose` | Print per-package timing, file count, and cache hit/miss status |
| `--json` | Print the resulting lockfile JSON to stdout |

Commit `warden.lock.json` to version control. New packages appear as `pending-review` and must be explicitly approved before enforcement can be enabled.

**Example output:**

```
Warden Scan Summary
  Total packages:    67
  With capabilities: 23
  Native addons:     1
  Clean:             44

Packages with detected capabilities:
  esbuild@0.28.1      [ENV]  [FS-READ]  [FS-WRITE]  [NETWORK]  [SPAWN]
  debug@4.4.3         [ENV]
```

### `warden diff`

Compares the current state of `node_modules` against the committed lockfile and reports any capability changes **and any new risk flags** — a package becoming a likely typosquat match, or gaining a life-cycle script, is surfaced even if it declares zero capabilities, which is often exactly the case for a package that's just trying to get installed unnoticed. Run this after `npm update` to understand the security impact before approving anything. In a monorepo, every workspace package's `node_modules` is scanned too (see [warden scan](#warden-scan)).

```
warden diff [--dir <path>] [--from <lockfile>] [--to <lockfile>] [--since <date>] [-v]
```

| Flag | Description |
|---|---|
| `--dir <path>` | Project directory (default: cwd) |
| `--from <lockfile>` | Baseline lockfile to compare against (default: `warden.lock.json`) |
| `--to <lockfile>` | Lockfile to compare to (default: scan current `node_modules` now) |
| `--since <date>` | Compare against the lockfile from git history at the given date (e.g. `"2026-08-01"`). Requires `warden.lock.json` to be committed. |
| `-v, --verbose` | Also show packages whose code changed but capabilities stayed the same |

```bash
warden diff --since 2026-08-01
```

**Example output:**

```
Warden Diff
  New packages:           1
  New capabilities:       1

  !! Packages with NEW capabilities (review required):

  some-lib@3.1.0
    + Added:   [NETWORK]
    note: New capabilities detected after update: network.
```

**Example output — a zero-capability typosquat, still caught:**

```
Warden Diff
  New packages:           1
  New capabilities:       0
  New risk flags:         1 (typosquat / life-cycle script)

  New packages with capabilities or risk flags:

  lodahs@1.0.0
     !  Possible typosquat of "lodash"
    note: Package name is one character away from popular package "lodash" — possible typosquat, verify this is the package you intended to install.
```

### `warden verify`

Compares the current state of `node_modules` against the committed lockfile. Exits `1` if any package has a changed content hash, new capabilities, or a `pending-review` status. Packages listed under `ignore` in `.wardenrc.json` are skipped. In a monorepo, every workspace package's `node_modules` is scanned too (see [warden scan](#warden-scan)).

```
warden verify [--dir <path>] [--json] [--sarif] [--junit]
```

| Flag | Description |
|---|---|
| `--dir <path>` | Project directory (default: cwd) |
| `--json` | Output `{ "ok": boolean, "violations": string[] }` |
| `--sarif` | Output SARIF 2.1.0 JSON for GitHub Advanced Security / code scanning integration |
| `--junit` | Output JUnit XML for Jenkins, GitLab CI, and other test-report consumers |

```yaml
# GitHub Actions
- run: warden verify

# With SARIF upload for GitHub code scanning
- run: warden verify --sarif > warden.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: warden.sarif

# With JUnit XML for GitLab CI / Jenkins
- run: warden verify --junit > warden-report.xml || true
```

### `warden approve`

Marks packages as reviewed in `warden.lock.json`. Approval is tied to the current content hash — any code change resets the package to `pending-review`.

```
warden approve [packages...] [--all] [--rescan] [--capability <cap>] [--deny <cap>] [--note <text>]
```

| Flag | Description |
|---|---|
| `packages...` | Package names (`axios`) or versioned keys (`axios@1.6.0`). Multiple accepted. |
| `--all` | Approve all `pending-review` packages at once |
| `--rescan` | Re-scan packages from disk before approving |
| `--capability <cap>` | Approve **only** this one capability — all others will be blocked at runtime even if declared |
| `--deny <cap>` | Explicitly block one capability — the package is approved for everything else it declared, but this one is denied at runtime. Deny always wins: a cap in both `allowedCapabilities` and `deniedCapabilities` is blocked. |
| `--note <text>` | Attach a human-readable note to the approval (stored in `warden.lock.json` for audit trail) |

**Examples:**

```bash
warden approve axios
warden approve axios lodash debug
warden approve --all
warden approve got --capability network
warden approve axios --deny filesystem-write
warden approve some-pkg --note "reviewed by alice 2026-08-02, only reads config files"
warden approve --all --rescan
```

`--capability` and `--deny` are complementary:
- `--capability network` -> allow only `network`, block everything else
- `--deny filesystem-write` -> allow everything declared, but block `filesystem-write`

Re-approving a package without `--deny` preserves any existing `deniedCapabilities`. Use `warden unapprove` to fully reset a package's approval state.

### `warden unapprove`

Reverts packages back to `pending-review`, removing all approval data (`allowedCapabilities`, `deniedCapabilities`, `note`). Useful when you realise an approval was too broad.

```
warden unapprove [packages...] [--all] [--dir <path>]
```

| Flag | Description |
|---|---|
| `packages...` | Package names or versioned keys to unapprove |
| `--all` | Unapprove all currently approved packages |
| `--dir <path>` | Project directory (default: cwd) |

```bash
warden unapprove axios
warden unapprove --all
```

### `warden run`

Executes a Node.js script with Warden's module hooks installed. Detects ESM (`.mjs`, or `"type": "module"`) vs CommonJS automatically.

```
warden run <script> [--enforce] [--watch] [--profile <profile>] [--timeout <ms>] [--dir <path>]
           [--json] [--on-violation <action>] [--stack]
```

| Flag | Description |
|---|---|
| `--enforce` | Block capability violations instead of logging them |
| `--watch` | Re-run the script whenever it changes on disk |
| `--profile <profile>` | `strict`, `default`, or `lenient` — see [Profiles](#profiles) |
| `--timeout <ms>` | Kill the script if it runs longer than N milliseconds |
| `--dir <path>` | Project directory where `warden.lock.json` lives (default: cwd) |
| `--json` | Emit violations as NDJSON (`{"level":"warn","source":"warden",...}`) instead of human-readable text |
| `--on-violation <action>` | `log` (default), `block` (throw on first violation), or `prompt` (interactive) |
| `--stack` | Capture and attach a V8 stack trace to each violation event |

**Observation mode (default):** every violation is logged and a summary is printed at the end. Execution is never interrupted.

**Enforcement mode (`--enforce`):** CJS packages run in `ses` Compartments with only approved capabilities as endowments. ESM imports are replaced with stub modules that throw on any access. Packages with `pending-review` status have zero capabilities in enforce mode.

```bash
warden run script.js
warden run --enforce script.js
warden run --enforce --profile strict script.js
warden run --enforce --watch --timeout 5000 script.js
```

**Watch mode:** spawns a fresh child process on each file save, so SES lockdown resets cleanly.

### `warden status`

Shows all packages grouped by approval status. Reads `warden.lock.json` directly — no rescan.

```
warden status [--dir <path>]
```

```
Warden Status

  + Approved        62
  ! Pending review  3
  x Unsandboxed     1
  ~ Unanalyzable    1

  Pending review — run `warden approve` to unblock:
    - some-lib@3.1.0   [NETWORK]  [ENV]
```

### `warden audit`

Shows which packages use each capability, grouped by risk level (HIGH / MEDIUM / LOW).

```
warden audit [--dir <path>] [--json] [--fix]
```

| Flag | Description |
|---|---|
| `--dir <path>` | Project directory (default: cwd) |
| `--json` | Output `{ "total": number, "byCapability": { "[cap]": ["pkg@version"] } }` |
| `--fix` | Auto-approve all `pending-review` packages whose only capabilities are `env-access` and/or `filesystem-read` (low-risk only). Writes the lockfile. |

```bash
warden audit --fix
```

```
Warden Capability Audit
  67 packages total — 44 clean, 23 with capabilities

  HIGH RISK
    [NETWORK] network              5 pkgs   axios@1.6.0, got@13.0.0 +3 more
    [SPAWN]   process-spawn        2 pkgs   esbuild@0.28.1, tsx@4.19.0

  MEDIUM RISK
    [FS-WRITE] filesystem-write   8 pkgs   esbuild@0.28.1 +7 more
    [ENV]      env-access         15 pkgs  debug@4.4.3 +14 more

  LOW RISK
    [FS-READ]  filesystem-read    12 pkgs  resolve@1.22.8 +11 more
```

### `warden report`

Generates a Markdown security report summarising the current lockfile state. Includes a risk-scored table of all packages, packages pending review, and a capability breakdown.

```
warden report [--dir <path>] [--output <file>] [--format md]
```

| Flag | Description |
|---|---|
| `--dir <path>` | Project directory (default: cwd) |
| `--output <file>` | Output file path (default: `warden-report.md`) |
| `--format <fmt>` | Output format. Currently only `md` is supported. |

```bash
warden report
warden report --output security/warden-report.md
```

The report includes:
- A summary table (total, approved, pending, unsandboxed, high-risk count)
- Top 10 highest-risk packages by score with their capabilities
- All packages pending review
- Capability breakdown table

### `warden explain`

Shows exactly which files and line numbers triggered each capability detection for a given package. Useful for understanding why a package was flagged and deciding whether it is a false positive.

```
warden explain <pkg> [--dir <path>] [--json]
```

| Flag | Description |
|---|---|
| `<pkg>` | Package name (`axios`) or versioned key (`axios@1.6.0`) |
| `--dir <path>` | Project directory (default: cwd) |
| `--json` | Output raw JSON with full evidence list |

**Example output:**

```
Warden Explain: axios@1.6.0
  Location: /project/node_modules/axios

  [NETWORK]  (3 occurrences)
    lib/adapters/http.js:14
      const http = require('http')
    lib/adapters/http.js:15
      const https = require('https')
    lib/adapters/http.js:18
      const followRedirects = require('follow-redirects')

  [ENV]  (1 occurrence)
    lib/defaults/index.js:22
      process.env.npm_package_version
```

### `warden inspect-script`

Reviews a package's npm life-cycle scripts (`preinstall`/`install`/`postinstall`) before you approve it. These scripts run at install time, before Warden's hooks exist, so they are never sandboxed automatically — this command closes part of that gap for the common case: when the script is a direct `node <file>.js` invocation, Warden runs that file through the same observation/enforcement hooks as `warden run`, scoped to the package's own lockfile policy. Anything else (shell pipelines, `node-gyp`, prebuilt binary installers, `npm-run-all`, ...) runs outside Node's module system — Warden cannot see into it, so it prints the raw command for manual review instead of guessing or running it unsandboxed.

```
warden inspect-script <pkg> [script] [--dir <path>] [--enforce] [--profile <profile>] [--timeout <ms>]
```

| Flag | Description |
|---|---|
| `<pkg>` | Package name (`axios`) or scoped name (`@scope/pkg`) |
| `[script]` | One of `preinstall`/`install`/`postinstall`. Omit to inspect every life-cycle script the package declares. |
| `--dir <path>` | Project directory (default: cwd) |
| `--enforce` | Block capability violations instead of just logging them (same semantics as `warden run --enforce`) |
| `--profile <profile>` | `strict`, `default`, or `lenient` |
| `--timeout <ms>` | Kill the script if it runs longer than N milliseconds |

```bash
warden inspect-script axios postinstall
warden inspect-script some-pkg postinstall --enforce
warden inspect-script some-pkg   # inspects every declared life-cycle script
```

**Example output (sandboxable):**

```
Warden Inspect: some-pkg — postinstall
  Command: node setup.js

[Warden] observation mode — violations will be logged

[Warden] 1 violation(s) recorded:
  - some-pkg → http (network)
```

**Example output (not sandboxable):**

```
Warden Inspect: some-pkg — preinstall
  Command: node-gyp rebuild
  Cannot be sandboxed automatically — not a direct `node <file>.js` invocation.
  Review the command above manually before approving this package.
```

### `warden graph`

Visualises the dependency tree with capability annotations. Shows which packages bring in high-risk capabilities (network, spawn, eval, native) transitively.

```
warden graph [pkg] [--dir <path>] [--depth <n>] [--json]
```

| Flag | Description |
|---|---|
| `pkg` | Optional starting package. If omitted, shows the full graph from top-level packages. |
| `--dir <path>` | Project directory (default: cwd) |
| `--depth <n>` | Maximum tree depth to display (default: 3) |
| `--json` | Output adjacency JSON `{ "pkg@version": { capabilities, deps } }` |

**Example output:**

```
Warden Dependency Graph

your-app@1.0.0
|-- axios@1.6.0  [NETWORK] [ENV]
|   `-- follow-redirects@1.15.9  [NETWORK]
|-- webpack@5.0.0
|   |-- terser@5.0.0  [EVAL]
|   `-- enhanced-resolve@5.0.0  [FS-READ]
`-- debug@4.4.3  [ENV]
```

Packages with high-risk capabilities (`[NETWORK]`, `[SPAWN]`, `[EVAL]`, `[NATIVE]`) are shown in bold red.

### `warden install`

Wraps your package manager's `install` command, then automatically rescans `node_modules` (including workspace packages, see [warden scan](#warden-scan)) and reports packages needing review. All unknown flags are forwarded to the package manager. Warden auto-detects which package manager to use: if `pnpm-lock.yaml` is present it uses `pnpm`, if `yarn.lock` is present it uses `yarn`, otherwise it uses `npm`.

```
warden install [packages...] [--approve-all] [--dir <path>] [...pm flags]
```

| Flag | Description |
|---|---|
| `packages...` | Packages to install — forwarded to the package manager |
| `--approve-all` | Auto-approve all new packages (or set `autoApprove: true` in `.wardenrc.json`) |
| `--dir <path>` | Project directory (default: cwd) |

```bash
warden install axios
warden install typescript --save-dev
warden install --approve-all
warden install some-package --legacy-peer-deps
```

### `warden update`

Wraps your package manager's `update` command, then rescans (including workspace packages, see [warden scan](#warden-scan)) and reports packages whose capabilities changed. Uses the same auto-detection as `warden install` (pnpm, yarn, or npm).

```
warden update [packages...] [--approve-all] [--dir <path>] [...pm flags]
```

| Flag | Description |
|---|---|
| `packages...` | Packages to update — forwarded to the package manager (updates all if omitted) |
| `--approve-all` | Auto-approve all changed packages after update |
| `--dir <path>` | Project directory (default: cwd) |

```bash
warden update
warden update axios
warden update --approve-all
```

After update, Warden lists every package whose capabilities changed. Without `--approve-all`, run `warden diff` to review and then `warden approve` to accept.

### `warden watch`

Watches `node_modules` for filesystem changes and automatically rescans when dependencies change. In a monorepo, every workspace package's `node_modules` is watched too (see [warden scan](#warden-scan)). Reports a capability diff after each change and warns if new capabilities are detected.

```
warden watch [--dir <path>]
```

| Flag | Description |
|---|---|
| `--dir <path>` | Project directory (default: cwd) |

```bash
warden watch
warden watch --dir /path/to/project
```

Changes are debounced by 1 second to avoid thrashing during multi-file installs. Press Ctrl+C to stop. Requires an existing `warden.lock.json` (run `warden scan` first).

### `warden integrity`

Reads `package-lock.json` and checks that all packages were installed from a trusted registry and have a valid integrity hash. Catches packages installed from git refs, local paths, or private URLs that bypass the registry.

Trusts `registry.npmjs.org` and `registry.yarnpkg.com` by default. Add your own private registry (Verdaccio, Artifactory, GitHub Packages, ...) via the `registries` field in `.wardenrc.json` — otherwise every package resolved from it is reported as a non-registry source.

```
warden integrity [--dir <path>] [--json]
```

| Flag | Description |
|---|---|
| `--dir <path>` | Project directory (default: cwd) |
| `--json` | Output `{ "checked": number, "issues": [{ package, issue }] }` |

Exit codes: `0` = all clear, `1` = issues found.

```bash
warden integrity
warden integrity --json
```

**Example output when issues are found:**

```
Warden Integrity Check
  Checked 67 packages from package-lock.json

  2 package(s) with integrity concerns:

  - internal-tool@2.0.0
    non-registry source: git+ssh://git@github.com/acme/internal-tool.git

  - patched-lib@1.0.0
    missing integrity hash — package may have been installed from a local path or git ref
```

### `warden ci`

Runs `warden integrity`, `warden verify`, and `warden audit` together as a single CI gate, with one exit code — instead of chaining three separate commands in your pipeline. `integrity` is skipped (not failed) when there is no `package-lock.json`, since it doesn't yet understand pnpm/yarn lockfiles; `audit` is informational only and never fails the gate on its own, it just surfaces the high-risk package count alongside the pass/fail result.

```
warden ci [--dir <path>] [--json]
```

| Flag | Description |
|---|---|
| `--dir <path>` | Project directory (default: cwd) |
| `--json` | Output `{ ok, integrity, verify, audit }` |

Exit codes: `0` = integrity and verify both passed (or integrity was skipped), `1` = either failed.

```yaml
# GitHub Actions — replaces separate integrity/verify/sarif/junit steps for a simple gate
- run: warden ci
```

```bash
warden ci
warden ci --json
```

**Example output:**

```
Warden CI

  + integrity   ok (67 package(s) checked)
  x verify      1 violation(s)
      - some-lib@3.1.0: new capabilities detected: network
  i audit       67 package(s) scanned, 2 high-risk

  CI gate failed.
```

### `warden config init`

Interactive wizard that creates a `.wardenrc.json` configuration file in your project directory.

```
warden config init [--dir <path>]
```

```
Warden config init

  Default profile [strict/default/lenient] (default: default): strict
  Auto-approve new packages after warden install/update? [y/N]: n
  Packages to ignore in warden verify (comma-separated, leave empty for none): internal-pkg

  Created .wardenrc.json:
  {
    "profile": "strict",
    "ignore": ["internal-pkg"]
  }
```

### `warden config recommend`

Analyses your `package.json` and generates a recommended `.wardenrc.json` tailored to your project type — no interactive prompts. Detected types: `frontend`, `backend`, `cli`, `library`, `unknown`.

```
warden config recommend [--dir <path>]
```

| Project type | Recommended profile | Rationale |
|---|---|---|
| `frontend` | `lenient` | Bundlers and dev tools legitimately need broad filesystem and env access |
| `backend` / `cli` | `default` | Standard enforcement; known network packages added to `ignore` automatically |
| `library` | `strict` | Minimal surface area — env access blocked even if declared |
| `unknown` | `default` | Falls back to safe default when type cannot be inferred |

```bash
warden config recommend
# Detected project type: backend
# Recommended .wardenrc.json:
# {
#   "profile": "default",
#   "autoApprove": false,
#   "ignore": ["axios"]
# }
```

## Configuration File (`.wardenrc.json`)

A `.wardenrc.json` file at the project root provides defaults for CLI flags. CLI flags always take precedence over config values.

```json
{
  "profile": "strict",
  "autoApprove": false,
  "ignore": ["my-trusted-internal-package"],
  "registries": ["https://npm.mycompany.internal/"]
}
```

| Field | Type | Description |
|---|---|---|
| `profile` | `"strict" \| "default" \| "lenient"` | Default profile for `warden run` |
| `autoApprove` | `boolean` | Equivalent to passing `--approve-all` to `warden install` / `warden update` |
| `ignore` | `string[]` | Package names excluded from `warden verify` violations (still scanned and in lockfile) |
| `registries` | `string[]` | Extra registry URL prefixes trusted by `warden integrity`, beyond the npm/yarn public registries |

Create it interactively with `warden config init`, or write it manually.

## `warden.lock.json` Format

```json
{
  "version": 1,
  "generatedAt": "2026-08-02T10:00:00.000Z",
  "packages": {
    "left-pad@1.3.0": {
      "contentHash": "sha256:abc...",
      "capabilities": [],
      "status": "approved"
    },
    "axios@1.6.0": {
      "contentHash": "sha256:def...",
      "capabilities": ["network", "env-access"],
      "allowedCapabilities": ["network"],
      "status": "approved",
      "note": "reviewed by alice 2026-08-02 — only uses network for HTTP requests"
    },
    "some-pkg@2.0.0": {
      "contentHash": "sha256:ghi...",
      "capabilities": ["network", "filesystem-write"],
      "deniedCapabilities": ["filesystem-write"],
      "status": "approved"
    },
    "suspicious-lib@4.0.1": {
      "contentHash": "sha256:jkl...",
      "capabilities": ["network", "env-access"],
      "status": "pending-review",
      "note": "New capabilities detected after update: network."
    }
  }
}
```

| Field | Type | Description |
|---|---|---|
| `contentHash` | `string` | SHA-256 of all JS files. Any code change invalidates the approval. |
| `capabilities` | `string[]` | Full list detected by static analysis. Do not edit manually. |
| `allowedCapabilities` | `string[]?` | Set by `--capability`. The runtime enforces this restricted list instead of `capabilities`. |
| `deniedCapabilities` | `string[]?` | Set by `--deny`. The runtime removes these from the effective capability set. |
| `status` | `string` | `approved`, `pending-review`, `unsandboxed`, or `unanalyzable` |
| `note` | `string?` | Human-readable note (auto-generated on capability changes, or set with `--note`). |
| `lifecycleScripts` | `string[]?` | npm life-cycle scripts (`preinstall`/`install`/`postinstall`) the package declares. Install-time only — not covered by runtime sandboxing. |
| `typosquatOf` | `string?` | Set when the package name is a likely one-character typo of a popular package. |

## Capabilities

| Label | Key | What it covers |
|---|---|---|
| `[NETWORK]` | `network` | `node:http`, `node:https`, `node:net`, `node:tls`, `node:dns`, `node:dgram`, `node:http2`, global `fetch()` / `WebSocket` (no import needed) |
| `[SPAWN]` | `process-spawn` | `node:child_process`, `node:cluster`, `node:worker_threads` |
| `[EVAL]` | `dynamic-code` | `eval`, `new Function()`, `node:vm` |
| `[NATIVE]` | `native-binding` | `.node` binary addon |
| `[FS-WRITE]` | `filesystem-write` | `writeFile`, `mkdir`, `unlink`, `rename`, ... |
| `[ENV]` | `env-access` | `process.env` reads |
| `[FS-READ]` | `filesystem-read` | `readFile`, `stat`, `readdir`, `createReadStream`, ... |

## Package Statuses

| Status | Meaning |
|---|---|
| `approved` | Capabilities reviewed and accepted. Hash matches last approval. |
| `pending-review` | New package, or capabilities/code changed since last approval. In enforce mode: zero capabilities allowed. |
| `unsandboxed` | Native `.node` addon — cannot be sandboxed. Runs with full OS access. |
| `unanalyzable` | All JS files failed to parse (obfuscated code). No capability claims can be made. |

## Exit Codes

All Warden commands follow a consistent exit code convention:

| Code | Meaning |
|---|---|
| `0` | Success — no issues |
| `1` | Policy violation — a package violated its declared capability policy |
| `2` | Runtime error — invalid arguments, missing file, corrupt lockfile, etc. |

## Profiles

The `--profile` flag (or `profile` in `.wardenrc.json`) adjusts what is enforced beyond the lockfile.

| Profile | Behaviour |
|---|---|
| `default` | Packages may use any capability that is declared and approved |
| `strict` | `env-access` is additionally blocked even if declared and approved |
| `lenient` | `filesystem-read` and `env-access` are always allowed regardless of approval status |

```bash
warden run --enforce --profile strict script.js
warden run --enforce --profile lenient script.js
```

## Performance

Warden maintains a shared scan cache at `~/.warden/cache/`. After a package has been scanned once on your machine, subsequent scans of the same version (by content hash) are instant regardless of which project you are scanning. The local project lockfile cache is also used as a first-level cache, with the global cache as a fallback.

A cache hit skips the expensive AST scan (the capabilities it already found are reused as-is), but name/metadata-derived checks — the typosquat match and declared life-cycle scripts — are always recomputed, even on a cache hit. This matters after upgrading Warden to a version with a larger typosquat list, or one with detection the lockfile predates: the next scan still catches it, rather than silently continuing to serve whatever verdict was cached the first time.

To disable the global cache for a single run, you can clear the directory:

```bash
rm -rf ~/.warden/cache/
```

## Security Limitations

These are design constraints, not bugs.

### Static analysis has blind spots

The AST scanner cannot detect capabilities hidden behind runtime `eval`, a genuinely dynamic `require(someFunctionCall())`, or obfuscated code. It does resolve `require()`/`import()` when the specifier is statically known — a literal, a no-interpolation template literal, a `const` bound to one of those, or a `+` concatenation of them (e.g. `const MOD = 'child_' + 'process'; require(MOD)`) — but anything resolved only at runtime (a reassignable variable, a function result, string interpolation) still falls through to the existing fallback. When these patterns appear, Warden flags the package as `dynamic-code` / `pending-review`. **`approved` status is not a security proof** — it means declared capabilities were reviewed by a human.

### Native addons cannot be sandboxed

A `.node` addon is a compiled binary loaded directly into the process. Warden detects these and marks them `unsandboxed`, but cannot restrict them at runtime.

### Install-time scripts are not sandboxed

Warden's hooks only exist once a script `require`s/`import`s a package — they cannot intercept `preinstall`/`install`/`postinstall` scripts, which run earlier, during `npm install`. `warden scan` detects and flags packages that declare these scripts (visible in the scan summary, `warden audit`, and `warden report`) so you know to review them manually. `warden inspect-script` can sandbox-run the common case — a script that is a direct `node <file>.js` invocation — but anything else (shell pipelines, `node-gyp`, prebuilt binary installers) is still outside Warden's reach and is only ever shown for manual review, never executed by Warden.

### Global fetch()/WebSocket shadowing check is file-wide, not true scope analysis

`fetch(...)` and `new WebSocket(...)` are flagged as `network` without requiring an import, since both are globals since Node 18 (`fetch`) / 22 (`WebSocket`). To avoid flagging a package that defines its own local `fetch` (a common test-mocking or polyfill pattern), Warden skips the check if `fetch`/`WebSocket` is declared or reassigned *anywhere* in the file — not scoped to the specific function. A file that shadows `fetch` in one function and calls the real global `fetch` in another will not be flagged; this is a deliberate trade-off toward fewer false positives.

### The typosquat list is small, static, and offline

`warden scan` flags package names that are a one-character edit away from a name in a small, bundled list of popular packages. It is not a registry lookup and does not grow over time on its own — it only catches typos of the packages already in that list, and it intentionally ignores scoped packages (`@scope/name`) and anything more than one character off, to keep false positives low.

A typosquat match forces a package back to `pending-review` — including an already-`approved`, content-unchanged entry, and including one in a lockfile written before Warden had typosquat detection at all — and `warden verify`/`warden ci` fail on it, not just `warden scan`'s terminal output. Approving it again (`warden approve`) is a one-time, explicit dismissal: once a lockfile entry records the same `typosquatOf` value, re-scanning it won't re-flag it. It only flags again if the match changes (e.g. a future, larger typosquat list matches a *different* popular package).

### Observation mode never blocks

`warden run` without `--enforce` only logs violations. This is intentional — a false positive that crashes production is worse than no protection. Test under `--enforce` in staging before enabling in production.

### SES lockdown is process-wide and irreversible

Enforcement mode calls SES's `lockdown()`, which deep-freezes all JavaScript primordials. This is irreversible for the lifetime of the process and may surface latent bugs in code that mutates built-in prototypes. `--watch` works around this by spawning a fresh child process per run.

### ESM enforcement requires Node.js >= 18.19

The ESM hook uses `module.register()`, stabilised in Node.js 18.19 / 20.6. On older versions, ESM hooks are silently disabled and only CJS enforcement is active.

## License

BSD 2-Clause License — Copyright (c) 2026, r-seize. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome at [github.com/r-seize/warden-sandbox](https://github.com/r-seize/warden-sandbox).
