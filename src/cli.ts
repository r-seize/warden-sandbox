#!/usr/bin/env node
import * as path from 'node:path';
import * as fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { Command } from 'commander';
import {
  scanNodeModules,
  ScanCacheEntry,
  loadGlobalCache,
} from './analyzer/packageScanner';
import { buildPolicyMap } from './policy/policyGenerator';
import {
  readLockfile,
  writeLockfile,
  mergeLockfile,
  LockfileData,
  LOCKFILE_NAME,
} from './policy/lockfile';
import { diffLockfiles } from './policy/policyDiff';
import {
  printScanSummary,
  printDiffSummary,
  printLockfileOverview,
  printVerifyResult,
  printProgress,
  printStatus,
  printAudit,
  printExplain,
  printDepGraph,
  generateMarkdownReport,
} from './report/cliReport';
import chalk from 'chalk';
import { readConfig, isIgnored } from './config';
import { explainPackage } from './analyzer/explainer';
import { buildDepGraph } from './analyzer/depGraph';

const program = new Command();

program
  .name('warden')
  .description('Runtime capability sandboxing for Node.js dependencies')
  .version('0.1.1');

// ─── scan ────────────────────────────────────────────────────────────────────

program
  .command('scan')
  .description('Scan node_modules and generate/update warden.lock.json')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--no-progress', 'Disable progress output')
  .option('--json', 'Output raw JSON instead of human-readable report')
  .action(async (opts: { dir: string; progress: boolean; json: boolean }) => {
    const projectDir = path.resolve(opts.dir);
    const nodeModulesDir = path.join(projectDir, 'node_modules');

    if (!fs.existsSync(nodeModulesDir)) {
      console.error(chalk.red(`Error: No node_modules found at ${nodeModulesDir}`));
      console.error('Run npm install first.');
      process.exit(1);
    }

    // Load existing lockfile to use as scan cache
    const existing = readLockfile(projectDir);
    const cache = buildCacheFromLockfile(existing);

    if (!opts.json) {
      console.log(chalk.bold(`\nWarden scan — ${projectDir}`));
    }

    const startTime = Date.now();

    const results = await scanNodeModules(
      nodeModulesDir,
      cache,
      opts.progress
        ? (done, total, pkg) => printProgress(done, total, pkg)
        : undefined,
    );

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    if (opts.json) {
      const newPolicies = buildPolicyMap(results);
      const merged = mergeLockfile(existing, newPolicies);
      console.log(JSON.stringify(merged, null, 2));
      return;
    }

    printScanSummary(results);
    console.log(chalk.dim(`  Scanned ${results.length} packages in ${elapsed}s`));

    // Write/update lockfile
    const newPolicies = buildPolicyMap(results);
    const merged = mergeLockfile(existing, newPolicies);
    writeLockfile(projectDir, merged);

    const lockPath = path.join(projectDir, LOCKFILE_NAME);
    console.log(chalk.green(`\n  Lockfile written to ${lockPath}`));

    // Show overview of pending-review packages
    const pending = Object.values(merged.packages).filter(p => p.status === 'pending-review');
    if (pending.length > 0) {
      console.log(chalk.yellow(`\n  ${pending.length} package(s) require review before enforcement can be enabled.`));
      console.log(chalk.dim('  Run `warden diff` to see what changed, then edit warden.lock.json to approve packages.'));
    }

    printLockfileOverview(merged);
  });

// ─── diff ────────────────────────────────────────────────────────────────────

program
  .command('diff')
  .description('Show capability changes between the current node_modules and the committed lockfile')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--from <lockfile>', 'Path to the baseline lockfile (default: warden.lock.json in --dir)')
  .option('--to <lockfile>', 'Path to the new lockfile (default: scan node_modules now)')
  .option('--since <date>', 'Compare against the lockfile from git history at the given date (e.g. "2026-08-01")')
  .option('-v, --verbose', 'Show content-only changes too')
  .action(async (opts: { dir: string; from?: string; to?: string; since?: string; verbose: boolean }) => {
    const projectDir = path.resolve(opts.dir);

    let oldLock: LockfileData | null;
    let newLock: LockfileData;

    if (opts.since) {
      const result = spawnSync('git', ['show', `HEAD@{${opts.since}}:warden.lock.json`], {
        cwd: projectDir,
        encoding: 'utf8',
      });
      if (result.status !== 0 || !result.stdout) {
        console.error(chalk.red(`Error: Could not retrieve warden.lock.json at date "${opts.since}" from git history.`));
        console.error(chalk.dim('  Make sure warden.lock.json is committed and the date is valid (e.g. "2026-08-01").'));
        process.exit(1);
      }
      oldLock = JSON.parse(result.stdout) as LockfileData;
    } else if (opts.from) {
      const raw = fs.readFileSync(path.resolve(opts.from), 'utf8');
      oldLock = JSON.parse(raw) as LockfileData;
    } else {
      oldLock = readLockfile(projectDir);
    }

    if (opts.to) {
      const raw = fs.readFileSync(path.resolve(opts.to), 'utf8');
      newLock = JSON.parse(raw) as LockfileData;
    } else {
      // Scan current node_modules
      const nodeModulesDir = path.join(projectDir, 'node_modules');
      if (!fs.existsSync(nodeModulesDir)) {
        console.error(chalk.red(`Error: No node_modules at ${nodeModulesDir}`));
        process.exit(1);
      }
      const cache = buildCacheFromLockfile(oldLock);
      console.log(chalk.bold('\nWarden — scanning node_modules for diff...'));
      const results = await scanNodeModules(nodeModulesDir, cache, (d, t, p) => printProgress(d, t, p));
      const newPolicies = buildPolicyMap(results);
      newLock = mergeLockfile(null, newPolicies);
    }

    const summary = diffLockfiles(oldLock, newLock);
    printDiffSummary(summary, opts.verbose);
  });

// ─── verify ──────────────────────────────────────────────────────────────────

program
  .command('verify')
  .description('Verify node_modules matches committed lockfile (exits non-zero if diverged)')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--json', 'Output machine-readable JSON (for CI pipelines)')
  .option('--sarif', 'Output SARIF 2.1.0 JSON (for GitHub Advanced Security / code scanning)')
  .action(async (opts: { dir: string; json: boolean; sarif: boolean }) => {
    const projectDir = path.resolve(opts.dir);
    const existing = readLockfile(projectDir);

    if (!existing) {
      console.error(chalk.red('Error: No warden.lock.json found. Run `warden scan` first.'));
      process.exit(1);
    }

    const nodeModulesDir = path.join(projectDir, 'node_modules');
    if (!fs.existsSync(nodeModulesDir)) {
      console.error(chalk.red(`Error: No node_modules at ${nodeModulesDir}`));
      process.exit(1);
    }

    const cache = buildCacheFromLockfile(existing);
    console.log(chalk.bold('\nWarden verify — scanning node_modules...'));
    const results = await scanNodeModules(nodeModulesDir, cache, (d, t, p) => printProgress(d, t, p));
    const newPolicies = buildPolicyMap(results);

    const config = readConfig(projectDir);
    const ignoreList = config.ignore ?? [];
    const violations: string[] = [];

    for (const [key, newPolicy] of Object.entries(newPolicies)) {
      if (isIgnored(key, ignoreList)) continue;

      const lockedPolicy = existing.packages[key];

      if (!lockedPolicy) {
        violations.push(`${key}: not in lockfile (run 'warden scan' to register)`);
        continue;
      }

      if (lockedPolicy.contentHash !== newPolicy.contentHash) {
        violations.push(`${key}: content hash changed (package modified since last scan)`);
        continue;
      }

      const lockedCaps = new Set(lockedPolicy.capabilities);
      const newCaps = newPolicy.capabilities.filter(c => !lockedCaps.has(c));
      if (newCaps.length > 0) {
        violations.push(`${key}: new capabilities detected: ${newCaps.join(', ')}`);
      }

      if (lockedPolicy.status === 'pending-review') {
        violations.push(`${key}: status is 'pending-review' — explicit approval required`);
      }
    }

    // Check for packages in lockfile that are gone from node_modules
    for (const key of Object.keys(existing.packages)) {
      if (!newPolicies[key]) {
        // Package removed — not a security violation, just informational
        // We don't fail verify for removed packages
      }
    }

    const ok = violations.length === 0;

    if (opts.sarif) {
      const sarifResults = violations.map(v => {
        let ruleId = 'WARDEN003';
        if (v.includes('not in lockfile')) ruleId = 'WARDEN004';
        else if (v.includes('content hash')) ruleId = 'WARDEN001';
        else if (v.includes('new capabilities')) ruleId = 'WARDEN002';
        const pkgKey = v.split(':')[0];
        return {
          ruleId,
          level: 'error',
          message: { text: v },
          locations: [{ physicalLocation: { artifactLocation: { uri: `node_modules/${pkgKey.slice(0, pkgKey.lastIndexOf('@'))}` } } }],
        };
      });

      const sarif = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
          tool: {
            driver: {
              name: 'warden',
              version: '0.1.0',
              informationUri: 'https://github.com/r-seize/Warden',
              rules: [
                { id: 'WARDEN001', name: 'ContentHashChanged', shortDescription: { text: 'Package content changed since last approval' } },
                { id: 'WARDEN002', name: 'NewCapabilities', shortDescription: { text: 'Package gained new capabilities' } },
                { id: 'WARDEN003', name: 'PendingReview', shortDescription: { text: 'Package not yet approved' } },
                { id: 'WARDEN004', name: 'NotInLockfile', shortDescription: { text: 'Package not registered in lockfile' } },
              ],
            },
          },
          results: sarifResults,
        }],
      };
      console.log(JSON.stringify(sarif, null, 2));
      process.exit(ok ? 0 : 1);
    }

    if (opts.json) {
      console.log(JSON.stringify({ ok, violations }, null, 2));
    } else {
      console.log('');
      printVerifyResult(violations, ok);
    }
    process.exit(ok ? 0 : 1);
  });

// ─── approve ─────────────────────────────────────────────────────────────────

program
  .command('approve [packages...]')
  .description('Approve packages in warden.lock.json (marks them as reviewed)')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--all', 'Approve all pending-review packages')
  .option('--rescan', 'Re-scan packages before approving (ensures capabilities are up-to-date)')
  .option(
    '--capability <cap>',
    'Approve only a specific capability (e.g. network). The package will be blocked from using any other capability.',
  )
  .option('--note <text>', 'Add a human-readable note to the approval (stored in warden.lock.json)')
  .option('--deny <cap>', 'Explicitly deny a specific capability (complement of --capability): package will be blocked from this capability even if it declared it')
  .action(async (pkgArgs: string[], opts: { dir: string; all: boolean; rescan: boolean; capability?: string; note?: string; deny?: string }) => {
    const projectDir = path.resolve(opts.dir);

    const VALID_CAPS = new Set(['network', 'process-spawn', 'dynamic-code', 'native-binding', 'filesystem-write', 'env-access', 'filesystem-read']);
    if (opts.capability && !VALID_CAPS.has(opts.capability)) {
      console.error(chalk.red(`Error: Unknown capability "${opts.capability}". Valid values: ${[...VALID_CAPS].join(', ')}`));
      process.exit(1);
    }
    if (opts.deny && !VALID_CAPS.has(opts.deny)) {
      console.error(chalk.red(`Error: Unknown capability "${opts.deny}". Valid values: ${[...VALID_CAPS].join(', ')}`));
      process.exit(1);
    }

    const lockfile = readLockfile(projectDir);

    if (!lockfile) {
      console.error(chalk.red('Error: No warden.lock.json found. Run `warden scan` first.'));
      process.exit(1);
    }

    if (!opts.all && pkgArgs.length === 0) {
      console.error(chalk.red('Error: Specify package name(s) or use --all.'));
      console.error(chalk.dim('  Examples:'));
      console.error(chalk.dim('    warden approve axios'));
      console.error(chalk.dim('    warden approve axios lodash debug'));
      console.error(chalk.dim('    warden approve --all'));
      process.exit(1);
    }

    // Determine which lockfile keys to approve
    let keysToApprove: string[];

    if (opts.all) {
      keysToApprove = Object.entries(lockfile.packages)
        .filter(([, p]) => p.status === 'pending-review')
        .map(([k]) => k);

      if (keysToApprove.length === 0) {
        console.log(chalk.green('\n  Nothing to approve — no packages are pending review.'));
        return;
      }
    } else {
      keysToApprove = pkgArgs.flatMap(arg => {
        // Match by exact key ("axios@1.6.0") or by name only ("axios")
        const exact = lockfile.packages[arg] ? [arg] : [];
        if (exact.length > 0) return exact;

        const byName = Object.keys(lockfile.packages).filter(k => {
          const nameEnd = k.lastIndexOf('@');
          return k.slice(0, nameEnd) === arg;
        });

        if (byName.length === 0) {
          console.error(chalk.red(`  Error: "${arg}" not found in lockfile.`));
        }
        return byName;
      });
    }

    if (keysToApprove.length === 0) {
      process.exit(1);
    }

    // Optional re-scan before approving
    if (opts.rescan) {
      const nodeModulesDir = path.join(projectDir, 'node_modules');
      if (fs.existsSync(nodeModulesDir)) {
        console.log(chalk.dim('\n  Re-scanning packages before approving...'));
        const { scanNodeModules } = await import('./analyzer/packageScanner') as typeof import('./analyzer/packageScanner');
        const { buildPolicyMap } = await import('./policy/policyGenerator') as typeof import('./policy/policyGenerator');
        const cache = buildCacheFromLockfile(lockfile);
        const results = await scanNodeModules(nodeModulesDir, cache);
        const fresh = buildPolicyMap(results);
        // Update capabilities from fresh scan (but don't overwrite status yet)
        for (const [key, newPol] of Object.entries(fresh)) {
          if (lockfile.packages[key]) {
            lockfile.packages[key].capabilities = newPol.capabilities;
            lockfile.packages[key].contentHash = newPol.contentHash;
          }
        }
      }
    }

    console.log('');
    let approved = 0;

    for (const key of keysToApprove) {
      const entry = lockfile.packages[key];
      if (!entry) continue;

      if (entry.status === 'unsandboxed') {
        console.log(
          chalk.yellow(`  !  Skipping ${chalk.bold(key)} `) +
          chalk.dim('(native .node addon — cannot be sandboxed, approval not meaningful)'),
        );
        continue;
      }

      const prevStatus = entry.status;
      entry.status = 'approved';
      delete entry.note;

      if (opts.note) { entry.note = opts.note; }

      if (opts.capability) {
        // Per-capability approval: record only the approved capability as allowed.
        // The hook uses allowedCapabilities (when present) in enforce mode.
        const existing = new Set(entry.allowedCapabilities ?? []);
        existing.add(opts.capability as import('./analyzer/capabilityMap').Capability);
        entry.allowedCapabilities = [...existing];
      } else {
        // Full approval: clear any previous per-capability restriction.
        delete entry.allowedCapabilities;
      }

      if (opts.deny) {
        const existingDenied = new Set(entry.deniedCapabilities ?? []);
        existingDenied.add(opts.deny as import('./analyzer/capabilityMap').Capability);
        entry.deniedCapabilities = [...existingDenied];
      }
      // Intentionally don't clear deniedCapabilities when --deny is absent:
      // re-approving preserves existing explicit denials. Use `warden unapprove` to reset.

      const capStr = opts.capability
        ? chalk.dim(`[allowed: ${opts.capability}]`)
        : entry.capabilities.length > 0
        ? chalk.dim(`[${entry.capabilities.join(', ')}]`)
        : chalk.dim('[no capabilities]');

      const statusChange = prevStatus !== 'approved'
        ? chalk.dim(` ${prevStatus} →`) + chalk.green(' approved')
        : chalk.green(' already approved');

      console.log(`  ${chalk.green('+')} ${chalk.bold(key)}  ${capStr}${statusChange}`);
      approved++;
    }

    if (approved > 0) {
      lockfile.generatedAt = new Date().toISOString();
      writeLockfile(projectDir, lockfile);
      console.log(chalk.green(`\n  ${approved} package(s) approved — ${LOCKFILE_NAME} updated.`));
    } else {
      console.log(chalk.dim('\n  No changes made.'));
    }
  });

// ─── run ─────────────────────────────────────────────────────────────────────

program
  .command('run <script>')
  .description('Execute a script with Warden observation (or enforcement with --enforce)')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--enforce', 'Block capability violations instead of just logging them')
  .option('--watch', 'Re-run the script whenever it changes (spawns a fresh child process each time)')
  .option(
    '--profile <profile>',
    'Policy profile: strict (additionally blocks env-access), lenient (allows filesystem-read + env-access without approval)',
  )
  .option('--timeout <ms>', 'Kill the script if it runs longer than this many milliseconds')
  .action(async (scriptArg: string, opts: { dir: string; enforce: boolean; watch: boolean; profile?: string; timeout?: string }) => {
    const projectDir = path.resolve(opts.dir);
    const config = readConfig(projectDir);
    const profile = (opts.profile ?? config.profile ?? 'default') as import('./runtime/moduleLoaderHook').Profile;
    const timeoutMs = opts.timeout ? parseInt(opts.timeout, 10) : 0;
    const scriptPath = path.resolve(scriptArg);

    if (!fs.existsSync(scriptPath)) {
      console.error(chalk.red(`Error: Script not found: ${scriptPath}`));
      process.exit(1);
    }

    const validProfiles = ['strict', 'default', 'lenient'];
    if (!validProfiles.includes(profile)) {
      console.error(chalk.red(`Error: Invalid profile "${profile}". Valid values: ${validProfiles.join(', ')}`));
      process.exit(1);
    }

    // --watch: delegate to child processes so hooks can be re-installed each run
    if (opts.watch) {
      const runArgs = [process.argv[1], 'run', scriptArg, '--dir', projectDir];
      if (opts.enforce) runArgs.push('--enforce');
      if (profile !== 'default') runArgs.push('--profile', profile);
      if (timeoutMs > 0) runArgs.push('--timeout', String(timeoutMs));

      const doRun = () => {
        process.stdout.write(chalk.dim(`\n[Warden] > Running ${scriptArg}\n`));
        spawnSync(process.execPath, runArgs, { stdio: 'inherit', timeout: timeoutMs || undefined });
      };

      doRun();
      process.stdout.write(chalk.dim(`\n[Warden] Watching ${scriptArg} for changes… (Ctrl+C to stop)\n`));

      let debounce: ReturnType<typeof setTimeout> | null = null;
      fs.watch(scriptPath, () => {
        if (debounce) clearTimeout(debounce);
        debounce = setTimeout(doRun, 150);
      });
      return; // keep process alive via fs.watch
    }

    const lockfile = readLockfile(projectDir);
    if (!lockfile) {
      console.error(chalk.red('Error: No warden.lock.json found. Run `warden scan` first.'));
      process.exit(1);
    }

    // Capture native import() before SES's lockdown() can patch Function.
    // new Function prevents tsc (module: CommonJS) from rewriting import() → require().
    // Must be created before any require('./runtime/...') calls since loading
    // moduleLoaderHook triggers ses/lockdown when --enforce is active.
    const { pathToFileURL } = require('node:url') as typeof import('node:url');
    const nativeImport = new Function('url', 'return import(url)') as (url: string) => Promise<unknown>;

    // Lazy imports: avoid loading ses before this command is chosen
    // (lockdown() must only be called here, not at module-load time)
    const { installModuleLoaderHook } = require('./runtime/moduleLoaderHook') as typeof import('./runtime/moduleLoaderHook');
    const { installEsmLoaderHook } = require('./runtime/esmLoaderHook') as typeof import('./runtime/esmLoaderHook');
    const { createViolationHandler } = require('./runtime/violationHandler') as typeof import('./runtime/violationHandler');

    const violationLog: Array<{ pkg: string; cap: string; api: string }> = [];

    const onViolation = createViolationHandler({
      mode: opts.enforce ? 'throw' : 'log',
      onViolation: (event) => {
        violationLog.push({ pkg: event.packageName, cap: event.capability, api: event.apiAccessed });
      },
    });

    // ESM violations arrive via MessagePort from the loader thread — calling them
    // from an event listener in enforce (throw) mode would produce an uncaught
    // event-loop exception (caught by SES before our try/catch).
    // ESM enforcement is handled by the loader thread returning stub modules;
    // we only need to log violations in the main thread.
    const esmOnViolation = createViolationHandler({
      mode: 'log',
      onViolation: (event) => {
        violationLog.push({ pkg: event.packageName, cap: event.capability, api: event.apiAccessed });
      },
    });

    const profileLabel = profile !== 'default' ? chalk.dim(` [${profile}]`) : '';
    const modeLabel = opts.enforce
      ? chalk.yellow.bold('[Warden] enforce mode active — violations will throw') + profileLabel
      : chalk.cyan.bold('[Warden] observation mode — violations will be logged') + profileLabel;
    console.log('\n' + modeLabel + '\n');

    // Install CJS hook (Module._load)
    const uninstallCjs = installModuleLoaderHook(lockfile, opts.enforce, onViolation, profile);

    // Install ESM hook (module.register) — works for import() and ESM scripts
    const uninstallEsm = installEsmLoaderHook(lockfile, opts.enforce, esmOnViolation, profile);

    // Detect whether the target script is ESM
    const isEsm = isEsmScript(scriptPath);

    let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
    if (timeoutMs > 0) {
      timeoutHandle = setTimeout(() => {
        console.error(chalk.red(`\n[Warden] Timeout: script exceeded ${timeoutMs}ms`));
        process.exit(1);
      }, timeoutMs);
      timeoutHandle.unref();
    }

    try {
      if (isEsm) {
        await nativeImport(pathToFileURL(scriptPath).href);
      } else {
        require(scriptPath);
      }
    } catch (err) {
      console.error(chalk.red(`\n[Warden] Script exited with error: ${(err as Error).message}`));
      process.exitCode = 1;
    } finally {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      uninstallCjs();
      uninstallEsm();
      if (violationLog.length > 0) {
        console.log(chalk.bold(`\n[Warden] ${violationLog.length} violation(s) recorded:`));
        for (const v of violationLog) {
          console.log(`  ${chalk.red('-')} ${v.pkg} → ${v.api} (${v.cap})`);
        }
      } else {
        console.log(chalk.green('\n[Warden] No capability violations detected.'));
      }
    }
  });

// ─── Helpers ─────────────────────────────────────────────────────────────────

function isEsmScript(scriptPath: string): boolean {
  if (scriptPath.endsWith('.mjs')) return true;
  if (scriptPath.endsWith('.cjs')) return false;
  // Check nearest package.json for "type": "module"
  let dir = path.dirname(scriptPath);
  for (let i = 0; i < 5; i++) {
    const pkgPath = path.join(dir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { type?: string };
        return pkg.type === 'module';
      } catch { break; }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return false;
}

function buildCacheFromLockfile(lock: LockfileData | null): Map<string, ScanCacheEntry> {
  const globalCache = loadGlobalCache();
  const cache = new Map<string, ScanCacheEntry>(globalCache);
  if (!lock) return cache;
  for (const [key, policy] of Object.entries(lock.packages)) {
    cache.set(key, {
      contentHash: policy.contentHash,
      result: {
        name: key.slice(0, key.lastIndexOf('@')),
        version: key.slice(key.lastIndexOf('@') + 1),
        contentHash: policy.contentHash,
        capabilities: policy.capabilities,
        status: policy.status === 'unsandboxed' ? 'unsandboxed' : 'scanned',
        hasNativeBindings: policy.status === 'unsandboxed',
        unanalyzableFiles: [],
        fileCount: 0,
      },
    });
  }
  return cache;
}

function detectPackageManager(projectDir: string): 'npm' | 'pnpm' | 'yarn' {
  if (fs.existsSync(path.join(projectDir, 'pnpm-lock.yaml'))) return 'pnpm';
  if (fs.existsSync(path.join(projectDir, 'yarn.lock'))) return 'yarn';
  return 'npm';
}

// ─── status ──────────────────────────────────────────────────────────────────

program
  .command('status')
  .description('Show approval status of all packages (reads lockfile, no rescan)')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .action((opts: { dir: string }) => {
    const projectDir = path.resolve(opts.dir);
    const lockfile = readLockfile(projectDir);

    if (!lockfile) {
      console.error(chalk.red('Error: No warden.lock.json found. Run `warden scan` first.'));
      process.exit(1);
    }

    printStatus(lockfile);
  });

// ─── audit ───────────────────────────────────────────────────────────────────

program
  .command('audit')
  .description('Show capability breakdown across all packages, grouped by risk level')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--json', 'Output raw JSON')
  .option('--fix', 'Auto-approve low-risk pending packages (only env-access and/or filesystem-read)')
  .action((opts: { dir: string; json: boolean; fix: boolean }) => {
    const projectDir = path.resolve(opts.dir);
    const lockfile = readLockfile(projectDir);

    if (!lockfile) {
      console.error(chalk.red('Error: No warden.lock.json found. Run `warden scan` first.'));
      process.exit(1);
    }

    if (opts.json) {
      const byCapability: Record<string, string[]> = {};
      for (const [key, policy] of Object.entries(lockfile.packages)) {
        for (const cap of policy.capabilities) {
          if (!byCapability[cap]) byCapability[cap] = [];
          byCapability[cap].push(key);
        }
      }
      console.log(JSON.stringify({
        total: Object.keys(lockfile.packages).length,
        byCapability,
      }, null, 2));
    } else {
      printAudit(lockfile);
    }

    if (opts.fix) {
      const LOW_RISK_ONLY = new Set(['env-access', 'filesystem-read']);
      const toFix = Object.entries(lockfile.packages).filter(([, p]) => {
        if (p.status !== 'pending-review') return false;
        return p.capabilities.every(c => LOW_RISK_ONLY.has(c));
      });

      if (toFix.length === 0) {
        console.log(chalk.dim('\n  --fix: No low-risk pending packages to auto-approve.'));
        return;
      }

      for (const [, entry] of toFix) {
        entry.status = 'approved';
        delete entry.note;
      }

      lockfile.generatedAt = new Date().toISOString();
      writeLockfile(projectDir, lockfile);
      console.log(chalk.green(`\n  --fix: Auto-approved ${toFix.length} low-risk package(s).`));
    }
  });

// ─── install ─────────────────────────────────────────────────────────────────

program
  .command('install [packages...]')
  .description('Run npm install then automatically scan and show packages needing approval')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--approve-all', 'Auto-approve all new packages after install (skips review prompt)')
  .allowUnknownOption()
  .action(async (pkgArgs: string[], opts: { dir: string; approveAll: boolean }, cmd) => {
    const projectDir = path.resolve(opts.dir);
    const config = readConfig(projectDir);
    const approveAll = opts.approveAll || (config.autoApprove ?? false);

    const pm = detectPackageManager(projectDir);
    const unknownArgs = cmd.args.filter((a: string) => !pkgArgs.includes(a));
    const pmArgs = ['install', ...pkgArgs, ...unknownArgs];

    console.log(chalk.bold(`\nWarden install — running ${pm} ${pmArgs.join(' ')}\n`));

    const result = spawnSync(pm, pmArgs, {
      cwd: projectDir,
      stdio: 'inherit',
      shell: false,
    });

    if (result.status !== 0) {
      console.error(chalk.red(`\nError: ${pm} install failed.`));
      process.exit(result.status ?? 1);
    }

    // Rescan node_modules
    const nodeModulesDir = path.join(projectDir, 'node_modules');
    if (!fs.existsSync(nodeModulesDir)) {
      console.error(chalk.red('Error: No node_modules found after install.'));
      process.exit(1);
    }

    console.log(chalk.bold('\nWarden install — scanning for new capabilities...\n'));

    const existing = readLockfile(projectDir);
    const cache = buildCacheFromLockfile(existing);
    const results = await scanNodeModules(
      nodeModulesDir,
      cache,
      (done, total, pkg) => printProgress(done, total, pkg),
    );

    const newPolicies = buildPolicyMap(results);
    const merged = mergeLockfile(existing, newPolicies);
    writeLockfile(projectDir, merged);

    const newPending = Object.entries(merged.packages).filter(([, p]) => p.status === 'pending-review');

    if (newPending.length === 0) {
      console.log(chalk.green('\n  All packages approved — no review needed.'));
      return;
    }

    if (approveAll) {
      for (const [key, entry] of newPending) {
        entry.status = 'approved';
        delete entry.note;
        console.log(`  ${chalk.green('+')} Auto-approved ${chalk.bold(key)}`);
      }
      merged.generatedAt = new Date().toISOString();
      writeLockfile(projectDir, merged);
      console.log(chalk.green(`\n  ${newPending.length} package(s) auto-approved.`));
    } else {
      console.log(chalk.yellow(`\n  ${newPending.length} package(s) need review before you can use --enforce:`));
      for (const [key, p] of newPending) {
        const caps = p.capabilities.join(', ') || 'none';
        console.log(`    ${chalk.yellow('-')} ${chalk.bold(key)}  ${chalk.dim(`[${caps}]`)}`);
        if (p.note) console.log(`      ${chalk.dim(p.note)}`);
      }
      console.log(chalk.dim('\n  Run `warden approve --all` to approve all, or `warden approve <package>` individually.'));
    }
  });

// ─── update ──────────────────────────────────────────────────────────────────

program
  .command('update [packages...]')
  .description('Run npm update then automatically scan and show packages needing approval')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--approve-all', 'Auto-approve all changed packages after update (skips review prompt)')
  .allowUnknownOption()
  .action(async (pkgArgs: string[], opts: { dir: string; approveAll: boolean }, cmd) => {
    const projectDir = path.resolve(opts.dir);
    const config = readConfig(projectDir);
    const approveAll = opts.approveAll || (config.autoApprove ?? false);

    const pm = detectPackageManager(projectDir);
    const unknownArgs = cmd.args.filter((a: string) => !pkgArgs.includes(a));
    const pmArgs = ['update', ...pkgArgs, ...unknownArgs];

    console.log(chalk.bold(`\nWarden update — running ${pm} ${pmArgs.join(' ')}\n`));

    const result = spawnSync(pm, pmArgs, {
      cwd: projectDir,
      stdio: 'inherit',
      shell: false,
    });

    if (result.status !== 0) {
      console.error(chalk.red(`\nError: ${pm} update failed.`));
      process.exit(result.status ?? 1);
    }

    const nodeModulesDir = path.join(projectDir, 'node_modules');
    if (!fs.existsSync(nodeModulesDir)) {
      console.error(chalk.red('Error: No node_modules found after update.'));
      process.exit(1);
    }

    console.log(chalk.bold('\nWarden update — scanning for capability changes...\n'));

    const existing = readLockfile(projectDir);
    const cache = buildCacheFromLockfile(existing);
    const results = await scanNodeModules(
      nodeModulesDir,
      cache,
      (done, total, pkg) => printProgress(done, total, pkg),
    );

    const newPolicies = buildPolicyMap(results);
    const merged = mergeLockfile(existing, newPolicies);
    writeLockfile(projectDir, merged);

    const newPending = Object.entries(merged.packages).filter(([, p]) => p.status === 'pending-review');

    if (newPending.length === 0) {
      console.log(chalk.green('\n  All packages approved — no capability changes detected.'));
      return;
    }

    if (approveAll) {
      for (const [key, entry] of newPending) {
        entry.status = 'approved';
        delete entry.note;
        console.log(`  ${chalk.green('+')} Auto-approved ${chalk.bold(key)}`);
      }
      merged.generatedAt = new Date().toISOString();
      writeLockfile(projectDir, merged);
      console.log(chalk.green(`\n  ${newPending.length} package(s) auto-approved.`));
    } else {
      console.log(chalk.yellow(`\n  ${newPending.length} package(s) have new or changed capabilities:`));
      for (const [key, p] of newPending) {
        const caps = p.capabilities.join(', ') || 'none';
        console.log(`    ${chalk.yellow('-')} ${chalk.bold(key)}  ${chalk.dim(`[${caps}]`)}`);
        if (p.note) console.log(`      ${chalk.dim(p.note)}`);
      }
      console.log(chalk.dim('\n  Run `warden diff` to see details, then `warden approve <package>` to approve.'));
    }
  });

// ─── explain ─────────────────────────────────────────────────────────────────

program
  .command('explain <pkg>')
  .description('Show which files and lines triggered each capability for a package')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--json', 'Output raw JSON')
  .action((pkgArg: string, opts: { dir: string; json: boolean }) => {
    const projectDir = path.resolve(opts.dir);
    const nodeModulesDir = path.join(projectDir, 'node_modules');

    if (!fs.existsSync(nodeModulesDir)) {
      console.error(chalk.red(`Error: No node_modules at ${nodeModulesDir}`));
      process.exit(1);
    }

    const result = explainPackage(nodeModulesDir, pkgArg);

    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    printExplain(result);
  });

// ─── unapprove ───────────────────────────────────────────────────────────────

program
  .command('unapprove [packages...]')
  .description('Revert packages back to pending-review status (removes approval)')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--all', 'Unapprove all currently approved packages')
  .action((pkgArgs: string[], opts: { dir: string; all: boolean }) => {
    const projectDir = path.resolve(opts.dir);
    const lockfile = readLockfile(projectDir);

    if (!lockfile) {
      console.error(chalk.red('Error: No warden.lock.json found. Run `warden scan` first.'));
      process.exit(1);
    }

    if (!opts.all && pkgArgs.length === 0) {
      console.error(chalk.red('Error: Specify package name(s) or use --all.'));
      process.exit(1);
    }

    let keysToUnapprove: string[];

    if (opts.all) {
      keysToUnapprove = Object.entries(lockfile.packages)
        .filter(([, p]) => p.status === 'approved')
        .map(([k]) => k);
    } else {
      keysToUnapprove = pkgArgs.flatMap(arg => {
        const exact = lockfile.packages[arg] ? [arg] : [];
        if (exact.length > 0) return exact;
        return Object.keys(lockfile.packages).filter(k => {
          const i = k.lastIndexOf('@');
          return k.slice(0, i) === arg;
        });
      });
    }

    if (keysToUnapprove.length === 0) {
      console.log(chalk.dim('\n  Nothing to unapprove.'));
      return;
    }

    console.log('');
    let count = 0;
    for (const key of keysToUnapprove) {
      const entry = lockfile.packages[key];
      if (!entry) continue;
      if (entry.status === 'unsandboxed') {
        console.log(chalk.dim(`  !  Skipping ${chalk.bold(key)} (native addon — unsandboxed status cannot be changed)`));
        continue;
      }
      entry.status = 'pending-review';
      delete entry.allowedCapabilities;
      delete entry.deniedCapabilities;
      delete entry.note;
      console.log(`  ${chalk.yellow('-')} ${chalk.bold(key)}  ${chalk.dim('approved -> pending-review')}`);
      count++;
    }

    if (count > 0) {
      lockfile.generatedAt = new Date().toISOString();
      writeLockfile(projectDir, lockfile);
      console.log(chalk.yellow(`\n  ${count} package(s) set to pending-review — ${LOCKFILE_NAME} updated.`));
    }
  });

// ─── graph ───────────────────────────────────────────────────────────────────

program
  .command('graph [pkg]')
  .description('Show the dependency tree with capability annotations')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--depth <n>', 'Maximum depth to display (default: 3)', '3')
  .option('--json', 'Output raw JSON')
  .action((pkgArg: string | undefined, opts: { dir: string; depth: string; json: boolean }) => {
    const projectDir = path.resolve(opts.dir);
    const nodeModulesDir = path.join(projectDir, 'node_modules');
    const lockfile = readLockfile(projectDir);

    if (!lockfile) {
      console.error(chalk.red('Error: No warden.lock.json found. Run `warden scan` first.'));
      process.exit(1);
    }

    if (!fs.existsSync(nodeModulesDir)) {
      console.error(chalk.red(`Error: No node_modules at ${nodeModulesDir}`));
      process.exit(1);
    }

    const graph = buildDepGraph(nodeModulesDir, lockfile);
    const maxDepth = parseInt(opts.depth, 10) || 3;

    if (opts.json) {
      const obj: Record<string, unknown> = {};
      for (const [key, node] of graph) {
        obj[key] = { capabilities: node.capabilities, deps: node.deps };
      }
      console.log(JSON.stringify(obj, null, 2));
      return;
    }

    let rootKeys: string[] = [];
    if (pkgArg) {
      rootKeys = Array.from(graph.keys()).filter(k => {
        const i = k.lastIndexOf('@');
        return k.slice(0, i) === pkgArg || k === pkgArg;
      });
      if (rootKeys.length === 0) {
        console.error(chalk.red(`Error: Package "${pkgArg}" not found in lockfile.`));
        process.exit(1);
      }
    }

    printDepGraph(graph, rootKeys, maxDepth);
  });

// ─── integrity ───────────────────────────────────────────────────────────────

program
  .command('integrity')
  .description('Check that all packages were installed from the npm registry and have integrity hashes')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--json', 'Output raw JSON')
  .action((opts: { dir: string; json: boolean }) => {
    const projectDir = path.resolve(opts.dir);

    // Try package-lock.json (npm 7+ v3) or node_modules/.package-lock.json
    const lockJsonPath = fs.existsSync(path.join(projectDir, 'package-lock.json'))
      ? path.join(projectDir, 'package-lock.json')
      : path.join(projectDir, 'node_modules', '.package-lock.json');

    if (!fs.existsSync(lockJsonPath)) {
      console.error(chalk.red('Error: No package-lock.json found. Run `npm install` first.'));
      process.exit(1);
    }

    let pkgLock: {
      packages?: Record<string, { version?: string; resolved?: string; integrity?: string; }>;
      dependencies?: Record<string, { version?: string; resolved?: string; integrity?: string; }>;
    };

    try {
      pkgLock = JSON.parse(fs.readFileSync(lockJsonPath, 'utf8'));
    } catch {
      console.error(chalk.red('Error: Could not parse package-lock.json.'));
      process.exit(1);
    }

    interface IntegrityIssue {
      package: string;
      issue: string;
    }
    const issues: IntegrityIssue[] = [];
    const checked: string[] = [];

    // Support both lockfileVersion 1 (dependencies) and 2/3 (packages)
    const entries = pkgLock.packages
      ? Object.entries(pkgLock.packages).filter(([k]) => k.startsWith('node_modules/') && !k.slice(13).includes('node_modules/'))
      : Object.entries(pkgLock.dependencies ?? {});

    for (const [pkgPath, meta] of entries) {
      const pkgName = pkgLock.packages
        ? pkgPath.replace(/^node_modules\//, '')
        : pkgPath;

      const displayName = meta.version ? `${pkgName}@${meta.version}` : pkgName;
      checked.push(displayName);

      if (!meta.integrity) {
        issues.push({ package: displayName, issue: 'missing integrity hash — package may have been installed from a local path or git ref' });
        continue;
      }

      if (meta.resolved && !meta.resolved.startsWith('https://registry.npmjs.org/') && !meta.resolved.startsWith('https://registry.yarnpkg.com/')) {
        issues.push({ package: displayName, issue: `non-registry source: ${meta.resolved}` });
      }
    }

    if (opts.json) {
      console.log(JSON.stringify({ checked: checked.length, issues }, null, 2));
      process.exit(issues.length > 0 ? 1 : 0);
    }

    console.log('');
    console.log(chalk.bold.underline('Warden Integrity Check'));
    console.log(`  Checked ${checked.length} packages from ${path.basename(lockJsonPath)}`);
    console.log('');

    if (issues.length === 0) {
      console.log(chalk.green('  All packages installed from registry with valid integrity hashes.'));
    } else {
      console.log(chalk.red.bold(`  ${issues.length} package(s) with integrity concerns:`));
      console.log('');
      for (const issue of issues) {
        console.log(`  ${chalk.red('-')} ${chalk.bold(issue.package)}`);
        console.log(`    ${chalk.dim(issue.issue)}`);
      }
    }
    console.log('');

    process.exit(issues.length > 0 ? 1 : 0);
  });

// ─── report ──────────────────────────────────────────────────────────────────

program
  .command('report')
  .description('Generate a Markdown security report for the current lockfile')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .option('--output <file>', 'Output file path (default: warden-report.md)', 'warden-report.md')
  .option('--format <fmt>', 'Output format (default: md)', 'md')
  .action((opts: { dir: string; output: string; format: string }) => {
    const projectDir = path.resolve(opts.dir);
    const lockfile = readLockfile(projectDir);

    if (!lockfile) {
      console.error(chalk.red('Error: No warden.lock.json found. Run `warden scan` first.'));
      process.exit(1);
    }

    const md = generateMarkdownReport(lockfile);
    const outPath = path.resolve(opts.output);
    fs.writeFileSync(outPath, md, 'utf8');
    console.log(chalk.green(`\n  Warden report written to ${outPath}`));
  });

// ─── watch ───────────────────────────────────────────────────────────────────

program
  .command('watch')
  .description('Watch node_modules for changes and auto-rescan on dependency updates')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .action(async (opts: { dir: string }) => {
    const projectDir = path.resolve(opts.dir);
    const nodeModulesDir = path.join(projectDir, 'node_modules');

    if (!fs.existsSync(nodeModulesDir)) {
      console.error(chalk.red(`Error: No node_modules at ${nodeModulesDir}`));
      process.exit(1);
    }

    let currentLock = readLockfile(projectDir);

    if (!currentLock) {
      console.error(chalk.red('Error: No warden.lock.json found. Run `warden scan` first.'));
      process.exit(1);
    }

    console.log(chalk.bold('\nWarden watch — monitoring node_modules for changes...'));
    console.log(chalk.dim('  Press Ctrl+C to stop.\n'));

    let debounce: ReturnType<typeof setTimeout> | null = null;

    const rescan = async () => {
      console.log(chalk.dim('\n[warden watch] Change detected — rescanning...'));
      try {
        const cache = buildCacheFromLockfile(currentLock);
        const results = await scanNodeModules(nodeModulesDir, cache);
        const newPolicies = buildPolicyMap(results);
        const newLock = mergeLockfile(null, newPolicies);

        const summary = diffLockfiles(currentLock, newLock);
        printDiffSummary(summary, false);

        if (summary.packagesWithNewCapabilities > 0) {
          console.log(chalk.red.bold('[warden watch] WARNING: New capabilities detected. Run `warden approve` after reviewing.'));
        }

        currentLock = readLockfile(projectDir) ?? currentLock;
      } catch (err) {
        console.error(chalk.red(`[warden watch] Rescan error: ${(err as Error).message}`));
      }
    };

    fs.watch(nodeModulesDir, { recursive: true }, () => {
      if (debounce) clearTimeout(debounce);
      debounce = setTimeout(() => { void rescan(); }, 1000);
    });
  });

// ─── config init ─────────────────────────────────────────────────────────────

const configCmd = program.command('config').description('Configuration management');

configCmd
  .command('init')
  .description('Interactively create a .wardenrc.json configuration file')
  .option('-d, --dir <path>', 'Project directory (default: cwd)', process.cwd())
  .action(async (opts: { dir: string }) => {
    const projectDir = path.resolve(opts.dir);
    const configPath = path.join(projectDir, '.wardenrc.json');

    if (fs.existsSync(configPath)) {
      console.log(chalk.yellow(`\n  .wardenrc.json already exists at ${configPath}`));
      console.log(chalk.dim('  Delete it first if you want to re-initialize.'));
      return;
    }

    const readline = await import('node:readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    const ask = (q: string): Promise<string> =>
      new Promise(resolve => rl.question(q, answer => resolve(answer.trim())));

    console.log('');
    console.log(chalk.bold('Warden config init'));
    console.log(chalk.dim('  This will create a .wardenrc.json in your project directory.'));
    console.log('');

    const profileAnswer = await ask('  Default profile [strict/default/lenient] (default: default): ');
    const profile = ['strict', 'default', 'lenient'].includes(profileAnswer) ? profileAnswer : 'default';

    const autoApproveAnswer = await ask('  Auto-approve new packages after warden install/update? [y/N]: ');
    const autoApprove = autoApproveAnswer.toLowerCase() === 'y';

    const ignoreAnswer = await ask('  Packages to ignore in warden verify (comma-separated, leave empty for none): ');
    const ignore = ignoreAnswer ? ignoreAnswer.split(',').map(s => s.trim()).filter(Boolean) : [];

    rl.close();

    const config = {
      ...(profile !== 'default' ? { profile } : {}),
      ...(autoApprove ? { autoApprove } : {}),
      ...(ignore.length > 0 ? { ignore } : {}),
    };

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8');

    console.log('');
    console.log(chalk.green(`  Created .wardenrc.json:`));
    console.log(chalk.dim('  ' + JSON.stringify(config, null, 2).replace(/\n/g, '\n  ')));
    console.log('');
  });

program.parse();
