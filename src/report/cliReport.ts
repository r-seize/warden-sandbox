import chalk from 'chalk';
import { Capability } from '../analyzer/capabilityMap';
import { PackageScanResult } from '../analyzer/packageScanner';
import { DiffSummary, PackageDiff } from '../policy/policyDiff';
import { LockfileData, PackageStatus } from '../policy/lockfile';
import { PackageExplainResult } from '../analyzer/explainer';
import { DepGraph } from '../analyzer/depGraph';
import { riskScore, riskLabel } from '../analyzer/riskScore';

// ─── Capability formatting ───────────────────────────────────────────────────

const CAPABILITY_COLORS: Record<Capability, (s: string) => string> = {
  'network':          chalk.red,
  'process-spawn':    chalk.red,
  'dynamic-code':     chalk.red,
  'native-binding':   chalk.bgRed.white,
  'filesystem-write': chalk.yellow,
  'env-access':       chalk.yellow,
  'filesystem-read':  chalk.cyan,
};

const CAPABILITY_LABELS: Record<Capability, string> = {
  'network':          '[NETWORK]',
  'process-spawn':    '[SPAWN]',
  'dynamic-code':     '[EVAL]',
  'native-binding':   '[NATIVE]',
  'filesystem-write': '[FS-WRITE]',
  'env-access':       '[ENV]',
  'filesystem-read':  '[FS-READ]',
};

export function formatCapability(cap: Capability): string {
  const color = CAPABILITY_COLORS[cap] ?? chalk.white;
  const label = CAPABILITY_LABELS[cap] ?? `[${cap.toUpperCase()}]`;
  return color(label);
}

const STATUS_COLORS: Record<PackageStatus, (s: string) => string> = {
  'approved':       chalk.green,
  'pending-review': chalk.yellow,
  'unsandboxed':    chalk.bgRed.white,
  'unanalyzable':   chalk.magenta,
};

export function formatStatus(status: PackageStatus): string {
  return STATUS_COLORS[status](status.toUpperCase());
}

// ─── Scan summary ────────────────────────────────────────────────────────────

export function printScanSummary(results: PackageScanResult[]): void {
  const withCaps = results.filter(r => r.capabilities.length > 0);
  const unsandboxed = results.filter(r => r.hasNativeBindings);
  const clean = results.filter(r => r.capabilities.length === 0 && !r.hasNativeBindings);

  console.log('');
  console.log(chalk.bold.underline('Warden Scan Summary'));
  console.log(`  Total packages:    ${chalk.bold(String(results.length))}`);
  console.log(`  With capabilities: ${chalk.yellow(String(withCaps.length))}`);
  console.log(`  Native addons:     ${unsandboxed.length > 0 ? chalk.bgRed.white(String(unsandboxed.length)) : chalk.green('0')}`);
  console.log(`  Clean:             ${chalk.green(String(clean.length))}`);
  console.log('');

  // Print packages with capabilities in a compact table
  if (withCaps.length > 0) {
    console.log(chalk.bold('Packages with detected capabilities:'));
    console.log('');

    const maxNameLen = Math.min(
      40,
      Math.max(...withCaps.map(r => `${r.name}@${r.version}`.length)),
    );

    for (const result of withCaps) {
      const nameVer = `${result.name}@${result.version}`;
      const padded = nameVer.length > maxNameLen
        ? nameVer.slice(0, maxNameLen - 1) + '…'
        : nameVer.padEnd(maxNameLen);

      const caps = result.capabilities.map(formatCapability).join('  ');
      const marker = result.hasNativeBindings
        ? chalk.bgRed.white(' NATIVE ') + ' '
        : result.unanalyzableFiles.length > 0
        ? chalk.magenta(' ~PARTIAL ') + ' '
        : '  ';

      console.log(`  ${chalk.dim(padded)}  ${marker}${caps}`);
    }
    console.log('');
  }

  if (unsandboxed.length > 0) {
    console.log(chalk.bgRed.white(' WARNING ') + chalk.bold(' Native addons found — these packages CANNOT be sandboxed:'));
    for (const r of unsandboxed) {
      console.log(`  ${chalk.red('-')} ${r.name}@${r.version}`);
    }
    console.log('');
  }
}

// ─── Diff output ─────────────────────────────────────────────────────────────

export function printDiffSummary(summary: DiffSummary, verbose = false): void {
  const { diffs } = summary;

  const hasChanges = summary.newPackages > 0
    || summary.removedPackages > 0
    || summary.packagesWithNewCapabilities > 0
    || summary.packagesWithContentChanges > 0;

  console.log('');
  console.log(chalk.bold.underline('Warden Diff'));
  console.log(`  New packages:           ${summary.newPackages > 0 ? chalk.yellow(String(summary.newPackages)) : chalk.green('0')}`);
  console.log(`  Removed packages:       ${String(summary.removedPackages)}`);
  console.log(`  New capabilities:       ${summary.packagesWithNewCapabilities > 0 ? chalk.red(String(summary.packagesWithNewCapabilities)) : chalk.green('0')}`);
  console.log(`  Content-only changes:   ${String(summary.packagesWithContentChanges)}`);
  console.log(`  Unchanged:              ${chalk.dim(String(summary.unchanged))}`);
  console.log('');

  if (!hasChanges) {
    console.log(chalk.green('  No security-relevant changes detected.'));
    console.log('');
    return;
  }

  // Security-critical: new capabilities on existing packages
  const newCapDiffs = diffs.filter(d => d.kind === 'new-capability');
  if (newCapDiffs.length > 0) {
    console.log(chalk.red.bold('  !! Packages with NEW capabilities (review required):'));
    console.log('');
    for (const d of newCapDiffs) {
      printPackageDiff(d);
    }
  }

  // New packages
  const newPkgDiffs = diffs.filter(d => d.kind === 'new-package' && d.addedCapabilities.length > 0);
  if (newPkgDiffs.length > 0) {
    console.log(chalk.yellow.bold('  New packages with capabilities:'));
    console.log('');
    for (const d of newPkgDiffs) {
      printPackageDiff(d);
    }
  }

  if (verbose) {
    const contentChanges = diffs.filter(d => d.kind === 'content-changed');
    if (contentChanges.length > 0) {
      console.log(chalk.cyan.bold('  Packages with content changes (same capabilities):'));
      for (const d of contentChanges) {
        console.log(`    ${chalk.dim(d.key)}  (hash changed)`);
      }
      console.log('');
    }
  }
}

function printPackageDiff(d: PackageDiff): void {
  console.log(`  ${chalk.bold(d.key)}`);
  if (d.addedCapabilities.length > 0) {
    console.log(`    ${chalk.red('+')} Added:   ${d.addedCapabilities.map(formatCapability).join('  ')}`);
  }
  if (d.removedCapabilities.length > 0) {
    console.log(`    ${chalk.green('-')} Removed: ${d.removedCapabilities.map(c => chalk.dim(c)).join('  ')}`);
  }
  if (d.newPolicy?.note) {
    console.log(`    ${chalk.dim('note:')} ${d.newPolicy.note}`);
  }
  console.log('');
}

// ─── Lockfile overview ───────────────────────────────────────────────────────

export function printLockfileOverview(lock: LockfileData): void {
  const entries = Object.entries(lock.packages);
  const pending = entries.filter(([, p]) => p.status === 'pending-review');
  const unsandboxed = entries.filter(([, p]) => p.status === 'unsandboxed');
  const approved = entries.filter(([, p]) => p.status === 'approved');

  console.log('');
  console.log(chalk.bold.underline('Warden Lockfile Status'));
  console.log(`  Generated: ${chalk.dim(lock.generatedAt)}`);
  console.log(`  Total:     ${entries.length}`);
  console.log(`  Approved:  ${chalk.green(String(approved.length))}`);
  console.log(`  Pending:   ${pending.length > 0 ? chalk.yellow(String(pending.length)) : '0'}`);
  console.log(`  Native:    ${unsandboxed.length > 0 ? chalk.bgRed.white(String(unsandboxed.length)) : '0'}`);
  console.log('');

  if (pending.length > 0) {
    console.log(chalk.yellow.bold('  Pending review:'));
    for (const [key, policy] of pending) {
      const caps = policy.capabilities.map(c => formatCapability(c as Capability)).join('  ');
      console.log(`    ${chalk.yellow('-')} ${key}  ${caps}`);
      if (policy.note) console.log(`      ${chalk.dim(policy.note)}`);
    }
    console.log('');
  }
}

// ─── Verify result ───────────────────────────────────────────────────────────

export function printVerifyResult(violations: string[], ok: boolean): void {
  if (ok) {
    console.log(chalk.green.bold('  + All packages match the committed lockfile.'));
    return;
  }
  console.log(chalk.red.bold('  x Lockfile violations found:'));
  for (const v of violations) {
    console.log(`    ${chalk.red('-')} ${v}`);
  }
}

// ─── Status overview ─────────────────────────────────────────────────────────

export function printStatus(lock: LockfileData): void {
  const entries = Object.entries(lock.packages);
  const byStatus: Record<string, typeof entries> = {
    'pending-review': [],
    'unsandboxed': [],
    'approved': [],
    'unanalyzable': [],
  };
  for (const entry of entries) {
    (byStatus[entry[1].status] ?? byStatus['approved']).push(entry);
  }

  console.log('');
  console.log(chalk.bold.underline('Warden Status'));
  console.log(chalk.dim(`  Generated: ${lock.generatedAt}`));
  console.log('');
  console.log(`  ${chalk.green('+')} Approved        ${chalk.green(String(byStatus['approved'].length))}`);
  console.log(`  ${chalk.yellow('!')} Pending review  ${byStatus['pending-review'].length > 0 ? chalk.yellow(String(byStatus['pending-review'].length)) : '0'}`);
  console.log(`  ${chalk.bgRed.white('x')} Unsandboxed    ${byStatus['unsandboxed'].length > 0 ? chalk.red(String(byStatus['unsandboxed'].length)) : '0'}`);
  console.log(`  ${chalk.magenta('~')} Unanalyzable    ${byStatus['unanalyzable'].length > 0 ? chalk.magenta(String(byStatus['unanalyzable'].length)) : '0'}`);
  console.log('');

  if (byStatus['pending-review'].length > 0) {
    console.log(chalk.yellow.bold('  Pending review — run `warden approve` to unblock:'));
    for (const [key, p] of byStatus['pending-review']) {
      const caps = p.capabilities.map(c => formatCapability(c as Capability)).join('  ');
      console.log(`    ${chalk.yellow('-')} ${chalk.bold(key)}  ${caps}`);
      if (p.note) console.log(`      ${chalk.dim(p.note)}`);
    }
    console.log('');
  }

  if (byStatus['unsandboxed'].length > 0) {
    console.log(chalk.red.bold('  Unsandboxed (native .node addons):'));
    for (const [key] of byStatus['unsandboxed']) {
      console.log(`    ${chalk.red('-')} ${key}`);
    }
    console.log('');
  }
}

// ─── Audit — capability breakdown ────────────────────────────────────────────

const HIGH_RISK: Capability[] = ['network', 'process-spawn', 'dynamic-code', 'native-binding'];
const MEDIUM_RISK: Capability[] = ['filesystem-write', 'env-access'];
const LOW_RISK: Capability[] = ['filesystem-read'];

export function printAudit(lock: LockfileData): void {
  const entries = Object.entries(lock.packages);

  // capability → packages that have it
  const byCapability = new Map<Capability, string[]>();
  for (const [key, policy] of entries) {
    for (const cap of policy.capabilities as Capability[]) {
      if (!byCapability.has(cap)) byCapability.set(cap, []);
      byCapability.get(cap)!.push(key);
    }
  }

  const total = entries.length;
  const withCaps = entries.filter(([, p]) => p.capabilities.length > 0 || p.status === 'unsandboxed').length;
  const clean = total - withCaps;

  console.log('');
  console.log(chalk.bold.underline('Warden Capability Audit'));
  console.log(`  ${total} packages total — ${chalk.green(String(clean))} clean, ${chalk.yellow(String(withCaps))} with capabilities`);
  console.log('');

  function printGroup(label: string, caps: Capability[], color: (s: string) => string): void {
    const relevant = caps.filter(c => byCapability.has(c));
    if (relevant.length === 0) return;

    console.log(color(chalk.bold(`  ${label}`)));
    for (const cap of relevant) {
      const pkgs = byCapability.get(cap)!;
      const icon = CAPABILITY_LABELS[cap] ?? `[${cap.toUpperCase()}]`;
      const sample = pkgs.slice(0, 3).map(p => chalk.dim(p)).join(', ');
      const more = pkgs.length > 3 ? chalk.dim(` +${pkgs.length - 3} more`) : '';
      console.log(`    ${color(`${icon} ${cap.padEnd(18)}`)}  ${pkgs.length} pkg${pkgs.length !== 1 ? 's' : ''}  ${sample}${more}`);
    }
    console.log('');
  }

  printGroup('HIGH RISK', HIGH_RISK, chalk.red);
  printGroup('MEDIUM RISK', MEDIUM_RISK, chalk.yellow);
  printGroup('LOW RISK', LOW_RISK, chalk.cyan);

  if (byCapability.size === 0) {
    console.log(chalk.green('  All packages are clean — no sensitive capabilities detected.'));
    console.log('');
  }
}

// ─── Progress bar ────────────────────────────────────────────────────────────

export function printProgress(done: number, total: number, current: string): void {
  const pct = total === 0 ? 100 : Math.floor((done / total) * 100);
  const bar = '█'.repeat(Math.floor(pct / 4)) + '░'.repeat(25 - Math.floor(pct / 4));
  const truncated = current.length > 35 ? current.slice(0, 34) + '…' : current.padEnd(35);
  process.stdout.write(`\r  ${bar} ${String(pct).padStart(3)}%  ${chalk.dim(truncated)}`);
  if (done === total) process.stdout.write('\n');
}

// ─── Explain ─────────────────────────────────────────────────────────────────

export function printExplain(result: PackageExplainResult): void {
  console.log('');
  console.log(chalk.bold.underline(`Warden Explain: ${result.name}@${result.version}`));
  console.log(chalk.dim(`  Location: ${result.pkgDir}`));
  console.log('');

  if (result.evidence.length === 0) {
    console.log(chalk.green('  No capabilities detected — package is clean.'));
    console.log('');
    return;
  }

  // Group evidence by capability
  const byCap = new Map<Capability, typeof result.evidence>();
  for (const ev of result.evidence) {
    if (!byCap.has(ev.capability)) byCap.set(ev.capability, []);
    byCap.get(ev.capability)!.push(ev);
  }

  for (const [cap, evList] of byCap) {
    console.log(`  ${formatCapability(cap)}  ${chalk.dim(`(${evList.length} occurrence${evList.length !== 1 ? 's' : ''})`)}`);
    for (const ev of evList.slice(0, 5)) {
      console.log(`    ${chalk.dim(ev.file)}:${chalk.cyan(String(ev.line))}`);
      console.log(`      ${chalk.dim(ev.snippet)}`);
    }
    if (evList.length > 5) {
      console.log(chalk.dim(`    ... and ${evList.length - 5} more`));
    }
    console.log('');
  }

  if (result.unanalyzableFiles.length > 0) {
    console.log(chalk.magenta(`  ${result.unanalyzableFiles.length} file(s) could not be parsed (may contain additional capabilities):`));
    for (const f of result.unanalyzableFiles.slice(0, 5)) {
      console.log(chalk.dim(`    - ${f}`));
    }
    console.log('');
  }
}

// ─── Markdown report ─────────────────────────────────────────────────────────

export function generateMarkdownReport(lock: LockfileData): string {
  const entries = Object.entries(lock.packages);
  const approved = entries.filter(([, p]) => p.status === 'approved');
  const pending = entries.filter(([, p]) => p.status === 'pending-review');
  const unsandboxed = entries.filter(([, p]) => p.status === 'unsandboxed');

  const scored = entries.map(([key, p]) => ({ key, policy: p, score: riskScore(p) }));
  const highRisk = scored.filter(e => e.score >= 40);
  const top10 = [...scored].sort((a, b) => b.score - a.score).slice(0, 10);

  const capCount = new Map<string, number>();
  for (const [, p] of entries) {
    for (const cap of p.capabilities) {
      capCount.set(cap, (capCount.get(cap) ?? 0) + 1);
    }
  }

  const lines: string[] = [];

  lines.push('# Warden Security Report');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Metric | Count |');
  lines.push('|---|---|');
  lines.push(`| Total packages | ${entries.length} |`);
  lines.push(`| Approved | ${approved.length} |`);
  lines.push(`| Pending review | ${pending.length} |`);
  lines.push(`| Unsandboxed (native) | ${unsandboxed.length} |`);
  lines.push(`| High-risk (score >= 40) | ${highRisk.length} |`);
  lines.push('');

  lines.push('## Top 10 Highest Risk Packages');
  lines.push('');
  lines.push('| Package | Score | Risk | Capabilities |');
  lines.push('|---|---|---|---|');
  for (const e of top10) {
    const label = riskLabel(e.score);
    const caps = e.policy.capabilities.join(', ') || 'none';
    lines.push(`| ${e.key} | ${e.score} | ${label} | ${caps} |`);
  }
  lines.push('');

  if (pending.length > 0) {
    lines.push('## Packages Pending Review');
    lines.push('');
    lines.push('| Package | Capabilities |');
    lines.push('|---|---|');
    for (const [key, p] of pending) {
      const caps = p.capabilities.join(', ') || 'none';
      lines.push(`| ${key} | ${caps} |`);
    }
    lines.push('');
  }

  lines.push('## Capability Breakdown');
  lines.push('');
  lines.push('| Capability | Package Count |');
  lines.push('|---|---|');
  const sortedCaps = [...capCount.entries()].sort((a, b) => b[1] - a[1]);
  for (const [cap, count] of sortedCaps) {
    lines.push(`| ${cap} | ${count} |`);
  }
  lines.push('');

  return lines.join('\n');
}

// ─── Dependency graph ─────────────────────────────────────────────────────────

const HIGH_RISK_CAPS = new Set<string>(['network', 'process-spawn', 'dynamic-code', 'native-binding']);

export function printDepGraph(graph: DepGraph, rootKeys: string[], maxDepth = 3): void {
  console.log('');
  console.log(chalk.bold.underline('Warden Dependency Graph'));
  console.log(chalk.dim('  Packages with capabilities are highlighted. Max depth: ' + maxDepth));
  console.log('');

  const visited = new Set<string>();

  function printNode(key: string, depth: number, prefix: string, isLast: boolean): void {
    if (depth > maxDepth) return;
    const node = graph.get(key);
    if (!node) return;

    const connector = depth === 0 ? '' : isLast ? '`-- ' : '|-- ';
    const childPrefix = depth === 0 ? '' : isLast ? '    ' : '|   ';

    const capStr = node.capabilities.length > 0
      ? '  ' + node.capabilities.map(c => {
          const label = `[${c.toUpperCase().replace(/-/g, '').slice(0, 6)}]`;
          return HIGH_RISK_CAPS.has(c) ? chalk.red(label) : chalk.yellow(label);
        }).join(' ')
      : '';

    const alreadySeen = visited.has(key);
    const nameStr = alreadySeen
      ? chalk.dim(`${node.name}@${node.version} (...)`)
      : node.capabilities.some(c => HIGH_RISK_CAPS.has(c))
      ? chalk.bold(`${node.name}@${node.version}`)
      : `${node.name}@${node.version}`;

    console.log(`${prefix}${connector}${nameStr}${capStr}`);

    if (!alreadySeen) {
      visited.add(key);
      const children = node.deps.filter(d => graph.has(d));
      for (let i = 0; i < children.length; i++) {
        printNode(children[i], depth + 1, prefix + childPrefix, i === children.length - 1);
      }
    }
  }

  if (rootKeys.length === 0) {
    // No root specified: show all top-level packages (not a dep of anything)
    const allDeps = new Set(Array.from(graph.values()).flatMap(n => n.deps));
    const roots = Array.from(graph.keys()).filter(k => !allDeps.has(k));
    for (let i = 0; i < roots.length; i++) {
      printNode(roots[i], 0, '', i === roots.length - 1);
    }
  } else {
    for (let i = 0; i < rootKeys.length; i++) {
      printNode(rootKeys[i], 0, '', i === rootKeys.length - 1);
    }
  }

  console.log('');
}
