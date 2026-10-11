import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const PROJECT_ROOT    = path.resolve(__dirname, '..');
const CLI             = path.join(PROJECT_ROOT, 'dist', 'cli.js');

const tmpDirs: string[] = [];

function makeProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-ci-test-'));
  tmpDirs.push(dir);
  return dir;
}

function warden(dir: string, args: string[]) {
  const result = spawnSync('node', [CLI, ...args], { cwd: dir, encoding: 'utf8', timeout: 20_000 });
  return { stdout: result.stdout ?? '', stderr: result.stderr ?? '', code: result.status ?? 1 };
}

function writePackage(nodeModulesDir: string, name: string, version: string, source = 'module.exports = {};\n') {
  const dir = path.join(nodeModulesDir, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name, version }));
  fs.writeFileSync(path.join(dir, 'index.js'), source);
}

function writePackageLock(dir: string, packages: Record<string, { version: string }>) {
  const lockPackages: Record<string, unknown> = { '': { name: 'ci-test' } };
  for (const [name, meta] of Object.entries(packages)) {
    lockPackages[`node_modules/${name}`] = {
      version: meta.version,
      resolved: `https://registry.npmjs.org/${name}/-/${name}-${meta.version}.tgz`,
      integrity: 'sha512-' + 'a'.repeat(86) + '==',
    };
  }
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({
    name: 'ci-test',
    lockfileVersion: 3,
    packages: lockPackages,
  }));
}

afterEach(() => {
  while (tmpDirs.length > 0) {
    fs.rmSync(tmpDirs.pop()!, { recursive: true, force: true });
  }
});

describe('warden ci', () => {
  it('passes (exit 0) when integrity and verify are both clean', () => {
    const dir    = makeProject();
    const nm     = path.join(dir, 'node_modules');
    writePackage(nm, 'clean-pkg', '1.0.0');
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'ci-test' }));
    writePackageLock(dir, { 'clean-pkg': { version: '1.0.0' } });

    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);
    expect(warden(dir, ['approve', '--all']).code).toBe(0);

    const result = warden(dir, ['ci']);
    expect(result.stdout).toContain('CI gate passed');
    expect(result.code).toBe(0);
  });

  it('fails (exit 1) when a package is not in the lockfile', () => {
    const dir    = makeProject();
    const nm     = path.join(dir, 'node_modules');
    writePackage(nm, 'clean-pkg', '1.0.0');
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'ci-test' }));
    writePackageLock(dir, { 'clean-pkg': { version: '1.0.0' } });

    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);
    expect(warden(dir, ['approve', '--all']).code).toBe(0);

    // A package appears after the lockfile was committed/approved.
    writePackage(nm, 'surprise-pkg', '1.0.0');

    const result = warden(dir, ['ci']);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain('CI gate failed');
    expect(result.stdout).toContain('surprise-pkg');
  });

  it('reports a machine-readable JSON summary with --json', () => {
    const dir    = makeProject();
    const nm     = path.join(dir, 'node_modules');
    writePackage(nm, 'clean-pkg', '1.0.0');
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'ci-test' }));
    writePackageLock(dir, { 'clean-pkg': { version: '1.0.0' } });

    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);
    expect(warden(dir, ['approve', '--all']).code).toBe(0);

    const result    = warden(dir, ['ci', '--json']);
    const parsed     = JSON.parse(result.stdout) as {
      ok: boolean;
      integrity: { ok: boolean; checked: number } | null;
      verify: { ok: boolean; violations: string[] };
      audit: { total: number; highRisk: number } | null;
    };

    expect(parsed.ok).toBe(true);
    expect(parsed.integrity?.ok).toBe(true);
    expect(parsed.verify.ok).toBe(true);
    expect(parsed.audit?.total).toBe(1);
  });

  it('skips the integrity check gracefully when there is no package-lock.json', () => {
    const dir    = makeProject();
    const nm     = path.join(dir, 'node_modules');
    writePackage(nm, 'clean-pkg', '1.0.0');
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'ci-test' }));
    // No package-lock.json — simulates a pnpm/yarn project.

    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);
    expect(warden(dir, ['approve', '--all']).code).toBe(0);

    const result    = warden(dir, ['ci', '--json']);
    const parsed     = JSON.parse(result.stdout) as { ok: boolean; integrity: unknown };

    expect(parsed.integrity).toBeNull();
    expect(parsed.ok).toBe(true);
    expect(result.code).toBe(0);
  });
});
