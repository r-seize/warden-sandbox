import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scanPackage, scanNodeModules, discoverScanTargets, scanProject } from '../src/analyzer/packageScanner';

const tmpDirs: string[] = [];

function makeTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-test-'));
  tmpDirs.push(dir);
  return dir;
}

function writePackage(dir: string, name: string, version: string, extra: Record<string, unknown> = {}, indexSrc = 'module.exports = {};\n') {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name, version, ...extra }));
  fs.writeFileSync(path.join(dir, 'index.js'), indexSrc);
}

afterEach(() => {
  while (tmpDirs.length > 0) {
    const dir = tmpDirs.pop()!;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('discoverPackages (via scanNodeModules) — symlinked packages', () => {
  it('finds a package installed as a real directory', async () => {
    const project = makeTmpDir();
    const nm      = path.join(project, 'node_modules');
    writePackage(path.join(nm, 'real-pkg'), 'real-pkg', '1.0.0');

    const results = await scanNodeModules(nm, new Map(), undefined, false);
    expect(results.map(r => r.name)).toContain('real-pkg');
  });

  it('finds a package linked via a symlink (pnpm-style node_modules)', async () => {
    const project    = makeTmpDir();
    const store      = path.join(project, '.pnpm', 'linked-pkg@2.0.0', 'node_modules', 'linked-pkg');
    writePackage(store, 'linked-pkg', '2.0.0');

    const nm = path.join(project, 'node_modules');
    fs.mkdirSync(nm, { recursive: true });
    fs.symlinkSync(store, path.join(nm, 'linked-pkg'), 'dir');

    const results = await scanNodeModules(nm, new Map(), undefined, false);
    expect(results.map(r => r.name)).toContain('linked-pkg');
  });

  it('finds a scoped package linked via a symlink', async () => {
    const project    = makeTmpDir();
    const store      = path.join(project, '.pnpm', '@scope+linked@1.0.0', 'node_modules', '@scope', 'linked');
    writePackage(store, '@scope/linked', '1.0.0');

    const nm = path.join(project, 'node_modules');
    fs.mkdirSync(path.join(nm, '@scope'), { recursive: true });
    fs.symlinkSync(store, path.join(nm, '@scope', 'linked'), 'dir');

    const results = await scanNodeModules(nm, new Map(), undefined, false);
    expect(results.map(r => r.name)).toContain('@scope/linked');
  });
});

describe('scanPackage — life-cycle script detection', () => {
  it('flags packages declaring postinstall/preinstall/install scripts', () => {
    const dir = makeTmpDir();
    writePackage(dir, 'has-scripts', '1.0.0', {
      scripts: { postinstall: 'node setup.js', test: 'echo ok' },
    });

    const result = scanPackage(dir);
    expect(result.lifecycleScripts).toEqual(['postinstall']);
  });

  it('reports no life-cycle scripts for packages without them', () => {
    const dir = makeTmpDir();
    writePackage(dir, 'clean-pkg', '1.0.0', { scripts: { test: 'echo ok' } });

    const result = scanPackage(dir);
    expect(result.lifecycleScripts).toEqual([]);
  });
});

describe('scanPackage — cache hits refresh name/metadata-derived fields', () => {
  it('recomputes typosquatOf on a cache hit, even though the cached result predates detection', () => {
    const dir = makeTmpDir();
    writePackage(dir, 'lodahs', '1.0.0');

    const fresh = scanPackage(dir);
    expect(fresh.contentHash).toBeTruthy();

    // Simulate a cache entry written by a warden version that didn't have
    // typosquat detection yet (or had a smaller list) — same content hash,
    // but a stale/absent typosquatOf baked into the cached result.
    const staleCachedEntry = {
      contentHash: fresh.contentHash,
      result: { ...fresh, typosquatOf: null },
    };

    const rescanned = scanPackage(dir, staleCachedEntry);
    expect(rescanned.contentHash).toBe(fresh.contentHash); // cache hit, not a full rescan
    expect(rescanned.typosquatOf).toBe('lodash'); // but the stale verdict was refreshed
  });

  it('recomputes lifecycleScripts on a cache hit', () => {
    const dir = makeTmpDir();
    writePackage(dir, 'has-scripts', '1.0.0', { scripts: { postinstall: 'node setup.js' } });

    const fresh = scanPackage(dir);
    const staleCachedEntry = {
      contentHash: fresh.contentHash,
      result: { ...fresh, lifecycleScripts: [] },
    };

    const rescanned = scanPackage(dir, staleCachedEntry);
    expect(rescanned.contentHash).toBe(fresh.contentHash);
    expect(rescanned.lifecycleScripts).toEqual(['postinstall']);
  });

  it('still skips the expensive AST scan on a cache hit (capabilities come from the cache)', () => {
    const dir = makeTmpDir();
    // Real source would trigger 'network', but the cached result says otherwise —
    // a cache hit must still trust the cache for capabilities (that's the point
    // of the cache); only typosquatOf/lifecycleScripts are refreshed.
    writePackage(dir, 'clean-pkg', '1.0.0', {}, "require('http');\n");
    const fresh = scanPackage(dir);

    const cachedEntry = { contentHash: fresh.contentHash, result: { ...fresh, capabilities: [] } };
    const rescanned    = scanPackage(dir, cachedEntry);
    expect(rescanned.capabilities).toEqual([]);
  });
});

describe('discoverScanTargets — workspace / monorepo support', () => {
  it('returns only the root when there are no workspaces', () => {
    const project = makeTmpDir();
    fs.mkdirSync(path.join(project, 'node_modules'));
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'root' }));

    const targets = discoverScanTargets(project);
    expect(targets).toHaveLength(1);
    expect(targets[0].dir).toBe(project);
  });

  it('expands npm/yarn "workspaces" glob patterns', () => {
    const project = makeTmpDir();
    fs.mkdirSync(path.join(project, 'node_modules'));
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'root', workspaces: ['packages/*'] }));

    fs.mkdirSync(path.join(project, 'packages', 'pkg-a', 'node_modules'), { recursive: true });
    fs.mkdirSync(path.join(project, 'packages', 'pkg-b', 'node_modules'), { recursive: true });

    const targets = discoverScanTargets(project);
    const dirs    = targets.map(t => t.dir).sort();
    expect(dirs).toEqual([
      project,
      path.join(project, 'packages', 'pkg-a'),
      path.join(project, 'packages', 'pkg-b'),
    ].sort());
  });

  it('expands pnpm-workspace.yaml packages list', () => {
    const project = makeTmpDir();
    fs.mkdirSync(path.join(project, 'node_modules'));
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'root' }));
    fs.writeFileSync(path.join(project, 'pnpm-workspace.yaml'), 'packages:\n  - "apps/*"\n');

    fs.mkdirSync(path.join(project, 'apps', 'web', 'node_modules'), { recursive: true });

    const targets = discoverScanTargets(project);
    const dirs    = targets.map(t => t.dir).sort();
    expect(dirs).toEqual([project, path.join(project, 'apps', 'web')].sort());
  });

  it('skips workspace packages that have no node_modules of their own', () => {
    const project = makeTmpDir();
    fs.mkdirSync(path.join(project, 'node_modules'));
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'root', workspaces: ['packages/*'] }));

    fs.mkdirSync(path.join(project, 'packages', 'pkg-no-deps'), { recursive: true });

    const targets = discoverScanTargets(project);
    expect(targets).toHaveLength(1);
  });
});

describe('scanProject — merges results across workspace targets', () => {
  it('aggregates packages from root and workspace node_modules without duplicates', async () => {
    const project = makeTmpDir();
    writePackage(path.join(project, 'node_modules', 'root-dep'), 'root-dep', '1.0.0');
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'root', workspaces: ['packages/*'] }));

    writePackage(path.join(project, 'packages', 'pkg-a', 'node_modules', 'nested-dep'), 'nested-dep', '1.0.0');
    // Same dependency hoisted at the root AND present in the workspace package — must not be double-counted.
    writePackage(path.join(project, 'packages', 'pkg-a', 'node_modules', 'root-dep'), 'root-dep', '1.0.0');

    const results = await scanProject(project, new Map(), undefined, false);
    const names    = results.map(r => `${r.name}@${r.version}`).sort();
    expect(names).toEqual(['nested-dep@1.0.0', 'root-dep@1.0.0']);
  });
});
