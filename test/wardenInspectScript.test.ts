import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const PROJECT_ROOT    = path.resolve(__dirname, '..');
const CLI             = path.join(PROJECT_ROOT, 'dist', 'cli.js');

const tmpDirs: string[] = [];

function makeProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-inspect-test-'));
  tmpDirs.push(dir);
  return dir;
}

function warden(dir: string, args: string[]) {
  const result = spawnSync('node', [CLI, ...args], { cwd: dir, encoding: 'utf8', timeout: 20_000 });
  return { stdout: result.stdout ?? '', stderr: result.stderr ?? '', output: (result.stdout ?? '') + (result.stderr ?? ''), code: result.status ?? 1 };
}

afterEach(() => {
  while (tmpDirs.length > 0) {
    fs.rmSync(tmpDirs.pop()!, { recursive: true, force: true });
  }
});

function setupScriptedPackage(dir: string, scripts: Record<string, string>, setupSource: string) {
  const pkgDir = path.join(dir, 'node_modules', 'scripted-pkg');
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: 'scripted-pkg', version: '1.0.0', scripts }));
  fs.writeFileSync(path.join(pkgDir, 'setup.js'), setupSource);
  fs.writeFileSync(path.join(pkgDir, 'index.js'), 'module.exports = {};\n');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'inspect-test' }));
}

describe('warden inspect-script', () => {
  it('runs a direct `node <file>` life-cycle script under observation and reports no violations when clean', () => {
    const dir = makeProject();
    setupScriptedPackage(dir, { postinstall: 'node setup.js' }, "console.log('clean setup ran');\n");
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);

    const result = warden(dir, ['inspect-script', 'scripted-pkg', 'postinstall']);
    expect(result.code).toBe(0);
    expect(result.output).toContain('clean setup ran');
    expect(result.output).toContain('No capability violations detected');
  });

  it('observes a capability the scan missed without blocking (default mode)', () => {
    const dir = makeProject();
    setupScriptedPackage(dir, { postinstall: 'node setup.js' }, "require('http');\nconsole.log('setup done');\n");
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);

    // Simulate a capability the static scan missed (e.g. runtime-only access) by
    // clearing the declared capabilities — observation mode only flags *undeclared*
    // capability usage, it never blocks on approval status alone.
    const lockPath = path.join(dir, 'warden.lock.json');
    const lock      = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    lock.packages['scripted-pkg@1.0.0'].capabilities = [];
    fs.writeFileSync(lockPath, JSON.stringify(lock));

    const result = warden(dir, ['inspect-script', 'scripted-pkg', 'postinstall']);
    expect(result.code).toBe(0);
    expect(result.output).toContain('setup done');
    expect(result.output).toContain('1 violation(s) recorded');
    expect(result.output).toContain('network');
  });

  it('blocks an undeclared capability and exits non-zero with --enforce', () => {
    const dir = makeProject();
    setupScriptedPackage(dir, { postinstall: 'node setup.js' }, "require('http');\nconsole.log('setup done');\n");
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);
    // Left as 'pending-review' (not approved) — enforce mode grants zero capabilities to it.

    const result = warden(dir, ['inspect-script', 'scripted-pkg', 'postinstall', '--enforce']);
    expect(result.code).toBe(1);
    expect(result.output).not.toContain('setup done'); // blocked before the second console.log
    expect(result.output).toContain('VIOLATION');
  });

  it('declines to sandbox a non-"node <file>" script and does not execute it', () => {
    const dir = makeProject();
    setupScriptedPackage(dir, { preinstall: 'node-gyp rebuild' }, "console.log('should not run');\n");
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);

    const result = warden(dir, ['inspect-script', 'scripted-pkg', 'preinstall']);
    expect(result.code).toBe(0);
    expect(result.output).toContain('Cannot be sandboxed automatically');
    expect(result.output).not.toContain('should not run');
  });

  it('inspects every declared life-cycle script when none is named', () => {
    const dir = makeProject();
    setupScriptedPackage(dir, { postinstall: 'node setup.js', preinstall: 'node-gyp rebuild' }, "console.log('clean setup ran');\n");
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);

    const result = warden(dir, ['inspect-script', 'scripted-pkg']);
    expect(result.code).toBe(0);
    expect(result.output).toContain('preinstall');
    expect(result.output).toContain('postinstall');
    expect(result.output).toContain('clean setup ran');
  });

  it('errors when the package declares no life-cycle scripts', () => {
    const dir = makeProject();
    const pkgDir = path.join(dir, 'node_modules', 'no-scripts-pkg');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: 'no-scripts-pkg', version: '1.0.0' }));
    fs.writeFileSync(path.join(pkgDir, 'index.js'), 'module.exports = {};\n');
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'inspect-test' }));
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);

    const result = warden(dir, ['inspect-script', 'no-scripts-pkg']);
    expect(result.code).toBe(0);
    expect(result.output).toContain('declares no life-cycle scripts');
  });
});
