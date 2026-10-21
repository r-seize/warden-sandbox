import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const PROJECT_ROOT    = path.resolve(__dirname, '..');
const CLI             = path.join(PROJECT_ROOT, 'dist', 'cli.js');

const tmpDirs: string[] = [];

function makeProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-typosquat-enforcement-'));
  tmpDirs.push(dir);
  return dir;
}

function warden(dir: string, args: string[]) {
  const result = spawnSync('node', [CLI, ...args], { cwd: dir, encoding: 'utf8', timeout: 20_000 });
  return { stdout: result.stdout ?? '', stderr: result.stderr ?? '', output: (result.stdout ?? '') + (result.stderr ?? ''), code: result.status ?? 1 };
}

function writeTyposquatPackage(dir: string) {
  const pkgDir = path.join(dir, 'node_modules', 'lodahs');
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: 'lodahs', version: '1.0.0' }));
  fs.writeFileSync(path.join(pkgDir, 'index.js'), 'module.exports = {};\n');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'enforcement-test' }));
}

function stripTyposquatOf(dir: string, key: string) {
  const lockPath    = path.join(dir, 'warden.lock.json');
  const lock        = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  delete lock.packages[key].typosquatOf;
  fs.writeFileSync(lockPath, JSON.stringify(lock, null, 2));
}

afterEach(() => {
  while (tmpDirs.length > 0) {
    fs.rmSync(tmpDirs.pop()!, { recursive: true, force: true });
  }
});

describe('typosquat detection actually gates CI (not just shown at scan time)', () => {
  it('warden verify itself catches a stale approval, even without an intervening warden scan', () => {
    const dir = makeProject();
    writeTyposquatPackage(dir);

    // Simulate a lockfile approved before warden had typosquat detection: scan + approve,
    // then strip the typosquatOf field — the committed lockfile now looks exactly like
    // one from an old warden version, fully approved, content unchanged.
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);
    expect(warden(dir, ['approve', '--all']).code).toBe(0);
    stripTyposquatOf(dir, 'lodahs@1.0.0');

    // No `warden scan` in between — verify must catch this on its own internal rescan.
    const verifyResult = warden(dir, ['verify']);
    expect(verifyResult.code).toBe(1);
    expect(verifyResult.output).toContain('typosquat');
  });

  it('warden verify --json reports the typosquat violation with the ok:false flag', () => {
    const dir = makeProject();
    writeTyposquatPackage(dir);
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);
    expect(warden(dir, ['approve', '--all']).code).toBe(0);
    stripTyposquatOf(dir, 'lodahs@1.0.0');

    const result    = warden(dir, ['verify', '--json']);
    const parsed    = JSON.parse(result.stdout) as { ok: boolean; violations: string[] };
    expect(parsed.ok).toBe(false);
    expect(parsed.violations.some(v => v.includes('typosquat'))).toBe(true);
  });

  it('a prior warden scan already catches and fixes the stale approval on its own (status flips to pending-review)', () => {
    const dir = makeProject();
    writeTyposquatPackage(dir);
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);
    expect(warden(dir, ['approve', '--all']).code).toBe(0);
    stripTyposquatOf(dir, 'lodahs@1.0.0');

    const scanResult = warden(dir, ['scan', '--no-progress']);
    expect(scanResult.code).toBe(0);
    expect(scanResult.output).toContain('Possible typosquat');

    const lock = JSON.parse(fs.readFileSync(path.join(dir, 'warden.lock.json'), 'utf8'));
    expect(lock.packages['lodahs@1.0.0'].status).toBe('pending-review');

    // verify now fails via the ordinary pending-review check, since scan already downgraded it.
    const verifyResult = warden(dir, ['verify']);
    expect(verifyResult.code).toBe(1);
  });

  it('warden audit --fix never auto-approves a typosquat, even with zero capabilities', () => {
    const dir = makeProject();
    writeTyposquatPackage(dir);
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);
    // Left as pending-review (not approved) — exactly the state --fix operates on.

    const fixResult = warden(dir, ['audit', '--fix']);
    expect(fixResult.output).toContain('No low-risk pending packages to auto-approve');

    const lock = JSON.parse(fs.readFileSync(path.join(dir, 'warden.lock.json'), 'utf8'));
    expect(lock.packages['lodahs@1.0.0'].status).toBe('pending-review');
  });

  it('does not re-flag (or re-fail) a typosquat that was already known and explicitly approved', () => {
    const dir = makeProject();
    writeTyposquatPackage(dir);
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);
    // Approved WITH full knowledge of the typosquatOf field already present.
    expect(warden(dir, ['approve', '--all']).code).toBe(0);

    // Re-scan with unchanged content: should stay approved, not flip back to pending.
    expect(warden(dir, ['scan', '--no-progress']).code).toBe(0);
    const lock = JSON.parse(fs.readFileSync(path.join(dir, 'warden.lock.json'), 'utf8'));
    expect(lock.packages['lodahs@1.0.0'].status).toBe('approved');

    const verifyResult = warden(dir, ['verify']);
    expect(verifyResult.code).toBe(0);
  });
});
