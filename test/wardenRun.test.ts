import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as path from 'node:path';

const PROJECT_ROOT    = path.resolve(__dirname, '..');
const CLI             = path.join(PROJECT_ROOT, 'dist', 'cli.js');
const FIXTURES        = path.join(PROJECT_ROOT, 'test', 'fixtures');

function warden(args: string[], timeoutMs = 10_000) {
  const result = spawnSync('node', [CLI, ...args], {
    cwd: PROJECT_ROOT,
    encoding: 'utf8',
    timeout: timeoutMs,
  });
  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    output: (result.stdout ?? '') + (result.stderr ?? ''),
    code: result.status ?? 1,
  };
}

function fixture(name: string) {
  return path.join(FIXTURES, name);
}

// ─── CJS — observation mode ───────────────────────────────────────────────────

describe('warden run CJS — observation mode', () => {
  it('clean script: exits 0 with no violations', () => {
    const r = warden(['run', fixture('clean-script.js')]);
    expect(r.code).toBe(0);
    expect(r.output).toContain('No capability violations detected');
    expect(r.output).not.toContain('VIOLATION');
  });

  it('script using evil package: logs network violation, exits 0', () => {
    const r = warden(['run', fixture('use-packages.js')]);
    expect(r.code).toBe(0);
    expect(r.output).toContain('VIOLATION');
    expect(r.output).toContain('warden-test-evil');
    expect(r.output).toContain('network');
    // Evil package still loads — observation only
    expect(r.output).toContain('evil module loaded');
  });

  it('env-sniffer: user script env access is trusted (not a package), no violation', () => {
    const r = warden(['run', fixture('env-sniffer.js')]);
    expect(r.code).toBe(0);
    expect(r.output).not.toContain('VIOLATION');
  });
});

// ─── CJS — enforce mode ───────────────────────────────────────────────────────

describe('warden run CJS — enforce mode', () => {
  it('clean script: exits 0 with no violations', () => {
    const r = warden(['run', '--enforce', fixture('clean-script.js')]);
    expect(r.code).toBe(0);
    expect(r.output).toContain('No capability violations detected');
    expect(r.output).not.toContain('VIOLATION');
  });

  it('evil package: throws on network access, exits 1', () => {
    const r = warden(['run', '--enforce', fixture('use-packages.js')]);
    expect(r.code).toBe(1);
    expect(r.output).toContain('VIOLATION');
    expect(r.output).toContain('warden-test-evil');
    expect(r.output).toContain('network');
    // Script should NOT complete loading the evil module
    expect(r.output).not.toContain('evil module loaded');
  });

  it('clean package (warden-test-clean) still works in enforce mode', () => {
    const r = warden(['run', '--enforce', fixture('use-packages.js')]);
    // The clean package output appears before the evil one throws
    expect(r.output).toContain('hello');
  });
});

// ─── ESM — observation mode ───────────────────────────────────────────────────

describe('warden run ESM — observation mode', () => {
  it('clean ESM script: exits 0 with no violations', () => {
    const r = warden(['run', fixture('esm-clean.mjs')]);
    expect(r.code).toBe(0);
    expect(r.output).toContain('No capability violations detected');
    expect(r.output).toContain('ESM clean result');
  });

  it('evil ESM package: logs network + filesystem violations, exits 0', () => {
    const r = warden(['run', fixture('use-evil-esm.mjs')]);
    expect(r.code).toBe(0);
    expect(r.output).toContain('warden-test-evil');
    expect(r.output).toContain('network');
    expect(r.output).toContain('filesystem-read');
    // Real modules still loaded in observe mode
    expect(r.output).toContain('loaded:');
    expect(r.output).toMatch(/2 violation\(s\)/);
  });
});

// ─── ESM — enforce mode ───────────────────────────────────────────────────────

describe('warden run ESM — enforce mode', () => {
  it('clean ESM script: exits 0 with no violations', () => {
    const r = warden(['run', '--enforce', fixture('esm-clean.mjs')]);
    expect(r.code).toBe(0);
    expect(r.output).toContain('No capability violations detected');
    expect(r.output).toContain('ESM clean result');
  });

  it('evil ESM package: violations logged, blocked stubs returned, exits 0', () => {
    const r = warden(['run', '--enforce', fixture('use-evil-esm.mjs')]);
    expect(r.code).toBe(0);
    expect(r.output).toContain('warden-test-evil');
    expect(r.output).toContain('network');
    expect(r.output).toContain('filesystem-read');
    expect(r.output).toMatch(/2 violation\(s\)/);
  });
});

// ─── Error handling ───────────────────────────────────────────────────────────

describe('warden run — error handling', () => {
  it('missing script: exits 1 with error message', () => {
    const r = warden(['run', 'does-not-exist.js']);
    expect(r.code).toBe(1);
    expect(r.output).toContain('Script not found');
  });

  it('missing lockfile: exits 1 with helpful message', () => {
    const r = warden(['run', '--dir', '/tmp', fixture('clean-script.js')]);
    expect(r.code).toBe(1);
    expect(r.output).toContain('warden.lock.json');
  });
});
