import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const PROJECT_ROOT    = path.resolve(__dirname, '..');
const CLI             = path.join(PROJECT_ROOT, 'dist', 'cli.js');

const tmpDirs: string[] = [];

function makeProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-integrity-test-'));
  tmpDirs.push(dir);
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'integrity-test' }));
  return dir;
}

function warden(dir: string, args: string[]) {
  const result = spawnSync('node', [CLI, ...args], { cwd: dir, encoding: 'utf8', timeout: 20_000 });
  return { stdout: result.stdout ?? '', stderr: result.stderr ?? '', output: (result.stdout ?? '') + (result.stderr ?? ''), code: result.status ?? 1 };
}

afterEach(() => {
  while (tmpDirs.length > 0) fs.rmSync(tmpDirs.pop()!, { recursive: true, force: true });
});

describe('warden integrity — pnpm/yarn lockfile support', () => {
  it('auto-detects and checks a pnpm-lock.yaml', () => {
    const dir = makeProject();
    fs.writeFileSync(path.join(dir, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      '',
      'packages:',
      '',
      '  axios@1.6.0:',
      '    resolution: {integrity: sha512-' + 'a'.repeat(86) + '==}',
      '',
      '  local-patch@1.0.0:',
      '    resolution: {tarball: file:../local-patch.tgz}',
      '',
    ].join('\n'));

    const result = warden(dir, ['integrity']);
    expect(result.code).toBe(1);
    expect(result.output).toContain('pnpm-lock.yaml');
    expect(result.output).toContain('local-patch');
  });

  it('auto-detects and checks a yarn.lock', () => {
    const dir = makeProject();
    fs.writeFileSync(path.join(dir, 'yarn.lock'), [
      '# yarn lockfile v1',
      '',
      'axios@^1.6.0:',
      '  version "1.6.0"',
      '  resolved "https://registry.yarnpkg.com/axios/-/axios-1.6.0.tgz#abc"',
      '  integrity sha512-' + 'a'.repeat(86) + '==',
      '',
    ].join('\n'));

    const result = warden(dir, ['integrity']);
    expect(result.code).toBe(0);
    expect(result.output).toContain('yarn.lock');
  });

  it('respects an explicit --lockfile selection over auto-detection', () => {
    const dir = makeProject();
    fs.writeFileSync(path.join(dir, 'yarn.lock'), '# yarn lockfile v1\n');
    // No pnpm-lock.yaml exists — forcing --lockfile pnpm must fail cleanly, not fall back to yarn.
    const result = warden(dir, ['integrity', '--lockfile', 'pnpm']);
    expect(result.code).toBe(2);
    expect(result.output).toContain('No package-lock.json, pnpm-lock.yaml, or yarn.lock found');
  });

  it('flags scope confusion when a configured private scope resolves from the public npm registry', () => {
    const dir = makeProject();
    fs.writeFileSync(path.join(dir, '.wardenrc.json'), JSON.stringify({ privateScopes: ['@acme'] }));
    fs.writeFileSync(path.join(dir, 'yarn.lock'), [
      '# yarn lockfile v1',
      '',
      '"@acme/internal@^1.0.0":',
      '  version "1.0.0"',
      '  resolved "https://registry.npmjs.org/@acme/internal/-/internal-1.0.0.tgz#def"',
      '  integrity sha512-' + 'a'.repeat(86) + '==',
      '',
    ].join('\n'));

    const result = warden(dir, ['integrity']);
    expect(result.code).toBe(1);
    expect(result.output).toContain('scope confusion');
  });

  it('does not flag scope confusion when the private scope resolves from a trusted non-public registry', () => {
    const dir = makeProject();
    fs.writeFileSync(path.join(dir, '.wardenrc.json'), JSON.stringify({
      privateScopes: ['@acme'],
      registries: ['https://npm.mycompany.internal/'],
    }));
    fs.writeFileSync(path.join(dir, 'yarn.lock'), [
      '# yarn lockfile v1',
      '',
      '"@acme/internal@^1.0.0":',
      '  version "1.0.0"',
      '  resolved "https://npm.mycompany.internal/@acme/internal/-/internal-1.0.0.tgz#def"',
      '  integrity sha512-' + 'a'.repeat(86) + '==',
      '',
    ].join('\n'));

    const result = warden(dir, ['integrity']);
    expect(result.code).toBe(0);
  });
});
