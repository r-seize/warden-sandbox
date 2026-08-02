import { describe, it, expect } from 'vitest';
import { diffLockfiles, diffHasSecurityRelevantChanges } from '../src/policy/policyDiff';
import { LockfileData } from '../src/policy/lockfile';

function makeLock(packages: LockfileData['packages']): LockfileData {
  return { version: 1, generatedAt: new Date().toISOString(), packages };
}

describe('diffLockfiles', () => {
  it('returns empty diffs when both lockfiles are identical', () => {
    const lock = makeLock({
      'left-pad@1.3.0': {
        contentHash: 'sha256:abc',
        capabilities: [],
        status: 'approved',
      },
    });
    const summary = diffLockfiles(lock, lock);
    expect(summary.unchanged).toBe(1);
    expect(summary.newPackages).toBe(0);
    expect(summary.packagesWithNewCapabilities).toBe(0);
  });

  it('detects a new package', () => {
    const old = makeLock({});
    const next = makeLock({
      'axios@1.0.0': {
        contentHash: 'sha256:def',
        capabilities: ['network'],
        status: 'pending-review',
      },
    });
    const summary = diffLockfiles(old, next);
    expect(summary.newPackages).toBe(1);
    expect(summary.diffs[0].kind).toBe('new-package');
    expect(summary.diffs[0].addedCapabilities).toEqual(['network']);
  });

  it('detects a removed package', () => {
    const old = makeLock({
      'some-lib@1.0.0': { contentHash: 'sha256:aaa', capabilities: [], status: 'approved' },
    });
    const next       = makeLock({});
    const summary    = diffLockfiles(old, next);
    expect(summary.removedPackages).toBe(1);
    expect(summary.diffs[0].kind).toBe('removed-package');
  });

  it('detects new capability on existing package', () => {
    const old = makeLock({
      'some-lib@2.0.0': { contentHash: 'sha256:aaa', capabilities: [], status: 'approved' },
    });
    const next = makeLock({
      'some-lib@2.0.0': {
        contentHash: 'sha256:bbb',
        capabilities: ['network'],
        status: 'pending-review',
      },
    });
    const summary = diffLockfiles(old, next);
    expect(summary.packagesWithNewCapabilities).toBe(1);
    expect(summary.diffs[0].kind).toBe('new-capability');
    expect(summary.diffs[0].addedCapabilities).toEqual(['network']);
    expect(summary.diffs[0].removedCapabilities).toEqual([]);
  });

  it('detects removed capability', () => {
    const old = makeLock({
      'some-lib@3.0.0': { contentHash: 'sha256:aaa', capabilities: ['env-access'], status: 'approved' },
    });
    const next = makeLock({
      'some-lib@3.0.0': { contentHash: 'sha256:bbb', capabilities: [], status: 'approved' },
    });
    const summary = diffLockfiles(old, next);
    expect(summary.diffs[0].kind).toBe('removed-capability');
    expect(summary.diffs[0].removedCapabilities).toEqual(['env-access']);
  });

  it('detects content change without capability change', () => {
    const old = makeLock({
      'some-lib@4.0.0': { contentHash: 'sha256:aaa', capabilities: ['filesystem-read'], status: 'approved' },
    });
    const next = makeLock({
      'some-lib@4.0.0': { contentHash: 'sha256:bbb', capabilities: ['filesystem-read'], status: 'approved' },
    });
    const summary = diffLockfiles(old, next);
    expect(summary.packagesWithContentChanges).toBe(1);
    expect(summary.diffs[0].kind).toBe('content-changed');
  });

  it('treats null old lockfile as first scan', () => {
    const next = makeLock({
      'pkg@1.0.0': { contentHash: 'sha256:abc', capabilities: ['network'], status: 'pending-review' },
    });
    const summary = diffLockfiles(null, next);
    expect(summary.newPackages).toBe(1);
  });

  it('sorts new-capability before new-package in output', () => {
    const old = makeLock({
      'existing@1.0.0': { contentHash: 'sha256:aaa', capabilities: [], status: 'approved' },
    });
    const next = makeLock({
      'existing@1.0.0': { contentHash: 'sha256:bbb', capabilities: ['network'], status: 'pending-review' },
      'brand-new@1.0.0': { contentHash: 'sha256:ccc', capabilities: ['env-access'], status: 'pending-review' },
    });
    const summary = diffLockfiles(old, next);
    expect(summary.diffs[0].kind).toBe('new-capability');
    expect(summary.diffs[1].kind).toBe('new-package');
  });
});

describe('diffHasSecurityRelevantChanges', () => {
  it('returns true when there are new capabilities', () => {
    const old = makeLock({
      'pkg@1.0.0': { contentHash: 'sha256:aaa', capabilities: [], status: 'approved' },
    });
    const next = makeLock({
      'pkg@1.0.0': { contentHash: 'sha256:bbb', capabilities: ['network'], status: 'pending-review' },
    });
    expect(diffHasSecurityRelevantChanges(diffLockfiles(old, next))).toBe(true);
  });

  it('returns true when a new package with capabilities is added', () => {
    const next = makeLock({
      'evil@1.0.0': { contentHash: 'sha256:ccc', capabilities: ['process-spawn'], status: 'pending-review' },
    });
    expect(diffHasSecurityRelevantChanges(diffLockfiles(null, next))).toBe(true);
  });

  it('returns false when only content hash changed (no new caps)', () => {
    const old = makeLock({
      'pkg@1.0.0': { contentHash: 'sha256:aaa', capabilities: ['filesystem-read'], status: 'approved' },
    });
    const next = makeLock({
      'pkg@1.0.0': { contentHash: 'sha256:bbb', capabilities: ['filesystem-read'], status: 'approved' },
    });
    expect(diffHasSecurityRelevantChanges(diffLockfiles(old, next))).toBe(false);
  });

  it('returns false when no changes', () => {
    const lock = makeLock({
      'pkg@1.0.0': { contentHash: 'sha256:aaa', capabilities: [], status: 'approved' },
    });
    expect(diffHasSecurityRelevantChanges(diffLockfiles(lock, lock))).toBe(false);
  });
});
