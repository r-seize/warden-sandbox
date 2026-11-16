import { describe, it, expect } from 'vitest';
import { mergeLockfile, LockfileData, PackagePolicy } from '../src/policy/lockfile';

function existingLock(packages: LockfileData['packages']): LockfileData {
  return { version: 1, generatedAt: new Date().toISOString(), packages };
}

describe('mergeLockfile — typosquat forces re-review', () => {
  it('downgrades an already-approved, content-unchanged package when a new typosquat match appears', () => {
    const old = existingLock({
      'lodahs@1.0.0': { contentHash: 'sha256:abc', capabilities: [], status: 'approved' },
    });
    const fresh: Record<string, PackagePolicy> = {
      'lodahs@1.0.0': { contentHash: 'sha256:abc', capabilities: [], status: 'approved', typosquatOf: 'lodash' },
    };

    const merged = mergeLockfile(old, fresh);
    expect(merged.packages['lodahs@1.0.0'].status).toBe('pending-review');
    expect(merged.packages['lodahs@1.0.0'].typosquatOf).toBe('lodash');
    expect(merged.packages['lodahs@1.0.0'].note).toMatch(/typosquat/i);
  });

  it('does not re-flag a typosquat that was already recorded on the old entry (respects an explicit re-approval)', () => {
    const old = existingLock({
      'lodahs@1.0.0': { contentHash: 'sha256:abc', capabilities: [], status: 'approved', typosquatOf: 'lodash' },
    });
    const fresh: Record<string, PackagePolicy> = {
      'lodahs@1.0.0': { contentHash: 'sha256:abc', capabilities: [], status: 'approved', typosquatOf: 'lodash' },
    };

    const merged = mergeLockfile(old, fresh);
    expect(merged.packages['lodahs@1.0.0'].status).toBe('approved');
  });

  it('downgrades on a content change too, even without any new capability', () => {
    const old = existingLock({
      'lodahs@1.0.0': { contentHash: 'sha256:aaa', capabilities: [], status: 'approved' },
    });
    const fresh: Record<string, PackagePolicy> = {
      'lodahs@1.0.0': { contentHash: 'sha256:bbb', capabilities: [], status: 'approved', typosquatOf: 'lodash' },
    };

    const merged = mergeLockfile(old, fresh);
    expect(merged.packages['lodahs@1.0.0'].status).toBe('pending-review');
  });

  it('drops a prior narrow --capability approval when a new typosquat flag forces re-review', () => {
    const old = existingLock({
      'lodahs@1.0.0': {
        contentHash: 'sha256:abc',
        capabilities: ['network'],
        allowedCapabilities: ['network'],
        status: 'approved',
      },
    });
    const fresh: Record<string, PackagePolicy> = {
      'lodahs@1.0.0': { contentHash: 'sha256:abc', capabilities: ['network'], status: 'approved', typosquatOf: 'lodash' },
    };

    const merged = mergeLockfile(old, fresh);
    expect(merged.packages['lodahs@1.0.0'].allowedCapabilities).toBeUndefined();
  });

  it('downgrades an already-approved package when a new life-cycle script risk pattern appears', () => {
    const old = existingLock({
      'risky-pkg@1.0.0': { contentHash: 'sha256:abc', capabilities: [], status: 'approved', lifecycleScripts: ['postinstall'] },
    });
    const fresh: Record<string, PackagePolicy> = {
      'risky-pkg@1.0.0': {
        contentHash: 'sha256:abc',
        capabilities: [],
        status: 'approved',
        lifecycleScripts: ['postinstall'],
        lifecycleScriptRisks: ['downloads over the network (curl)'],
      },
    };

    const merged = mergeLockfile(old, fresh);
    expect(merged.packages['risky-pkg@1.0.0'].status).toBe('pending-review');
    expect(merged.packages['risky-pkg@1.0.0'].note).toMatch(/risk pattern/i);
  });

  it('does not re-flag a risk pattern already recorded on the old entry', () => {
    const old = existingLock({
      'risky-pkg@1.0.0': {
        contentHash: 'sha256:abc',
        capabilities: [],
        status: 'approved',
        lifecycleScriptRisks: ['downloads over the network (curl)'],
      },
    });
    const fresh: Record<string, PackagePolicy> = {
      'risky-pkg@1.0.0': {
        contentHash: 'sha256:abc',
        capabilities: [],
        status: 'approved',
        lifecycleScriptRisks: ['downloads over the network (curl)'],
      },
    };

    const merged = mergeLockfile(old, fresh);
    expect(merged.packages['risky-pkg@1.0.0'].status).toBe('approved');
  });

  it('never un-downgrades a native-addon package (unsandboxed stays unsandboxed)', () => {
    const old = existingLock({
      'native-lib@1.0.0': { contentHash: 'sha256:abc', capabilities: ['native-binding'], status: 'unsandboxed' },
    });
    const fresh: Record<string, PackagePolicy> = {
      'native-lib@1.0.0': { contentHash: 'sha256:abc', capabilities: ['native-binding'], status: 'unsandboxed', typosquatOf: 'some-pkg' },
    };

    const merged = mergeLockfile(old, fresh);
    expect(merged.packages['native-lib@1.0.0'].status).toBe('unsandboxed');
  });
});
