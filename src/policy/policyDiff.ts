import { Capability } from '../analyzer/capabilityMap';
import { LockfileData, PackagePolicy } from './lockfile';

export type DiffKind =
  | 'new-package'          // package didn't exist in old lockfile
  | 'removed-package'      // package no longer in node_modules
  | 'new-capability'       // package gained one or more capabilities
  | 'removed-capability'   // package lost capabilities (version downgrade, cleanup)
  | 'content-changed'      // hash changed but capabilities unchanged
  | 'status-changed'       // status field changed (e.g., manually approved)
  | 'unchanged';           // identical

export interface PackageDiff {
  key: string;
  kind: DiffKind;
  oldPolicy?: PackagePolicy;
  newPolicy?: PackagePolicy;
  addedCapabilities: Capability[];
  removedCapabilities: Capability[];
}

export interface DiffSummary {
  diffs: PackageDiff[];
  newPackages: number;
  removedPackages: number;
  packagesWithNewCapabilities: number;
  packagesWithContentChanges: number;
  unchanged: number;
}

export function diffLockfiles(
  oldLock: LockfileData | null,
  newLock: LockfileData,
): DiffSummary {
  const oldPkgs = oldLock?.packages ?? {};
  const newPkgs = newLock.packages;

  const allKeys = new Set([...Object.keys(oldPkgs), ...Object.keys(newPkgs)]);
  const diffs: PackageDiff[] = [];

  for (const key of allKeys) {
    const oldPolicy = oldPkgs[key] as PackagePolicy | undefined;
    const newPolicy = newPkgs[key] as PackagePolicy | undefined;

    if (!oldPolicy && newPolicy) {
      diffs.push({
        key,
        kind: 'new-package',
        oldPolicy: undefined,
        newPolicy,
        addedCapabilities: newPolicy.capabilities as Capability[],
        removedCapabilities: [],
      });
      continue;
    }

    if (oldPolicy && !newPolicy) {
      diffs.push({
        key,
        kind: 'removed-package',
        oldPolicy,
        newPolicy: undefined,
        addedCapabilities: [],
        removedCapabilities: oldPolicy.capabilities as Capability[],
      });
      continue;
    }

    // Both exist
    if (!oldPolicy || !newPolicy) continue;

    const oldCaps = new Set<Capability>(oldPolicy.capabilities as Capability[]);
    const newCaps = new Set<Capability>(newPolicy.capabilities as Capability[]);

    const addedCapabilities = newPolicy.capabilities.filter(
      (c): c is Capability => !oldCaps.has(c as Capability),
    );
    const removedCapabilities = oldPolicy.capabilities.filter(
      (c): c is Capability => !newCaps.has(c as Capability),
    );

    if (addedCapabilities.length > 0) {
      diffs.push({
        key,
        kind: 'new-capability',
        oldPolicy,
        newPolicy,
        addedCapabilities,
        removedCapabilities,
      });
    } else if (removedCapabilities.length > 0) {
      diffs.push({
        key,
        kind: 'removed-capability',
        oldPolicy,
        newPolicy,
        addedCapabilities: [],
        removedCapabilities,
      });
    } else if (oldPolicy.contentHash !== newPolicy.contentHash) {
      diffs.push({
        key,
        kind: 'content-changed',
        oldPolicy,
        newPolicy,
        addedCapabilities: [],
        removedCapabilities: [],
      });
    } else if (oldPolicy.status !== newPolicy.status) {
      diffs.push({
        key,
        kind: 'status-changed',
        oldPolicy,
        newPolicy,
        addedCapabilities: [],
        removedCapabilities: [],
      });
    } else {
      diffs.push({
        key,
        kind: 'unchanged',
        oldPolicy,
        newPolicy,
        addedCapabilities: [],
        removedCapabilities: [],
      });
    }
  }

  // Sort: most important changes first
  const priority: Record<DiffKind, number> = {
    'new-capability':       0,
    'new-package':          1,
    'removed-package':      2,
    'content-changed':      3,
    'status-changed':       4,
    'removed-capability':   5,
    'unchanged':            6,
  };
  diffs.sort((a, b) => priority[a.kind] - priority[b.kind] || a.key.localeCompare(b.key));

  return {
    diffs,
    newPackages: diffs.filter(d => d.kind === 'new-package').length,
    removedPackages: diffs.filter(d => d.kind === 'removed-package').length,
    packagesWithNewCapabilities: diffs.filter(d => d.kind === 'new-capability').length,
    packagesWithContentChanges: diffs.filter(d => d.kind === 'content-changed').length,
    unchanged: diffs.filter(d => d.kind === 'unchanged').length,
  };
}

// Returns true if the diff has any security-relevant changes (new caps or new packages with caps).
export function diffHasSecurityRelevantChanges(summary: DiffSummary): boolean {
  return summary.packagesWithNewCapabilities > 0 ||
    summary.diffs.some(
      d => d.kind === 'new-package' && d.addedCapabilities.length > 0,
    );
}
