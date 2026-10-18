import { Capability } from '../analyzer/capabilityMap';
import { LockfileData, PackagePolicy } from './lockfile';

export type DiffKind =
  | 'new-package'          // package didn't exist in old lockfile
  | 'removed-package'      // package no longer in node_modules
  | 'new-capability'       // package gained one or more capabilities
  | 'risk-flag-changed'    // typosquat match and/or a new life-cycle script appeared, capabilities did not change
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
  /** Set when the new policy flags this package as a likely typosquat — independent
   *  of capability changes, since a typosquat with zero declared capabilities is
   *  still worth surfacing (it's often the whole point of typosquatting). */
  typosquatOf?: string;
  /** Life-cycle scripts present in the new policy that weren't in the old one
   *  (or every declared script, for a brand new package). */
  newLifecycleScripts: string[];
}

export interface DiffSummary {
  diffs: PackageDiff[];
  newPackages: number;
  removedPackages: number;
  packagesWithNewCapabilities: number;
  /** Packages (any kind) where a typosquat match and/or a new life-cycle script appeared. */
  packagesWithNewRiskFlags: number;
  packagesWithContentChanges: number;
  unchanged: number;
}

/** Life-cycle scripts in `newPolicy` that weren't declared in `oldPolicy` (or all of them, if `oldPolicy` is absent). */
function diffNewLifecycleScripts(oldPolicy: PackagePolicy | undefined, newPolicy: PackagePolicy): string[] {
  const oldScripts = new Set(oldPolicy?.lifecycleScripts ?? []);
  return (newPolicy.lifecycleScripts ?? []).filter(s => !oldScripts.has(s));
}

/** The new typosquat match, only when it wasn't already flagged on the old policy. */
function diffTyposquat(oldPolicy: PackagePolicy | undefined, newPolicy: PackagePolicy): string | undefined {
  return newPolicy.typosquatOf && newPolicy.typosquatOf !== oldPolicy?.typosquatOf
    ? newPolicy.typosquatOf
    : undefined;
}

export function diffLockfiles(
  oldLock: LockfileData | null,
  newLock: LockfileData,
): DiffSummary {
  const oldPkgs    = oldLock?.packages ?? {};
  const newPkgs    = newLock.packages;

  const allKeys                 = new Set([...Object.keys(oldPkgs), ...Object.keys(newPkgs)]);
  const diffs: PackageDiff[]    = [];

  for (const key of allKeys) {
    const oldPolicy    = oldPkgs[key] as PackagePolicy | undefined;
    const newPolicy    = newPkgs[key] as PackagePolicy | undefined;

    if (!oldPolicy && newPolicy) {
      diffs.push({
        key,
        kind: 'new-package',
        oldPolicy: undefined,
        newPolicy,
        addedCapabilities: newPolicy.capabilities as Capability[],
        removedCapabilities: [],
        typosquatOf: newPolicy.typosquatOf,
        newLifecycleScripts: diffNewLifecycleScripts(undefined, newPolicy),
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
        newLifecycleScripts: [],
      });
      continue;
    }

    // Both exist
    if (!oldPolicy || !newPolicy) continue;

    const oldCaps    = new Set<Capability>(oldPolicy.capabilities as Capability[]);
    const newCaps    = new Set<Capability>(newPolicy.capabilities as Capability[]);

    const addedCapabilities = newPolicy.capabilities.filter(
      (c): c is Capability => !oldCaps.has(c as Capability),
    );
    const removedCapabilities = oldPolicy.capabilities.filter(
      (c): c is Capability => !newCaps.has(c as Capability),
    );

    const typosquatOf           = diffTyposquat(oldPolicy, newPolicy);
    const newLifecycleScripts   = diffNewLifecycleScripts(oldPolicy, newPolicy);
    const hasNewRiskFlag        = Boolean(typosquatOf) || newLifecycleScripts.length > 0;

    if (addedCapabilities.length > 0) {
      diffs.push({
        key,
        kind: 'new-capability',
        oldPolicy,
        newPolicy,
        addedCapabilities,
        removedCapabilities,
        typosquatOf,
        newLifecycleScripts,
      });
    } else if (removedCapabilities.length > 0) {
      diffs.push({
        key,
        kind: 'removed-capability',
        oldPolicy,
        newPolicy,
        addedCapabilities: [],
        removedCapabilities,
        typosquatOf,
        newLifecycleScripts,
      });
    } else if (hasNewRiskFlag) {
      // No capability change, but a typosquat match or a new life-cycle script
      // appeared — still worth surfacing even though nothing else changed.
      diffs.push({
        key,
        kind: 'risk-flag-changed',
        oldPolicy,
        newPolicy,
        addedCapabilities: [],
        removedCapabilities: [],
        typosquatOf,
        newLifecycleScripts,
      });
    } else if (oldPolicy.contentHash !== newPolicy.contentHash) {
      diffs.push({
        key,
        kind: 'content-changed',
        oldPolicy,
        newPolicy,
        addedCapabilities: [],
        removedCapabilities: [],
        newLifecycleScripts: [],
      });
    } else if (oldPolicy.status !== newPolicy.status) {
      diffs.push({
        key,
        kind: 'status-changed',
        oldPolicy,
        newPolicy,
        addedCapabilities: [],
        removedCapabilities: [],
        newLifecycleScripts: [],
      });
    } else {
      diffs.push({
        key,
        kind: 'unchanged',
        oldPolicy,
        newPolicy,
        addedCapabilities: [],
        removedCapabilities: [],
        newLifecycleScripts: [],
      });
    }
  }

  // Sort: most important changes first
  const priority: Record<DiffKind, number> = {
    'new-capability':       0,
    'risk-flag-changed':    1,
    'new-package':          2,
    'removed-package':      3,
    'content-changed':      4,
    'status-changed':       5,
    'removed-capability':   6,
    'unchanged':            7,
  };
  diffs.sort((a, b) => priority[a.kind] - priority[b.kind] || a.key.localeCompare(b.key));

  return {
    diffs,
    newPackages: diffs.filter(d => d.kind === 'new-package').length,
    removedPackages: diffs.filter(d => d.kind === 'removed-package').length,
    packagesWithNewCapabilities: diffs.filter(d => d.kind === 'new-capability').length,
    packagesWithNewRiskFlags: diffs.filter(d => d.typosquatOf || d.newLifecycleScripts.length > 0).length,
    packagesWithContentChanges: diffs.filter(d => d.kind === 'content-changed').length,
    unchanged: diffs.filter(d => d.kind === 'unchanged').length,
  };
}

// Returns true if the diff has any security-relevant changes (new caps, a new risk
// flag, or a new package carrying capabilities or a risk flag).
export function diffHasSecurityRelevantChanges(summary: DiffSummary): boolean {
  return summary.packagesWithNewCapabilities > 0 ||
    summary.packagesWithNewRiskFlags > 0 ||
    summary.diffs.some(
      d => d.kind === 'new-package' && d.addedCapabilities.length > 0,
    );
}
