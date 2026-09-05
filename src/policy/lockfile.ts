import * as fs from 'node:fs';
import * as path from 'node:path';
import { Capability } from '../analyzer/capabilityMap';

export type PackageStatus = 'approved' | 'pending-review' | 'unsandboxed' | 'unanalyzable';

export interface PackagePolicy {
  contentHash: string;
  capabilities: Capability[];
  /** Explicit subset of capabilities approved with `warden approve --capability`. When
   *  present, the runtime enforces ONLY these capabilities (ignoring the full capabilities
   *  list), so the package is blocked from accessing anything outside this list. */
  allowedCapabilities?: Capability[];
  /** Capabilities explicitly denied with `warden approve --deny`. These are subtracted
   *  from the effective capability set at runtime, even if the package declared them. */
  deniedCapabilities?: Capability[];
  status: PackageStatus;
  note?: string;
}

export interface LockfileData {
  version: 1;
  generatedAt: string;
  packages: Record<string, PackagePolicy>;
}

export const LOCKFILE_NAME = 'warden.lock.json';

export function readLockfile(dir: string): LockfileData | null {
  const lockPath = path.join(dir, LOCKFILE_NAME);
  try {
    const raw       = fs.readFileSync(lockPath, 'utf8');
    const parsed    = JSON.parse(raw) as LockfileData;
    if (parsed.version !== 1) {
      throw new Error(`Unsupported lockfile version: ${parsed.version}`);
    }
    return parsed;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw new Error(
      `Failed to parse ${lockPath}: ${(err as Error).message}. Run "warden scan" to regenerate.`,
    );
  }
}

export function writeLockfile(dir: string, data: LockfileData): void {
  const lockPath = path.join(dir, LOCKFILE_NAME);
  fs.writeFileSync(lockPath, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

export function createEmptyLockfile(): LockfileData {
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    packages: {},
  };
}

// Merge a new set of scan results into an existing lockfile, preserving
// user-approved statuses and notes where the content hash hasn't changed.
export function mergeLockfile(
  existing: LockfileData | null,
  newEntries: Record<string, PackagePolicy>,
): LockfileData {
  const base                                     = existing ?? createEmptyLockfile();
  const merged: Record<string, PackagePolicy>    = {};

  for (const [key, newEntry] of Object.entries(newEntries)) {
    const oldEntry = base.packages[key];

    if (!oldEntry) {
      // New package, never seen before
      merged[key] = { ...newEntry };
      continue;
    }

    if (oldEntry.contentHash === newEntry.contentHash) {
      // Content unchanged: preserve user policy overrides, status, and note
      merged[key] = {
        ...newEntry,
        status: oldEntry.status,
        note: oldEntry.note,
        ...(oldEntry.allowedCapabilities ? { allowedCapabilities: oldEntry.allowedCapabilities } : {}),
        ...(oldEntry.deniedCapabilities  ? { deniedCapabilities:  oldEntry.deniedCapabilities  } : {}),
      };
      continue;
    }

    // Content changed: detect new capabilities and downgrade status
    const oldCaps      = new Set(oldEntry.capabilities);
    const addedCaps    = newEntry.capabilities.filter(c => !oldCaps.has(c));

    let note: string | undefined;
    if (addedCaps.length > 0) {
      note = `New capabilities detected after update: ${addedCaps.join(', ')}. Previously approved as: [${oldEntry.capabilities.join(', ') || 'none'}].`;
    } else if (oldEntry.status === 'approved') {
      note = 'Content hash changed (code modified). Re-review recommended.';
    }

    merged[key] = {
      ...newEntry,
      status: addedCaps.length > 0 || newEntry.status === 'unsandboxed'
        ? newEntry.status === 'unsandboxed' ? 'unsandboxed' : 'pending-review'
        : oldEntry.status,
      note,
      // allowedCapabilities is intentionally dropped on content change (capabilities may differ).
      // deniedCapabilities is preserved — the user's explicit deny intent remains valid.
      ...(oldEntry.deniedCapabilities ? { deniedCapabilities: oldEntry.deniedCapabilities } : {}),
    };
  }

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    packages: merged,
  };
}
