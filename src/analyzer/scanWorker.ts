/**
 * Worker thread entry point for parallel package scanning.
 * Receives a batch of package directories via workerData and posts one
 * WorkerMessage per package back to the main thread.
 */
import { workerData, parentPort } from 'node:worker_threads';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { scanPackage, saveToGlobalCache, ScanCacheEntry, PackageScanResult } from './packageScanner';

export interface WorkerInput {
  pkgDirs: string[];
  /** Pre-serialised cache entries, null when the package is not cached. */
  cacheEntries: Array<ScanCacheEntry | null>;
}

export interface WorkerMessage {
  type: 'result';
  /** Position of this package in the original pkgDirs array. */
  index: number;
  result: PackageScanResult;
  name: string;
  timeMs: number;
  /** Whether the result came from the cache (no re-scan was performed). */
  cached: boolean;
}

const { pkgDirs, cacheEntries } = workerData as WorkerInput;

for (let i = 0; i < pkgDirs.length; i++) {
  const pkgDir         = pkgDirs[i];
  const cachedEntry    = cacheEntries[i] ?? undefined;
  const isCached       = cachedEntry !== undefined;

  const t0        = Date.now();
  const result    = scanPackage(pkgDir, cachedEntry);
  const timeMs    = Date.now() - t0;

  if (!isCached) {
    saveToGlobalCache(result);
  }

  // Read package name directly so we can report it even when the scan is cached
  let displayName = result.name;
  if (!displayName) {
    try {
      const raw      = fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8');
      displayName    = (JSON.parse(raw) as { name?: string }).name ?? path.basename(pkgDir);
    } catch {
      displayName = path.basename(pkgDir);
    }
  }

  parentPort!.postMessage({
    type: 'result',
    index: i,
    result,
    name: displayName,
    timeMs,
    cached: isCached,
  } as WorkerMessage);
}
