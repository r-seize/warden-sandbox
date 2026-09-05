import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Capability } from './capabilityMap';
import { scanFile, scanFileHeuristic } from './astScanner';
import { collectJsFiles, hasNativeAddon } from './fileUtils';
import type { WorkerInput, WorkerMessage } from './scanWorker';

export interface PackageScanResult {
  name: string;
  version: string;
  contentHash: string;
  capabilities: Capability[];
  status: 'scanned' | 'unanalyzable' | 'unsandboxed';
  hasNativeBindings: boolean;
  unanalyzableFiles: string[];
  fileCount: number;
}

export interface ScanCacheEntry {
  contentHash: string;
  result: PackageScanResult;
}

/** Progress info emitted per-package when verbose scanning is active. */
export interface VerboseInfo {
  pkg: string;
  cached: boolean;
  timeMs: number;
  fileCount: number;
}

const MAX_FILE_SIZE = 5 * 1024 * 1024;

function hashDir(jsFiles: string[]): string {
  const hasher = crypto.createHash('sha256');
  for (const file of [...jsFiles].sort()) {
    hasher.update(file);
    try {
      const content = fs.readFileSync(file);
      hasher.update(content);
    } catch {
      // ignore unreadable files
    }
  }
  return 'sha256:' + hasher.digest('hex');
}

/** Read name + version from a package's package.json, returning empty object on failure. */
export function readPackageJson(pkgDir: string): { name?: string; version?: string } {
  try {
    const raw = fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8');
    return JSON.parse(raw) as { name?: string; version?: string };
  } catch {
    return {};
  }
}

/**
 * Scan a single package directory and return its capability profile.
 * Returns the cached result immediately when the content hash matches.
 */
export function scanPackage(
  pkgDir: string,
  cachedEntry?: ScanCacheEntry,
): PackageScanResult {
  const pkgJson    = readPackageJson(pkgDir);
  const name       = pkgJson.name ?? path.basename(pkgDir);
  const version    = pkgJson.version ?? 'unknown';

  const jsFiles        = collectJsFiles(pkgDir);
  const contentHash    = hashDir(jsFiles);

  if (cachedEntry && cachedEntry.contentHash === contentHash) {
    return cachedEntry.result;
  }

  const nativeBindings = hasNativeAddon(pkgDir);
  if (nativeBindings) {
    return {
      name,
      version,
      contentHash,
      capabilities: ['native-binding'] as Capability[],
      status: 'unsandboxed',
      hasNativeBindings: true,
      unanalyzableFiles: [],
      fileCount: jsFiles.length,
    };
  }

  const allCapabilities                = new Set<Capability>();
  const unanalyzableFiles: string[]    = [];

  for (const file of jsFiles) {
    let source: string;
    try {
      const stat = fs.statSync(file);
      if (stat.size > MAX_FILE_SIZE) {
        const raw = fs.readFileSync(file, 'utf8');
        for (const cap of scanFileHeuristic(raw)) allCapabilities.add(cap);
        unanalyzableFiles.push(path.relative(pkgDir, file) + ' (oversized)');
        continue;
      }
      source = fs.readFileSync(file, 'utf8');
    } catch {
      unanalyzableFiles.push(path.relative(pkgDir, file) + ' (unreadable)');
      continue;
    }

    const fileResult = scanFile(source);
    if (fileResult.unanalyzable) {
      for (const cap of scanFileHeuristic(source)) allCapabilities.add(cap);
      unanalyzableFiles.push(path.relative(pkgDir, file));
    } else {
      for (const cap of fileResult.capabilities) allCapabilities.add(cap);
    }
  }

  const capabilities = [...allCapabilities].sort() as Capability[];

  return {
    name,
    version,
    contentHash,
    capabilities,
    status: unanalyzableFiles.length > 0 && jsFiles.length > 0 && unanalyzableFiles.length === jsFiles.length
      ? 'unanalyzable'
      : 'scanned',
    hasNativeBindings: false,
    unanalyzableFiles,
    fileCount: jsFiles.length,
  };
}

/** Return the path to the global warden cache directory (~/.warden/cache). */
export function getGlobalCacheDir(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
  return path.join(home, '.warden', 'cache');
}

/** Load all cached scan results from the global cache directory. */
export function loadGlobalCache(): Map<string, ScanCacheEntry> {
  const cacheDir    = getGlobalCacheDir();
  const cache       = new Map<string, ScanCacheEntry>();
  try {
    if (!fs.existsSync(cacheDir)) return cache;
    const files = fs.readdirSync(cacheDir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const entry = JSON.parse(fs.readFileSync(path.join(cacheDir, file), 'utf8')) as ScanCacheEntry;
        cache.set(entry.result.name + '@' + entry.result.version, entry);
      } catch { /* skip corrupt entries */ }
    }
  } catch { /* ignore */ }
  return cache;
}

/** Persist a scan result to the global cache so future scans in other projects skip it. */
export function saveToGlobalCache(result: PackageScanResult): void {
  const cacheDir = getGlobalCacheDir();
  try {
    fs.mkdirSync(cacheDir, { recursive: true });
    const key                      = result.name.replace(/\//g, '__') + '@' + result.version;
    const entry: ScanCacheEntry    = { contentHash: result.contentHash, result };
    fs.writeFileSync(path.join(cacheDir, `${key}.json`), JSON.stringify(entry), 'utf8');
  } catch { /* ignore cache write errors */ }
}

// ─── Worker-pool parallel scan ───────────────────────────────────────────────

/** Maximum number of worker threads to spawn for parallel scanning. */
const MAX_WORKERS = 4;

/**
 * Distribute packages across worker threads and collect results.
 * Falls back silently to sequential scanning when the compiled worker
 * file is not found (e.g. running under tsx in dev mode).
 */
async function scanWithWorkers(
  packages: string[],
  cache: Map<string, ScanCacheEntry>,
  globalCache: Map<string, ScanCacheEntry>,
  useGlobalCache: boolean,
  results: PackageScanResult[],
  onPackageDone: (name: string, cached: boolean, timeMs: number, fileCount: number) => void,
): Promise<boolean> {
  const workerPath = path.join(__dirname, 'scanWorker.js');
  if (!fs.existsSync(workerPath)) return false;

  const { Worker } = await import('node:worker_threads');

  const numWorkers    = Math.min(MAX_WORKERS, packages.length);
  const chunkSize     = Math.ceil(packages.length / numWorkers);

  interface Chunk {
    pkgDirs: string[];
    cacheEntries: Array<ScanCacheEntry | null>;
    baseIndex: number;
  }

  const chunks: Chunk[] = [];
  for (let i = 0; i < packages.length; i += chunkSize) {
    const pkgDirs = packages.slice(i, i + chunkSize);
    const cacheEntries: Array<ScanCacheEntry | null> = pkgDirs.map(pkgDir => {
      const { name, version }    = readPackageJson(pkgDir);
      const key                  = `${name ?? path.basename(pkgDir)}@${version ?? 'unknown'}`;
      return cache.get(key) ?? (useGlobalCache ? globalCache.get(key) : undefined) ?? null;
    });
    chunks.push({ pkgDirs, cacheEntries, baseIndex: i });
  }

  await Promise.all(chunks.map(chunk =>
    new Promise<void>((resolve, reject) => {
      const input: WorkerInput = {
        pkgDirs: chunk.pkgDirs,
        cacheEntries: chunk.cacheEntries,
      };
      const worker = new Worker(workerPath, { workerData: input });

      worker.on('message', (msg: WorkerMessage) => {
        results[chunk.baseIndex + msg.index] = msg.result;
        onPackageDone(msg.name, msg.cached, msg.timeMs, msg.result.fileCount);
      });
      worker.on('error', reject);
      worker.on('exit', code => {
        if (code !== 0) reject(new Error(`Scan worker exited with code ${code}`));
        else resolve();
      });
    }),
  ));

  return true;
}

/**
 * Scan all packages in a node_modules directory.
 *
 * Uses up to 4 worker threads when the compiled worker file is present
 * (production), falling back to sequential scanning in dev mode.
 *
 * @param nodeModulesDir  Absolute path to the node_modules directory.
 * @param cache           Per-project cache seeded from the current lockfile.
 * @param onProgress      Optional callback invoked after each package completes.
 * @param useGlobalCache  When true, reads/writes the ~/.warden/cache global cache.
 * @param onVerbose       Optional callback with per-package timing and cache info.
 */
export async function scanNodeModules(
  nodeModulesDir: string,
  cache: Map<string, ScanCacheEntry>,
  onProgress?: (done: number, total: number, pkgName: string) => void,
  useGlobalCache = true,
  onVerbose?: (info: VerboseInfo) => void,
): Promise<PackageScanResult[]> {
  const globalCache = useGlobalCache ? loadGlobalCache() : new Map<string, ScanCacheEntry>();

  const packages                        = discoverPackages(nodeModulesDir);
  const results: PackageScanResult[]    = new Array(packages.length);
  let done                              = 0;

  const onPackageDone = (name: string, cached: boolean, timeMs: number, fileCount: number) => {
    done++;
    onProgress?.(done, packages.length, name);
    onVerbose?.({ pkg: name, cached, timeMs, fileCount });
  };

  const usedWorkers = await scanWithWorkers(
    packages, cache, globalCache, useGlobalCache, results, onPackageDone,
  );

  if (!usedWorkers) {
    // Sequential fallback (dev mode or very small package list)
    for (let i = 0; i < packages.length; i++) {
      const pkgDir         = packages[i];
      const pkgJson        = readPackageJson(pkgDir);
      const name           = pkgJson.name ?? path.basename(pkgDir);
      const version        = pkgJson.version ?? 'unknown';
      const cacheKey       = `${name}@${version}`;
      const cachedEntry    = cache.get(cacheKey) ?? globalCache.get(cacheKey);

      const t0            = Date.now();
      const isCacheHit    = cachedEntry !== undefined;
      const result        = scanPackage(pkgDir, cachedEntry);
      const timeMs        = Date.now() - t0;
      results[i]          = result;

      if (!isCacheHit && useGlobalCache) {
        saveToGlobalCache(result);
      }

      onPackageDone(name, isCacheHit, timeMs, result.fileCount);
    }
  }

  onProgress?.(done, packages.length, '');
  return results.filter(Boolean);
}

/** Enumerate all top-level (and scoped) package directories inside node_modules. */
function discoverPackages(nodeModulesDir: string): string[] {
  const packages: string[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(nodeModulesDir, { withFileTypes: true });
  } catch {
    return packages;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith('.')) continue;
    if (entry.name.startsWith('@')) {
      const scopedDir = path.join(nodeModulesDir, entry.name);
      let scoped: fs.Dirent[];
      try {
        scoped = fs.readdirSync(scopedDir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const s of scoped) {
        if (s.isDirectory()) {
          packages.push(path.join(scopedDir, s.name));
        }
      }
    } else {
      packages.push(path.join(nodeModulesDir, entry.name));
    }
  }
  return packages;
}
