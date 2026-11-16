import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Capability } from './capabilityMap';
import { scanFile, scanFileHeuristic, scanFileHeuristicEvasion } from './astScanner';
import { collectJsFiles, hasNativeAddon, isDirEntry } from './fileUtils';
import { detectTyposquat, TyposquatOptions } from './typosquat';
import { analyzeLifecycleScriptRisk } from './scriptRisk';
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
  /** npm life-cycle script names ('preinstall' | 'install' | 'postinstall') the package declares.
   *  These run at install time, outside Warden's load-time sandboxing — surfaced for visibility only. */
  lifecycleScripts: string[];
  /** Static risk-pattern labels matched across all declared life-cycle script commands
   *  (curl/wget, base64, chmod +x, piping into a shell, ...). See scriptRisk.ts. */
  lifecycleScriptRisks: string[];
  /** Set when the package name is a likely one-character typo of a popular package (see typosquat.ts). */
  typosquatOf: string | null;
  /** Static code-obfuscation idioms found in the package's JS (base64-decoded strings
   *  feeding a call, indirect Function constructor access). See astEngine.ts. */
  evasionPatterns: string[];
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

interface PackageJsonMeta {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
}

/** Read name + version from a package's package.json, returning empty object on failure. */
export function readPackageJson(pkgDir: string): PackageJsonMeta {
  try {
    const raw = fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8');
    return JSON.parse(raw) as PackageJsonMeta;
  } catch {
    return {};
  }
}

const LIFECYCLE_SCRIPT_NAMES = ['preinstall', 'install', 'postinstall'];

/** Names of npm life-cycle install scripts ('preinstall'/'install'/'postinstall') the package declares. */
function detectLifecycleScripts(pkgJson: PackageJsonMeta): string[] {
  const scripts = pkgJson.scripts ?? {};
  return LIFECYCLE_SCRIPT_NAMES.filter(name => typeof scripts[name] === 'string' && scripts[name].trim().length > 0);
}

/** Static risk-pattern labels matched across all of the package's declared life-cycle scripts. */
function detectLifecycleScriptRisks(pkgJson: PackageJsonMeta, lifecycleScripts: string[]): string[] {
  const scripts    = pkgJson.scripts ?? {};
  const matched    = new Set<string>();
  for (const name of lifecycleScripts) {
    for (const risk of analyzeLifecycleScriptRisk(scripts[name] ?? '')) matched.add(risk);
  }
  return [...matched];
}

/**
 * Scan a single package directory and return its capability profile.
 * Returns the cached result immediately when the content hash matches.
 */
export function scanPackage(
  pkgDir: string,
  cachedEntry?: ScanCacheEntry,
  typosquatOptions?: TyposquatOptions,
): PackageScanResult {
  const pkgJson    = readPackageJson(pkgDir);
  const name       = pkgJson.name ?? path.basename(pkgDir);
  const version    = pkgJson.version ?? 'unknown';

  const jsFiles                 = collectJsFiles(pkgDir);
  const contentHash             = hashDir(jsFiles);
  const lifecycleScripts        = detectLifecycleScripts(pkgJson);
  const lifecycleScriptRisks    = detectLifecycleScriptRisks(pkgJson, lifecycleScripts);
  const typosquatOf             = detectTyposquat(name, typosquatOptions);

  if (cachedEntry && cachedEntry.contentHash === contentHash) {
    // The expensive part (AST-scanning every file for capabilities) is skipped —
    // that's the whole point of the cache. But typosquatOf/lifecycleScripts are
    // cheap, name/metadata-derived checks that must stay current: otherwise a
    // cached package silently keeps serving whatever verdict was computed the
    // first time it was scanned, even after a warden upgrade changes the
    // detection (e.g. a larger typosquat list) — exactly the case a cache
    // should never cause a security check to go stale for.
    return { ...cachedEntry.result, typosquatOf, lifecycleScripts, lifecycleScriptRisks };
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
      lifecycleScripts,
      lifecycleScriptRisks,
      typosquatOf,
      evasionPatterns: [],
    };
  }

  const allCapabilities                = new Set<Capability>();
  const allEvasionPatterns             = new Set<string>();
  const unanalyzableFiles: string[]    = [];

  for (const file of jsFiles) {
    let source: string;
    try {
      const stat = fs.statSync(file);
      if (stat.size > MAX_FILE_SIZE) {
        const raw = fs.readFileSync(file, 'utf8');
        for (const cap of scanFileHeuristic(raw)) allCapabilities.add(cap);
        for (const pattern of scanFileHeuristicEvasion(raw)) allEvasionPatterns.add(pattern);
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
      for (const pattern of scanFileHeuristicEvasion(source)) allEvasionPatterns.add(pattern);
      unanalyzableFiles.push(path.relative(pkgDir, file));
    } else {
      for (const cap of fileResult.capabilities) allCapabilities.add(cap);
      for (const pattern of fileResult.evasionPatterns) allEvasionPatterns.add(pattern);
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
    evasionPatterns: [...allEvasionPatterns],
    fileCount: jsFiles.length,
    lifecycleScripts,
    lifecycleScriptRisks,
    typosquatOf,
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
  typosquatOptions?: TyposquatOptions,
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
        typosquatOptions,
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
  typosquatOptions?: TyposquatOptions,
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
    packages, cache, globalCache, useGlobalCache, results, onPackageDone, typosquatOptions,
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
      const result        = scanPackage(pkgDir, cachedEntry, typosquatOptions);
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

/**
 * Scan a whole project: the root node_modules plus any workspace packages'
 * own node_modules (npm/yarn `workspaces`, or pnpm-workspace.yaml). Results
 * are merged by `name@version`; a package already seen in an earlier target
 * is not re-scanned under a later one.
 */
export async function scanProject(
  projectDir: string,
  cache: Map<string, ScanCacheEntry>,
  onProgress?: (done: number, total: number, pkgName: string) => void,
  useGlobalCache = true,
  onVerbose?: (info: VerboseInfo) => void,
  typosquatOptions?: TyposquatOptions,
): Promise<PackageScanResult[]> {
  const targets = discoverScanTargets(projectDir);
  if (targets.length <= 1) {
    const nodeModulesDir = targets[0]?.nodeModulesDir ?? path.join(projectDir, 'node_modules');
    return scanNodeModules(nodeModulesDir, cache, onProgress, useGlobalCache, onVerbose, typosquatOptions);
  }

  const merged    = new Map<string, PackageScanResult>();
  for (const target of targets) {
    const results = await scanNodeModules(target.nodeModulesDir, cache, onProgress, useGlobalCache, onVerbose, typosquatOptions);
    for (const result of results) {
      const key = `${result.name}@${result.version}`;
      if (!merged.has(key)) merged.set(key, result);
    }
  }
  return [...merged.values()];
}

/**
 * Enumerate all top-level (and scoped) package directories inside node_modules.
 *
 * pnpm (and npm/yarn workspaces) link packages into node_modules via symlinks
 * rather than real directories, so entries are checked with {@link isDirEntry}
 * (which resolves symlinks) instead of the raw, symlink-blind `Dirent.isDirectory()`.
 */
function discoverPackages(nodeModulesDir: string): string[] {
  const packages: string[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(nodeModulesDir, { withFileTypes: true });
  } catch {
    return packages;
  }
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    const fullPath = path.join(nodeModulesDir, entry.name);
    if (!isDirEntry(fullPath, entry)) continue;
    if (entry.name.startsWith('@')) {
      let scoped: fs.Dirent[];
      try {
        scoped = fs.readdirSync(fullPath, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const s of scoped) {
        const scopedPath = path.join(fullPath, s.name);
        if (isDirEntry(scopedPath, s)) {
          packages.push(scopedPath);
        }
      }
    } else {
      packages.push(fullPath);
    }
  }
  return packages;
}

// ─── Workspace / monorepo discovery ──────────────────────────────────────────

export interface ScanTarget {
  /** Directory the node_modules belongs to (project root, or a workspace package). */
  dir: string;
  nodeModulesDir: string;
}

interface RootPackageJson {
  workspaces?: string[] | { packages?: string[] };
}

/** Read workspace glob patterns from package.json ("workspaces") and pnpm-workspace.yaml. */
function readWorkspacePatterns(projectDir: string): string[] {
  const patterns: string[] = [];

  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8')) as RootPackageJson;
    if (Array.isArray(pkg.workspaces)) {
      patterns.push(...pkg.workspaces);
    } else if (pkg.workspaces?.packages) {
      patterns.push(...pkg.workspaces.packages);
    }
  } catch { /* no package.json, or no workspaces field */ }

  try {
    const raw     = fs.readFileSync(path.join(projectDir, 'pnpm-workspace.yaml'), 'utf8');
    const lines   = raw.split('\n');
    let inList    = false;
    for (const line of lines) {
      if (/^\s*packages\s*:/.test(line)) { inList = true; continue; }
      if (inList) {
        const item = line.match(/^\s*-\s*['"]?([^'"]+)['"]?\s*$/);
        if (item) { patterns.push(item[1]); continue; }
        if (line.trim().length > 0 && !line.startsWith(' ') && !line.startsWith('-')) break;
      }
    }
  } catch { /* no pnpm-workspace.yaml */ }

  return patterns;
}

/**
 * Expand a single workspace glob pattern into directories.
 * Supports literal paths ("apps/api") and a single trailing wildcard segment
 * ("packages/*"). Other glob syntax (nested wildcards, "!" exclusions) is not
 * supported and is skipped rather than mis-resolved.
 */
function expandWorkspacePattern(projectDir: string, pattern: string): string[] {
  const normalized = pattern.replace(/\/+$/, '');

  if (normalized.endsWith('/*')) {
    const baseDir = path.join(projectDir, normalized.slice(0, -2));
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(baseDir, { withFileTypes: true });
    } catch {
      return [];
    }
    return entries
      .filter(e => !e.name.startsWith('.') && isDirEntry(path.join(baseDir, e.name), e))
      .map(e => path.join(baseDir, e.name));
  }

  if (normalized.includes('*')) return []; // unsupported glob shape — skip

  const dir = path.join(projectDir, normalized);
  return fs.existsSync(dir) ? [dir] : [];
}

/** Discover every node_modules directory relevant to a project: the root, plus any workspace packages. */
export function discoverScanTargets(projectDir: string): ScanTarget[] {
  const targets: ScanTarget[]    = [];
  const seen                     = new Set<string>();

  const add = (dir: string) => {
    const nodeModulesDir = path.join(dir, 'node_modules');
    if (seen.has(nodeModulesDir)) return;
    if (!fs.existsSync(nodeModulesDir)) return;
    seen.add(nodeModulesDir);
    targets.push({ dir, nodeModulesDir });
  };

  add(projectDir);

  const patterns = readWorkspacePatterns(projectDir);
  for (const pattern of patterns) {
    for (const wsDir of expandWorkspacePattern(projectDir, pattern)) {
      add(wsDir);
    }
  }

  return targets;
}
