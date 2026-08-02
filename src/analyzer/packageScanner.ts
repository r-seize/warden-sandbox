import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Capability } from './capabilityMap';
import { scanFile, scanFileHeuristic } from './astScanner';

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

const JS_EXTENSIONS = new Set(['.js', '.cjs', '.mjs']);
const SKIP_DIRS = new Set(['node_modules', '.git', '.github', '__tests__', '__mocks__', 'test', 'tests', 'spec', 'docs', 'examples', 'fixtures', 'coverage']);
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB — skip absurdly large files

function collectJsFiles(dir: string): string[] {
  const results: string[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      results.push(...collectJsFiles(path.join(dir, entry.name)));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (JS_EXTENSIONS.has(ext)) {
        results.push(path.join(dir, entry.name));
      }
    }
  }
  return results;
}

function hasNativeAddon(dir: string): boolean {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith('.node')) return true;
    if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) {
      if (hasNativeAddon(path.join(dir, entry.name))) return true;
    }
  }
  return false;
}

function hashDir(jsFiles: string[]): string {
  const hasher = crypto.createHash('sha256');
  // Sort for determinism
  for (const file of [...jsFiles].sort()) {
    hasher.update(file); // include path so renames are detected
    try {
      const content = fs.readFileSync(file);
      hasher.update(content);
    } catch {
      // ignore unreadable files
    }
  }
  return 'sha256:' + hasher.digest('hex');
}

function readPackageJson(pkgDir: string): { name?: string; version?: string } {
  try {
    const raw = fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8');
    return JSON.parse(raw) as { name?: string; version?: string };
  } catch {
    return {};
  }
}

export interface ScanCacheEntry {
  contentHash: string;
  result: PackageScanResult;
}

export function scanPackage(
  pkgDir: string,
  cachedEntry?: ScanCacheEntry,
): PackageScanResult {
  const pkgJson = readPackageJson(pkgDir);
  const name = pkgJson.name ?? path.basename(pkgDir);
  const version = pkgJson.version ?? 'unknown';

  const jsFiles = collectJsFiles(pkgDir);
  const contentHash = hashDir(jsFiles);

  // Cache hit: same content hash → return cached result
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

  const allCapabilities = new Set<Capability>();
  const unanalyzableFiles: string[] = [];

  for (const file of jsFiles) {
    let source: string;
    try {
      const stat = fs.statSync(file);
      if (stat.size > MAX_FILE_SIZE) {
        // Oversized file: use heuristic scan instead of full AST
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
      // Fall back to heuristic regex scan so we still get some signal
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

// Scan all packages in a node_modules directory with optional progress callback.
export async function scanNodeModules(
  nodeModulesDir: string,
  cache: Map<string, ScanCacheEntry>,
  onProgress?: (done: number, total: number, pkgName: string) => void,
): Promise<PackageScanResult[]> {
  const packages = discoverPackages(nodeModulesDir);
  const results: PackageScanResult[] = [];
  let done = 0;

  for (const pkgDir of packages) {
    const pkgJson = readPackageJson(pkgDir);
    const name = pkgJson.name ?? path.basename(pkgDir);
    const version = pkgJson.version ?? 'unknown';
    const cacheKey = `${name}@${version}`;
    const cachedEntry = cache.get(cacheKey);

    onProgress?.(done, packages.length, name);

    const result = scanPackage(pkgDir, cachedEntry);
    results.push(result);
    done++;
  }

  onProgress?.(done, packages.length, '');
  return results;
}

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
      // Scoped package: e.g. @types/node
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
