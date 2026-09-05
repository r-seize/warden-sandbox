import * as fs from 'node:fs';
import * as path from 'node:path';

/** Directories skipped during recursive JS file collection. */
export const SKIP_DIRS = new Set([
  'node_modules', '.git', '.github',
  '__tests__', '__mocks__',
  'test', 'tests', 'spec',
  'docs', 'examples', 'fixtures', 'coverage',
]);

const JS_EXTENSIONS = new Set(['.js', '.cjs', '.mjs']);

/**
 * Recursively collect all JavaScript files under `dir`, skipping
 * test/doc/coverage directories. Files larger than `maxSize` bytes are
 * included (callers decide how to handle oversized files).
 */
export function collectJsFiles(dir: string): string[] {
  const results: string[] = [];
  _collect(dir, results);
  return results;
}

function _collect(dir: string, out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) _collect(path.join(dir, entry.name), out);
    } else if (entry.isFile() && JS_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      out.push(path.join(dir, entry.name));
    }
  }
}

/**
 * Check recursively whether `dir` contains any native `.node` addon files.
 */
export function hasNativeAddon(dir: string): boolean {
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

/**
 * Build a sorted array of line-start character offsets for `source`.
 * Index 0 = start of line 1 (always 0).
 * Used for O(log n) position-to-line conversion.
 */
export function buildLineIndex(source: string): number[] {
  const offsets: number[] = [0];
  for (let i = 0; i < source.length; i++) {
    if (source[i] === '\n') offsets.push(i + 1);
  }
  return offsets;
}

/**
 * Convert a character position to a 1-based line number using a pre-built
 * line index (see {@link buildLineIndex}). O(log n).
 */
export function posToLine(lineIndex: number[], pos: number): number {
  let lo    = 0;
  let hi    = lineIndex.length - 1;
  while (lo < hi) {
    const mid                        = (lo + hi + 1) >> 1;
    if (lineIndex[mid] <= pos) lo    = mid;
    else hi                          = mid - 1;
  }
  return lo + 1;
}
