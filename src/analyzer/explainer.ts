import * as fs from 'node:fs';
import * as path from 'node:path';
import { analyzeSource } from './astEngine';
import { collectJsFiles, buildLineIndex, posToLine } from './fileUtils';
import { Capability } from './capabilityMap';

export interface CapabilityEvidence {
  capability: Capability;
  file: string;
  line: number;
  snippet: string;
}

export interface PackageExplainResult {
  name: string;
  version: string;
  pkgDir: string;
  capabilities: Capability[];
  evidence: CapabilityEvidence[];
  unanalyzableFiles: string[];
}

function makeSnippet(source: string, start: number, end: number): string {
  const raw = source.slice(start, end).trim();
  return raw.length > 80 ? raw.slice(0, 79) + '…' : raw;
}

/**
 * Analyse a single source file for capability evidence, returning one
 * {@link CapabilityEvidence} entry per detected AST node.
 */
export function explainFile(source: string, relPath: string): CapabilityEvidence[] {
  const { evidence: rawEvidence, unanalyzable } = analyzeSource(source, true);
  if (unanalyzable) return [];

  const lineIndex = buildLineIndex(source);
  const evidence: CapabilityEvidence[] = rawEvidence.map(e => ({
    capability: e.capability,
    file: relPath,
    line: posToLine(lineIndex, e.start),
    snippet: makeSnippet(source, e.start, e.end),
  }));

  // Supplement: native .node require() calls — not handled by astEngine
  const nativeRe = /require\(['"]([^'"]*\.node)['"]\)/g;
  let m: RegExpExecArray | null;
  while ((m = nativeRe.exec(source)) !== null) {
    const line = posToLine(lineIndex, m.index);
    if (!evidence.some(e => e.capability === 'native-binding' && e.line === line)) {
      const raw = m[0];
      evidence.push({
        capability: 'native-binding',
        file: relPath,
        line,
        snippet: raw.length > 80 ? raw.slice(0, 79) + '…' : raw,
      });
    }
  }

  return evidence;
}

/** Scan all JS files in a package directory and return aggregated capability evidence. */
export function explainPackage(nodeModulesDir: string, pkgName: string): PackageExplainResult {
  let pkgDir: string;
  if (pkgName.startsWith('@')) {
    const parts = pkgName.split('/');
    if (parts.length < 2 || !parts[1]) {
      return { name: pkgName, version: 'unknown', pkgDir: '', capabilities: [], evidence: [], unanalyzableFiles: ['malformed scoped package name'] };
    }
    pkgDir = path.join(nodeModulesDir, parts[0], parts[1]);
  } else {
    pkgDir = path.join(nodeModulesDir, pkgName);
  }

  let name       = pkgName;
  let version    = 'unknown';
  try {
    const pkgJson = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')) as {
      name?: string;
      version?: string;
    };
    if (pkgJson.name) name          = pkgJson.name;
    if (pkgJson.version) version    = pkgJson.version;
  } catch { /* package.json missing or unreadable */ }

  const jsFiles                              = collectJsFiles(pkgDir);
  const allEvidence: CapabilityEvidence[]    = [];
  const unanalyzableFiles: string[]          = [];

  for (const absFile of jsFiles) {
    let source: string;
    try {
      source = fs.readFileSync(absFile, 'utf8');
    } catch {
      unanalyzableFiles.push(path.relative(pkgDir, absFile));
      continue;
    }

    const { unanalyzable } = analyzeSource(source);
    if (unanalyzable) {
      unanalyzableFiles.push(path.relative(pkgDir, absFile));
      continue;
    }

    const relPath = path.relative(pkgDir, absFile);
    allEvidence.push(...explainFile(source, relPath));
  }

  const capSet          = new Set<Capability>(allEvidence.map(e => e.capability));
  const capabilities    = Array.from(capSet);

  return { name, version, pkgDir, capabilities, evidence: allEvidence, unanalyzableFiles };
}
