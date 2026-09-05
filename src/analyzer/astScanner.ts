import { analyzeSource } from './astEngine';
import { Capability } from './capabilityMap';

export interface FileScanResult {
  capabilities: Set<Capability>;
  unanalyzable: boolean;
}

/** Analyse `source` for capability usage via AST walking (CJS + ESM). */
export function scanFile(source: string): FileScanResult {
  const { capabilities, unanalyzable } = analyzeSource(source);
  return { capabilities, unanalyzable };
}

/** Regex fallback for minified/obfuscated files that cannot be parsed by Acorn. */
export function scanFileHeuristic(source: string): Set<Capability> {
  const caps = new Set<Capability>();
  if (/\beval\s*\(/.test(source)) caps.add('dynamic-code');
  if (/new\s+Function\s*\(/.test(source)) caps.add('dynamic-code');
  if (/process\.env/.test(source)) caps.add('env-access');
  if (/require\(['"](?:child_process|node:child_process)['"]\)/.test(source)) caps.add('process-spawn');
  if (/require\(['"](?:http|https|net|tls|dns|dgram|node:http|node:https|node:net|node:tls)['"]\)/.test(source)) caps.add('network');
  if (/require\(['"](?:fs|node:fs)['"]\)/.test(source)) {
    caps.add('filesystem-read');
    if (/\b(?:writeFile|appendFile|mkdir|unlink|rename|createWriteStream)\b/.test(source)) {
      caps.add('filesystem-write');
    }
  }
  return caps;
}
