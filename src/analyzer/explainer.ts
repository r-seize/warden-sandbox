import * as fs from 'node:fs';
import * as path from 'node:path';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import { Capability, FS_MODULE_NAMES, FS_WRITE_METHODS, SENSITIVE_MODULES } from './capabilityMap';

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

// ─── Helpers ──────────────────────────────────────────────────────────────────

function posToLine(source: string, pos: number): number {
  let line = 1;
  for (let i = 0; i < pos && i < source.length; i++) {
    if (source[i] === '\n') line++;
  }
  return line;
}

function makeSnippet(source: string, start: number, end: number): string {
  const raw = source.slice(start, end).trim();
  return raw.length > 80 ? raw.slice(0, 79) + '…' : raw;
}

// ─── Minimal ESTree-compatible node interfaces ────────────────────────────────

interface BaseNode { type: string; start: number; end: number; }
interface IdentifierNode extends BaseNode { type: 'Identifier'; name: string; }
interface LiteralNode extends BaseNode { type: 'Literal'; value: unknown; }
interface MemberExprNode extends BaseNode {
  type: 'MemberExpression';
  object: AcornNode;
  property: AcornNode;
  computed: boolean;
}
interface CallExprNode extends BaseNode {
  type: 'CallExpression';
  callee: AcornNode;
  arguments: AcornNode[];
}
interface NewExprNode extends BaseNode {
  type: 'NewExpression';
  callee: AcornNode;
  arguments: AcornNode[];
}
interface VarDeclNode extends BaseNode {
  type: 'VariableDeclarator';
  id: AcornNode;
  init: AcornNode | null;
}
interface ObjPatternNode extends BaseNode {
  type: 'ObjectPattern';
  properties: PropertyNode[];
}
interface PropertyNode extends BaseNode {
  type: 'Property';
  key: AcornNode;
  value: AcornNode;
}
interface AssignExprNode extends BaseNode {
  type: 'AssignmentExpression';
  left: AcornNode;
  right: AcornNode;
}
type AcornNode = acorn.Node & Record<string, unknown>;

function getRequiredModule(node: AcornNode): string | null {
  if (node.type !== 'CallExpression') return null;
  const call = node as unknown as CallExprNode;
  const callee = call.callee as unknown as AcornNode;
  const isRequire =
    (callee.type === 'Identifier' && (callee as unknown as IdentifierNode).name === 'require') ||
    (callee.type === 'MemberExpression' &&
      (callee as unknown as MemberExprNode).property.type === 'Identifier' &&
      ((callee as unknown as MemberExprNode).property as unknown as IdentifierNode).name === 'require');
  if (!isRequire) return null;
  if (call.arguments.length === 0) return null;
  const firstArg = call.arguments[0] as unknown as AcornNode;
  if (firstArg.type !== 'Literal') return null;
  const val = (firstArg as unknown as LiteralNode).value;
  return typeof val === 'string' ? val : null;
}

function getMemberProp(node: MemberExprNode): string | null {
  if (node.computed) return null;
  const prop = node.property as unknown as AcornNode;
  if (prop.type === 'Identifier') return (prop as unknown as IdentifierNode).name;
  return null;
}

// ─── File explainer ───────────────────────────────────────────────────────────

export function explainFile(source: string, relPath: string): CapabilityEvidence[] {
  const evidence: CapabilityEvidence[] = [];

  let ast: acorn.Program;
  try {
    ast = acorn.parse(source, {
      ecmaVersion: 'latest',
      sourceType: 'script',
      allowHashBang: true,
      allowAwaitOutsideFunction: true,
      allowReturnOutsideFunction: true,
    });
  } catch {
    try {
      ast = acorn.parse(source, {
        ecmaVersion: 'latest',
        sourceType: 'module',
        allowHashBang: true,
      });
    } catch {
      return evidence; // unanalyzable
    }
  }

  // Pass 1: collect variable → module bindings
  const varToModule = new Map<string, string>();
  const destructuredFsMethods = new Set<string>();
  let fsRequired = false;

  walk.simple(ast as unknown as acorn.Node, {
    VariableDeclarator(rawNode) {
      const node = rawNode as unknown as VarDeclNode;
      if (!node.init) return;
      const modName = getRequiredModule(node.init as unknown as AcornNode);
      if (!modName) return;

      if (node.id.type === 'Identifier') {
        const name = (node.id as unknown as IdentifierNode).name;
        varToModule.set(name, modName);
        if (FS_MODULE_NAMES.has(modName)) fsRequired = true;
      } else if (node.id.type === 'ObjectPattern') {
        if (FS_MODULE_NAMES.has(modName)) {
          fsRequired = true;
          const pattern = node.id as unknown as ObjPatternNode;
          for (const prop of pattern.properties) {
            if (prop.type !== 'Property') continue;
            const key = prop.key as unknown as AcornNode;
            if (key.type === 'Identifier') {
              destructuredFsMethods.add((key as unknown as IdentifierNode).name);
            }
          }
        }
      }
    },

    AssignmentExpression(rawNode) {
      const node = rawNode as unknown as AssignExprNode;
      const modName = getRequiredModule(node.right as unknown as AcornNode);
      if (!modName) return;
      if (node.left.type === 'Identifier') {
        const name = (node.left as unknown as IdentifierNode).name;
        varToModule.set(name, modName);
        if (FS_MODULE_NAMES.has(modName)) fsRequired = true;
      }
    },
  });

  // Pass 2: detect capability usage patterns and record evidence
  const fsMethods = new Set<string>();

  walk.simple(ast as unknown as acorn.Node, {
    CallExpression(rawNode) {
      const node = rawNode as unknown as CallExprNode;
      const calleeNode = node.callee as unknown as AcornNode;

      // require('some-module') inline
      const inlineMod = getRequiredModule(rawNode as unknown as AcornNode);
      if (inlineMod) {
        if (FS_MODULE_NAMES.has(inlineMod)) {
          fsRequired = true;
          // We'll emit fs evidence at the end
        } else if (SENSITIVE_MODULES[inlineMod]) {
          for (const cap of SENSITIVE_MODULES[inlineMod]) {
            evidence.push({
              capability: cap,
              file: relPath,
              line: posToLine(source, node.start),
              snippet: makeSnippet(source, node.start, node.end),
            });
          }
        } else if (typeof inlineMod === 'string' && /\.node['"]?$/.test(inlineMod)) {
          // native .node require
          evidence.push({
            capability: 'native-binding',
            file: relPath,
            line: posToLine(source, node.start),
            snippet: makeSnippet(source, node.start, node.end),
          });
        }
        return;
      }

      // eval('...')
      if (calleeNode.type === 'Identifier' &&
          (calleeNode as unknown as IdentifierNode).name === 'eval') {
        evidence.push({
          capability: 'dynamic-code',
          file: relPath,
          line: posToLine(source, node.start),
          snippet: makeSnippet(source, node.start, node.end),
        });
        return;
      }

      if (calleeNode.type === 'MemberExpression') {
        const mem = calleeNode as unknown as MemberExprNode;
        const methodName = getMemberProp(mem);
        const obj = mem.object as unknown as AcornNode;

        // require('fs').method()
        const objMod = getRequiredModule(obj);
        if (objMod && FS_MODULE_NAMES.has(objMod) && methodName) {
          fsRequired = true;
          fsMethods.add(methodName);
          evidence.push({
            capability: FS_WRITE_METHODS.has(methodName) ? 'filesystem-write' : 'filesystem-read',
            file: relPath,
            line: posToLine(source, node.start),
            snippet: makeSnippet(source, node.start, node.end),
          });
          return;
        }

        // fs.method() where fs = require('fs')
        if (obj.type === 'Identifier') {
          const objName = (obj as unknown as IdentifierNode).name;
          const mod = varToModule.get(objName);
          if (mod && FS_MODULE_NAMES.has(mod) && methodName) {
            fsMethods.add(methodName);
            evidence.push({
              capability: FS_WRITE_METHODS.has(methodName) ? 'filesystem-write' : 'filesystem-read',
              file: relPath,
              line: posToLine(source, node.start),
              snippet: makeSnippet(source, node.start, node.end),
            });
            return;
          }
          if (mod && SENSITIVE_MODULES[mod]) {
            for (const cap of SENSITIVE_MODULES[mod]) {
              evidence.push({
                capability: cap,
                file: relPath,
                line: posToLine(source, node.start),
                snippet: makeSnippet(source, node.start, node.end),
              });
            }
          }
        }
      }

      // Destructured fs method call
      if (calleeNode.type === 'Identifier') {
        const name = (calleeNode as unknown as IdentifierNode).name;
        if (destructuredFsMethods.has(name)) {
          fsMethods.add(name);
          evidence.push({
            capability: FS_WRITE_METHODS.has(name) ? 'filesystem-write' : 'filesystem-read',
            file: relPath,
            line: posToLine(source, node.start),
            snippet: makeSnippet(source, node.start, node.end),
          });
        }
      }
    },

    NewExpression(rawNode) {
      const node = rawNode as unknown as NewExprNode;
      const calleeNode = node.callee as unknown as AcornNode;
      if (calleeNode.type === 'Identifier' &&
          (calleeNode as unknown as IdentifierNode).name === 'Function') {
        evidence.push({
          capability: 'dynamic-code',
          file: relPath,
          line: posToLine(source, node.start),
          snippet: makeSnippet(source, node.start, node.end),
        });
      }
    },

    MemberExpression(rawNode) {
      const node = rawNode as unknown as MemberExprNode;
      const obj = node.object as unknown as AcornNode;
      const prop = node.property as unknown as AcornNode;

      // process.env
      if (obj.type === 'Identifier' &&
          (obj as unknown as IdentifierNode).name === 'process') {
        const propName = prop.type === 'Identifier'
          ? (prop as unknown as IdentifierNode).name
          : prop.type === 'Literal' ? String((prop as unknown as LiteralNode).value) : null;
        if (propName === 'env') {
          evidence.push({
            capability: 'env-access',
            file: relPath,
            line: posToLine(source, node.start),
            snippet: makeSnippet(source, node.start, node.end),
          });
        }
      }

      // Sensitive module access via variable
      if (obj.type === 'Identifier') {
        const objName = (obj as unknown as IdentifierNode).name;
        const mod = varToModule.get(objName);
        if (mod && SENSITIVE_MODULES[mod]) {
          for (const cap of SENSITIVE_MODULES[mod]) {
            evidence.push({
              capability: cap,
              file: relPath,
              line: posToLine(source, node.start),
              snippet: makeSnippet(source, node.start, node.end),
            });
          }
        }
      }
    },

    // process.env destructuring at top level
    VariableDeclarator(rawNode) {
      const node = rawNode as unknown as VarDeclNode;
      if (!node.init) return;
      const init = node.init as unknown as AcornNode;
      if (init.type === 'MemberExpression') {
        const mem = init as unknown as MemberExprNode;
        const obj = mem.object as unknown as AcornNode;
        const prop = mem.property as unknown as AcornNode;
        if (obj.type === 'Identifier' &&
            (obj as unknown as IdentifierNode).name === 'process' &&
            prop.type === 'Identifier' &&
            (prop as unknown as IdentifierNode).name === 'env') {
          evidence.push({
            capability: 'env-access',
            file: relPath,
            line: posToLine(source, node.start),
            snippet: makeSnippet(source, node.start, node.end),
          });
        }
      }
    },
  });

  // Resolve sensitive modules from varToModule that weren't caught by method calls
  for (const [varName, modName] of varToModule) {
    if (SENSITIVE_MODULES[modName]) {
      // Check if we already have evidence for this (avoid duplicates from MemberExpression)
      // Only add if we don't have any evidence yet for this module's caps
      const existingCaps = new Set(evidence.map(e => e.capability));
      for (const cap of SENSITIVE_MODULES[modName]) {
        if (!existingCaps.has(cap)) {
          // Find the require() call node position
          // We can't easily get the exact position here without re-walking, so we
          // rely on the Pass 2 MemberExpression/CallExpression walkers for evidence.
          // This loop only handles modules that were required but never method-called.
          void varName; // used implicitly via varToModule
        }
      }
    }
  }

  // Emit fs-required evidence (when only `require('fs')` was found, no specific method call)
  if (fsRequired && !evidence.some(e => e.capability === 'filesystem-read' || e.capability === 'filesystem-write')) {
    // Collect all require('fs') positions, emit only the first to avoid duplicate evidence
    const fsRequirePositions: Array<{ start: number; end: number }> = [];
    walk.simple(ast as unknown as acorn.Node, {
      CallExpression(rawNode) {
        const node = rawNode as unknown as CallExprNode;
        const mod = getRequiredModule(rawNode as unknown as AcornNode);
        if (mod && FS_MODULE_NAMES.has(mod)) {
          fsRequirePositions.push({ start: node.start, end: node.end });
        }
      },
    });
    if (fsRequirePositions.length > 0) {
      const first = fsRequirePositions[0];
      evidence.push({
        capability: 'filesystem-read',
        file: relPath,
        line: posToLine(source, first.start),
        snippet: makeSnippet(source, first.start, first.end),
      });
    }
  }

  // Detect native .node requires via regex as a supplement
  const nativeRequireRe = /require\(['"]([^'"]*\.node)['"]\)/g;
  let m: RegExpExecArray | null;
  while ((m = nativeRequireRe.exec(source)) !== null) {
    const alreadyHas = evidence.some(
      e => e.capability === 'native-binding' && e.line === posToLine(source, m!.index),
    );
    if (!alreadyHas) {
      evidence.push({
        capability: 'native-binding',
        file: relPath,
        line: posToLine(source, m.index),
        snippet: m[0].length > 80 ? m[0].slice(0, 79) + '…' : m[0],
      });
    }
  }

  return evidence;
}

// ─── Package explainer ────────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'test', 'tests', 'spec', 'docs', 'examples',
  '__tests__', 'fixtures', 'coverage',
]);

function collectJsFiles(dir: string, results: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        collectJsFiles(path.join(dir, entry.name), results);
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (ext === '.js' || ext === '.cjs' || ext === '.mjs') {
        results.push(path.join(dir, entry.name));
      }
    }
  }
}

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

  // Read package.json for name/version
  let name = pkgName;
  let version = 'unknown';
  try {
    const pkgJson = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')) as {
      name?: string;
      version?: string;
    };
    if (pkgJson.name) name = pkgJson.name;
    if (pkgJson.version) version = pkgJson.version;
  } catch {
    // package.json missing or unreadable
  }

  const jsFiles: string[] = [];
  collectJsFiles(pkgDir, jsFiles);

  const allEvidence: CapabilityEvidence[] = [];
  const unanalyzableFiles: string[] = [];

  for (const absFile of jsFiles) {
    let source: string;
    try {
      source = fs.readFileSync(absFile, 'utf8');
    } catch {
      unanalyzableFiles.push(path.relative(pkgDir, absFile));
      continue;
    }

    // Check if file is parseable first
    let parseable = true;
    try {
      acorn.parse(source, { ecmaVersion: 'latest', sourceType: 'script', allowHashBang: true, allowAwaitOutsideFunction: true, allowReturnOutsideFunction: true });
    } catch {
      try {
        acorn.parse(source, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true });
      } catch {
        parseable = false;
      }
    }

    if (!parseable) {
      unanalyzableFiles.push(path.relative(pkgDir, absFile));
      continue;
    }

    const relPath = path.relative(pkgDir, absFile);
    const fileEvidence = explainFile(source, relPath);
    allEvidence.push(...fileEvidence);
  }

  // Deduplicate capabilities
  const capSet = new Set<Capability>(allEvidence.map(e => e.capability));
  const capabilities = Array.from(capSet);

  return {
    name,
    version,
    pkgDir,
    capabilities,
    evidence: allEvidence,
    unanalyzableFiles,
  };
}
