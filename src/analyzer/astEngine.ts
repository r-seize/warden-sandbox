/**
 * Unified AST capability analysis engine.
 *
 * Handles both CJS (require / module.require) and ESM (static import,
 * re-export, dynamic import()) in a single two-pass walk.
 *
 * Consumers:
 *   - astScanner.ts  →  analyzeSource(source)          (capabilities only)
 *   - explainer.ts   →  analyzeSource(source, true)    (capabilities + raw evidence positions)
 */
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import {
  Capability,
  FS_MODULE_NAMES,
  FS_WRITE_METHODS,
  SENSITIVE_MODULES,
} from './capabilityMap';

// ─── ESTree node interfaces ───────────────────────────────────────────────────

interface BaseNode { type: string; start: number; end: number; }
interface IdentifierNode  extends BaseNode { type: 'Identifier'; name: string; }
interface LiteralNode     extends BaseNode { type: 'Literal'; value: unknown; raw: string; }
interface MemberExprNode  extends BaseNode {
  type: 'MemberExpression'; object: AstNode; property: AstNode; computed: boolean;
}
interface CallExprNode    extends BaseNode { type: 'CallExpression'; callee: AstNode; arguments: AstNode[]; }
interface NewExprNode     extends BaseNode { type: 'NewExpression'; callee: AstNode; arguments: AstNode[]; }
interface VarDeclNode     extends BaseNode { type: 'VariableDeclarator'; id: AstNode; init: AstNode | null; }
interface ObjPatternNode  extends BaseNode { type: 'ObjectPattern'; properties: PropertyNode[]; }
interface PropertyNode    extends BaseNode { type: 'Property'; key: AstNode; value: AstNode; }
interface AssignExprNode  extends BaseNode { type: 'AssignmentExpression'; left: AstNode; right: AstNode; }

// ESM
interface ImportDeclNode extends BaseNode {
  type: 'ImportDeclaration';
  specifiers: Array<ImportDefaultSpecNode | ImportNamespaceSpecNode | ImportSpecNode>;
  source: LiteralNode;
}
interface ImportDefaultSpecNode   extends BaseNode { type: 'ImportDefaultSpecifier'; local: IdentifierNode; }
interface ImportNamespaceSpecNode extends BaseNode { type: 'ImportNamespaceSpecifier'; local: IdentifierNode; }
interface ImportSpecNode          extends BaseNode {
  type: 'ImportSpecifier'; imported: IdentifierNode; local: IdentifierNode;
}
interface ImportExprNode          extends BaseNode { type: 'ImportExpression'; source: AstNode; }
interface ExportNamedDeclNode     extends BaseNode { type: 'ExportNamedDeclaration'; source: LiteralNode | null; }
interface ExportAllDeclNode       extends BaseNode { type: 'ExportAllDeclaration'; source: LiteralNode; }

type AstNode = acorn.Node & Record<string, unknown>;

// ─── Public API ───────────────────────────────────────────────────────────────

/** A detected capability at a specific source range (character positions). */
export interface RawEvidence {
  capability: Capability;
  /** Start character offset in the source string. */
  start: number;
  /** End character offset in the source string. */
  end: number;
}

export interface AnalysisResult {
  capabilities: Set<Capability>;
  /**
   * Only populated when `collectEvidence: true`. One entry per AST node that
   * triggered a capability — may contain duplicates for the same capability
   * (different call sites). Callers deduplicate as needed.
   */
  evidence: RawEvidence[];
  unanalyzable: boolean;
}

/**
 * Analyse a single JavaScript/TypeScript source file for capability usage.
 *
 * Detects both CJS (`require`) and ESM (`import`, `import()`, re-exports).
 *
 * @param source          Source code string.
 * @param collectEvidence When true, populate `result.evidence` with per-node positions.
 */
export function analyzeSource(source: string, collectEvidence = false): AnalysisResult {
  const result: AnalysisResult = {
    capabilities: new Set<Capability>(),
    evidence: [],
    unanalyzable: false,
  };

  const ast = parseAST(source);
  if (!ast) {
    result.unanalyzable = true;
    return result;
  }

  // ── Pass 1 : collect module bindings ──────────────────────────────────────
  // varName → module specifier  (const fs = require('fs') / import fs from 'fs')
  const varToModule = new Map<string, string>();
  // fs methods directly destructured: const { readFile } = require('fs')
  const destructuredFsMethods = new Set<string>();
  // Whether any fs module was referenced
  let fsRequired = false;

  const addCapability = (cap: Capability, start: number, end: number) => {
    result.capabilities.add(cap);
    if (collectEvidence) result.evidence.push({ capability: cap, start, end });
  };

  const handleModuleRef = (modName: string, bindingName: string | null, nodeStart: number, nodeEnd: number) => {
    if (FS_MODULE_NAMES.has(modName)) {
      fsRequired = true;
      if (bindingName) varToModule.set(bindingName, modName);
    } else if (SENSITIVE_MODULES[modName]) {
      for (const cap of SENSITIVE_MODULES[modName]) addCapability(cap, nodeStart, nodeEnd);
      if (bindingName) varToModule.set(bindingName, modName);
    } else if (bindingName) {
      varToModule.set(bindingName, modName);
    }
  };

  walk.simple(ast as unknown as acorn.Node, {

    // ── CJS: const x = require('mod') ──────────────────────────────────────
    VariableDeclarator(rawNode) {
      const node = rawNode as unknown as VarDeclNode;
      if (!node.init) return;
      const modName = extractRequiredModule(node.init as unknown as AstNode);
      if (!modName) return;

      if (node.id.type === 'Identifier') {
        const name = (node.id as unknown as IdentifierNode).name;
        handleModuleRef(modName, name, node.init.start, node.init.end);
      } else if (node.id.type === 'ObjectPattern') {
        const pattern = node.id as unknown as ObjPatternNode;
        if (FS_MODULE_NAMES.has(modName)) {
          fsRequired = true;
          for (const prop of pattern.properties) {
            if (prop.type !== 'Property') continue;
            const key = prop.key as unknown as AstNode;
            if (key.type === 'Identifier') destructuredFsMethods.add((key as unknown as IdentifierNode).name);
          }
        } else if (SENSITIVE_MODULES[modName]) {
          for (const cap of SENSITIVE_MODULES[modName]) addCapability(cap, node.init.start, node.init.end);
        }
      }
    },

    // ── CJS: x = require('mod') ────────────────────────────────────────────
    AssignmentExpression(rawNode) {
      const node       = rawNode as unknown as AssignExprNode;
      const modName    = extractRequiredModule(node.right as unknown as AstNode);
      if (!modName) return;
      if (node.left.type === 'Identifier') {
        const name = (node.left as unknown as IdentifierNode).name;
        handleModuleRef(modName, name, node.right.start, node.right.end);
      }
    },

    // ── ESM static: import x from 'mod' / import { a } from 'mod' / import * as x ──
    ImportDeclaration(rawNode) {
      const node       = rawNode as unknown as ImportDeclNode;
      const modName    = node.source.value as string;

      for (const spec of node.specifiers) {
        if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportNamespaceSpecifier') {
          handleModuleRef(modName, spec.local.name, node.start, node.end);
        } else if (spec.type === 'ImportSpecifier') {
          if (FS_MODULE_NAMES.has(modName)) {
            fsRequired = true;
            destructuredFsMethods.add(spec.imported.name);
          } else if (SENSITIVE_MODULES[modName]) {
            for (const cap of SENSITIVE_MODULES[modName]) addCapability(cap, node.start, node.end);
          }
        }
      }

      // Side-effect-only import: import 'http'  (no specifiers)
      if (node.specifiers.length === 0) {
        handleModuleRef(modName, null, node.start, node.end);
      }
    },

    // ── ESM re-export: export { x } from 'mod' ────────────────────────────
    ExportNamedDeclaration(rawNode) {
      const node = rawNode as unknown as ExportNamedDeclNode;
      if (!node.source) return;
      const modName = node.source.value as string;
      handleModuleRef(modName, null, node.start, node.end);
    },

    // ── ESM re-export all: export * from 'mod' ─────────────────────────────
    ExportAllDeclaration(rawNode) {
      const node       = rawNode as unknown as ExportAllDeclNode;
      const modName    = node.source.value as string;
      handleModuleRef(modName, null, node.start, node.end);
    },

  });

  // ── Pass 2 : detect capability usage ──────────────────────────────────────

  // fs methods detected in call expressions (used to distinguish read vs write)
  const fsMethods = new Set<string>();

  walk.simple(ast as unknown as acorn.Node, {

    // ── Dynamic import: import('mod') ──────────────────────────────────────
    ImportExpression(rawNode) {
      const node    = rawNode as unknown as ImportExprNode;
      const src     = node.source as unknown as AstNode;
      if (src.type !== 'Literal') return; // dynamic string → unanalyzable, skip
      const modName = (src as unknown as LiteralNode).value as string;
      if (FS_MODULE_NAMES.has(modName)) {
        fsRequired = true;
      } else if (SENSITIVE_MODULES[modName]) {
        for (const cap of SENSITIVE_MODULES[modName]) addCapability(cap, node.start, node.end);
      }
    },

    // ── eval('...') ────────────────────────────────────────────────────────
    CallExpression(rawNode) {
      const node      = rawNode as unknown as CallExprNode;
      const callee    = node.callee as unknown as AstNode;

      // Inline require — already handled in pass 1 for bindings, but may appear
      // as an expression not assigned to anything: require('net')
      const inlineMod = extractRequiredModule(rawNode as unknown as AstNode);
      if (inlineMod) {
        if (FS_MODULE_NAMES.has(inlineMod)) {
          fsRequired = true;
        } else if (SENSITIVE_MODULES[inlineMod]) {
          for (const cap of SENSITIVE_MODULES[inlineMod]) addCapability(cap, node.start, node.end);
        }
        return;
      }

      if (callee.type === 'Identifier' && (callee as unknown as IdentifierNode).name === 'eval') {
        addCapability('dynamic-code', node.start, node.end);
        return;
      }

      if (callee.type === 'MemberExpression') {
        const mem           = callee as unknown as MemberExprNode;
        const methodName    = getMemberProp(mem);
        const obj           = mem.object as unknown as AstNode;

        // require('fs').readFile(...)
        const objMod = extractRequiredModule(obj);
        if (objMod && FS_MODULE_NAMES.has(objMod) && methodName) {
          fsRequired = true;
          trackFsMethod(methodName, fsMethods, addCapability, node.start, node.end);
          return;
        }

        if (obj.type === 'Identifier') {
          const objName    = (obj as unknown as IdentifierNode).name;
          const mod        = varToModule.get(objName);
          if (mod && FS_MODULE_NAMES.has(mod) && methodName) {
            trackFsMethod(methodName, fsMethods, addCapability, node.start, node.end);
            return;
          }
          // http.request(), net.connect(), etc.
          if (mod && SENSITIVE_MODULES[mod]) {
            for (const cap of SENSITIVE_MODULES[mod]) addCapability(cap, node.start, node.end);
          }
        }
      }

      // Destructured fs method call: readFile(...) where const { readFile } = require('fs')
      if (callee.type === 'Identifier') {
        const name = (callee as unknown as IdentifierNode).name;
        if (destructuredFsMethods.has(name)) {
          trackFsMethod(name, fsMethods, addCapability, node.start, node.end);
        }
      }
    },

    // ── new Function('...') ────────────────────────────────────────────────
    NewExpression(rawNode) {
      const node      = rawNode as unknown as NewExprNode;
      const callee    = node.callee as unknown as AstNode;
      if (callee.type === 'Identifier' && (callee as unknown as IdentifierNode).name === 'Function') {
        addCapability('dynamic-code', node.start, node.end);
      }
    },

    // ── process.env, net.xxx, etc. ─────────────────────────────────────────
    MemberExpression(rawNode) {
      const node    = rawNode as unknown as MemberExprNode;
      const obj     = node.object as unknown as AstNode;
      const prop    = node.property as unknown as AstNode;

      if (obj.type === 'Identifier' && (obj as unknown as IdentifierNode).name === 'process') {
        const propName = prop.type === 'Identifier'
          ? (prop as unknown as IdentifierNode).name
          : prop.type === 'Literal' ? String((prop as unknown as LiteralNode).value) : null;
        if (propName === 'env') addCapability('env-access', node.start, node.end);
      }

      // sensitive-module variable method access that wasn't caught as a CallExpression
      if (obj.type === 'Identifier') {
        const objName    = (obj as unknown as IdentifierNode).name;
        const mod        = varToModule.get(objName);
        if (mod && SENSITIVE_MODULES[mod]) {
          for (const cap of SENSITIVE_MODULES[mod]) {
            // Only add if not already present (avoid duplicate evidence per walk)
            if (!result.capabilities.has(cap)) addCapability(cap, node.start, node.end);
          }
        }
      }
    },

    // ── const { HOME } = process.env (destructure) ─────────────────────────
    VariableDeclarator(rawNode) {
      const node = rawNode as unknown as VarDeclNode;
      if (!node.init) return;
      const init = node.init as unknown as AstNode;
      if (init.type !== 'MemberExpression') return;
      const mem     = init as unknown as MemberExprNode;
      const obj     = mem.object as unknown as AstNode;
      const prop    = mem.property as unknown as AstNode;
      if (
        obj.type === 'Identifier' && (obj as unknown as IdentifierNode).name === 'process' &&
        prop.type === 'Identifier' && (prop as unknown as IdentifierNode).name === 'env'
      ) {
        addCapability('env-access', init.start, init.end);
      }
    },

  });

  // Resolve capabilities from varToModule entries whose modules weren't caught
  // by a method call in pass 2 (e.g. `const http = require('http'); http`) —
  // note: we only add capabilities not already in the set to avoid duplicate evidence.
  for (const modName of varToModule.values()) {
    if (SENSITIVE_MODULES[modName]) {
      for (const cap of SENSITIVE_MODULES[modName]) result.capabilities.add(cap);
    }
  }

  // Resolve fs capabilities
  if (fsRequired) {
    result.capabilities.add('filesystem-read');
    const hasWrite = [...fsMethods, ...destructuredFsMethods].some(m => FS_WRITE_METHODS.has(m));
    if (hasWrite) result.capabilities.add('filesystem-write');

    // If no specific method call was found but fs was imported, emit a generic
    // filesystem-read evidence at the require/import site (evidence-only path).
    if (collectEvidence && !result.evidence.some(e => e.capability === 'filesystem-read')) {
      emitFsRequireEvidence(ast, result.evidence);
    }
  }

  return result;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function parseAST(source: string): acorn.Program | null {
  try {
    return acorn.parse(source, {
      ecmaVersion: 'latest', sourceType: 'script',
      allowHashBang: true, allowAwaitOutsideFunction: true, allowReturnOutsideFunction: true,
    });
  } catch {
    try {
      return acorn.parse(source, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true });
    } catch {
      return null;
    }
  }
}

function extractRequiredModule(node: AstNode): string | null {
  if (node.type !== 'CallExpression') return null;
  const call      = node as unknown as CallExprNode;
  const callee    = call.callee as unknown as AstNode;
  const isRequire =
    (callee.type === 'Identifier' && (callee as unknown as IdentifierNode).name === 'require') ||
    (callee.type === 'MemberExpression' &&
      (callee as unknown as MemberExprNode).property.type === 'Identifier' &&
      ((callee as unknown as MemberExprNode).property as unknown as IdentifierNode).name === 'require');
  if (!isRequire || call.arguments.length === 0) return null;
  const firstArg = call.arguments[0] as unknown as AstNode;
  if (firstArg.type !== 'Literal') return null;
  const val = (firstArg as unknown as LiteralNode).value;
  return typeof val === 'string' ? val : null;
}

function getMemberProp(node: MemberExprNode): string | null {
  if (node.computed) return null;
  const prop = node.property as unknown as AstNode;
  return prop.type === 'Identifier' ? (prop as unknown as IdentifierNode).name : null;
}

function trackFsMethod(
  method: string,
  fsMethods: Set<string>,
  addCapability: (cap: Capability, s: number, e: number) => void,
  start: number,
  end: number,
): void {
  fsMethods.add(method);
  const cap: Capability = FS_WRITE_METHODS.has(method) ? 'filesystem-write' : 'filesystem-read';
  addCapability(cap, start, end);
}

function emitFsRequireEvidence(ast: acorn.Program, evidence: RawEvidence[]): void {
  walk.simple(ast as unknown as acorn.Node, {
    CallExpression(rawNode) {
      const node    = rawNode as unknown as CallExprNode;
      const mod     = extractRequiredModule(rawNode as unknown as AstNode);
      if (mod && FS_MODULE_NAMES.has(mod)) {
        evidence.push({ capability: 'filesystem-read', start: node.start, end: node.end });
      }
    },
    ImportDeclaration(rawNode) {
      const node = rawNode as unknown as ImportDeclNode;
      if (FS_MODULE_NAMES.has(node.source.value as string)) {
        evidence.push({ capability: 'filesystem-read', start: node.start, end: node.end });
      }
    },
    ImportExpression(rawNode) {
      const node    = rawNode as unknown as ImportExprNode;
      const src     = node.source as unknown as AstNode;
      if (src.type === 'Literal' && FS_MODULE_NAMES.has((src as unknown as LiteralNode).value as string)) {
        evidence.push({ capability: 'filesystem-read', start: node.start, end: node.end });
      }
    },
  });
}
