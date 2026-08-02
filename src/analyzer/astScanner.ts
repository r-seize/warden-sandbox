import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import {
  Capability,
  FS_MODULE_NAMES,
  FS_WRITE_METHODS,
  SENSITIVE_MODULES,
} from './capabilityMap';

export interface FileScanResult {
  capabilities: Set<Capability>;
  unanalyzable: boolean;
  parseError?: string;
}

// Minimal ESTree-compatible node interfaces for what we need
interface BaseNode { type: string; start: number; end: number; }
interface IdentifierNode extends BaseNode { type: 'Identifier'; name: string; }
interface LiteralNode extends BaseNode { type: 'Literal'; value: unknown; raw: string; }
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
interface VarDeclNode extends BaseNode { type: 'VariableDeclarator'; id: AcornNode; init: AcornNode | null; }
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

// Extract the module name from a require('name') call, or null if not a require call.
function getRequiredModule(node: AcornNode): string | null {
  if (node.type !== 'CallExpression') return null;
  const call = node as unknown as CallExprNode;
  const callee = call.callee as unknown as AcornNode;
  // require('x') or module.require('x')
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

// Extract property name from a MemberExpression (non-computed only).
function getMemberProp(node: MemberExprNode): string | null {
  if (node.computed) return null;
  const prop = node.property as unknown as AcornNode;
  if (prop.type === 'Identifier') return (prop as unknown as IdentifierNode).name;
  return null;
}


export function scanFile(source: string): FileScanResult {
  const result: FileScanResult = {
    capabilities: new Set<Capability>(),
    unanalyzable: false,
  };

  let ast: acorn.Program;
  try {
    ast = acorn.parse(source, {
      ecmaVersion: 'latest',
      sourceType: 'script',
      allowHashBang: true,
      allowAwaitOutsideFunction: true,
      allowReturnOutsideFunction: true,
    });
  } catch (scriptErr) {
    // Some packages ship with ES module syntax; try parsing as module
    try {
      ast = acorn.parse(source, {
        ecmaVersion: 'latest',
        sourceType: 'module',
        allowHashBang: true,
      });
    } catch (moduleErr) {
      result.unanalyzable = true;
      result.parseError = (scriptErr as Error).message;
      return result;
    }
  }

  // --- Pass 1: collect variable → module bindings from require() calls ---

  // varName → module name  (for `const fs = require('fs')`)
  const varToModule = new Map<string, string>();
  // method names directly destructured from fs: `const { readFile } = require('fs')`
  const destructuredFsMethods = new Set<string>();
  // whether any fs module was required at all (including inline uses)
  let fsRequired = false;

  walk.simple(ast as unknown as acorn.Node, {
    VariableDeclarator(rawNode) {
      const node = rawNode as unknown as VarDeclNode;
      if (!node.init) return;
      const modName = getRequiredModule(node.init as unknown as AcornNode);
      if (!modName) return;

      if (node.id.type === 'Identifier') {
        // const x = require('mod')
        const name = (node.id as unknown as IdentifierNode).name;
        varToModule.set(name, modName);
        if (FS_MODULE_NAMES.has(modName)) fsRequired = true;
      } else if (node.id.type === 'ObjectPattern') {
        if (FS_MODULE_NAMES.has(modName)) {
          // const { readFile, writeFile } = require('fs')
          fsRequired = true;
          const pattern = node.id as unknown as ObjPatternNode;
          for (const prop of pattern.properties) {
            if (prop.type !== 'Property') continue;
            const key = prop.key as unknown as AcornNode;
            if (key.type === 'Identifier') {
              destructuredFsMethods.add((key as unknown as IdentifierNode).name);
            }
          }
        } else if (SENSITIVE_MODULES[modName]) {
          // const { exec } = require('child_process') — capability from the module itself
          for (const cap of SENSITIVE_MODULES[modName]) {
            result.capabilities.add(cap);
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

  // --- Pass 2: detect capability usage patterns ---

  const fsMethods = new Set<string>();

  walk.simple(ast as unknown as acorn.Node, {
    CallExpression(rawNode) {
      const node = rawNode as unknown as CallExprNode;
      const calleeNode = node.callee as unknown as AcornNode;

      // Direct require('mod') inline — detect non-fs sensitive modules
      const inlineMod = getRequiredModule(rawNode as unknown as AcornNode);
      if (inlineMod) {
        if (FS_MODULE_NAMES.has(inlineMod)) {
          // inline require('fs') usage detected
          fsRequired = true;
        }
        return;
      }

      // eval('...')
      if (calleeNode.type === 'Identifier' &&
          (calleeNode as unknown as IdentifierNode).name === 'eval') {
        result.capabilities.add('dynamic-code');
        return;
      }

      // require('fs').method() inline
      if (calleeNode.type === 'MemberExpression') {
        const mem = calleeNode as unknown as MemberExprNode;
        const methodName = getMemberProp(mem);
        const obj = mem.object as unknown as AcornNode;

        // require('fs').readFile(...)
        const objMod = getRequiredModule(obj);
        if (objMod && FS_MODULE_NAMES.has(objMod) && methodName) {
          fsRequired = true;
          fsMethods.add(methodName);
          return;
        }

        // fs.readFile(...) where fs = require('fs')
        if (obj.type === 'Identifier') {
          const objName = (obj as unknown as IdentifierNode).name;
          const mod = varToModule.get(objName);
          if (mod && FS_MODULE_NAMES.has(mod) && methodName) {
            fsMethods.add(methodName);
            return;
          }
          // Detect sensitive non-fs module method calls: net.connect(), http.request(), etc.
          if (mod && SENSITIVE_MODULES[mod]) {
            for (const cap of SENSITIVE_MODULES[mod]) {
              result.capabilities.add(cap);
            }
          }
        }
      }

      // Detect destructured fs method call: readFile(path, cb) where readFile was destructured
      if (calleeNode.type === 'Identifier') {
        const name = (calleeNode as unknown as IdentifierNode).name;
        if (destructuredFsMethods.has(name)) {
          fsMethods.add(name);
        }
      }
    },

    NewExpression(rawNode) {
      const node = rawNode as unknown as NewExprNode;
      const calleeNode = node.callee as unknown as AcornNode;
      if (calleeNode.type === 'Identifier' &&
          (calleeNode as unknown as IdentifierNode).name === 'Function') {
        result.capabilities.add('dynamic-code');
      }
    },

    MemberExpression(rawNode) {
      const node = rawNode as unknown as MemberExprNode;
      const obj = node.object as unknown as AcornNode;
      const prop = node.property as unknown as AcornNode;

      // process.env or process['env']
      if (obj.type === 'Identifier' &&
          (obj as unknown as IdentifierNode).name === 'process') {
        const propName = prop.type === 'Identifier'
          ? (prop as unknown as IdentifierNode).name
          : prop.type === 'Literal' ? String((prop as unknown as LiteralNode).value) : null;
        if (propName === 'env') {
          result.capabilities.add('env-access');
        }
      }

      // Detect require assignments inline: account for `varToModule` populated above
      // and watch for varName.method calls on sensitive-module vars
      if (obj.type === 'Identifier') {
        const objName = (obj as unknown as IdentifierNode).name;
        const mod = varToModule.get(objName);
        if (mod && SENSITIVE_MODULES[mod]) {
          for (const cap of SENSITIVE_MODULES[mod]) {
            result.capabilities.add(cap);
          }
        }
      }
    },

    // Detect: process.env destructuring at top level
    // e.g. const { HOME } = process.env
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
          result.capabilities.add('env-access');
        }
      }
    },
  });

  // Resolve sensitive modules (non-fs) from varToModule
  for (const [, modName] of varToModule) {
    if (SENSITIVE_MODULES[modName]) {
      for (const cap of SENSITIVE_MODULES[modName]) {
        result.capabilities.add(cap);
      }
    }
  }

  // Resolve fs capabilities.
  // Conservative: requiring fs means you have the module handle and could call any method.
  // Always flag filesystem-read when fs is imported; add filesystem-write only when
  // write methods are explicitly detected.
  if (fsRequired) {
    result.capabilities.add('filesystem-read');
    const hasWrite = [...fsMethods, ...destructuredFsMethods].some(m => FS_WRITE_METHODS.has(m));
    if (hasWrite) result.capabilities.add('filesystem-write');
  }

  return result;
}

// Detect eval/Function patterns via regexp for minified/unanalyzable-fallback heuristic
export function scanFileHeuristic(source: string): Set<Capability> {
  const caps = new Set<Capability>();
  // Only used as a last resort when AST parse fails
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
