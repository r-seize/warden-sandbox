import NodeModule from 'node:module';
import * as nodeFs from 'node:fs';
import * as nodePath from 'node:path';
import { LockfileData, PackagePolicy } from '../policy/lockfile';
import { Capability } from '../analyzer/capabilityMap';
import { ViolationFn } from './violationHandler';
import {
  buildTamedBuiltin,
  ensureLockdown,
  evaluateInCompartment,
  PackageEvalContext,
} from './compartmentFactory';

// ─── Node.js internals typing ─────────────────────────────────────────────────

interface CJSModule {
  filename: string;
  id: string;
  exports: Record<string, unknown>;
  loaded: boolean;
  parent: CJSModule | null;
  children: CJSModule[];
  paths: string[];
  require(id: string): unknown;
}

// Module._load and related private APIs
const NodeModulePrivate = NodeModule as unknown as {
  _load(request: string, parent: CJSModule | null, isMain: boolean): unknown;
  _resolveFilename(request: string, parent: CJSModule | null, isMain: boolean, options?: object): string;
  _cache: Record<string, CJSModule>;
  _pathCache: Record<string, string>;
  isBuiltin(moduleName: string): boolean;
  builtinModules: string[];
};

// ─── Package identification from file path ─────────────────────────────────────

function getPackageNameFromPath(filePath: string): string | null {
  if (!filePath) return null;
  const nmIdx = filePath.lastIndexOf('node_modules' + nodePath.sep);
  if (nmIdx === -1) return null;

  const rest = filePath.slice(nmIdx + 'node_modules'.length + 1);
  if (rest.startsWith('@')) {
    // Scoped: @scope/pkg/...
    const parts = rest.split(nodePath.sep);
    if (parts.length >= 2) return `${parts[0]}/${parts[1]}`;
    return null;
  }
  return rest.split(nodePath.sep)[0] ?? null;
}

function getPolicyKey(lockfile: LockfileData, pkgName: string): string | undefined {
  // Find the key like "express@4.18.2" for package name "express"
  return Object.keys(lockfile.packages).find(k => {
    const at = k.lastIndexOf('@');
    return k.slice(0, at) === pkgName;
  });
}

function getPolicy(lockfile: LockfileData, pkgName: string): PackagePolicy | null {
  const key = getPolicyKey(lockfile, pkgName);
  return key ? (lockfile.packages[key] ?? null) : null;
}

// ─── Controlled require builder ───────────────────────────────────────────────

function buildControlledRequire(
  _callerFilename: string,
  callerPkgName: string,
  caps: Set<Capability>,
  lockfile: LockfileData,
  onViolation: ViolationFn,
  enforce: boolean,
  originalLoad: typeof NodeModulePrivate._load,
  callerModule: CJSModule,
  profile: Profile = 'default',
): (request: string) => unknown {
  return function controlledRequire(request: string): unknown {
    const isBuiltin = NodeModulePrivate.isBuiltin(request);

    if (isBuiltin) {
      return buildTamedBuiltin(request, caps, callerPkgName, onViolation);
    }

    // Resolve to absolute path
    let resolvedFilename: string;
    try {
      resolvedFilename = NodeModulePrivate._resolveFilename(request, callerModule, false);
    } catch {
      // Let original handle resolution errors
      return originalLoad(request, callerModule, false);
    }

    if (enforce) {
      // Determine which package the required module belongs to
      const targetPkgName = getPackageNameFromPath(resolvedFilename);
      const targetPolicy = targetPkgName ? getPolicy(lockfile, targetPkgName) : null;
      const targetCaps: Set<Capability> = targetPolicy
        ? effectiveCaps(targetPolicy, profile, enforce)
        : new Set<Capability>();

      // Read source and evaluate in Compartment
      let source: string;
      try {
        source = nodeFs.readFileSync(resolvedFilename, 'utf8');
      } catch {
        // Binary or unreadable — fall back to original loader
        return originalLoad(request, callerModule, false);
      }

      const ctx: PackageEvalContext = {
        packageName: targetPkgName ?? resolvedFilename,
        caps: targetCaps,
        onViolation,
        // The controlled require for the sub-module is itself controlled
        controlledRequire: buildControlledRequire(
          resolvedFilename,
          targetPkgName ?? resolvedFilename,
          targetCaps,
          lockfile,
          onViolation,
          enforce,
          originalLoad,
          {
            filename: resolvedFilename,
            id: resolvedFilename,
            exports: {},
            loaded: false,
            parent: callerModule,
            children: [],
            paths: [],
            require: (() => {}) as unknown as CJSModule['require'],
          },
          profile,
        ),
      };

      try {
        return evaluateInCompartment(resolvedFilename, source, ctx);
      } catch {
        // Compartment evaluation failed — fall back to normal load
        // (this can happen with binary extensions, JSON, etc.)
        return originalLoad(request, callerModule, false);
      }
    }

    // Observation mode: delegate to original loader
    return originalLoad(request, callerModule, false);
  };
}

// ─── Public hook API ──────────────────────────────────────────────────────────

let originalLoad: typeof NodeModulePrivate._load | null = null;

export type Profile = 'strict' | 'default' | 'lenient';

/** Capabilities that are always blocked in strict mode (even if approved). */
const STRICT_EXTRA_BLOCKED = new Set<Capability>(['env-access']);
/** Capabilities that are always allowed in lenient mode (no approval required). */
const LENIENT_ALWAYS_ALLOWED = new Set<Capability>(['filesystem-read', 'env-access']);

/** Returns the effective capability set to use in enforce mode, after applying policy
 *  (allowedCapabilities > capabilities) and profile overrides. */
function effectiveCaps(
  policy: PackagePolicy,
  profile: Profile,
  enforce: boolean,
): Set<Capability> {
  if (enforce && policy.status !== 'approved' && policy.status !== 'unsandboxed') {
    if (profile === 'lenient') {
      const base = new Set<Capability>(LENIENT_ALWAYS_ALLOWED);
      if (policy.deniedCapabilities) {
        for (const cap of policy.deniedCapabilities) base.delete(cap);
      }
      return base;
    }
    return new Set<Capability>();
  }

  const base = new Set<Capability>(
    (policy.allowedCapabilities ?? policy.capabilities) as Capability[],
  );

  if (profile === 'strict') {
    for (const cap of STRICT_EXTRA_BLOCKED) base.delete(cap);
  } else if (profile === 'lenient') {
    for (const cap of LENIENT_ALWAYS_ALLOWED) base.add(cap);
  }

  if (policy.deniedCapabilities) {
    for (const cap of policy.deniedCapabilities) base.delete(cap);
  }

  return base;
}

export function installModuleLoaderHook(
  lockfile: LockfileData,
  enforce: boolean,
  onViolation: ViolationFn,
  profile: Profile = 'default',
): () => void {
  if (originalLoad !== null) {
    throw new Error('[Warden] Module loader hook is already installed');
  }

  if (enforce) {
    ensureLockdown();
  }

  originalLoad = NodeModulePrivate._load;

  NodeModulePrivate._load = function wardenLoad(
    request: string,
    parent: CJSModule | null,
    isMain: boolean,
  ): unknown {
    const orig = originalLoad!;

    // Determine the calling package
    const callerPkgName = parent?.filename ? getPackageNameFromPath(parent.filename) : null;

    // Only apply policy to packages in node_modules
    if (!callerPkgName) {
      return orig(request, parent, isMain);
    }

    const policy = getPolicy(lockfile, callerPkgName);
    if (!policy) {
      // Unknown package (not in lockfile) — log and allow
      if (NodeModulePrivate.isBuiltin(request)) {
        const cap = guessCapabilityFromBuiltin(request);
        if (cap) {
          onViolation({
            packageName: callerPkgName,
            capability: cap,
            apiAccessed: request,
          });
        }
      }
      return orig(request, parent, isMain);
    }

    const caps = effectiveCaps(policy, profile, enforce);
    const isBuiltin = NodeModulePrivate.isBuiltin(request);

    if (isBuiltin) {
      return buildTamedBuiltin(request, caps, callerPkgName, onViolation);
    }

    if (enforce) {
      // Resolve filename
      let resolvedFilename: string;
      try {
        resolvedFilename = NodeModulePrivate._resolveFilename(request, parent, isMain);
      } catch {
        return orig(request, parent, isMain);
      }

      // Skip JSON, .node addons — let original loader handle them
      const ext = nodePath.extname(resolvedFilename).toLowerCase();
      if (ext === '.json' || ext === '.node') {
        return orig(request, parent, isMain);
      }

      // Read and evaluate in Compartment
      let source: string;
      try {
        source = nodeFs.readFileSync(resolvedFilename, 'utf8');
      } catch {
        return orig(request, parent, isMain);
      }

      const targetPkgName = getPackageNameFromPath(resolvedFilename) ?? resolvedFilename;
      const targetPolicy = getPolicy(lockfile, targetPkgName);
      const targetCaps = targetPolicy
        ? effectiveCaps(targetPolicy, profile, enforce)
        : new Set<Capability>();

      const ctx: PackageEvalContext = {
        packageName: targetPkgName,
        caps: targetCaps,
        onViolation,
        controlledRequire: buildControlledRequire(
          resolvedFilename,
          targetPkgName,
          targetCaps,
          lockfile,
          onViolation,
          enforce,
          orig,
          parent ?? ({
            filename: '',
            id: '',
            exports: {},
            loaded: true,
            parent: null,
            children: [],
            paths: [],
            require: (() => {}) as unknown as CJSModule['require'],
          }),
          profile,
        ),
      };

      try {
        return evaluateInCompartment(resolvedFilename, source, ctx);
      } catch {
        // Fall back to normal load on compartment error
        return orig(request, parent, isMain);
      }
    }

    // Observation mode: just delegate
    return orig(request, parent, isMain);
  };

  // Return an uninstall function
  return function uninstall(): void {
    if (originalLoad !== null) {
      NodeModulePrivate._load = originalLoad;
      originalLoad = null;
    }
  };
}

function guessCapabilityFromBuiltin(name: string): Capability | null {
  const n = name.replace(/^node:/, '');
  if (['fs', 'fs/promises'].includes(n)) return 'filesystem-read';
  if (['http', 'https', 'net', 'tls', 'dns', 'dgram', 'http2'].includes(n)) return 'network';
  if (['child_process', 'cluster', 'worker_threads'].includes(n)) return 'process-spawn';
  if (n === 'vm') return 'dynamic-code';
  return null;
}
