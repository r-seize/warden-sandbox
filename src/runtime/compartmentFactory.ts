// This file must be imported before lockdown() is called —
// it only adds 'ses' globals to globalThis, not calls lockdown.
import 'ses';
import * as nodeFs from 'node:fs';
import * as nodePath from 'node:path';
import { Capability, FS_READ_METHODS, FS_WRITE_METHODS } from '../analyzer/capabilityMap';
import { ViolationFn } from './violationHandler';

// ─── Lockdown lifecycle ───────────────────────────────────────────────────────

let lockdownDone = false;

export function ensureLockdown(): void {
  if (lockdownDone) return;
  lockdownDone = true;
  // evalTaming 'safe-eval': eval() is still available but confined to compartment scope,
  // cannot reach the outer realm. Required for packages that use eval() internally.
  // consoleTaming 'unsafe': keep console unchanged so we can see output.
  // errorTaming 'unsafe': keep Error.stack accessible for debugging.
  lockdown({
    evalTaming: 'safe-eval',
    consoleTaming: 'unsafe',
    errorTaming: 'unsafe',
    stackFiltering: 'verbose',
    overrideTaming: 'moderate',
  });
}

// ─── Tamed built-in modules ──────────────────────────────────────────────────

function makeBlockedProxy(pkgName: string, moduleName: string, cap: Capability, onViolation: ViolationFn): unknown {
  return new Proxy({}, {
    get(_target, prop) {
      onViolation({ packageName: pkgName, capability: cap, apiAccessed: `${moduleName}.${String(prop)}` });
      // After logging (observe mode), return a no-op to avoid crash
      return () => { throw new Error(`[Warden] ${moduleName}.${String(prop)} blocked for ${pkgName}`); };
    },
    apply() {
      onViolation({ packageName: pkgName, capability: cap, apiAccessed: moduleName });
      throw new Error(`[Warden] ${moduleName} blocked for ${pkgName}`);
    },
  });
}

function buildTamedFs(caps: Set<Capability>, pkgName: string, onViolation: ViolationFn): Record<string, unknown> {
  const tamed: Record<string, unknown> = {};
  const fsAny = nodeFs as unknown as Record<string, unknown>;
  const promisesAny = nodeFs.promises as unknown as Record<string, unknown>;

  const block = (methodName: string, cap: Capability) => () => {
    onViolation({ packageName: pkgName, capability: cap, apiAccessed: `fs.${methodName}` });
    throw new Error(`[Warden] fs.${methodName} blocked for ${pkgName} (missing: ${cap})`);
  };

  for (const method of FS_READ_METHODS) {
    if (method in fsAny) {
      tamed[method] = caps.has('filesystem-read')
        ? (fsAny[method] as Function).bind(nodeFs)
        : block(method, 'filesystem-read');
    }
  }
  for (const method of FS_WRITE_METHODS) {
    if (method in fsAny) {
      tamed[method] = caps.has('filesystem-write')
        ? (fsAny[method] as Function).bind(nodeFs)
        : block(method, 'filesystem-write');
    }
  }

  // fs.promises sub-object
  const tamedPromises: Record<string, unknown> = {};
  for (const method of FS_READ_METHODS) {
    if (method in promisesAny) {
      tamedPromises[method] = caps.has('filesystem-read')
        ? (promisesAny[method] as Function).bind(nodeFs.promises)
        : block(`promises.${method}`, 'filesystem-read');
    }
  }
  for (const method of FS_WRITE_METHODS) {
    if (method in promisesAny) {
      tamedPromises[method] = caps.has('filesystem-write')
        ? (promisesAny[method] as Function).bind(nodeFs.promises)
        : block(`promises.${method}`, 'filesystem-write');
    }
  }
  tamed.promises = tamedPromises;
  tamed.constants = nodeFs.constants;

  return tamed;
}

function buildTamedProcess(caps: Set<Capability>, pkgName: string, onViolation: ViolationFn): Record<string, unknown> {
  const envViolator = new Proxy(
    {},
    {
      get(_t, prop) {
        onViolation({ packageName: pkgName, capability: 'env-access', apiAccessed: `process.env.${String(prop)}` });
        return undefined;
      },
      set() {
        onViolation({ packageName: pkgName, capability: 'env-access', apiAccessed: 'process.env (write)' });
        return false;
      },
      has(_t, _prop) { return false; },
    },
  );

  return {
    version:    process.version,
    versions:   process.versions,
    platform:   process.platform,
    arch:       process.arch,
    pid:        process.pid,
    ppid:       process.ppid,
    env:        caps.has('env-access') ? process.env : envViolator,
    argv:       process.argv,
    argv0:      process.argv0,
    execPath:   process.execPath,
    execArgv:   process.execArgv,
    cwd:        process.cwd.bind(process),
    nextTick:   process.nextTick.bind(process),
    hrtime:     process.hrtime.bind(process),
    uptime:     process.uptime.bind(process),
    exit:       process.exit.bind(process),
    stdout:     process.stdout,
    stderr:     process.stderr,
    stdin:      process.stdin,
    on:         process.on.bind(process),
    once:       process.once.bind(process),
    off:        process.off.bind(process),
    removeListener: process.removeListener.bind(process),
    emit:       process.emit.bind(process),
  };
}

// Returns a tamed version of a Node.js built-in module, or throws/logs if not allowed.
export function buildTamedBuiltin(
  moduleName: string,
  caps: Set<Capability>,
  pkgName: string,
  onViolation: ViolationFn,
): unknown {
  const norm = moduleName.replace(/^node:/, '');

  if (norm === 'fs' || norm === 'fs/promises') {
    if (!caps.has('filesystem-read') && !caps.has('filesystem-write')) {
      onViolation({ packageName: pkgName, capability: 'filesystem-read', apiAccessed: moduleName });
    }
    const tamed = buildTamedFs(caps, pkgName, onViolation);
    return norm === 'fs/promises' ? tamed.promises : tamed;
  }

  if (norm === 'process') {
    return buildTamedProcess(caps, pkgName, onViolation);
  }

  const networkModules = new Set(['http', 'https', 'net', 'tls', 'dns', 'dns/promises', 'dgram', 'http2']);
  if (networkModules.has(norm)) {
    if (!caps.has('network')) {
      onViolation({ packageName: pkgName, capability: 'network', apiAccessed: moduleName });
      return makeBlockedProxy(pkgName, moduleName, 'network', onViolation);
    }
    return require(moduleName);
  }

  const spawnModules = new Set(['child_process', 'cluster', 'worker_threads']);
  if (spawnModules.has(norm)) {
    if (!caps.has('process-spawn')) {
      onViolation({ packageName: pkgName, capability: 'process-spawn', apiAccessed: moduleName });
      return makeBlockedProxy(pkgName, moduleName, 'process-spawn', onViolation);
    }
    return require(moduleName);
  }

  if (norm === 'vm') {
    if (!caps.has('dynamic-code')) {
      onViolation({ packageName: pkgName, capability: 'dynamic-code', apiAccessed: 'vm' });
      return makeBlockedProxy(pkgName, 'vm', 'dynamic-code', onViolation);
    }
    return require('vm');
  }

  // All other built-ins (path, os, events, stream, url, crypto, buffer, etc.): allow freely
  return require(moduleName);
}

// ─── Compartment creation ─────────────────────────────────────────────────────

// Cache: one Compartment per package name (not per file)
const compartmentCache = new Map<string, ReturnType<typeof buildCompartment>>();
// Module evaluation cache: filename → exports (for circular dep handling)
const moduleCache = new Map<string, { exports: Record<string, unknown> }>();

export interface PackageEvalContext {
  packageName: string;
  caps: Set<Capability>;
  onViolation: ViolationFn;
  // Controlled require passed INTO the compartment
  controlledRequire: (request: string) => unknown;
}

function buildCompartment(ctx: PackageEvalContext): { evaluate(code: string): unknown } {
  const tamedProcess = buildTamedProcess(ctx.caps, ctx.packageName, ctx.onViolation);

  // Base globals that every package gets: safe, no sensitive powers.
  // harden() deep-freezes so compartment code cannot mutate our endowments.
  const globals = harden({
    console,
    process: tamedProcess,
    Buffer,
    // Timers
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    setImmediate,
    clearImmediate,
    // Standard constructors
    URL,
    URLSearchParams,
    TextEncoder,
    TextDecoder,
    AbortController,
    AbortSignal,
    // Needed by many packages
    queueMicrotask,
    structuredClone,
  });

  // ses Compartment with new options-object form (ses@2.x)
  return new Compartment({ globals, __options__: true });
}

// Evaluate a CJS module source inside a Compartment for the given package.
// Returns module.exports.
export function evaluateInCompartment(
  filename: string,
  source: string,
  ctx: PackageEvalContext,
): Record<string, unknown> {
  // Return cached result to handle circular deps
  const cached = moduleCache.get(filename);
  if (cached) return cached.exports;

  // Insert placeholder early so circular deps get the partial object
  const mod: { exports: Record<string, unknown> } = { exports: {} };
  moduleCache.set(filename, mod);

  let compartment = compartmentCache.get(ctx.packageName);
  if (!compartment) {
    compartment = buildCompartment(ctx);
    compartmentCache.set(ctx.packageName, compartment);
  }

  // CJS modules are wrapped in a function by Node.js — replicate that here.
  // We add a 'use strict' so the Compartment's strict enforcement is explicit.
  const wrapped = `(function(require, module, exports, __filename, __dirname) {\n${source}\n})`;

  let factory: Function;
  try {
    factory = compartment.evaluate(wrapped) as Function;
  } catch (err) {
    // Parse/eval error — fall back to normal require so we don't break the app
    moduleCache.delete(filename);
    throw err;
  }

  const dir = nodePath.dirname(filename);
  factory(ctx.controlledRequire, mod, mod.exports, filename, dir);

  return mod.exports;
}

export function clearCompartmentCache(): void {
  compartmentCache.clear();
  moduleCache.clear();
  lockdownDone = false;
}
