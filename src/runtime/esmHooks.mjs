/**
 * ESM Loader Hook — runs in the Node.js loader thread (isolated from main thread).
 * Registered via module.register() in esmLoaderHook.ts.
 * Must be plain ESM — no TypeScript compilation.
 *
 * Architecture:
 *   resolve() — has context.parentURL; detects violations and rewrites blocked
 *               imports to a warden:blocked:... sentinel URL
 *   load()    — handles the warden:blocked:... URL; returns a synthetic stub
 *               module that throws on every access
 */

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { sep } from 'node:path';

const _require = createRequire(import.meta.url);

// ── State injected by initialize() ──────────────────────────────────────────

/** @type {object|null} */
let lockfile       = null;
let enforceMode    = false;
let profile        = 'default'; // 'strict' | 'default' | 'lenient'
/** @type {import('node:worker_threads').MessagePort|null} */
let violationPort = null;

const STRICT_EXTRA_BLOCKED      = new Set(['env-access']);
const LENIENT_ALWAYS_ALLOWED    = new Set(['filesystem-read', 'env-access']);

// ── Capability map ───────────────────────────────────────────────────────────

const CAPABILITY_MAP = {
  'node:fs':             'filesystem',
  'node:fs/promises':    'filesystem',
  'node:http':           'network',
  'node:https':          'network',
  'node:net':            'network',
  'node:tls':            'network',
  'node:dns':            'network',
  'node:dns/promises':   'network',
  'node:dgram':          'network',
  'node:http2':          'network',
  'node:child_process':  'process-spawn',
  'node:cluster':        'process-spawn',
  'node:worker_threads': 'process-spawn',
  'node:vm':             'dynamic-code',
};

// Also handle bare specifiers without node: prefix
const BARE_TO_NODE = Object.fromEntries(
  Object.keys(CAPABILITY_MAP).map(k => [k.replace('node:', ''), k])
);

// ── Helpers ──────────────────────────────────────────────────────────────────

function normalizeSpecifier(specifier) {
  if (specifier.startsWith('node:')) return specifier;
  return BARE_TO_NODE[specifier] ?? specifier;
}

function getPackageNameFromURL(fileURL) {
  if (!fileURL) return null;
  let filePath;
  try { filePath    = fileURLToPath(fileURL); } catch { return null; }
  const marker      = `node_modules${sep}`;
  const idx         = filePath.lastIndexOf(marker);
  if (idx === -1) return null;
  const rest = filePath.slice(idx + marker.length);
  if (rest.startsWith('@')) {
    const parts = rest.split(sep);
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  }
  return rest.split(sep)[0] ?? null;
}

function getPolicyForPackage(pkgName) {
  if (!lockfile) return null;
  const key = Object.keys(lockfile.packages).find(k => {
    const at = k.lastIndexOf('@');
    return k.slice(0, at) === pkgName;
  });
  return key ? lockfile.packages[key] : null;
}

function effectiveCaps(policy) {
  if (enforceMode && policy.status !== 'approved' && policy.status !== 'unsandboxed') {
    if (profile === 'lenient') {
      const base = new Set(LENIENT_ALWAYS_ALLOWED);
      if (policy.deniedCapabilities) {
        for (const cap of policy.deniedCapabilities) base.delete(cap);
      }
      return base;
    }
    return new Set();
  }

  const base = new Set(policy.allowedCapabilities ?? policy.capabilities);

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

function policyAllows(caps, requiredCap) {
  if (requiredCap === 'filesystem') {
    return caps.has('filesystem-read') || caps.has('filesystem-write');
  }
  return caps.has(requiredCap);
}

function fireViolation(event) {
  if (violationPort) {
    violationPort.postMessage(event);
  } else {
    process.stderr.write(
      `\n[Warden] VIOLATION (ESM): ${event.packageName} accessed ${event.apiAccessed}` +
      ` (capability: ${event.capability}) — not declared in policy\n`,
    );
  }
}

/**
 * Builds a synthetic ESM module source that throws on any access.
 * Introspects the real CJS module's named exports so stubs are correctly named
 * (ESM named exports must be statically declared).
 */
function buildBlockedModuleSource(nodeUrl, pkgName, cap) {
  const moduleName    = nodeUrl.replace(/^node:/, '');
  let namedExports    = [];
  try {
    const real      = _require(moduleName);
    namedExports    = Object.keys(real).filter(k => /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(k));
  } catch { /* ignore */ }

  const namedStubs = namedExports.map(name => {
    const msg = JSON.stringify(
      `[Warden] VIOLATION: ${pkgName} accessed ${moduleName}.${name} (capability: ${cap}) — not declared in policy`,
    );
    return `export const ${name} = (..._) => { throw new Error(${msg}); };`;
  }).join('\n');

  const defaultMsg = JSON.stringify(
    `[Warden] VIOLATION: ${pkgName} accessed ${moduleName} (capability: ${cap}) — not declared in policy`,
  );

  return `
${namedStubs}
const _blocked = new Proxy({}, {
  get(_, prop) {
    // Allow symbol and introspection accesses so util.inspect / console.log don't throw
    if (typeof prop === 'symbol') return undefined;
    if (prop === 'constructor') return Object;
    if (prop === 'toString' || prop === 'valueOf' || prop === 'toJSON') {
      return () => '[Warden: blocked module ${moduleName}]';
    }
    // Any real API call throws
    const msg = ${defaultMsg};
    throw new Error(msg.replace(${JSON.stringify(moduleName)}, \`${moduleName}.\${String(prop)}\`));
  },
});
export default _blocked;
`.trimStart();
}

// ── Hooks ────────────────────────────────────────────────────────────────────

export function initialize({ lockfile: lf, enforce, port, profile: p }) {
  lockfile         = lf;
  enforceMode      = enforce ?? false;
  profile          = p ?? 'default';
  violationPort    = port ?? null;
}

/**
 * resolve() — runs before load(); has context.parentURL so we can identify
 * which package is importing what.
 *
 * Enforcement: rewrite blocked imports to a data: URL containing a stub module
 *   that throws on any real API usage. data: URLs are natively supported by
 *   Node's ESM loader (unlike custom protocols) so they bypass further hooks.
 * Observation: fire violation and allow through.
 */
export async function resolve(specifier, context, nextResolve) {
  const normalized     = normalizeSpecifier(specifier);
  const requiredCap    = CAPABILITY_MAP[normalized];
  if (!requiredCap) return nextResolve(specifier, context);

  const callerPkg = getPackageNameFromURL(context.parentURL);
  if (!callerPkg) {
    // User's own code — full trust
    return nextResolve(specifier, context);
  }

  const rawPolicy = getPolicyForPackage(callerPkg);

  if (!rawPolicy) {
    // Not in lockfile — treat as violation
    fireViolation({
      packageName: callerPkg,
      capability: requiredCap === 'filesystem' ? 'filesystem-read' : requiredCap,
      apiAccessed: normalized.replace('node:', '') + ' (package not in lockfile)',
    });
    return nextResolve(specifier, context);
  }

  const caps = effectiveCaps(rawPolicy);

  if (policyAllows(caps, requiredCap)) {
    return nextResolve(specifier, context);
  }

  // Violation
  const capForEvent    = requiredCap === 'filesystem' ? 'filesystem-read' : requiredCap;
  const apiName        = normalized.replace('node:', '');

  fireViolation({ packageName: callerPkg, capability: capForEvent, apiAccessed: apiName });

  if (enforceMode) {
    // Return stub source as a data: URL — avoids custom protocol issues and
    // makes load() unnecessary for the blocked case.
    const source = buildBlockedModuleSource(normalized, callerPkg, capForEvent);
    return {
      url: `data:text/javascript,${encodeURIComponent(source)}`,
      shortCircuit: true,
    };
  }

  // Observation: allow through
  return nextResolve(specifier, context);
}

/**
 * load() — only needed for data: URLs we produce (Node handles them natively,
 * so this hook just passes through everything).
 */
export async function load(url, context, nextLoad) {
  return nextLoad(url, context);
}
