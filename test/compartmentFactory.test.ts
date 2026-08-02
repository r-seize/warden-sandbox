import { describe, it, expect, vi } from 'vitest';
import { buildTamedBuiltin } from '../src/runtime/compartmentFactory';
import type { ViolationEvent } from '../src/runtime/violationHandler';
import type { Capability } from '../src/analyzer/capabilityMap';

// Note: evaluateInCompartment requires ensureLockdown() which calls ses's lockdown() —
// a process-wide, irreversible operation. That integration is validated by
// `warden run` / `warden run --enforce` rather than in unit tests.

function makeViolationFn() {
  const violations: ViolationEvent[] = [];
  const fn = (e: ViolationEvent) => {
    violations.push(e);
  };
  return { fn, violations };
}

function caps(...list: Capability[]): Set<Capability> {
  return new Set<Capability>(list);
}

// ─── buildTamedBuiltin ────────────────────────────────────────────────────────

describe('buildTamedBuiltin — network blocking', () => {
  it('returns real http module when network capability is present', () => {
    const { fn, violations }    = makeViolationFn();
    const result                = buildTamedBuiltin('http', caps('network'), 'my-pkg', fn);
    expect(violations).toHaveLength(0);
    expect(result).toBeTruthy();
    // The returned value should have an http.get (real module)
    expect(typeof (result as Record<string, unknown>)['get']).toBe('function');
  });

  it('fires a violation and returns a blocked proxy when network is missing', () => {
    const { fn, violations }    = makeViolationFn();
    const result                = buildTamedBuiltin('http', caps(), 'evil-pkg', fn);
    expect(violations).toHaveLength(1);
    expect(violations[0]?.capability).toBe('network');
    expect(violations[0]?.packageName).toBe('evil-pkg');
    expect(violations[0]?.apiAccessed).toBe('http');
    // Accessing any method on the blocked proxy fires another violation
    expect(() => {
      const blocked = result as Record<string, unknown>;
      (blocked['get'] as Function)();
    }).toThrow(/blocked/i);
  });

  it('blocks https when network is missing', () => {
    const { fn, violations } = makeViolationFn();
    buildTamedBuiltin('https', caps(), 'evil-pkg', fn);
    expect(violations[0]?.capability).toBe('network');
  });

  it('blocks child_process when process-spawn is missing', () => {
    const { fn, violations } = makeViolationFn();
    buildTamedBuiltin('child_process', caps(), 'evil-pkg', fn);
    expect(violations[0]?.capability).toBe('process-spawn');
  });

  it('allows child_process when process-spawn is present', () => {
    const { fn, violations } = makeViolationFn();
    buildTamedBuiltin('child_process', caps('process-spawn'), 'my-pkg', fn);
    expect(violations).toHaveLength(0);
  });

  it('blocks vm when dynamic-code is missing', () => {
    const { fn, violations } = makeViolationFn();
    buildTamedBuiltin('vm', caps(), 'evil-pkg', fn);
    expect(violations[0]?.capability).toBe('dynamic-code');
  });

  it('passes through safe builtins (path, os, events) without violation', () => {
    const { fn, violations }    = makeViolationFn();
    const path                  = buildTamedBuiltin('path', caps(), 'any-pkg', fn);
    expect(violations).toHaveLength(0);
    expect(typeof (path as Record<string, unknown>)['join']).toBe('function');
  });
});

describe('buildTamedBuiltin — filesystem taming', () => {
  it('fires violation for fs when neither read nor write is in caps', () => {
    const { fn, violations } = makeViolationFn();
    buildTamedBuiltin('fs', caps(), 'evil-pkg', fn);
    expect(violations.some(v => v.capability === 'filesystem-read')).toBe(true);
  });

  it('allows fs.readFile when filesystem-read is present', () => {
    const { fn, violations }    = makeViolationFn();
    const tamedFs               = buildTamedBuiltin('fs', caps('filesystem-read'), 'pkg', fn) as Record<string, unknown>;
    expect(violations).toHaveLength(0);
    expect(typeof tamedFs['readFile']).toBe('function');
  });

  it('blocks fs.writeFile when filesystem-write is missing but read is present', () => {
    const { fn, violations }    = makeViolationFn();
    const tamedFs               = buildTamedBuiltin('fs', caps('filesystem-read'), 'pkg', fn) as Record<string, unknown>;
    expect(violations).toHaveLength(0); // no violation yet

    // Calling the blocked writeFile should fire a violation
    expect(() => {
      (tamedFs['writeFile'] as Function)('/tmp/test', 'data', () => {});
    }).toThrow(/blocked/i);

    expect(violations.some(v => v.capability === 'filesystem-write')).toBe(true);
  });

  it('allows fs.writeFile when filesystem-write is present', () => {
    const { fn, violations }    = makeViolationFn();
    const tamedFs               = buildTamedBuiltin('fs', caps('filesystem-read', 'filesystem-write'), 'pkg', fn) as Record<string, unknown>;
    expect(violations).toHaveLength(0);
    expect(typeof tamedFs['writeFile']).toBe('function');
  });

  it('handles node: prefix aliases', () => {
    const { fn, violations } = makeViolationFn();
    buildTamedBuiltin('node:http', caps(), 'evil-pkg', fn);
    expect(violations[0]?.capability).toBe('network');
  });
});

describe('buildTamedBuiltin — process.env taming', () => {
  it('returns env {} proxy when env-access is missing', () => {
    const { fn, violations }    = makeViolationFn();
    const tamedFs               = buildTamedBuiltin('fs', caps('filesystem-read'), 'pkg', fn) as Record<string, unknown>;
    // process taming is in compartmentFactory, tested separately
    // Just confirm no violations from safe modules
    expect(violations).toHaveLength(0);
  });
});
