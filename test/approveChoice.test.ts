import { describe, it, expect } from 'vitest';
import { parseApproveChoice, applyApproveChoice } from '../src/policy/approveChoice';
import { PackagePolicy } from '../src/policy/lockfile';

const VALID_CAPS = new Set(['network', 'process-spawn', 'dynamic-code', 'native-binding', 'filesystem-write', 'env-access', 'filesystem-read']);

function policy(overrides: Partial<PackagePolicy> = {}): PackagePolicy {
  return { contentHash: 'sha256:test', capabilities: ['network'], status: 'pending-review', ...overrides };
}

describe('parseApproveChoice', () => {
  it('parses each single-letter choice', () => {
    expect(parseApproveChoice('a')).toBe('allow');
    expect(parseApproveChoice('d')).toBe('deny');
    expect(parseApproveChoice('r')).toBe('restrict');
    expect(parseApproveChoice('q')).toBe('quit');
    expect(parseApproveChoice('s')).toBe('skip');
  });

  it('treats an empty answer as skip', () => {
    expect(parseApproveChoice('')).toBe('skip');
    expect(parseApproveChoice('   ')).toBe('skip');
  });

  it('is case-insensitive and trims whitespace', () => {
    expect(parseApproveChoice('A')).toBe('allow');
    expect(parseApproveChoice('  q  ')).toBe('quit');
  });

  it('returns invalid for anything else', () => {
    expect(parseApproveChoice('x')).toBe('invalid');
    expect(parseApproveChoice('allow')).toBe('invalid');
  });
});

describe('applyApproveChoice', () => {
  it('allow: approves fully and clears any prior allowedCapabilities restriction', () => {
    const entry = policy({ allowedCapabilities: ['filesystem-read'] });
    const result = applyApproveChoice(entry, 'allow', undefined, undefined, VALID_CAPS);

    expect(result.changed).toBe(true);
    expect(entry.status).toBe('approved');
    expect(entry.allowedCapabilities).toBeUndefined();
  });

  it('allow: sets a note when provided, clears it when not', () => {
    const withNote = policy();
    applyApproveChoice(withNote, 'allow', undefined, 'reviewed by alice', VALID_CAPS);
    expect(withNote.note).toBe('reviewed by alice');

    const withoutNote = policy({ note: 'stale note' });
    applyApproveChoice(withoutNote, 'allow', undefined, undefined, VALID_CAPS);
    expect(withoutNote.note).toBeUndefined();
  });

  it('restrict: sets allowedCapabilities to exactly the chosen capability', () => {
    const entry = policy({ capabilities: ['network', 'env-access'] });
    const result = applyApproveChoice(entry, 'restrict', 'network', undefined, VALID_CAPS);

    expect(result.changed).toBe(true);
    expect(entry.status).toBe('approved');
    expect(entry.allowedCapabilities).toEqual(['network']);
  });

  it('deny: adds to deniedCapabilities and clears allowedCapabilities', () => {
    const entry = policy({ allowedCapabilities: ['network'] });
    const result = applyApproveChoice(entry, 'deny', 'env-access', undefined, VALID_CAPS);

    expect(result.changed).toBe(true);
    expect(entry.status).toBe('approved');
    expect(entry.deniedCapabilities).toEqual(['env-access']);
    expect(entry.allowedCapabilities).toBeUndefined();
  });

  it('deny: preserves any previously denied capabilities', () => {
    const entry = policy({ deniedCapabilities: ['filesystem-write'] });
    applyApproveChoice(entry, 'deny', 'env-access', undefined, VALID_CAPS);
    expect(entry.deniedCapabilities).toEqual(['filesystem-write', 'env-access']);
  });

  it('deny/restrict: rejects an unknown capability and leaves the entry untouched', () => {
    const entry = policy();
    const result = applyApproveChoice(entry, 'deny', 'not-a-real-capability', undefined, VALID_CAPS);

    expect(result.changed).toBe(false);
    expect(entry.status).toBe('pending-review');
  });

  it('deny/restrict: rejects a missing capability answer', () => {
    const entry = policy();
    const result = applyApproveChoice(entry, 'restrict', undefined, undefined, VALID_CAPS);

    expect(result.changed).toBe(false);
    expect(entry.status).toBe('pending-review');
  });

  it('skip: leaves the entry completely untouched', () => {
    const entry = policy();
    const result = applyApproveChoice(entry, 'skip', undefined, undefined, VALID_CAPS);

    expect(result.changed).toBe(false);
    expect(entry.status).toBe('pending-review');
  });

  it('quit: leaves the entry completely untouched (same as skip at the entry level)', () => {
    const entry = policy();
    const result = applyApproveChoice(entry, 'quit', undefined, undefined, VALID_CAPS);

    expect(result.changed).toBe(false);
    expect(entry.status).toBe('pending-review');
  });

  it('invalid: leaves the entry completely untouched', () => {
    const entry = policy();
    const result = applyApproveChoice(entry, 'invalid', undefined, undefined, VALID_CAPS);

    expect(result.changed).toBe(false);
    expect(entry.status).toBe('pending-review');
  });
});
