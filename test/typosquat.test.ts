import { describe, it, expect } from 'vitest';
import { detectTyposquat } from '../src/analyzer/typosquat';

describe('detectTyposquat', () => {
  it('flags a one-character substitution of a popular package', () => {
    expect(detectTyposquat('lodahs')).toBe('lodash');
  });

  it('flags a one-character deletion of a popular package', () => {
    expect(detectTyposquat('expres')).toBe('express');
  });

  it('flags a one-character insertion against a popular package', () => {
    expect(detectTyposquat('chalkk')).toBe('chalk');
  });

  it('does not flag the popular package itself', () => {
    expect(detectTyposquat('lodash')).toBeNull();
    expect(detectTyposquat('express')).toBeNull();
  });

  it('does not flag unrelated package names', () => {
    expect(detectTyposquat('my-internal-tool')).toBeNull();
  });

  it('does not flag legitimate submodule-style variants (large edit distance)', () => {
    expect(detectTyposquat('lodash.debounce')).toBeNull();
    expect(detectTyposquat('babel-core')).not.toBe('express'); // sanity: unrelated popular entries don't match
  });

  it('skips scoped packages entirely', () => {
    expect(detectTyposquat('@scope/lodahs')).toBeNull();
  });

  it('skips names shorter than the minimum length', () => {
    expect(detectTyposquat('ws')).toBeNull();
    expect(detectTyposquat('fs')).toBeNull();
  });
});
