import { describe, it, expect } from 'vitest';
import { riskScore, riskLabel } from '../src/analyzer/riskScore';
import { PackagePolicy } from '../src/policy/lockfile';

function policy(
  caps: PackagePolicy['capabilities'],
  status: PackagePolicy['status'] = 'approved',
): PackagePolicy {
  return { contentHash: 'sha256:test', capabilities: caps, status };
}

describe('riskScore', () => {
  it('returns 100 for unsandboxed packages regardless of capabilities', () => {
    expect(riskScore(policy([], 'unsandboxed'))).toBe(100);
    expect(riskScore(policy(['network'], 'unsandboxed'))).toBe(100);
  });

  it('returns 0 for an approved package with no capabilities', () => {
    expect(riskScore(policy([]))).toBe(0);
  });

  it('scores network at 40', () => {
    expect(riskScore(policy(['network']))).toBe(40);
  });

  it('scores process-spawn at 35', () => {
    expect(riskScore(policy(['process-spawn']))).toBe(35);
  });

  it('scores dynamic-code at 30', () => {
    expect(riskScore(policy(['dynamic-code']))).toBe(30);
  });

  it('scores filesystem-write at 20', () => {
    expect(riskScore(policy(['filesystem-write']))).toBe(20);
  });

  it('scores env-access at 10', () => {
    expect(riskScore(policy(['env-access']))).toBe(10);
  });

  it('scores filesystem-read at 5', () => {
    expect(riskScore(policy(['filesystem-read']))).toBe(5);
  });

  it('adds 20 bonus for pending-review status', () => {
    const base = riskScore(policy(['env-access']));       // 10
    const pending = riskScore(policy(['env-access'], 'pending-review')); // 10 + 20 = 30
    expect(pending - base).toBe(20);
  });

  it('sums scores for multiple capabilities', () => {
    // network (40) + filesystem-write (20) = 60
    expect(riskScore(policy(['network', 'filesystem-write']))).toBe(60);
  });

  it('caps the score at 100', () => {
    // network(40) + process-spawn(35) + dynamic-code(30) = 105 → capped at 100
    expect(riskScore(policy(['network', 'process-spawn', 'dynamic-code']))).toBe(100);
  });

  it('caps at 100 even with pending-review bonus', () => {
    // network(40) + process-spawn(35) + dynamic-code(30) + pending-review(20) = 125 → capped at 100
    const score = riskScore(policy(['network', 'process-spawn', 'dynamic-code'], 'pending-review'));
    expect(score).toBe(100);
  });
});

describe('riskLabel', () => {
  it('returns NONE for score 0', () => {
    expect(riskLabel(0)).toBe('NONE');
  });

  it('returns LOW for scores 1–19', () => {
    expect(riskLabel(1)).toBe('LOW');
    expect(riskLabel(5)).toBe('LOW');
    expect(riskLabel(19)).toBe('LOW');
  });

  it('returns MEDIUM for scores 20–39', () => {
    expect(riskLabel(20)).toBe('MEDIUM');
    expect(riskLabel(39)).toBe('MEDIUM');
  });

  it('returns HIGH for scores 40–69', () => {
    expect(riskLabel(40)).toBe('HIGH');
    expect(riskLabel(69)).toBe('HIGH');
  });

  it('returns CRITICAL for scores 70–100', () => {
    expect(riskLabel(70)).toBe('CRITICAL');
    expect(riskLabel(100)).toBe('CRITICAL');
  });

  it('is consistent with riskScore output', () => {
    const unsandboxed = policy([], 'unsandboxed');
    expect(riskLabel(riskScore(unsandboxed))).toBe('CRITICAL');

    const clean = policy([]);
    expect(riskLabel(riskScore(clean))).toBe('NONE');

    const high = policy(['network']);
    expect(riskLabel(riskScore(high))).toBe('HIGH');
  });
});
