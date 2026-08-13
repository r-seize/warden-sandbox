import { Capability } from './capabilityMap';
import { PackagePolicy } from '../policy/lockfile';

const CAP_SCORES: Record<Capability, number> = {
  'native-binding':   50,
  'network':          40,
  'process-spawn':    35,
  'dynamic-code':     30,
  'filesystem-write': 20,
  'env-access':       10,
  'filesystem-read':  5,
};

export function riskScore(policy: PackagePolicy): number {
  if (policy.status === 'unsandboxed') return 100;
  let score = 0;
  for (const cap of policy.capabilities as Capability[]) {
    score += CAP_SCORES[cap] ?? 0;
  }
  if (policy.status === 'pending-review') score += 20;
  return Math.min(100, score);
}

export function riskLabel(score: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' {
  if (score >= 70) return 'CRITICAL';
  if (score >= 40) return 'HIGH';
  if (score >= 20) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}
