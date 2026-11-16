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

// A likely typosquat is itself a strong deception signal — independent of (and
// often preceding) any capability it declares, since the whole point of
// typosquatting is to get installed before anyone looks closely.
const TYPOSQUAT_BONUS = 50;
// Install-time scripts run outside Warden's sandboxing entirely; weighted lower
// than a typosquat match since plenty of legitimate packages have them.
const LIFECYCLE_SCRIPT_BONUS = 15;
// A life-cycle script matching an actual risk pattern (curl|sh, base64, sudo, ...)
// is far more specific than merely declaring a script at all.
const LIFECYCLE_SCRIPT_RISK_BONUS = 25;
// Code-obfuscation idioms (base64-decoded strings feeding a call, indirect
// Function constructor access) are a deliberate attempt to dodge static
// analysis — about as strong a signal as a typosquat.
const EVASION_BONUS = 40;

export function riskScore(policy: PackagePolicy): number {
  if (policy.status === 'unsandboxed') return 100;
  let score = 0;
  for (const cap of policy.capabilities as Capability[]) {
    score += CAP_SCORES[cap] ?? 0;
  }
  if (policy.status === 'pending-review') score += 20;
  if (policy.typosquatOf) score += TYPOSQUAT_BONUS;
  if (policy.lifecycleScripts && policy.lifecycleScripts.length > 0) score += LIFECYCLE_SCRIPT_BONUS;
  if (policy.lifecycleScriptRisks && policy.lifecycleScriptRisks.length > 0) score += LIFECYCLE_SCRIPT_RISK_BONUS;
  if (policy.evasionPatterns && policy.evasionPatterns.length > 0) score += EVASION_BONUS;
  return Math.min(100, score);
}

export function riskLabel(score: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' {
  if (score >= 70) return 'CRITICAL';
  if (score >= 40) return 'HIGH';
  if (score >= 20) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}
