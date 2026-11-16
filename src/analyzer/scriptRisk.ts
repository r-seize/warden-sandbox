/**
 * Static, string-pattern risk analysis for npm life-cycle scripts
 * (`preinstall`/`install`/`postinstall`) that are NOT a direct `node <file>.js`
 * invocation — i.e. the ones `warden inspect-script` cannot sandbox-run.
 *
 * This never executes anything; it only looks for well-known suspicious
 * substrings in the script's command text, to turn "cannot be sandboxed,
 * review manually" into a concrete list of what to look for. A command
 * matching none of these patterns is not proven safe — it's just not
 * flagged by this narrow heuristic.
 */

interface RiskPattern {
  label: string;
  regex: RegExp;
}

const RISK_PATTERNS: RiskPattern[] = [
  { label: 'downloads over the network (curl)', regex: /\bcurl\b/ },
  { label: 'downloads over the network (wget)', regex: /\bwget\b/ },
  { label: 'raw network tool (nc/netcat/ncat)', regex: /\b(?:nc|ncat|netcat)\b/ },
  { label: 'base64 encoding/decoding (common obfuscation technique)', regex: /\bbase64\b/ },
  { label: 'makes a file executable (chmod +x or similar)', regex: /\bchmod\s+(?:\+x|[0-7]*7[0-7]*)\b/ },
  { label: 'pipes content directly into a shell or interpreter', regex: /\|\s*(?:sh|bash|zsh|python[23]?|node|perl|ruby)\b/ },
  { label: 'writes to a shell profile or crontab', regex: /\.(?:bashrc|bash_profile|zshrc|profile)\b|\bcrontab\b/ },
  { label: 'reads/writes SSH keys', regex: /\.ssh\b/ },
  { label: 'runs with elevated privileges (sudo)', regex: /\bsudo\b/ },
  { label: 'eval-like dynamic shell execution', regex: /\beval\b/ },
];

/**
 * Return the list of matched risk-pattern labels for a life-cycle script
 * command string. Empty when nothing matched — not a guarantee the script
 * is safe, just that none of these specific patterns were found.
 */
export function analyzeLifecycleScriptRisk(command: string): string[] {
  const matched: string[] = [];
  for (const pattern of RISK_PATTERNS) {
    if (pattern.regex.test(command)) matched.push(pattern.label);
  }
  return matched;
}
