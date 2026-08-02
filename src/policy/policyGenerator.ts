import { PackageScanResult } from '../analyzer/packageScanner';
import { PackagePolicy, PackageStatus } from './lockfile';

export function packageScanResultToPolicy(result: PackageScanResult): PackagePolicy {
  let status: PackageStatus;

  if (result.hasNativeBindings || result.status === 'unsandboxed') {
    status = 'unsandboxed';
  } else if (result.status === 'unanalyzable') {
    // All files failed to parse — mark pending-review so humans see it
    status = 'pending-review';
  } else if (result.unanalyzableFiles.length > 0) {
    // Partial parse failure — still flag for review since we may have missed capabilities
    status = 'pending-review';
  } else if (result.capabilities.length === 0) {
    status = 'approved';
  } else {
    // Has capabilities but hasn't been reviewed yet
    status = 'pending-review';
  }

  const policy: PackagePolicy = {
    contentHash: result.contentHash,
    capabilities: result.capabilities,
    status,
  };

  if (result.hasNativeBindings) {
    policy.note = 'Package contains native .node addon(s). Cannot be sandboxed — runs with full system access.';
  } else if (result.unanalyzableFiles.length > 0) {
    policy.note = `${result.unanalyzableFiles.length} file(s) could not be parsed (may use non-standard syntax or be obfuscated). Capabilities may be incomplete.`;
  }

  return policy;
}

export function buildPolicyMap(
  results: PackageScanResult[],
): Record<string, PackagePolicy> {
  const map: Record<string, PackagePolicy> = {};
  for (const result of results) {
    const key = `${result.name}@${result.version}`;
    map[key] = packageScanResultToPolicy(result);
  }
  return map;
}
