import * as fs from 'node:fs';
import * as path from 'node:path';
import { PackageScanResult } from '../analyzer/packageScanner';
import { PackagePolicy, PackageStatus } from './lockfile';
import { WardenConfig } from '../config';

/**
 * Convert a single package scan result into a lockfile policy entry.
 * Packages with native addons are marked 'unsandboxed'; packages that
 * could not be fully parsed are marked 'pending-review'.
 */
export function packageScanResultToPolicy(result: PackageScanResult): PackagePolicy {
  let status: PackageStatus;

  if (result.hasNativeBindings || result.status === 'unsandboxed') {
    status = 'unsandboxed';
  } else if (result.status === 'unanalyzable') {
    status = 'pending-review';
  } else if (result.unanalyzableFiles.length > 0) {
    status = 'pending-review';
  } else if (result.capabilities.length === 0) {
    status = 'approved';
  } else {
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

/**
 * Build a complete policy map (package key → policy) from a list of scan results.
 * The key format is "name@version" (e.g. "axios@1.6.0").
 */
export function buildPolicyMap(
  results: PackageScanResult[],
): Record<string, PackagePolicy> {
  const map: Record<string, PackagePolicy> = {};
  for (const result of results) {
    const key    = `${result.name}@${result.version}`;
    map[key]     = packageScanResultToPolicy(result);
  }
  return map;
}

// ─── Project type detection ───────────────────────────────────────────────────

export type ProjectType = 'frontend' | 'backend' | 'cli' | 'library' | 'unknown';

const FRONTEND_DEPS = new Set([
  'react', 'vue', 'angular', '@angular/core', 'svelte', 'solid-js',
  'next', 'nuxt', 'gatsby', 'remix', '@remix-run/node', 'vite',
  'webpack', 'parcel', 'rollup', 'esbuild',
]);

const BACKEND_DEPS = new Set([
  'express', 'fastify', 'koa', 'hapi', '@hapi/hapi', 'nestjs', '@nestjs/core',
  'restify', 'polka', 'micro', 'feathers', '@feathersjs/feathers',
  'socket.io', 'ws', 'grpc', '@grpc/grpc-js', 'sequelize', 'typeorm',
  'mongoose', 'pg', 'mysql2', 'better-sqlite3', 'redis', 'ioredis',
  'bull', 'bullmq', 'agenda', 'node-cron',
]);

const CLI_DEPS = new Set([
  'commander', 'yargs', 'meow', 'oclif', '@oclif/core', 'caporal', 'vorpal',
  'inquirer', 'prompts', 'ora', 'listr', 'listr2', 'ink',
]);

interface PackageJsonFull {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  bin?: Record<string, string> | string;
}

/**
 * Detect the type of the project at `projectDir` by inspecting its package.json.
 * Returns 'unknown' when the package.json is missing or unclassifiable.
 */
export function detectProjectType(projectDir: string): ProjectType {
  let pkg: PackageJsonFull;
  try {
    const raw    = fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8');
    pkg          = JSON.parse(raw) as PackageJsonFull;
  } catch {
    return 'unknown';
  }

  const allDeps = new Set([
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.devDependencies ?? {}),
    ...Object.keys(pkg.peerDependencies ?? {}),
  ]);

  const hasBin = pkg.bin !== undefined &&
    (typeof pkg.bin === 'string' || Object.keys(pkg.bin).length > 0);

  let frontendScore    = 0;
  let backendScore     = 0;
  let cliScore         = hasBin ? 2 : 0;

  for (const dep of allDeps) {
    if (FRONTEND_DEPS.has(dep)) frontendScore++;
    if (BACKEND_DEPS.has(dep)) backendScore++;
    if (CLI_DEPS.has(dep)) cliScore++;
  }

  // Library heuristic: no bin, no clear UI or server deps, has peerDependencies
  const isLibrary =
    !hasBin &&
    frontendScore === 0 &&
    backendScore === 0 &&
    cliScore === 0 &&
    Object.keys(pkg.peerDependencies ?? {}).length > 0;

  if (isLibrary) return 'library';

  const max = Math.max(frontendScore, backendScore, cliScore);
  if (max === 0) return 'unknown';

  if (cliScore >= max) return 'cli';
  if (frontendScore >= max) return 'frontend';
  return 'backend';
}

/**
 * Generate a recommended `.wardenrc.json` configuration for the project.
 *
 * - **frontend**: lenient profile (bundlers, dev tools need broad access)
 * - **backend / cli**: default profile with network packages in ignore list
 * - **library**: strict profile (minimal surface area)
 */
export function recommendConfig(projectDir: string): WardenConfig & { _projectType: ProjectType } {
  const projectType = detectProjectType(projectDir);

  // Detect common infra packages that legitimately need network / spawn
  const pkgJsonPath                   = path.join(projectDir, 'package.json');
  const knownNetworkPkgs: string[]    = [];
  try {
    const pkg              = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8')) as PackageJsonFull;
    const allDeps          = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    const KNOWN_NETWORK    = ['axios', 'node-fetch', 'got', 'superagent', 'ky', 'undici', 'cross-fetch'];
    for (const dep of allDeps) {
      if (KNOWN_NETWORK.includes(dep)) knownNetworkPkgs.push(dep);
    }
  } catch { /* ignore */ }

  let profile: 'strict' | 'default' | 'lenient';
  let autoApprove: boolean;

  switch (projectType) {
    case 'frontend':
      profile        = 'lenient';
      autoApprove    = false;
      break;
    case 'library':
      profile        = 'strict';
      autoApprove    = false;
      break;
    default:
      profile        = 'default';
      autoApprove    = false;
  }

  const config: WardenConfig & { _projectType: ProjectType } = {
    profile,
    autoApprove,
    _projectType: projectType,
  };

  if (knownNetworkPkgs.length > 0) {
    config.ignore = knownNetworkPkgs;
  }

  return config;
}
