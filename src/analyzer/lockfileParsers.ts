/**
 * Narrow, hand-rolled parsers for the three package-manager lockfile formats
 * `warden integrity` needs to read: npm's `package-lock.json` (JSON, already
 * handled inline in cli.ts), classic Yarn v1's `yarn.lock` (a custom
 * human-readable format, not YAML), and pnpm's `pnpm-lock.yaml` (real YAML,
 * but only a small, well-known subset is parsed — no general YAML parser is
 * pulled in as a dependency).
 *
 * These are deliberately narrow: a security check that silently says
 * "all clear" because it misunderstood the file is worse than one that
 * refuses to run. Both parsers throw rather than return an empty result
 * when the file doesn't look like the format they expect.
 */

export interface LockfileIntegrityEntry {
  name: string;
  version?: string;
  /** Resolved source URL, when the format records one (npm, yarn). pnpm's
   *  `pnpm-lock.yaml` generally does not — `integrity` is the only signal there. */
  resolved?: string;
  /** Content integrity hash (e.g. "sha512-..."), when present. */
  integrity?: string;
}

// ─── yarn.lock (classic v1 format) ───────────────────────────────────────────

function parseYarnDescriptorName(descriptor: string): string | null {
  const trimmed = descriptor.trim().replace(/^"|"$/g, '');
  if (trimmed.startsWith('@')) {
    const at = trimmed.indexOf('@', 1);
    return at === -1 ? null : trimmed.slice(0, at);
  }
  const at = trimmed.indexOf('@');
  return at === -1 ? trimmed : trimmed.slice(0, at);
}

/**
 * Parse a classic Yarn v1 `yarn.lock`. Only this format is supported — Yarn
 * Berry (v2+) lockfiles use different fields (`resolution`/`checksum` instead
 * of `resolved`/`integrity`) and are not covered; such a file is detected and
 * rejected rather than silently misread.
 */
export function parseYarnLockfile(raw: string): LockfileIntegrityEntry[] {
  if (/^__metadata:/m.test(raw)) {
    throw new Error('This looks like a Yarn Berry (v2+) lockfile, which uses a different format — not supported.');
  }

  const entries: LockfileIntegrityEntry[]    = [];
  let descriptors: string[] | null           = null;
  let version: string | undefined;
  let resolved: string | undefined;
  let integrity: string | undefined;

  const flush = () => {
    if (descriptors && descriptors.length > 0) {
      const name = parseYarnDescriptorName(descriptors[0]);
      if (name) entries.push({ name, version, resolved, integrity });
    }
    descriptors = null;
    version = resolved = integrity = undefined;
  };

  for (const rawLine of raw.split('\n')) {
    if (rawLine.startsWith('#') || rawLine.trim() === '') continue;

    if (!rawLine.startsWith(' ') && !rawLine.startsWith('\t')) {
      flush();
      const header = rawLine.trim().replace(/:$/, '');
      descriptors = header.split(',').map(s => s.trim());
      continue;
    }

    const line = rawLine.trim();
    const versionMatch = /^version\s+"?([^"\s]+)"?$/.exec(line);
    if (versionMatch) { version = versionMatch[1]; continue; }

    const resolvedMatch = /^resolved\s+"([^"]+)"$/.exec(line);
    if (resolvedMatch) { resolved = resolvedMatch[1]; continue; }

    const integrityMatch = /^integrity\s+(.+)$/.exec(line);
    if (integrityMatch) { integrity = integrityMatch[1].trim().replace(/^"|"$/g, ''); continue; }
  }
  flush();

  if (entries.length === 0 && raw.trim().length > 0 && !/@.*:\s*$/m.test(raw)) {
    throw new Error('Could not find any package entries — this may not be a valid yarn.lock file.');
  }

  return entries;
}

// ─── pnpm-lock.yaml (narrow subset) ──────────────────────────────────────────

/**
 * Parse the `packages:` section of a pnpm-lock.yaml. Only a small, flat
 * subset of YAML is understood: a top-level `packages:` block mapping
 * `<name>@<version>:` (optionally prefixed with `/`, used by older pnpm
 * versions) to a block containing a `resolution: {integrity: ..., tarball: ...}`
 * inline mapping. Anything else under `packages:` is ignored rather than
 * mis-parsed. If no `packages:` key is found at all, the file doesn't look
 * like a pnpm lockfile — the caller gets a clear error instead of a silent
 * "0 issues found".
 */
export function parsePnpmLockfile(raw: string): LockfileIntegrityEntry[] {
  const lines              = raw.split('\n');
  const packagesLineIdx    = lines.findIndex(l => /^packages:\s*$/.test(l));

  if (packagesLineIdx === -1) {
    throw new Error('Could not find a top-level "packages:" section — this may not be a valid pnpm-lock.yaml file.');
  }

  const entries: LockfileIntegrityEntry[]    = [];
  let current: LockfileIntegrityEntry | null = null;

  for (let i = packagesLineIdx + 1; i < lines.length; i++) {
    const line = lines[i];

    // A non-indented, non-blank line ends the `packages:` block.
    if (line.length > 0 && !/^\s/.test(line)) break;
    if (line.trim() === '') continue;

    // Package header, exactly 2 spaces of indent: "  /name@1.0.0:" or "  name@1.0.0:"
    // (pnpm quotes scoped-package headers — "  '@scope/pkg@1.0.0':" — hence the strip.)
    const header = /^ {2}\/?(.+):\s*$/.exec(line);
    if (header) {
      if (current) entries.push(current);
      const spec    = header[1].replace(/^['"]|['"]$/g, '');
      const at      = spec.lastIndexOf('@');
      current       = at > 0 ? { name: spec.slice(0, at), version: spec.slice(at + 1) } : { name: spec };
      continue;
    }

    if (!current) continue;

    // resolution: {integrity: sha512-..., tarball: https://...}
    const resolutionMatch = /^\s+resolution:\s*\{(.+)\}\s*$/.exec(line);
    if (resolutionMatch) {
      const body            = resolutionMatch[1];
      const integrityMatch  = /integrity:\s*([^,}\s]+)/.exec(body);
      const tarballMatch    = /tarball:\s*([^,}\s]+)/.exec(body);
      if (integrityMatch) current.integrity = integrityMatch[1];
      if (tarballMatch) current.resolved = tarballMatch[1];
      continue;
    }
  }
  if (current) entries.push(current);

  return entries;
}

export type LockfileKind = 'npm' | 'pnpm' | 'yarn';

export interface DetectedLockfile {
  kind: LockfileKind;
  path: string;
}
