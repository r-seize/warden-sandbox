import * as fs from 'node:fs';
import * as path from 'node:path';

interface PackageJsonMeta {
  version: string;
}

function loadVersion(): string {
  try {
    const pkgPath    = path.join(__dirname, '..', 'package.json');
    const pkg        = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as PackageJsonMeta;
    return pkg.version;
  } catch {
    return '0.0.0';
  }
}

/** Warden's own version, read once from package.json (single source of truth). */
export const VERSION = loadVersion();
